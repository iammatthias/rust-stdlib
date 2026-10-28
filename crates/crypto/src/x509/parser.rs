//! Parsing of certificates, certificate requests and revocation lists, a port
//! of Go's `parser.go` (and the `encoding/asn1` based parts of `x509.go`).

use std::collections::HashSet;

use super::asn1::{self, BitString, ObjectIdentifier, RawValue, Reader};
use super::asn1_time;
use super::asn1_unmarshal::{shapes, unmarshal_value, Node, Ty, Value as Parsed};
use super::cert::*;
use super::error::{quote, quote_bytes};
use super::keys;
use super::net::{Ip, IpNet};
use super::oid::Oid;
use super::pkix::{
    self, AlgorithmIdentifier, AttributeTypeAndValue, Extension, RDNSequence,
    RelativeDistinguishedNameSET, Value,
};
use super::time::Time;
use super::types::*;
use super::url::{self, Url};
use super::verify::parse_rfc2821_mailbox;
use super::Error;

fn err<T>(msg: &str) -> Result<T, Error> {
    Err(Error::new(msg))
}

/// `isPrintable` of `parser.go`: whether `b` is in the ASN.1 PrintableString
/// set, with the leniencies Go allows.
fn is_printable(b: u8) -> bool {
    b.is_ascii_lowercase()
        || b.is_ascii_uppercase()
        || b.is_ascii_digit()
        || (b'\''..=b')').contains(&b)
        || (b'+'..=b'/').contains(&b)
        || b == b' '
        || b == b':'
        || b == b'='
        || b == b'?'
        // Technically not allowed, but wildcard strings don't always use the
        // correct string type.
        || b == b'*'
        // Not allowed either, but relatively common.
        || b == b'&'
}

/// Go's `parseASN1String`.
pub(crate) fn parse_asn1_string(tag: u8, value: &[u8]) -> Result<String, String> {
    match tag {
        asn1::T61_STRING => {
            // T.61 is treated as Latin-1, as BoringSSL does.
            Ok(value.iter().map(|&b| b as char).collect())
        }
        asn1::PRINTABLE_STRING => {
            if value.iter().all(|&b| is_printable(b)) {
                Ok(String::from_utf8_lossy(value).into_owned())
            } else {
                Err("invalid PrintableString".to_string())
            }
        }
        asn1::UTF8_STRING => match std::str::from_utf8(value) {
            Ok(s) => Ok(s.to_string()),
            Err(_) => Err("invalid UTF-8 string".to_string()),
        },
        asn1::BMP_STRING => {
            if !value.len().is_multiple_of(2) {
                return Err("invalid BMPString".to_string());
            }
            let mut value = value;
            // Strip terminator if present.
            let l = value.len();
            if l >= 2 && value[l - 1] == 0 && value[l - 2] == 0 {
                value = &value[..l - 2];
            }
            let mut units = Vec::with_capacity(value.len() / 2);
            for pair in value.chunks(2) {
                let point = u16::from(pair[0]) << 8 | u16::from(pair[1]);
                // Reject permanently reserved noncharacters and surrogates.
                if point == 0xfffe
                    || point == 0xffff
                    || (0xfdd0..=0xfdef).contains(&point)
                    || (0xd800..=0xdfff).contains(&point)
                {
                    return Err("invalid BMPString".to_string());
                }
                units.push(point);
            }
            Ok(String::from_utf16_lossy(&units))
        }
        asn1::IA5_STRING => {
            if value.is_ascii() {
                Ok(String::from_utf8_lossy(value).into_owned())
            } else {
                Err("invalid IA5String".to_string())
            }
        }
        asn1::NUMERIC_STRING => {
            if value.iter().all(|&b| b.is_ascii_digit() || b == b' ') {
                Ok(String::from_utf8_lossy(value).into_owned())
            } else {
                Err("invalid NumericString".to_string())
            }
        }
        _ => Err(format!("unsupported string type: {tag}")),
    }
}

/// Go's `readASN1Any`: parses the types documented at [`Value`].
pub(crate) fn read_asn1_any(der: &mut Reader<'_>) -> Result<Value, String> {
    let Some((value_tag, full_value)) = der.read_any_element() else {
        return Err("invalid ASN.1 element".to_string());
    };
    let mut full = Reader(full_value);
    match value_tag {
        asn1::T61_STRING
        | asn1::PRINTABLE_STRING
        | asn1::UTF8_STRING
        | asn1::BMP_STRING
        | asn1::IA5_STRING
        | asn1::NUMERIC_STRING => {
            let Some(raw) = full.read(value_tag) else {
                return Err("invalid ASN.1 element".to_string());
            };
            parse_asn1_string(value_tag, raw).map(Value::String)
        }
        asn1::INTEGER => match full.read_i64() {
            Some(i) => Ok(Value::Int(i)),
            None => Err("invalid ASN.1 integer".to_string()),
        },
        asn1::BIT_STRING => match full.read_bit_string() {
            Some(bs) => Ok(Value::BitString(bs)),
            None => Err("invalid ASN.1 BIT STRING".to_string()),
        },
        asn1::OCTET_STRING => match full.read(asn1::OCTET_STRING) {
            Some(s) => Ok(Value::Bytes(s.to_vec())),
            None => Err("invalid ASN.1 OCTET STRING".to_string()),
        },
        asn1::OBJECT_IDENTIFIER => match full.read_oid() {
            Some(oid) => Ok(Value::ObjectIdentifier(oid)),
            None => Err("invalid ASN.1 OBJECT IDENTIFIER".to_string()),
        },
        asn1::UTC_TIME | asn1::GENERALIZED_TIME => read_asn1_time(&mut full)
            .map(Value::Time)
            .map_err(|e| e.to_string()),
        asn1::BOOLEAN => match full.read_boolean() {
            Some(b) => Ok(Value::Bool(b)),
            None => Err("invalid ASN.1 BOOLEAN".to_string()),
        },
        asn1::NULL => Ok(Value::Nil),
        _ => {
            let mut v = RawValue {
                class: i64::from(value_tag >> 6),
                is_compound: value_tag & 0x20 == 0x20,
                tag: i64::from(value_tag & 0x1f),
                full_bytes: full_value.to_vec(),
                ..RawValue::default()
            };
            match Reader(full_value).read_any() {
                Some((_, contents)) => v.bytes = contents.to_vec(),
                None => return Err("invalid ASN.1 element".to_string()),
            }
            Ok(Value::Raw(v))
        }
    }
}

/// Go's `parseName`: parses a DER encoded Name as defined in RFC 5280.
pub(crate) fn parse_name(raw: &[u8]) -> Result<RDNSequence, Error> {
    let mut raw = Reader(raw);
    let Some(content) = raw.read(asn1::SEQUENCE) else {
        return err("x509: invalid RDNSequence");
    };
    let mut raw = Reader(content);
    let mut rdn_seq = RDNSequence::default();
    while !raw.empty() {
        let mut rdn_set = RelativeDistinguishedNameSET::default();
        let Some(set) = raw.read(asn1::SET) else {
            return err("x509: invalid RDNSequence");
        };
        let mut set = Reader(set);
        while !set.empty() {
            let Some(atav) = set.read(asn1::SEQUENCE) else {
                return err("x509: invalid RDNSequence: invalid attribute");
            };
            let mut atav = Reader(atav);
            let Some(type_) = atav.read_oid() else {
                return err("x509: invalid RDNSequence: invalid attribute type");
            };
            let value = read_asn1_any(&mut atav).map_err(|e| {
                Error::new(format!(
                    "x509: invalid RDNSequence: invalid attribute value: {e}"
                ))
            })?;
            rdn_set.0.push(AttributeTypeAndValue { type_, value });
        }
        rdn_seq.0.push(rdn_set);
    }
    Ok(rdn_seq)
}

/// Go's `parseAI`.
pub(crate) fn parse_ai(der: &[u8]) -> Result<AlgorithmIdentifier, Error> {
    let mut der = Reader(der);
    let Some(algorithm) = der.read_oid() else {
        return err("x509: malformed OID");
    };
    let mut ai = AlgorithmIdentifier {
        algorithm,
        parameters: RawValue::default(),
    };
    if der.empty() {
        return Ok(ai);
    }
    let Some((tag, params)) = der.read_any_element() else {
        return err("x509: malformed parameters");
    };
    ai.parameters.tag = i64::from(tag);
    ai.parameters.full_bytes = params.to_vec();
    Ok(ai)
}

/// Go's `readASN1Time`.
pub(crate) fn read_asn1_time(der: &mut Reader<'_>) -> Result<Time, Error> {
    if der.peek_tag(asn1::UTC_TIME) {
        der.read_utc_time()
            .ok_or_else(|| Error::new("x509: malformed UTCTime"))
    } else if der.peek_tag(asn1::GENERALIZED_TIME) {
        der.read_generalized_time()
            .ok_or_else(|| Error::new("x509: malformed GeneralizedTime"))
    } else {
        err("x509: unsupported time format")
    }
}

fn parse_validity(der: &[u8]) -> Result<(Time, Time), Error> {
    let mut der = Reader(der);
    let not_before = read_asn1_time(&mut der)?;
    let not_after = read_asn1_time(&mut der)?;
    Ok((not_before, not_after))
}

/// Go's `parseExtension`.
pub(crate) fn parse_extension(der: &[u8]) -> Result<Extension, Error> {
    let mut der = Reader(der);
    let mut ext = Extension::default();
    let Some(id) = der.read_oid() else {
        return err("x509: malformed extension OID field");
    };
    ext.id = id;
    if der.peek_tag(asn1::BOOLEAN) {
        match der.read_boolean() {
            Some(b) => ext.critical = b,
            None => return err("x509: malformed extension critical field"),
        }
    }
    let Some(val) = der.read(asn1::OCTET_STRING) else {
        return err("x509: malformed extension value field");
    };
    ext.value = val.to_vec();
    Ok(ext)
}

fn parse_key_usage_extension(der: &[u8]) -> Result<KeyUsage, Error> {
    let mut der = Reader(der);
    let Some(usage_bits) = der.read_bit_string() else {
        return err("x509: invalid key usage");
    };
    let mut usage = 0;
    for i in 0..9 {
        if usage_bits.at(i) != 0 {
            usage |= 1 << i;
        }
    }
    Ok(KeyUsage(usage))
}

fn parse_basic_constraints_extension(der: &[u8]) -> Result<(bool, i64), Error> {
    let mut der = Reader(der);
    let Some(seq) = der.read(asn1::SEQUENCE) else {
        return err("x509: invalid basic constraints");
    };
    let mut der = Reader(seq);
    let mut is_ca = false;
    if der.peek_tag(asn1::BOOLEAN) {
        match der.read_boolean() {
            Some(b) => is_ca = b,
            None => return err("x509: invalid basic constraints"),
        }
    }
    let mut max_path_len = -1;
    if der.peek_tag(asn1::INTEGER) {
        match der.read_u64() {
            Some(mpl) if mpl <= i64::MAX as u64 => max_path_len = mpl as i64,
            _ => return err("x509: invalid basic constraints"),
        }
    }
    Ok((is_ca, max_path_len))
}

const NAME_TYPE_EMAIL: i32 = 1;
const NAME_TYPE_DNS: i32 = 2;
const NAME_TYPE_URI: i32 = 6;
const NAME_TYPE_IP: i32 = 7;

fn for_each_san(
    der: &[u8],
    mut callback: impl FnMut(i32, &[u8]) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut der = Reader(der);
    let Some(seq) = der.read(asn1::SEQUENCE) else {
        return err("x509: invalid subject alternative names");
    };
    let mut der = Reader(seq);
    while !der.empty() {
        let Some((tag, san)) = der.read_any() else {
            return err("x509: invalid subject alternative name");
        };
        callback(i32::from(tag ^ 0x80), san)?;
    }
    Ok(())
}

pub(crate) type San = (Vec<String>, Vec<String>, Vec<Ip>, Vec<Url>);

/// Go's `parseSANExtension`.
pub(crate) fn parse_san_extension(der: &[u8]) -> Result<San, Error> {
    let mut dns_names = Vec::new();
    let mut email_addresses = Vec::new();
    let mut ip_addresses = Vec::new();
    let mut uris = Vec::new();
    for_each_san(der, |tag, data| {
        match tag {
            NAME_TYPE_EMAIL => {
                let email = String::from_utf8_lossy(data).into_owned();
                if is_ia5_string(&email).is_err() || !data.is_ascii() {
                    return err("x509: SAN rfc822Name is malformed");
                }
                email_addresses.push(email);
            }
            NAME_TYPE_DNS => {
                let name = String::from_utf8_lossy(data).into_owned();
                if is_ia5_string(&name).is_err() || !data.is_ascii() {
                    return err("x509: SAN dNSName is malformed");
                }
                dns_names.push(name);
            }
            NAME_TYPE_URI => {
                let uri_str = String::from_utf8_lossy(data).into_owned();
                if is_ia5_string(&uri_str).is_err() || !data.is_ascii() {
                    return err("x509: SAN uniformResourceIdentifier is malformed");
                }
                let uri = url::parse(&uri_str).map_err(|e| {
                    Error::new(format!("x509: cannot parse URI {}: {e}", quote(&uri_str)))
                })?;
                if !uri.host.is_empty() && !domain_name_valid(&uri.host, false) {
                    return Err(Error::new(format!(
                        "x509: cannot parse URI {}: invalid domain",
                        quote(&uri_str)
                    )));
                }
                uris.push(uri);
            }
            NAME_TYPE_IP => match data.len() {
                16 => {
                    if Ip(data.to_vec()).to4().is_some() {
                        return err("x509: SAN iPAddress contains IPv4-mapped IPv6 address");
                    }
                    ip_addresses.push(Ip(data.to_vec()));
                }
                4 => ip_addresses.push(Ip(data.to_vec())),
                n => {
                    return Err(Error::new(format!(
                        "x509: cannot parse IP address of length {n}"
                    )))
                }
            },
            _ => {}
        }
        Ok(())
    })?;
    Ok((dns_names, email_addresses, ip_addresses, uris))
}

fn parse_authority_key_identifier(e: &Extension) -> Result<Vec<u8>, Error> {
    // RFC 5280, Section 4.2.1.1
    if e.critical {
        // Conforming CAs MUST mark this extension as non-critical.
        return err("x509: authority key identifier incorrectly marked critical");
    }
    let mut val = Reader(&e.value);
    let Some(akid) = val.read(asn1::SEQUENCE) else {
        return err("x509: invalid authority key identifier");
    };
    let mut akid = Reader(akid);
    if akid.peek_tag(asn1::context(0)) {
        let Some(id) = akid.read(asn1::context(0)) else {
            return err("x509: invalid authority key identifier");
        };
        return Ok(id.to_vec());
    }
    Ok(Vec::new())
}

fn parse_ext_key_usage_extension(
    der: &[u8],
) -> Result<(Vec<ExtKeyUsage>, Vec<ObjectIdentifier>), Error> {
    let mut der = Reader(der);
    let Some(seq) = der.read(asn1::SEQUENCE) else {
        return err("x509: invalid extended key usages");
    };
    let mut der = Reader(seq);
    let mut ext_key_usages = Vec::new();
    let mut unknown_usages = Vec::new();
    while !der.empty() {
        let Some(eku) = der.read_oid() else {
            return err("x509: invalid extended key usages");
        };
        match ext_key_usage_from_oid(&eku) {
            Some(usage) => ext_key_usages.push(usage),
            None => unknown_usages.push(eku),
        }
    }
    Ok((ext_key_usages, unknown_usages))
}

fn parse_certificate_policies_extension(der: &[u8]) -> Result<Vec<Oid>, Error> {
    let mut oids = Vec::new();
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    let mut der = Reader(der);
    let Some(seq) = der.read(asn1::SEQUENCE) else {
        return err("x509: invalid certificate policies");
    };
    let mut der = Reader(seq);
    while !der.empty() {
        let Some(cp) = der.read(asn1::SEQUENCE) else {
            return err("x509: invalid certificate policies");
        };
        let mut cp = Reader(cp);
        let Some(oid_bytes) = cp.read(asn1::OBJECT_IDENTIFIER) else {
            return err("x509: invalid certificate policies");
        };
        if !seen.insert(oid_bytes.to_vec()) {
            return err("x509: invalid certificate policies");
        }
        let Some(oid) = Oid::from_der(oid_bytes) else {
            return err("x509: invalid certificate policies");
        };
        oids.push(oid);
    }
    Ok(oids)
}

/// Go's `isValidIPMask`: whether `mask` consists of zero or more 1 bits,
/// followed by zero bits.
fn is_valid_ip_mask(mask: &[u8]) -> bool {
    let mut seen_zero = false;
    for &b in mask {
        if seen_zero {
            if b != 0 {
                return false;
            }
            continue;
        }
        match b {
            0x00 | 0x80 | 0xc0 | 0xe0 | 0xf0 | 0xf8 | 0xfc | 0xfe => seen_zero = true,
            0xff => {}
            _ => return false,
        }
    }
    true
}

type Subtrees = (Vec<String>, Vec<IpNet>, Vec<String>, Vec<String>);

fn parse_name_constraints_extension(out: &mut Certificate, e: &Extension) -> Result<bool, Error> {
    // RFC 5280, 4.2.1.10
    let mut outer = Reader(&e.value);
    let mut unhandled = false;
    let parsed = (|| {
        let toplevel = outer.read(asn1::SEQUENCE)?;
        if !outer.empty() {
            return None;
        }
        let mut toplevel = Reader(toplevel);
        let permitted = toplevel.read_optional(asn1::context_constructed(0))?;
        let excluded = toplevel.read_optional(asn1::context_constructed(1))?;
        if !toplevel.empty() {
            return None;
        }
        Some((permitted, excluded))
    })();
    let Some((permitted, excluded)) = parsed else {
        return err("x509: invalid NameConstraints extension");
    };

    let have_permitted = permitted.is_some();
    let have_excluded = excluded.is_some();
    let permitted = permitted.unwrap_or(&[]);
    let excluded = excluded.unwrap_or(&[]);
    if !have_permitted && !have_excluded || permitted.is_empty() && excluded.is_empty() {
        // From RFC 5280, Section 4.2.1.10: "either the permittedSubtrees field
        // or the excludedSubtrees MUST be present".
        return err("x509: empty name constraints extension");
    }

    let mut get_values = |subtrees: &[u8]| -> Result<Subtrees, Error> {
        let mut subtrees = Reader(subtrees);
        let mut dns_names = Vec::new();
        let mut ips = Vec::new();
        let mut emails = Vec::new();
        let mut uri_domains = Vec::new();
        while !subtrees.empty() {
            let Some(seq) = subtrees.read(asn1::SEQUENCE) else {
                return err("x509: invalid NameConstraints extension");
            };
            let Some((tag, value)) = Reader(seq).read_any() else {
                return err("x509: invalid NameConstraints extension");
            };
            let dns_tag = asn1::context(2);
            let email_tag = asn1::context(1);
            let ip_tag = asn1::context(7);
            let uri_tag = asn1::context(6);
            let text = || String::from_utf8_lossy(value).into_owned();
            if tag == dns_tag {
                let domain = text();
                if let Err(e) = is_ia5_string_bytes(value) {
                    return Err(Error::new(format!("x509: invalid constraint value: {e}")));
                }
                if !domain_name_valid(&domain, true) {
                    return Err(Error::new(format!(
                        "x509: failed to parse dnsName constraint {}",
                        quote(&domain)
                    )));
                }
                dns_names.push(domain);
            } else if tag == ip_tag {
                let l = value.len();
                let (ip, mask) = match l {
                    8 => (&value[..4], &value[4..]),
                    32 => (&value[..16], &value[16..]),
                    _ => {
                        return Err(Error::new(format!(
                            "x509: IP constraint contained value of length {l}"
                        )))
                    }
                };
                if !is_valid_ip_mask(mask) {
                    return Err(Error::new(format!(
                        "x509: IP constraint contained invalid mask {}",
                        asn1::hex(mask)
                    )));
                }
                if ip.len() == 16 && Ip(ip.to_vec()).to4().is_some() {
                    return err("x509: IP constraint contained IPv4-mapped IPv6 address");
                }
                ips.push(IpNet {
                    ip: Ip(ip.to_vec()),
                    mask: mask.to_vec(),
                });
            } else if tag == email_tag {
                let constraint = text();
                if let Err(e) = is_ia5_string_bytes(value) {
                    return Err(Error::new(format!("x509: invalid constraint value: {e}")));
                }
                // If the constraint contains an @ then it specifies an exact
                // mailbox name.
                if constraint.contains('@') {
                    if parse_rfc2821_mailbox(&constraint).is_none() {
                        return Err(Error::new(format!(
                            "x509: failed to parse rfc822Name constraint {}",
                            quote(&constraint)
                        )));
                    }
                } else if !domain_name_valid(&constraint, true) {
                    return Err(Error::new(format!(
                        "x509: failed to parse rfc822Name constraint {}",
                        quote(&constraint)
                    )));
                }
                emails.push(constraint);
            } else if tag == uri_tag {
                let domain = text();
                if let Err(e) = is_ia5_string_bytes(value) {
                    return Err(Error::new(format!("x509: invalid constraint value: {e}")));
                }
                if super::net::parse_ip(&domain).is_some() {
                    return Err(Error::new(format!(
                        "x509: failed to parse URI constraint {}: cannot be IP address",
                        quote(&domain)
                    )));
                }
                if !domain_name_valid(&domain, true) {
                    return Err(Error::new(format!(
                        "x509: failed to parse URI constraint {}",
                        quote(&domain)
                    )));
                }
                uri_domains.push(domain);
            } else {
                unhandled = true;
            }
        }
        Ok((dns_names, ips, emails, uri_domains))
    };

    let (a, b, c, d) = get_values(permitted)?;
    out.permitted_dns_domains = a;
    out.permitted_ip_ranges = b;
    out.permitted_email_addresses = c;
    out.permitted_uri_domains = d;
    let (a, b, c, d) = get_values(excluded)?;
    out.excluded_dns_domains = a;
    out.excluded_ip_ranges = b;
    out.excluded_email_addresses = c;
    out.excluded_uri_domains = d;
    out.permitted_dns_domains_critical = e.critical;

    Ok(unhandled)
}

fn process_extensions(out: &mut Certificate) -> Result<(), Error> {
    let extensions = out.extensions.clone();
    for e in &extensions {
        let mut unhandled = false;
        let id = &e.id.0;

        if id.len() == 4 && id[0] == 2 && id[1] == 5 && id[2] == 29 {
            match id[3] {
                15 => out.key_usage = parse_key_usage_extension(&e.value)?,
                19 => {
                    let (is_ca, max_path_len) = parse_basic_constraints_extension(&e.value)?;
                    out.is_ca = is_ca;
                    out.max_path_len = max_path_len;
                    out.basic_constraints_valid = true;
                    out.max_path_len_zero = out.max_path_len == 0;
                }
                17 => {
                    let (dns, email, ips, uris) = parse_san_extension(&e.value)?;
                    out.dns_names = dns;
                    out.email_addresses = email;
                    out.ip_addresses = ips;
                    out.uris = uris;
                    if out.dns_names.is_empty()
                        && out.email_addresses.is_empty()
                        && out.ip_addresses.is_empty()
                        && out.uris.is_empty()
                    {
                        // If we didn't parse anything then we do the critical
                        // check, below.
                        unhandled = true;
                    }
                }
                30 => unhandled = parse_name_constraints_extension(out, e)?,
                31 => {
                    // RFC 5280, 4.2.1.13
                    let mut val = Reader(&e.value);
                    let Some(seq) = val.read(asn1::SEQUENCE) else {
                        return err("x509: invalid CRL distribution points");
                    };
                    let mut val = Reader(seq);
                    while !val.empty() {
                        let Some(dp_der) = val.read(asn1::SEQUENCE) else {
                            return err("x509: invalid CRL distribution point");
                        };
                        let mut dp_der = Reader(dp_der);
                        let Some(dp_name) = dp_der.read_optional(asn1::context_constructed(0))
                        else {
                            return err("x509: invalid CRL distribution point");
                        };
                        let Some(dp_name) = dp_name else {
                            continue;
                        };
                        let mut dp_name = Reader(dp_name);
                        let Some(inner) = dp_name.read(asn1::context_constructed(0)) else {
                            return err("x509: invalid CRL distribution point");
                        };
                        let mut dp_name = Reader(inner);
                        while !dp_name.empty() {
                            if !dp_name.peek_tag(asn1::context(6)) {
                                break;
                            }
                            let Some(uri) = dp_name.read(asn1::context(6)) else {
                                return err("x509: invalid CRL distribution point");
                            };
                            out.crl_distribution_points
                                .push(String::from_utf8_lossy(uri).into_owned());
                        }
                    }
                }
                35 => out.authority_key_id = parse_authority_key_identifier(e)?,
                36 => {
                    let mut val = Reader(&e.value);
                    let Some(seq) = val.read(asn1::SEQUENCE) else {
                        return err("x509: invalid policy constraints extension");
                    };
                    let mut val = Reader(seq);
                    if val.peek_tag(asn1::context(0)) {
                        let Some(v) = val.read_i64_tagged(asn1::context(0)) else {
                            return err("x509: invalid policy constraints extension");
                        };
                        out.require_explicit_policy = v;
                        out.require_explicit_policy_zero = out.require_explicit_policy == 0;
                    }
                    if val.peek_tag(asn1::context(1)) {
                        let Some(v) = val.read_i64_tagged(asn1::context(1)) else {
                            return err("x509: invalid policy constraints extension");
                        };
                        out.inhibit_policy_mapping = v;
                        out.inhibit_policy_mapping_zero = out.inhibit_policy_mapping == 0;
                    }
                }
                37 => {
                    let (known, unknown) = parse_ext_key_usage_extension(&e.value)?;
                    out.ext_key_usage = known;
                    out.unknown_ext_key_usage = unknown;
                }
                14 => {
                    // RFC 5280, 4.2.1.2
                    if e.critical {
                        // Conforming CAs MUST mark this extension as
                        // non-critical.
                        return err("x509: subject key identifier incorrectly marked critical");
                    }
                    let mut val = Reader(&e.value);
                    let Some(skid) = val.read(asn1::OCTET_STRING) else {
                        return err("x509: invalid subject key identifier");
                    };
                    out.subject_key_id = skid.to_vec();
                }
                32 => {
                    out.policies = parse_certificate_policies_extension(&e.value)?;
                    out.policy_identifiers =
                        out.policies.iter().filter_map(Oid::to_asn1_oid).collect();
                }
                33 => {
                    let mut val = Reader(&e.value);
                    let Some(seq) = val.read(asn1::SEQUENCE) else {
                        return err("x509: invalid policy mappings extension");
                    };
                    let mut val = Reader(seq);
                    while !val.empty() {
                        let parsed = (|| {
                            let s = val.read(asn1::SEQUENCE)?;
                            let mut s = Reader(s);
                            let issuer = s.read(asn1::OBJECT_IDENTIFIER)?;
                            let subject = s.read(asn1::OBJECT_IDENTIFIER)?;
                            Some((issuer, subject))
                        })();
                        let Some((issuer, subject)) = parsed else {
                            return err("x509: invalid policy mappings extension");
                        };
                        out.policy_mappings.push(PolicyMapping {
                            issuer_domain_policy: Oid::from_raw(issuer),
                            subject_domain_policy: Oid::from_raw(subject),
                        });
                    }
                }
                54 => {
                    let mut val = Reader(&e.value);
                    let Some(v) = val.read_i64() else {
                        return err("x509: invalid inhibit any policy extension");
                    };
                    out.inhibit_any_policy = v;
                    out.inhibit_any_policy_zero = out.inhibit_any_policy == 0;
                }
                _ => {
                    // Unknown extensions are recorded if critical.
                    unhandled = true;
                }
            }
        } else if e.id.0 == OID_EXTENSION_AUTHORITY_INFO_ACCESS {
            // RFC 5280 4.2.2.1: Authority Information Access
            if e.critical {
                // Conforming CAs MUST mark this extension as non-critical.
                return err("x509: authority info access incorrectly marked critical");
            }
            let mut val = Reader(&e.value);
            let Some(seq) = val.read(asn1::SEQUENCE) else {
                return err("x509: invalid authority info access");
            };
            let mut val = Reader(seq);
            while !val.empty() {
                let Some(aia_der) = val.read(asn1::SEQUENCE) else {
                    return err("x509: invalid authority info access");
                };
                let mut aia_der = Reader(aia_der);
                let Some(method) = aia_der.read_oid() else {
                    return err("x509: invalid authority info access");
                };
                if !aia_der.peek_tag(asn1::context(6)) {
                    continue;
                }
                let Some(location) = aia_der.read(asn1::context(6)) else {
                    return err("x509: invalid authority info access");
                };
                let location = String::from_utf8_lossy(location).into_owned();
                if method.0 == OID_AUTHORITY_INFO_ACCESS_OCSP {
                    out.ocsp_server.push(location);
                } else if method.0 == OID_AUTHORITY_INFO_ACCESS_ISSUERS {
                    out.issuing_certificate_url.push(location);
                }
            }
        } else {
            // Unknown extensions are recorded if critical.
            unhandled = true;
        }

        if e.critical && unhandled {
            out.unhandled_critical_extensions.push(e.id.clone());
        }
    }
    Ok(())
}

/// Go's `getSignatureAlgorithmFromAI`.
pub(crate) fn signature_algorithm_from_ai(ai: &AlgorithmIdentifier) -> SignatureAlgorithm {
    let alg = &ai.algorithm;
    if alg.is(&OID_SIGNATURE_ED25519)
        || alg.is(&OID_PUBLIC_KEY_MLDSA44)
        || alg.is(&OID_PUBLIC_KEY_MLDSA65)
        || alg.is(&OID_PUBLIC_KEY_MLDSA87)
    {
        // RFC 8410, Section 3 and RFC 9881, Section 2: the parameters MUST be
        // absent.
        if !ai.parameters.full_bytes.is_empty() {
            return SignatureAlgorithm::UNKNOWN_SIGNATURE_ALGORITHM;
        }
    }

    if !alg.is(&OID_SIGNATURE_RSA_PSS) {
        for details in SIGNATURE_ALGORITHM_DETAILS {
            if alg.is(details.oid) {
                return details.algo;
            }
        }
        return SignatureAlgorithm::UNKNOWN_SIGNATURE_ALGORITHM;
    }

    // RSA PSS is special because it encodes important parameters in the
    // Parameters.
    let Some(params) = parse_pss_parameters(&ai.parameters.full_bytes) else {
        return SignatureAlgorithm::UNKNOWN_SIGNATURE_ALGORITHM;
    };

    let Ok(mgf1_hash_func) =
        keys::read_algorithm_identifier(&mut Reader(&params.mgf.parameters.full_bytes))
    else {
        return SignatureAlgorithm::UNKNOWN_SIGNATURE_ALGORITHM;
    };

    // PSS is greatly overburdened with options. This code forces them into
    // three buckets by requiring that the MGF1 hash function always match the
    // message hash function, that the salt length matches the hash length, and
    // that the trailer field has the default value.
    let null_or_empty = |b: &[u8]| b.is_empty() || b == asn1::NULL_BYTES;
    if !null_or_empty(&params.hash.parameters.full_bytes)
        || !params.mgf.algorithm.is(&OID_MGF1)
        || !mgf1_hash_func.algorithm.equal(&params.hash.algorithm)
        || !null_or_empty(&mgf1_hash_func.parameters.full_bytes)
        || params.trailer_field != 1
    {
        return SignatureAlgorithm::UNKNOWN_SIGNATURE_ALGORITHM;
    }

    if params.hash.algorithm.is(&OID_SHA256) && params.salt_length == 32 {
        SignatureAlgorithm::SHA256_WITH_RSAPSS
    } else if params.hash.algorithm.is(&OID_SHA384) && params.salt_length == 48 {
        SignatureAlgorithm::SHA384_WITH_RSAPSS
    } else if params.hash.algorithm.is(&OID_SHA512) && params.salt_length == 64 {
        SignatureAlgorithm::SHA512_WITH_RSAPSS
    } else {
        SignatureAlgorithm::UNKNOWN_SIGNATURE_ALGORITHM
    }
}

struct PssParameters {
    hash: AlgorithmIdentifier,
    mgf: AlgorithmIdentifier,
    salt_length: i64,
    trailer_field: i64,
}

/// `asn1.Unmarshal` of Go's `pssParameters`.
fn parse_pss_parameters(data: &[u8]) -> Option<PssParameters> {
    let mut r = Reader(data);
    let seq = r.read(asn1::SEQUENCE)?;
    let mut s = Reader(seq);
    if !s.read_explicit_header(asn1::context_constructed(0))? {
        return None;
    }
    let hash = keys::read_algorithm_identifier(&mut s).ok()?;
    if !s.read_explicit_header(asn1::context_constructed(1))? {
        return None;
    }
    let mgf = keys::read_algorithm_identifier(&mut s).ok()?;
    if !s.read_explicit_header(asn1::context_constructed(2))? {
        return None;
    }
    let salt_length = s.read_i64()?;
    let mut trailer_field = 1;
    if s.read_explicit_header(asn1::context_constructed(3))? {
        trailer_field = s.read_i64()?;
    }
    Some(PssParameters {
        hash,
        mgf,
        salt_length,
        trailer_field,
    })
}

/// Go's `isIA5String`.
pub(crate) fn is_ia5_string(s: &str) -> Result<(), Error> {
    for r in s.chars() {
        // Per RFC5280 "IA5String is limited to the set of ASCII characters".
        if r as u32 > 0x7f {
            return Err(Error::new(format!(
                "x509: {} cannot be encoded as an IA5String",
                quote(s)
            )));
        }
    }
    Ok(())
}

/// `isIA5String(string(b))`: Go's `range` decodes an invalid byte as U+FFFD,
/// so any non-ASCII byte fails, and `%q` prints the raw bytes.
fn is_ia5_string_bytes(b: &[u8]) -> Result<(), Error> {
    if b.is_ascii() {
        Ok(())
    } else {
        Err(Error::new(format!(
            "x509: {} cannot be encoded as an IA5String",
            quote_bytes(b)
        )))
    }
}

/// Go's `domainNameValid`.
pub(crate) fn domain_name_valid(s: &str, constraint: bool) -> bool {
    // TODO(#75835) in Go: this omits a number of checks on purpose.
    if s.is_empty() {
        return true;
    }
    let bytes = s.as_bytes();
    // Do not allow trailing period (FQDN format is not allowed in SANs or
    // constraints).
    if bytes[bytes.len() - 1] == b'.' {
        return false;
    }
    let mut bytes = bytes;
    let mut last_dot: i64 = -1;
    if constraint && bytes[0] == b'.' {
        bytes = &bytes[1..];
    }
    let n = bytes.len();
    for i in 0..=n {
        if i < n && !(33..=126).contains(&bytes[i]) {
            // Invalid character.
            return false;
        }
        if i == n || bytes.get(i) == Some(&b'.') {
            let mut label_len = i as i64;
            if last_dot >= 0 {
                label_len -= last_dot + 1;
            }
            if label_len == 0 {
                return false;
            }
            last_dot = i as i64;
        }
    }
    true
}

/// A public key info for [`keys::parse_public_key`].
fn parse_spki(spki: &[u8]) -> Result<(AlgorithmIdentifier, BitString), Error> {
    let mut spki = Reader(spki);
    let Some(inner) = spki.read(asn1::SEQUENCE) else {
        return err("x509: malformed spki");
    };
    let mut inner = Reader(inner);
    let Some(pk_ai_seq) = inner.read(asn1::SEQUENCE) else {
        return err("x509: malformed public key algorithm identifier");
    };
    let pk_ai = parse_ai(pk_ai_seq)?;
    let Some(spk) = inner.read_bit_string() else {
        return err("x509: malformed subjectPublicKey");
    };
    Ok((pk_ai, spk))
}

fn parse_certificate_inner(der: &[u8]) -> Result<Certificate, Error> {
    let mut cert = Certificate::default();

    let mut input = Reader(der);
    // Read the SEQUENCE including length and tag bytes so that Raw can be
    // populated, before unwrapping the SEQUENCE.
    let Some(raw) = input.read_element(asn1::SEQUENCE) else {
        return err("x509: malformed certificate");
    };
    cert.raw = raw.to_vec();
    let mut input = Reader(raw);
    let Some(content) = input.read(asn1::SEQUENCE) else {
        return err("x509: malformed certificate");
    };
    let mut input = Reader(content);

    let Some(tbs_el) = input.read_element(asn1::SEQUENCE) else {
        return err("x509: malformed tbs certificate");
    };
    cert.raw_tbs_certificate = tbs_el.to_vec();
    let Some(tbs) = Reader(tbs_el).read(asn1::SEQUENCE) else {
        return err("x509: malformed tbs certificate");
    };
    let mut tbs = Reader(tbs);

    // The optional [0] EXPLICIT version.
    let version = (|| {
        let present = tbs.read_optional(asn1::context_constructed(0))?;
        match present {
            None => Some(0),
            Some(i) => {
                let mut i = Reader(i);
                let v = i.read_i64()?;
                if !i.empty() {
                    return None;
                }
                Some(v)
            }
        }
    })();
    let Some(version) = version else {
        return err("x509: malformed version");
    };
    cert.version = version;
    if cert.version < 0 {
        return err("x509: malformed version");
    }
    // For backwards compatibility Version is one-indexed.
    cert.version += 1;
    if cert.version > 3 {
        return err("x509: invalid version");
    }

    let Some(serial) = tbs.read_big_integer() else {
        return err("x509: malformed serial number");
    };
    if serial.sign() == -1 && crate::sysrng::godebug("x509negativeserial").as_deref() != Some("1") {
        return err("x509: negative serial number");
    }
    cert.serial_number = Some(serial);

    let Some(sig_ai_el) = tbs.read_element(asn1::SEQUENCE) else {
        return err("x509: malformed signature algorithm identifier");
    };
    cert.raw_signature_algorithm = sig_ai_el.to_vec();
    let Some(sig_ai_seq) = Reader(sig_ai_el).read(asn1::SEQUENCE) else {
        return err("x509: malformed signature algorithm identifier");
    };
    // Before parsing the inner algorithm identifier, extract the outer
    // algorithm identifier and make sure that they match.
    let Some(outer_sig_ai_seq) = input.read(asn1::SEQUENCE) else {
        return err("x509: malformed algorithm identifier");
    };
    if outer_sig_ai_seq != sig_ai_seq {
        return err("x509: inner and outer signature algorithm identifiers don't match");
    }
    let sig_ai = parse_ai(sig_ai_seq)?;
    cert.signature_algorithm = signature_algorithm_from_ai(&sig_ai);

    let Some(issuer_seq) = tbs.read_element(asn1::SEQUENCE) else {
        return err("x509: malformed issuer");
    };
    cert.raw_issuer = issuer_seq.to_vec();
    let issuer_rdns = parse_name(issuer_seq)?;
    cert.issuer.fill_from_rdn_sequence(&issuer_rdns);

    let Some(validity) = tbs.read(asn1::SEQUENCE) else {
        return err("x509: malformed validity");
    };
    let (not_before, not_after) = parse_validity(validity)?;
    cert.not_before = not_before;
    cert.not_after = not_after;

    let Some(subject_seq) = tbs.read_element(asn1::SEQUENCE) else {
        return err("x509: malformed issuer");
    };
    cert.raw_subject = subject_seq.to_vec();
    let subject_rdns = parse_name(subject_seq)?;
    cert.subject.fill_from_rdn_sequence(&subject_rdns);

    let Some(spki_el) = tbs.read_element(asn1::SEQUENCE) else {
        return err("x509: malformed spki");
    };
    cert.raw_subject_public_key_info = spki_el.to_vec();
    let (pk_ai, spk) = parse_spki(spki_el)?;
    cert.public_key_algorithm = keys::public_key_algorithm_from_oid(&pk_ai.algorithm);
    if cert.public_key_algorithm != PublicKeyAlgorithm::UNKNOWN_PUBLIC_KEY_ALGORITHM {
        cert.public_key = Some(keys::parse_public_key(&pk_ai, &spk.right_align())?);
    }

    if cert.version > 1 {
        if !tbs.skip_optional(asn1::context(1)) {
            return err("x509: malformed issuerUniqueID");
        }
        if !tbs.skip_optional(asn1::context(2)) {
            return err("x509: malformed subjectUniqueID");
        }
        if cert.version == 3 {
            let Some(extensions) = tbs.read_optional(asn1::context_constructed(3)) else {
                return err("x509: malformed extensions");
            };
            if let Some(extensions) = extensions {
                let mut seen_exts: HashSet<String> = HashSet::new();
                let Some(exts) = Reader(extensions).read(asn1::SEQUENCE) else {
                    return err("x509: malformed extensions");
                };
                let mut extensions = Reader(exts);
                while !extensions.empty() {
                    let Some(extension) = extensions.read(asn1::SEQUENCE) else {
                        return err("x509: malformed extension");
                    };
                    let ext = parse_extension(extension)?;
                    let oid_str = ext.id.to_string();
                    if !seen_exts.insert(oid_str.clone()) {
                        return Err(Error::new(format!(
                            "x509: certificate contains duplicate extension with OID {}",
                            quote(&oid_str)
                        )));
                    }
                    cert.extensions.push(ext);
                }
                process_extensions(&mut cert)?;
            }
        }
    }

    let Some(signature) = input.read_bit_string() else {
        return err("x509: malformed signature");
    };
    cert.signature = signature.right_align();

    Ok(cert)
}

/// Go's `ParseCertificate`: parses a single certificate from the given ASN.1
/// DER data.
///
/// Before Go 1.23, certificates with negative serial numbers were accepted.
/// This behavior can be restored by including `x509negativeserial=1` in the
/// `GODEBUG` environment variable.
pub fn parse_certificate(der: &[u8]) -> Result<Certificate, Error> {
    let cert = parse_certificate_inner(der)?;
    if der.len() != cert.raw.len() {
        return err("x509: trailing data");
    }
    Ok(cert)
}

/// Go's `ParseCertificates`: parses one or more certificates from the given
/// ASN.1 DER data. The certificates must be concatenated with no intermediate
/// padding.
pub fn parse_certificates(mut der: &[u8]) -> Result<Vec<Certificate>, Error> {
    let mut certs = Vec::new();
    while !der.is_empty() {
        let cert = parse_certificate_inner(der)?;
        der = &der[cert.raw.len()..];
        certs.push(cert);
    }
    Ok(certs)
}

/// Go's `ParseRevocationList`: parses a X509 v2 Certificate Revocation List
/// from the given ASN.1 DER data.
pub fn parse_revocation_list(der: &[u8]) -> Result<RevocationList, Error> {
    let mut rl = RevocationList::default();

    let mut input = Reader(der);
    let Some(raw) = input.read_element(asn1::SEQUENCE) else {
        return err("x509: malformed crl");
    };
    rl.raw = raw.to_vec();
    let Some(content) = Reader(raw).read(asn1::SEQUENCE) else {
        return err("x509: malformed crl");
    };
    let mut input = Reader(content);

    let Some(tbs_el) = input.read_element(asn1::SEQUENCE) else {
        return err("x509: malformed tbs crl");
    };
    rl.raw_tbs_revocation_list = tbs_el.to_vec();
    let Some(tbs) = Reader(tbs_el).read(asn1::SEQUENCE) else {
        return err("x509: malformed tbs crl");
    };
    let mut tbs = Reader(tbs);

    if !tbs.peek_tag(asn1::INTEGER) {
        return err("x509: unsupported crl version");
    }
    let Some(version) = tbs.read_i64() else {
        return err("x509: malformed crl");
    };
    if version != 1 {
        return Err(Error::new(format!(
            "x509: unsupported crl version: {version}"
        )));
    }

    let Some(sig_ai_el) = tbs.read_element(asn1::SEQUENCE) else {
        return err("x509: malformed signature algorithm identifier");
    };
    rl.raw_signature_algorithm = sig_ai_el.to_vec();
    let Some(sig_ai_seq) = Reader(sig_ai_el).read(asn1::SEQUENCE) else {
        return err("x509: malformed signature algorithm identifier");
    };
    let Some(outer_sig_ai_seq) = input.read(asn1::SEQUENCE) else {
        return err("x509: malformed algorithm identifier");
    };
    if outer_sig_ai_seq != sig_ai_seq {
        return err("x509: inner and outer signature algorithm identifiers don't match");
    }
    let sig_ai = parse_ai(sig_ai_seq)?;
    rl.signature_algorithm = signature_algorithm_from_ai(&sig_ai);

    let Some(signature) = input.read_bit_string() else {
        return err("x509: malformed signature");
    };
    rl.signature = signature.right_align();

    let Some(issuer_seq) = tbs.read_element(asn1::SEQUENCE) else {
        return err("x509: malformed issuer");
    };
    rl.raw_issuer = issuer_seq.to_vec();
    let issuer_rdns = parse_name(issuer_seq)?;
    rl.issuer.fill_from_rdn_sequence(&issuer_rdns);

    rl.this_update = read_asn1_time(&mut tbs)?;
    if tbs.peek_tag(asn1::GENERALIZED_TIME) || tbs.peek_tag(asn1::UTC_TIME) {
        rl.next_update = read_asn1_time(&mut tbs)?;
    }

    if tbs.peek_tag(asn1::SEQUENCE) {
        let Some(revoked_seq) = tbs.read(asn1::SEQUENCE) else {
            return err("x509: malformed crl");
        };
        let mut revoked_seq = Reader(revoked_seq);
        while !revoked_seq.empty() {
            let mut rce = RevocationListEntry::default();

            let Some(cert_el) = revoked_seq.read_element(asn1::SEQUENCE) else {
                return err("x509: malformed crl");
            };
            rce.raw = cert_el.to_vec();
            let Some(cert_seq) = Reader(cert_el).read(asn1::SEQUENCE) else {
                return err("x509: malformed crl");
            };
            let mut cert_seq = Reader(cert_seq);

            let Some(serial) = cert_seq.read_big_integer() else {
                return err("x509: malformed serial number");
            };
            rce.serial_number = Some(serial);
            rce.revocation_time = read_asn1_time(&mut cert_seq)?;
            let Some(extensions) = cert_seq.read_optional(asn1::SEQUENCE) else {
                return err("x509: malformed extensions");
            };
            if let Some(extensions) = extensions {
                let mut extensions = Reader(extensions);
                while !extensions.empty() {
                    let Some(extension) = extensions.read(asn1::SEQUENCE) else {
                        return err("x509: malformed extension");
                    };
                    let ext = parse_extension(extension)?;
                    if ext.id.0 == OID_EXTENSION_REASON_CODE {
                        let mut val = Reader(&ext.value);
                        match val.read_enum() {
                            Some(v) => rce.reason_code = v,
                            None => return err("x509: malformed reasonCode extension"),
                        }
                    }
                    rce.extensions.push(ext);
                }
            }

            rl.revoked_certificates.push(pkix::RevokedCertificate {
                serial_number: rce.serial_number.clone().unwrap_or_default(),
                revocation_time: rce.revocation_time,
                extensions: rce.extensions.clone(),
            });
            rl.revoked_certificate_entries.push(rce);
        }
    }

    let Some(extensions) = tbs.read_optional(asn1::context_constructed(0)) else {
        return err("x509: malformed extensions");
    };
    if let Some(extensions) = extensions {
        let Some(exts) = Reader(extensions).read(asn1::SEQUENCE) else {
            return err("x509: malformed extensions");
        };
        let mut extensions = Reader(exts);
        while !extensions.empty() {
            let Some(extension) = extensions.read(asn1::SEQUENCE) else {
                return err("x509: malformed extension");
            };
            let ext = parse_extension(extension)?;
            if ext.id.0 == OID_EXTENSION_AUTHORITY_KEY_ID {
                rl.authority_key_id = parse_authority_key_identifier(&ext)?;
            } else if ext.id.0 == OID_EXTENSION_CRL_NUMBER {
                let mut value = Reader(&ext.value);
                match value.read_big_integer() {
                    Some(n) => rl.number = Some(n),
                    None => return err("x509: malformed crl number"),
                }
            }
            rl.extensions.push(ext);
        }
    }

    Ok(rl)
}

// ---- encoding/asn1 based parsing ---------------------------------------
//
// `asn1_unmarshal` checks the structure exactly as `asn1.Unmarshal` does and
// hands back the parsed elements; the functions below turn them into values.

fn asn1_syntax(msg: &str) -> Error {
    Error::new(format!("asn1: syntax error: {msg}"))
}

fn node_of<'a>(value: &Parsed<'a>) -> Node<'a> {
    value.node().copied().expect("field is present")
}

fn oid_of(value: &Parsed<'_>) -> ObjectIdentifier {
    value
        .node()
        .and_then(|n| asn1::parse_oid_contents(n.content))
        .unwrap_or_default()
}

fn int64_of(value: &Parsed<'_>) -> i64 {
    let content = value.node().map_or(&[][..], |n| n.content);
    content.iter().fold(
        if content.first().is_some_and(|b| b & 0x80 != 0) {
            -1
        } else {
            0
        },
        |acc, &b| acc << 8 | i64::from(b),
    )
}

fn big_int_of(value: &Parsed<'_>) -> asn1::BigInt {
    asn1::BigInt::from_der_contents(value.node().map_or(&[][..], |n| n.content))
}

fn bit_string_of(value: &Parsed<'_>) -> BitString {
    let content = value.node().map_or(&[][..], |n| n.content);
    match content.split_first() {
        Some((&padding, bytes)) => BitString {
            bytes: bytes.to_vec(),
            bit_length: bytes.len() * 8 - usize::from(padding),
        },
        None => BitString::default(),
    }
}

fn time_of(node: &Node<'_>) -> Time {
    if node.tag == i64::from(asn1::GENERALIZED_TIME) {
        asn1_time::parse_generalized_time(node.content)
    } else {
        asn1_time::parse_utc_time(node.content)
    }
    .unwrap_or_default()
}

fn raw_value_of(value: &Parsed<'_>) -> RawValue {
    match value.node() {
        Some(n) => RawValue {
            class: n.class,
            tag: n.tag,
            is_compound: n.is_compound,
            bytes: n.content.to_vec(),
            full_bytes: n.full.to_vec(),
        },
        None => RawValue::default(),
    }
}

fn algorithm_identifier_of(value: &Parsed<'_>) -> AlgorithmIdentifier {
    let fields = value.fields();
    AlgorithmIdentifier {
        algorithm: oid_of(&fields[0]),
        parameters: raw_value_of(&fields[1]),
    }
}

/// An `any` field as `encoding/asn1` stores it: the universal primitive types
/// it knows are decoded, anything else leaves the value nil.
fn any_value_of(node: &Node<'_>) -> Value {
    if node.is_compound || node.class != 0 {
        return Value::Nil;
    }
    let content = node.content;
    let leaf = Parsed::Leaf(*node);
    match node.tag {
        1 => Value::Bool(content == [0xff]),
        // PrintableString, NumericString, IA5String and UTF8String were
        // checked to be valid text.
        0x13 | 0x12 | 0x16 | 0x0c => Value::String(String::from_utf8_lossy(content).into_owned()),
        // T.61 is treated as Latin-1, as BoringSSL does.
        0x14 => Value::String(content.iter().map(|&b| b as char).collect()),
        0x1e => {
            // Strip the terminator if present.
            let content = match content {
                [rest @ .., 0, 0] => rest,
                _ => content,
            };
            let units: Vec<u16> = content
                .chunks(2)
                .map(|pair| u16::from(pair[0]) << 8 | u16::from(pair[1]))
                .collect();
            Value::String(String::from_utf16_lossy(&units))
        }
        2 => Value::Int(int64_of(&leaf)),
        3 => Value::BitString(bit_string_of(&leaf)),
        6 => Value::ObjectIdentifier(oid_of(&leaf)),
        0x17 | 0x18 => Value::Time(time_of(node)),
        4 => Value::Bytes(content.to_vec()),
        _ => Value::Nil,
    }
}

/// A `[]pkix.AttributeTypeAndValue` element list.
fn attribute_type_and_values_of(items: &[Parsed<'_>]) -> Vec<AttributeTypeAndValue> {
    items
        .iter()
        .map(|atv| AttributeTypeAndValue {
            type_: oid_of(&atv.fields()[0]),
            value: any_value_of(&node_of(&atv.fields()[1])),
        })
        .collect()
}

/// A `pkix.RDNSequence`.
fn rdn_sequence_of(value: &Parsed<'_>) -> RDNSequence {
    RDNSequence(
        value
            .items()
            .iter()
            .map(|rdn| RelativeDistinguishedNameSET(attribute_type_and_values_of(rdn.items())))
            .collect(),
    )
}

/// A `[]pkix.Extension`; an absent field is empty.
fn extensions_of(value: &Parsed<'_>) -> Vec<Extension> {
    value
        .items()
        .iter()
        .map(|ext| {
            let fields = ext.fields();
            Extension {
                id: oid_of(&fields[0]),
                critical: fields[1].node().is_some_and(|n| n.content == [0xff]),
                value: node_of(&fields[2]).content.to_vec(),
            }
        })
        .collect()
}

/// Go's `ParseCertificateRequest`: parses a single certificate request from
/// the given ASN.1 DER data.
pub fn parse_certificate_request(asn1_data: &[u8]) -> Result<CertificateRequest, Error> {
    let (used, csr) =
        unmarshal_value(asn1_data, Ty::Struct(&shapes::CERTIFICATE_REQUEST)).map_err(Error::new)?;
    if used != asn1_data.len() {
        return Err(asn1_syntax("trailing data"));
    }
    let [tbs, signature_algorithm, signature_value] = csr.fields() else {
        unreachable!("certificateRequest has three fields");
    };
    let [version, subject, public_key_info, raw_attributes] = tbs.fields() else {
        unreachable!("tbsCertificateRequest has four fields");
    };
    let pk_algorithm = algorithm_identifier_of(&public_key_info.fields()[0]);
    let pk_bits = bit_string_of(&public_key_info.fields()[1]);
    let sig_algorithm = AlgorithmIdentifier {
        algorithm: oid_of(&signature_algorithm.fields()[0]),
        parameters: raw_value_of(&signature_algorithm.fields()[1]),
    };
    let raw_attributes: Vec<&[u8]> = raw_attributes
        .items()
        .iter()
        .map(|attr| node_of(attr).full)
        .collect();
    let subject_full = node_of(subject).full;

    let mut out = CertificateRequest {
        raw: node_of(&csr).full.to_vec(),
        raw_tbs_certificate_request: node_of(tbs).full.to_vec(),
        raw_subject_public_key_info: node_of(public_key_info).full.to_vec(),
        raw_subject: subject_full.to_vec(),
        raw_signature_algorithm: node_of(signature_algorithm).full.to_vec(),
        signature: bit_string_of(signature_value).right_align(),
        signature_algorithm: signature_algorithm_from_ai(&sig_algorithm),
        public_key_algorithm: keys::public_key_algorithm_from_oid(&pk_algorithm.algorithm),
        version: int64_of(version),
        attributes: parse_raw_attributes(&raw_attributes),
        ..CertificateRequest::default()
    };

    if out.public_key_algorithm != PublicKeyAlgorithm::UNKNOWN_PUBLIC_KEY_ALGORITHM {
        out.public_key = Some(keys::parse_public_key(
            &pk_algorithm,
            &pk_bits.right_align(),
        )?);
    }

    let subject = parse_name(subject_full)?;
    out.subject.fill_from_rdn_sequence(&subject);

    out.extensions = parse_csr_extensions(&raw_attributes)?;

    for extension in &out.extensions {
        if extension.id.0 == OID_EXTENSION_SUBJECT_ALT_NAME {
            let (dns, email, ips, uris) = parse_san_extension(&extension.value)?;
            out.dns_names = dns;
            out.email_addresses = email;
            out.ip_addresses = ips;
            out.uris = uris;
        }
    }

    Ok(out)
}

/// Go's `parseRawAttributes`.
fn parse_raw_attributes(raw_attributes: &[&[u8]]) -> Vec<pkix::AttributeTypeAndValueSET> {
    let mut attributes = Vec::new();
    for raw_attr in raw_attributes {
        // Ignore attributes that don't parse into AttributeTypeAndValueSET
        // (for example challengePassword or unstructuredName).
        let Ok((used, attr)) =
            unmarshal_value(raw_attr, Ty::Struct(&shapes::ATTRIBUTE_TYPE_AND_VALUE_SET))
        else {
            continue;
        };
        if used != raw_attr.len() {
            continue;
        }
        let fields = attr.fields();
        attributes.push(pkix::AttributeTypeAndValueSET {
            type_: oid_of(&fields[0]),
            value: fields[1]
                .items()
                .iter()
                .map(|set| {
                    set.items()
                        .iter()
                        .map(|atv| AttributeTypeAndValue {
                            type_: oid_of(&atv.fields()[0]),
                            value: any_value_of(&node_of(&atv.fields()[1])),
                        })
                        .collect()
                })
                .collect(),
        });
    }
    attributes
}

/// Go's `parseCSRExtensions`.
fn parse_csr_extensions(raw_attributes: &[&[u8]]) -> Result<Vec<Extension>, Error> {
    let mut ret = Vec::new();
    let mut requested: HashSet<String> = HashSet::new();
    for raw_attr in raw_attributes {
        // pkcs10Attribute reflects the Attribute structure from RFC 2986.
        let Ok((used, attr)) = unmarshal_value(raw_attr, Ty::Struct(&shapes::PKCS10_ATTRIBUTE))
        else {
            continue;
        };
        let values = attr.fields()[1].items();
        // Ignore attributes that don't parse.
        if used != raw_attr.len() || values.is_empty() {
            continue;
        }
        if oid_of(&attr.fields()[0]).0 != OID_EXTENSION_REQUEST {
            continue;
        }

        let (_, list) = unmarshal_value(node_of(&values[0]).full, Ty::Slice(&shapes::EXTENSIONS))
            .map_err(Error::new)?;
        let extensions = extensions_of(&list);
        for ext in &extensions {
            let oid_str = ext.id.to_string();
            if !requested.insert(oid_str) {
                return err("x509: certificate request contains duplicate requested extensions");
            }
        }
        ret.extend(extensions);
    }
    Ok(ret)
}

/// Go's `ParseDERCRL`: parses a DER encoded CRL from the given bytes.
///
/// Deprecated in Go: use [`parse_revocation_list`].
pub fn parse_der_crl(der_bytes: &[u8]) -> Result<pkix::CertificateList, Error> {
    let (used, list) =
        unmarshal_value(der_bytes, Ty::Struct(&shapes::CERTIFICATE_LIST)).map_err(Error::new)?;
    if used != der_bytes.len() {
        return err("x509: trailing data after CRL");
    }
    let [tbs, signature_algorithm, signature_value] = list.fields() else {
        unreachable!("CertificateList has three fields");
    };
    let [version, signature, issuer, this_update, next_update, revoked, extensions] = tbs.fields()
    else {
        unreachable!("TBSCertificateList has seven fields");
    };
    let revoked_certificates = revoked
        .items()
        .iter()
        .map(|rc| {
            let [serial_number, revocation_time, extensions] = rc.fields() else {
                unreachable!("RevokedCertificate has three fields");
            };
            pkix::RevokedCertificate {
                serial_number: big_int_of(serial_number),
                revocation_time: time_of(&node_of(revocation_time)),
                extensions: extensions_of(extensions),
            }
        })
        .collect();
    Ok(pkix::CertificateList {
        tbs_cert_list: pkix::TBSCertificateList {
            raw: node_of(tbs).full.to_vec(),
            version: if version.node().is_some() {
                int64_of(version)
            } else {
                0
            },
            signature: algorithm_identifier_of(signature),
            issuer: rdn_sequence_of(issuer),
            this_update: time_of(&node_of(this_update)),
            next_update: next_update.node().map(time_of).unwrap_or_default(),
            revoked_certificates,
            extensions: extensions_of(extensions),
        },
        signature_algorithm: algorithm_identifier_of(signature_algorithm),
        signature_value: bit_string_of(signature_value),
    })
}

/// Go's `ParseCRL`: parses a CRL from the given bytes. PEM encoded CRLs are
/// handled transparently as long as there isn't any leading garbage.
///
/// Deprecated in Go: use [`parse_revocation_list`].
pub fn parse_crl(crl_bytes: &[u8]) -> Result<pkix::CertificateList, Error> {
    let mut bytes = crl_bytes;
    let decoded;
    if crl_bytes.starts_with(b"-----BEGIN X509 CRL") {
        if let (Some(block), _) = super::pem::decode(crl_bytes) {
            if block.type_ == "X509 CRL" {
                decoded = block.bytes;
                bytes = &decoded;
            }
        }
    }
    parse_der_crl(bytes)
}
