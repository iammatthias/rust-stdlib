//! Go's `crypto/x509/pkix`: shared, low level structures used for ASN.1
//! parsing and serialization of X.509 certificates, CRLs and OCSP.

use std::fmt::Write;

use super::asn1::{self, hex};
pub use super::asn1::{BigInt, BitString, ObjectIdentifier, RawValue};
use super::time::Time;
use super::Error;

/// Go's `pkix.AlgorithmIdentifier`: the ASN.1 structure of the same name
/// (RFC 5280, section 4.1.1.2).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AlgorithmIdentifier {
    pub algorithm: ObjectIdentifier,
    /// Optional; the zero [`RawValue`] means absent.
    pub parameters: RawValue,
}

impl AlgorithmIdentifier {
    /// `asn1.Marshal` of the identifier: `None` for an invalid OID.
    pub(crate) fn marshal(&self) -> Result<Vec<u8>, Error> {
        let mut content = asn1::oid(&self.algorithm.0).ok_or_else(asn1::err_oid)?;
        if self.parameters != RawValue::default() {
            content.extend(marshal_raw_value(&self.parameters));
        }
        Ok(asn1::tlv(asn1::SEQUENCE, &content))
    }
}

/// `asn1.Marshal(RawValue)`: the full bytes if present, otherwise the header
/// built from the fields followed by the contents.
pub(crate) fn marshal_raw_value(rv: &RawValue) -> Vec<u8> {
    if !rv.full_bytes.is_empty() {
        return rv.full_bytes.clone();
    }
    let mut out = Vec::new();
    // appendTagAndLength
    let mut b0 = (rv.class as u8) << 6;
    if rv.is_compound {
        b0 |= 0x20;
    }
    if rv.tag >= 31 {
        out.push(b0 | 0x1f);
        let mut tmp = Vec::new();
        asn1::append_base128(&mut tmp, rv.tag as u64);
        out.extend(tmp);
    } else {
        out.push(b0 | rv.tag as u8);
    }
    asn1::append_length(&mut out, rv.bytes.len());
    out.extend_from_slice(&rv.bytes);
    out
}

/// The value of an [`AttributeTypeAndValue`], Go's `any`.
///
/// When parsed as part of a [`Name`] in a `crypto/x509` type, the value is
///
///   - a [`Value::String`] if the ASN.1 type is PrintableString, IA5String,
///     NumericString, BMPString, T61String, or UTF8String;
///   - a [`Value::Int`] if the ASN.1 type is INTEGER;
///   - a [`Value::BitString`] if the ASN.1 type is BIT STRING;
///   - a [`Value::Bytes`] if the ASN.1 type is OCTET STRING;
///   - a [`Value::ObjectIdentifier`] if the ASN.1 type is OBJECT IDENTIFIER;
///   - a [`Value::Time`] if the ASN.1 type is UTCTIME or GENERALIZEDTIME;
///   - a [`Value::Bool`] if the ASN.1 type is BOOLEAN;
///   - [`Value::Nil`] if the ASN.1 type is NULL;
///   - a [`Value::Raw`] otherwise.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum Value {
    /// Go's `nil` interface.
    #[default]
    Nil,
    String(String),
    Int(i64),
    BitString(BitString),
    Bytes(Vec<u8>),
    ObjectIdentifier(ObjectIdentifier),
    Time(Time),
    Bool(bool),
    Raw(RawValue),
}

impl Value {
    /// `asn1.Marshal(value)`; `None` where Go returns an error.
    pub(crate) fn marshal(&self) -> Result<Vec<u8>, Error> {
        match self {
            Value::Nil => Err(Error::new("asn1: cannot marshal nil value")),
            Value::String(s) => Ok(asn1::string_auto(s)),
            Value::Int(i) => Ok(asn1::integer_i64(*i)),
            Value::BitString(b) => Ok(asn1::bit_string(&b.bytes, b.bit_length)),
            Value::Bytes(b) => Ok(asn1::octet_string(b)),
            Value::ObjectIdentifier(o) => asn1::oid(&o.0).ok_or_else(asn1::err_oid),
            Value::Time(t) => asn1::time(t).ok_or_else(asn1::err_time),
            Value::Bool(b) => Ok(asn1::boolean(*b)),
            Value::Raw(r) => Ok(marshal_raw_value(r)),
        }
    }

    /// `fmt.Sprint(value)`.
    pub(crate) fn sprint(&self) -> String {
        match self {
            Value::Nil => "<nil>".to_string(),
            Value::String(s) => s.clone(),
            Value::Int(i) => i.to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Bytes(b) => sprint_bytes(b),
            Value::BitString(b) => format!("{{{} {}}}", sprint_bytes(&b.bytes), b.bit_length),
            Value::ObjectIdentifier(o) => o.to_string(),
            Value::Time(t) => t.to_string(),
            Value::Raw(r) => format!(
                "{{{} {} {} {} {}}}",
                r.class,
                r.tag,
                r.is_compound,
                sprint_bytes(&r.bytes),
                sprint_bytes(&r.full_bytes)
            ),
        }
    }

    fn is_string(&self) -> bool {
        matches!(self, Value::String(_))
    }
}

fn sprint_bytes(b: &[u8]) -> String {
    let mut s = String::from("[");
    for (i, v) in b.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        let _ = write!(s, "{v}");
    }
    s.push(']');
    s
}

/// Go's `pkix.AttributeTypeAndValue`: the ASN.1 structure of the same name in
/// RFC 5280, section 4.1.2.4.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AttributeTypeAndValue {
    pub type_: ObjectIdentifier,
    pub value: Value,
}

impl AttributeTypeAndValue {
    fn marshal(&self) -> Result<Vec<u8>, Error> {
        let mut content = asn1::oid(&self.type_.0).ok_or_else(asn1::err_oid)?;
        content.extend(self.value.marshal()?);
        Ok(asn1::tlv(asn1::SEQUENCE, &content))
    }
}

/// Go's `pkix.AttributeTypeAndValueSET`: a set of ASN.1 sequences of
/// [`AttributeTypeAndValue`] sequences from RFC 2986 (PKCS #10).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AttributeTypeAndValueSET {
    pub type_: ObjectIdentifier,
    pub value: Vec<Vec<AttributeTypeAndValue>>,
}

impl AttributeTypeAndValueSET {
    /// `asn1.Marshal`: the type and a SET OF SEQUENCE OF
    /// `AttributeTypeAndValue` with the elements sorted, as `asn1:"set"` does.
    pub(crate) fn marshal(&self) -> Result<Vec<u8>, Error> {
        let mut content = asn1::oid(&self.type_.0).ok_or_else(asn1::err_oid)?;
        let mut elements: Vec<Vec<u8>> = Vec::new();
        for atvs in &self.value {
            let mut seq = Vec::new();
            for atv in atvs {
                seq.extend(atv.marshal()?);
            }
            elements.push(asn1::tlv(asn1::SEQUENCE, &seq));
        }
        elements.sort();
        content.extend(asn1::tlv(asn1::SET, &elements.concat()));
        Ok(asn1::tlv(asn1::SEQUENCE, &content))
    }
}

/// Go's `pkix.Extension`: the ASN.1 structure of the same name (RFC 5280,
/// section 4.2).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Extension {
    pub id: ObjectIdentifier,
    pub critical: bool,
    pub value: Vec<u8>,
}

impl Extension {
    pub(crate) fn marshal(&self) -> Result<Vec<u8>, Error> {
        let mut content = asn1::oid(&self.id.0).ok_or_else(asn1::err_oid)?;
        if self.critical {
            content.extend(asn1::boolean(true));
        }
        content.extend(asn1::octet_string(&self.value));
        Ok(asn1::tlv(asn1::SEQUENCE, &content))
    }
}

/// Go's `pkix.RelativeDistinguishedNameSET`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RelativeDistinguishedNameSET(pub Vec<AttributeTypeAndValue>);

/// Go's `pkix.RDNSequence`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RDNSequence(pub Vec<RelativeDistinguishedNameSET>);

fn attribute_type_name(oid: &ObjectIdentifier) -> Option<&'static str> {
    match oid.0.as_slice() {
        [2, 5, 4, 6] => Some("C"),
        [2, 5, 4, 10] => Some("O"),
        [2, 5, 4, 11] => Some("OU"),
        [2, 5, 4, 3] => Some("CN"),
        [2, 5, 4, 5] => Some("SERIALNUMBER"),
        [2, 5, 4, 7] => Some("L"),
        [2, 5, 4, 8] => Some("ST"),
        [2, 5, 4, 9] => Some("STREET"),
        [2, 5, 4, 17] => Some("POSTALCODE"),
        _ => None,
    }
}

impl RDNSequence {
    /// `asn1.Marshal(rdns)`: `None` where Go returns an error.
    pub fn marshal(&self) -> Result<Vec<u8>, Error> {
        let mut content = Vec::new();
        for rdn in &self.0 {
            // encoding/asn1 encodes a SET OF in DER order, sorting the
            // encodings of its elements.
            let mut elements = Vec::new();
            for atv in &rdn.0 {
                elements.push(atv.marshal()?);
            }
            elements.sort();
            content.extend(asn1::tlv(asn1::SET, &elements.concat()));
        }
        Ok(asn1::tlv(asn1::SEQUENCE, &content))
    }

    /// Go's `RDNSequence.String`: a string representation of the sequence,
    /// roughly following the RFC 2253 Distinguished Names syntax.
    fn string(&self) -> String {
        let mut buf = String::new();
        let r = &self.0;
        for i in 0..r.len() {
            let rdn = &r[r.len() - 1 - i];
            if i > 0 {
                buf.push(',');
            }
            for (j, tv) in rdn.0.iter().enumerate() {
                if j > 0 {
                    buf.push('+');
                }
                let oid_string = tv.type_.to_string();
                let type_name = match attribute_type_name(&tv.type_) {
                    Some(name) => name.to_string(),
                    None => {
                        // RFC 2253 section 2.4: if the value's ASN.1 type has a
                        // string representation, render it as a string;
                        // otherwise hex-encode the DER.
                        if !tv.value.is_string() {
                            if let Ok(der) = tv.value.marshal() {
                                buf.push_str(&oid_string);
                                buf.push_str("=#");
                                buf.push_str(&hex(&der));
                                continue; // No value escaping necessary.
                            }
                        }
                        oid_string
                    }
                };

                let value_string = tv.value.sprint();
                let chars: Vec<(usize, char)> = value_string.char_indices().collect();
                let mut escaped = String::with_capacity(value_string.len());
                for &(k, c) in &chars {
                    let escape = match c {
                        ',' | '+' | '"' | '\\' | '<' | '>' | ';' => true,
                        ' ' => k == 0 || k == value_string.len() - 1,
                        '#' => k == 0,
                        _ => false,
                    };
                    if escape {
                        escaped.push('\\');
                    }
                    escaped.push(c);
                }
                buf.push_str(&type_name);
                buf.push('=');
                buf.push_str(&escaped);
            }
        }
        buf
    }
}

impl std::fmt::Display for RDNSequence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.string())
    }
}

/// Go's `pkix.Name`: an X.509 distinguished name. This only includes the
/// common elements of a DN; it is only an approximation of the X.509
/// structure. If an accurate representation is needed, parse the raw subject
/// or issuer as an [`RDNSequence`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Name {
    pub country: Vec<String>,
    pub organization: Vec<String>,
    pub organizational_unit: Vec<String>,
    pub locality: Vec<String>,
    pub province: Vec<String>,
    pub street_address: Vec<String>,
    pub postal_code: Vec<String>,
    pub serial_number: String,
    pub common_name: String,

    /// All parsed attributes. When parsing distinguished names, this can be
    /// used to extract non-standard attributes that are not parsed by this
    /// package. When marshaling to RDNSequences, the field is ignored, see
    /// `extra_names`.
    pub names: Vec<AttributeTypeAndValue>,

    /// Attributes to be copied, raw, into any marshaled distinguished names.
    /// Values override any attributes with the same OID. The field is not
    /// populated when parsing, see `names`. `None` is Go's nil slice, which
    /// matters for `Name::string`: only a nil `ExtraNames` surfaces `names`.
    pub extra_names: Option<Vec<AttributeTypeAndValue>>,
}

impl Name {
    /// Go's `Name.FillFromRDNSequence`: populates `self` from the
    /// [`RDNSequence`]. Multi-entry RDNs are flattened, all entries are added
    /// to the relevant fields, and the grouping is not preserved.
    pub fn fill_from_rdn_sequence(&mut self, rdns: &RDNSequence) {
        for rdn in &rdns.0 {
            if rdn.0.is_empty() {
                continue;
            }
            for atv in &rdn.0 {
                self.names.push(atv.clone());
                let Value::String(value) = &atv.value else {
                    continue;
                };
                if let [2, 5, 4, last] = atv.type_.0.as_slice() {
                    let value = value.clone();
                    match last {
                        3 => self.common_name = value,
                        5 => self.serial_number = value,
                        6 => self.country.push(value),
                        7 => self.locality.push(value),
                        8 => self.province.push(value),
                        9 => self.street_address.push(value),
                        10 => self.organization.push(value),
                        11 => self.organizational_unit.push(value),
                        17 => self.postal_code.push(value),
                        _ => {}
                    }
                }
            }
        }
    }

    fn append_rdns(&self, mut input: RDNSequence, values: &[String], oid: &[i64]) -> RDNSequence {
        let extra = self.extra_names.as_deref().unwrap_or(&[]);
        if values.is_empty() || extra.iter().any(|a| a.type_.0 == oid) {
            return input;
        }
        let s = values
            .iter()
            .map(|value| AttributeTypeAndValue {
                type_: ObjectIdentifier(oid.to_vec()),
                value: Value::String(value.clone()),
            })
            .collect();
        input.0.push(RelativeDistinguishedNameSET(s));
        input
    }

    /// Go's `Name.ToRDNSequence`: converts `self` into a single
    /// [`RDNSequence`]. Country, Organization, OrganizationalUnit, Locality,
    /// Province, StreetAddress and PostalCode are encoded as multi-value RDNs;
    /// each extra name is an individual RDN.
    pub fn to_rdn_sequence(&self) -> RDNSequence {
        let mut ret = RDNSequence::default();
        ret = self.append_rdns(ret, &self.country, &[2, 5, 4, 6]);
        ret = self.append_rdns(ret, &self.province, &[2, 5, 4, 8]);
        ret = self.append_rdns(ret, &self.locality, &[2, 5, 4, 7]);
        ret = self.append_rdns(ret, &self.street_address, &[2, 5, 4, 9]);
        ret = self.append_rdns(ret, &self.postal_code, &[2, 5, 4, 17]);
        ret = self.append_rdns(ret, &self.organization, &[2, 5, 4, 10]);
        ret = self.append_rdns(ret, &self.organizational_unit, &[2, 5, 4, 11]);
        if !self.common_name.is_empty() {
            ret = self.append_rdns(ret, std::slice::from_ref(&self.common_name), &[2, 5, 4, 3]);
        }
        if !self.serial_number.is_empty() {
            ret = self.append_rdns(
                ret,
                std::slice::from_ref(&self.serial_number),
                &[2, 5, 4, 5],
            );
        }
        for atv in self.extra_names.iter().flatten() {
            ret.0.push(RelativeDistinguishedNameSET(vec![atv.clone()]));
        }
        ret
    }

    /// Go's `Name.String`: the string form of `self`, roughly following the
    /// RFC 2253 Distinguished Names syntax.
    fn string(&self) -> String {
        let mut rdns = RDNSequence::default();
        // If there are no ExtraNames, surface the parsed value (all entries in
        // Names) instead.
        if self.extra_names.is_none() {
            for atv in &self.names {
                if let [2, 5, 4, 3 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 17] = atv.type_.0.as_slice() {
                    // These attributes were already parsed into named fields.
                    continue;
                }
                // Place non-standard parsed values at the beginning of the
                // sequence so they will be at the end of the string.
                rdns.0.push(RelativeDistinguishedNameSET(vec![atv.clone()]));
            }
        }
        rdns.0.extend(self.to_rdn_sequence().0);
        rdns.string()
    }
}

impl std::fmt::Display for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.string())
    }
}

/// Go's `pkix.CertificateList`: the ASN.1 structure of the same name (RFC
/// 5280, section 5.1). Use `Certificate::check_crl_signature` to verify the
/// signature.
///
/// Deprecated in Go: use `RevocationList` instead.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CertificateList {
    pub tbs_cert_list: TBSCertificateList,
    pub signature_algorithm: AlgorithmIdentifier,
    pub signature_value: BitString,
}

impl CertificateList {
    /// Go's `CertificateList.HasExpired`: whether the list should have been
    /// updated by now.
    pub fn has_expired(&self, now: &Time) -> bool {
        !now.before(&self.tbs_cert_list.next_update)
    }
}

/// Go's `pkix.TBSCertificateList`: the ASN.1 structure of the same name (RFC
/// 5280, section 5.1).
///
/// Deprecated in Go: use `RevocationList` instead.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TBSCertificateList {
    /// The complete DER encoding (Go's `asn1.RawContent`).
    pub raw: Vec<u8>,
    pub version: i64,
    pub signature: AlgorithmIdentifier,
    pub issuer: RDNSequence,
    pub this_update: Time,
    pub next_update: Time,
    pub revoked_certificates: Vec<RevokedCertificate>,
    pub extensions: Vec<Extension>,
}

/// Go's `pkix.RevokedCertificate`: the ASN.1 structure of the same name (RFC
/// 5280, section 5.1).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RevokedCertificate {
    pub serial_number: BigInt,
    pub revocation_time: Time,
    pub extensions: Vec<Extension>,
}

impl RevokedCertificate {
    pub(crate) fn marshal(&self) -> Result<Vec<u8>, Error> {
        let mut content = asn1::integer_big(&self.serial_number);
        content.extend(asn1::time(&self.revocation_time).ok_or_else(asn1::err_time)?);
        if !self.extensions.is_empty() {
            let mut exts = Vec::new();
            for e in &self.extensions {
                exts.extend(e.marshal()?);
            }
            content.extend(asn1::tlv(asn1::SEQUENCE, &exts));
        }
        Ok(asn1::tlv(asn1::SEQUENCE, &content))
    }
}
