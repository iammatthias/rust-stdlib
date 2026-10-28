//! Hybrid Public Key Encryption (RFC 9180), compatible with Go's
//! `crypto/hpke`.
//!
//! The key schedule, encapsulation, key derivation and AEAD sealing run in the
//! reviewed `hpke` crate (rozbb/rust-hpke 0.14.1) over RustCrypto primitives;
//! this module adds Go's runtime-selected KEM/KDF/AEAD values and key types.
//!
//! Supported suites: the RFC 9180 DHKEMs (P-256 with HKDF-SHA256, P-384 with
//! HKDF-SHA384, P-521 with HKDF-SHA512, X25519 with HKDF-SHA256), the KDFs
//! HKDF-SHA256/384/512 and the AEADs AES-128-GCM, AES-256-GCM,
//! ChaCha20-Poly1305 and export-only.
//!
//! Not supported (documented deviations, ADR 0003): the post-quantum and hybrid
//! KEMs (ML-KEM-768/1024, MLKEM768-X25519, MLKEM768-P256, MLKEM1024-P384) and
//! the SHAKE KDFs of Go's HPKE post-quantum draft, whose crate features would
//! need a second major version of `sha3` next to the one the rest of the crate
//! uses; and `DHKEM` pairings other than the RFC 9180 ones. The functions that
//! construct them return values whose operations report an error.

use std::fmt;
use std::sync::Arc;

use hpke::aead::{AeadCtxR, AeadCtxS, AesGcm128, AesGcm256, ChaCha20Poly1305, ExportOnlyAead};
use hpke::kdf::{HkdfSha256, HkdfSha384, HkdfSha512};
use hpke::kem::{DhP256HkdfSha256, DhP384HkdfSha384, DhP521HkdfSha512, X25519HkdfSha256};
use hpke::{Deserializable, Kem as _, OpModeR, OpModeS, Serializable};

use crate::ecdh;
use crate::sysrng::Source;
use crate::Decapsulator;

/// An error with a message in the style of Go's `crypto/hpke`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error(String);

impl Error {
    fn new(message: impl Into<String>) -> Error {
        Error(message.into())
    }

    fn unsupported(what: &str) -> Error {
        Error(format!(
            "hpke: {what} is not supported by the reviewed hpke crate configuration"
        ))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<hpke::HpkeError> for Error {
    fn from(error: hpke::HpkeError) -> Error {
        Error(format!("hpke: {error}"))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DhKind {
    P256,
    P384,
    P521,
    X25519,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KdfKind {
    Sha256,
    Sha384,
    Sha512,
    Shake128,
    Shake256,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AeadKind {
    Aes128,
    Aes256,
    ChaCha20Poly1305,
    ExportOnly,
}

mod sealed {
    pub trait Sealed {}
}

/// Go's `hpke.KDF`: a key derivation function identified by its code point.
pub trait Kdf: sealed::Sealed + fmt::Debug + Send + Sync {
    /// Go's `KDF.ID`.
    fn id(&self) -> u16;
    #[doc(hidden)]
    fn kind(&self) -> Option<KdfId>;
}

/// Go's `hpke.AEAD`: an authenticated encryption algorithm identified by its
/// code point.
pub trait Aead: sealed::Sealed + fmt::Debug + Send + Sync {
    /// Go's `AEAD.ID`.
    fn id(&self) -> u16;
    #[doc(hidden)]
    fn kind(&self) -> AeadId;
}

#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KdfId(KdfKind);

#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AeadId(AeadKind);

#[derive(Debug)]
struct SimpleKdf(KdfKind, u16);

#[derive(Debug)]
struct SimpleAead(AeadKind, u16);

impl sealed::Sealed for SimpleKdf {}
impl sealed::Sealed for SimpleAead {}

impl Kdf for SimpleKdf {
    fn id(&self) -> u16 {
        self.1
    }

    fn kind(&self) -> Option<KdfId> {
        match self.0 {
            KdfKind::Shake128 | KdfKind::Shake256 => None,
            kind => Some(KdfId(kind)),
        }
    }
}

impl Aead for SimpleAead {
    fn id(&self) -> u16 {
        self.1
    }

    fn kind(&self) -> AeadId {
        AeadId(self.0)
    }
}

/// Go's `hpke.HKDFSHA256`.
pub fn hkdf_sha256() -> Arc<dyn Kdf> {
    Arc::new(SimpleKdf(KdfKind::Sha256, 0x0001))
}

/// Go's `hpke.HKDFSHA384`.
pub fn hkdf_sha384() -> Arc<dyn Kdf> {
    Arc::new(SimpleKdf(KdfKind::Sha384, 0x0002))
}

/// Go's `hpke.HKDFSHA512`.
pub fn hkdf_sha512() -> Arc<dyn Kdf> {
    Arc::new(SimpleKdf(KdfKind::Sha512, 0x0003))
}

/// Go's `hpke.SHAKE128`. Operations with it report an error (see the module
/// documentation).
pub fn shake128() -> Arc<dyn Kdf> {
    Arc::new(SimpleKdf(KdfKind::Shake128, 0x0010))
}

/// Go's `hpke.SHAKE256`. Operations with it report an error (see the module
/// documentation).
pub fn shake256() -> Arc<dyn Kdf> {
    Arc::new(SimpleKdf(KdfKind::Shake256, 0x0011))
}

/// Go's `hpke.AES128GCM`.
pub fn aes128gcm() -> Arc<dyn Aead> {
    Arc::new(SimpleAead(AeadKind::Aes128, 0x0001))
}

/// Go's `hpke.AES256GCM`.
pub fn aes256gcm() -> Arc<dyn Aead> {
    Arc::new(SimpleAead(AeadKind::Aes256, 0x0002))
}

/// Go's `hpke.ChaCha20Poly1305`.
pub fn chacha20poly1305() -> Arc<dyn Aead> {
    Arc::new(SimpleAead(AeadKind::ChaCha20Poly1305, 0x0003))
}

/// Go's `hpke.ExportOnly`: an AEAD that cannot seal or open, for contexts
/// used only to export secrets.
pub fn export_only() -> Arc<dyn Aead> {
    Arc::new(SimpleAead(AeadKind::ExportOnly, 0xFFFF))
}

/// Go's `hpke.NewKDF`: the KDF with the given code point.
pub fn kdf_from_id(id: u16) -> Result<Arc<dyn Kdf>, Error> {
    match id {
        0x0001 => Ok(hkdf_sha256()),
        0x0002 => Ok(hkdf_sha384()),
        0x0003 => Ok(hkdf_sha512()),
        0x0010 => Ok(shake128()),
        0x0011 => Ok(shake256()),
        _ => Err(Error::new(format!("unsupported KDF {id:#04x}"))),
    }
}

/// Go's `hpke.NewAEAD`: the AEAD with the given code point.
pub fn aead_from_id(id: u16) -> Result<Arc<dyn Aead>, Error> {
    match id {
        0x0001 => Ok(aes128gcm()),
        0x0002 => Ok(aes256gcm()),
        0x0003 => Ok(chacha20poly1305()),
        0xFFFF => Ok(export_only()),
        _ => Err(Error::new(format!("unsupported AEAD {id:#04x}"))),
    }
}

/// Go's `hpke.PublicKey`: a KEM public key.
pub trait PublicKey: sealed::Sealed + fmt::Debug + Send + Sync {
    /// Go's `PublicKey.KEM`.
    fn kem(&self) -> Arc<dyn Kem>;
    /// Go's `PublicKey.Bytes`.
    fn bytes(&self) -> Vec<u8>;
    #[doc(hidden)]
    fn dh(&self) -> Option<(DhId, Vec<u8>)>;
}

/// Go's `hpke.PrivateKey`: a KEM private key.
pub trait PrivateKey: sealed::Sealed + fmt::Debug + Send + Sync {
    /// Go's `PrivateKey.KEM`.
    fn kem(&self) -> Arc<dyn Kem>;
    /// Go's `PrivateKey.Bytes`.
    fn bytes(&self) -> Result<Vec<u8>, Error>;
    /// Go's `PrivateKey.PublicKey`.
    fn public_key(&self) -> Box<dyn PublicKey>;
    #[doc(hidden)]
    fn dh(&self) -> Option<(DhId, Vec<u8>)>;
}

/// Go's `hpke.KEM`: a key encapsulation mechanism identified by its code
/// point.
pub trait Kem: sealed::Sealed + fmt::Debug + Send + Sync {
    /// Go's `KEM.ID`.
    fn id(&self) -> u16;
    /// Go's `KEM.GenerateKey`.
    fn generate_key(&self) -> Result<Box<dyn PrivateKey>, Error>;
    /// Go's `KEM.NewPublicKey`.
    fn public_key_from_bytes(&self, data: &[u8]) -> Result<Box<dyn PublicKey>, Error>;
    /// Go's `KEM.NewPrivateKey`.
    fn private_key_from_bytes(&self, data: &[u8]) -> Result<Box<dyn PrivateKey>, Error>;
    /// Go's `KEM.DeriveKeyPair`.
    fn derive_key_pair(&self, ikm: &[u8]) -> Result<Box<dyn PrivateKey>, Error>;
    #[doc(hidden)]
    fn dh(&self) -> Option<DhId>;
    #[doc(hidden)]
    fn enc_size(&self) -> usize;
}

#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DhId(DhKind);

/// The DHKEMs of RFC 9180 and the KEMs this configuration cannot run.
#[derive(Debug)]
struct KemValue {
    id: u16,
    dh: Option<DhKind>,
    name: &'static str,
}

impl sealed::Sealed for KemValue {}

#[derive(Clone, Debug)]
struct DhPublic {
    kind: DhKind,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
struct DhPrivate {
    kind: DhKind,
    bytes: Vec<u8>,
    public: DhPublic,
}

impl sealed::Sealed for DhPublic {}
impl sealed::Sealed for DhPrivate {}

fn kem_value(kind: DhKind) -> Arc<dyn Kem> {
    let (id, name) = match kind {
        DhKind::P256 => (0x0010, "DHKEM(P-256, HKDF-SHA256)"),
        DhKind::P384 => (0x0011, "DHKEM(P-384, HKDF-SHA384)"),
        DhKind::P521 => (0x0012, "DHKEM(P-521, HKDF-SHA512)"),
        DhKind::X25519 => (0x0020, "DHKEM(X25519, HKDF-SHA256)"),
    };
    Arc::new(KemValue {
        id,
        dh: Some(kind),
        name,
    })
}

fn unsupported_kem(id: u16, name: &'static str) -> Arc<dyn Kem> {
    Arc::new(KemValue { id, dh: None, name })
}

macro_rules! with_dh {
    ($kind:expr, $k:ident => $body:expr) => {
        match $kind {
            DhKind::P256 => {
                type $k = DhP256HkdfSha256;
                $body
            }
            DhKind::P384 => {
                type $k = DhP384HkdfSha384;
                $body
            }
            DhKind::P521 => {
                type $k = DhP521HkdfSha512;
                $body
            }
            DhKind::X25519 => {
                type $k = X25519HkdfSha256;
                $body
            }
        }
    };
}

fn parse_public<K: hpke::Kem>(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let key = <K::PublicKey as Deserializable>::from_bytes(bytes)?;
    Ok(key.to_bytes().to_vec())
}

fn private_from_bytes<K: hpke::Kem>(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let key = <K::PrivateKey as Deserializable>::from_bytes(bytes)?;
    let public = K::sk_to_pk(&key);
    Ok((key.to_bytes().to_vec(), public.to_bytes().to_vec()))
}

fn make_private(kind: DhKind, private: Vec<u8>, public: Vec<u8>) -> Box<dyn PrivateKey> {
    Box::new(DhPrivate {
        kind,
        bytes: private,
        public: DhPublic {
            kind,
            bytes: public,
        },
    })
}

impl Kem for KemValue {
    fn id(&self) -> u16 {
        self.id
    }

    fn generate_key(&self) -> Result<Box<dyn PrivateKey>, Error> {
        let kind = self.dh.ok_or_else(|| Error::unsupported(self.name))?;
        with_dh!(kind, K => {
            let (sk, pk) = K::gen_keypair_with_rng(&mut Source::System);
            Ok(make_private(kind, sk.to_bytes().to_vec(), pk.to_bytes().to_vec()))
        })
    }

    fn public_key_from_bytes(&self, data: &[u8]) -> Result<Box<dyn PublicKey>, Error> {
        let kind = self.dh.ok_or_else(|| Error::unsupported(self.name))?;
        let bytes = with_dh!(kind, K => parse_public::<K>(data))?;
        Ok(Box::new(DhPublic { kind, bytes }))
    }

    fn private_key_from_bytes(&self, data: &[u8]) -> Result<Box<dyn PrivateKey>, Error> {
        let kind = self.dh.ok_or_else(|| Error::unsupported(self.name))?;
        let (private, public) = with_dh!(kind, K => private_from_bytes::<K>(data))?;
        Ok(make_private(kind, private, public))
    }

    fn derive_key_pair(&self, ikm: &[u8]) -> Result<Box<dyn PrivateKey>, Error> {
        let kind = self.dh.ok_or_else(|| Error::unsupported(self.name))?;
        with_dh!(kind, K => {
            let (sk, pk) = K::derive_keypair(ikm);
            Ok(make_private(kind, sk.to_bytes().to_vec(), pk.to_bytes().to_vec()))
        })
    }

    fn dh(&self) -> Option<DhId> {
        self.dh.map(DhId)
    }

    fn enc_size(&self) -> usize {
        match self.dh {
            Some(DhKind::P256) => 65,
            Some(DhKind::P384) => 97,
            Some(DhKind::P521) => 133,
            Some(DhKind::X25519) => 32,
            None => 0,
        }
    }
}

impl PublicKey for DhPublic {
    fn kem(&self) -> Arc<dyn Kem> {
        kem_value(self.kind)
    }

    fn bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    fn dh(&self) -> Option<(DhId, Vec<u8>)> {
        Some((DhId(self.kind), self.bytes.clone()))
    }
}

impl PrivateKey for DhPrivate {
    fn kem(&self) -> Arc<dyn Kem> {
        kem_value(self.kind)
    }

    fn bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(self.bytes.clone())
    }

    fn public_key(&self) -> Box<dyn PublicKey> {
        Box::new(self.public.clone())
    }

    fn dh(&self) -> Option<(DhId, Vec<u8>)> {
        Some((DhId(self.kind), self.bytes.clone()))
    }
}

/// Go's `hpke.DHKEM`: the DHKEM of an ECDH curve and a KDF. Only the RFC 9180
/// pairings (P-256/HKDF-SHA256, P-384/HKDF-SHA384, P-521/HKDF-SHA512,
/// X25519/HKDF-SHA256) can run; the value for any other pairing reports an
/// error when used.
pub fn dhkem(curve: &dyn ecdh::Curve, kdf: &dyn Kdf) -> Arc<dyn Kem> {
    let pairing = (curve.name(), kdf.id());
    match pairing {
        ("P-256", 0x0001) => kem_value(DhKind::P256),
        ("P-384", 0x0002) => kem_value(DhKind::P384),
        ("P-521", 0x0003) => kem_value(DhKind::P521),
        ("X25519", 0x0001) => kem_value(DhKind::X25519),
        _ => unsupported_kem(0, "this DHKEM pairing"),
    }
}

/// Go's `hpke.MLKEM768`. Operations with it report an error (see the module
/// documentation).
pub fn mlkem768() -> Arc<dyn Kem> {
    unsupported_kem(0x0041, "ML-KEM-768")
}

/// Go's `hpke.MLKEM1024`. Operations with it report an error.
pub fn mlkem1024() -> Arc<dyn Kem> {
    unsupported_kem(0x0042, "ML-KEM-1024")
}

/// Go's `hpke.MLKEM768X25519`. Operations with it report an error.
pub fn mlkem768x25519() -> Arc<dyn Kem> {
    unsupported_kem(0x647a, "MLKEM768-X25519")
}

/// Go's `hpke.MLKEM768P256`. Operations with it report an error.
pub fn mlkem768p256() -> Arc<dyn Kem> {
    unsupported_kem(0x0050, "MLKEM768-P256")
}

/// Go's `hpke.MLKEM1024P384`. Operations with it report an error.
pub fn mlkem1024p384() -> Arc<dyn Kem> {
    unsupported_kem(0x0051, "MLKEM1024-P384")
}

/// Go's `hpke.NewKEM`: the KEM with the given code point.
pub fn kem_from_id(id: u16) -> Result<Arc<dyn Kem>, Error> {
    match id {
        0x0010 => Ok(kem_value(DhKind::P256)),
        0x0011 => Ok(kem_value(DhKind::P384)),
        0x0012 => Ok(kem_value(DhKind::P521)),
        0x0020 => Ok(kem_value(DhKind::X25519)),
        0x0041 => Ok(mlkem768()),
        0x0042 => Ok(mlkem1024()),
        0x647a => Ok(mlkem768x25519()),
        0x0050 => Ok(mlkem768p256()),
        0x0051 => Ok(mlkem1024p384()),
        _ => Err(Error::new(format!("unsupported KEM {id:#04x}"))),
    }
}

fn dh_kind_of(curve: &dyn ecdh::Curve) -> Result<DhKind, Error> {
    match curve.name() {
        "P-256" => Ok(DhKind::P256),
        "P-384" => Ok(DhKind::P384),
        "P-521" => Ok(DhKind::P521),
        "X25519" => Ok(DhKind::X25519),
        other => Err(Error::new(format!("unsupported curve {other}"))),
    }
}

/// Go's `hpke.NewDHKEMPrivateKey`: wraps an ECDH private key for the DHKEM of
/// its curve.
pub fn dhkem_private_key(key: &ecdh::PrivateKey) -> Result<Box<dyn PrivateKey>, Error> {
    let kind = dh_kind_of(key.curve())?;
    let kem = kem_value(kind);
    kem.private_key_from_bytes(&key.bytes())
}

/// Go's `hpke.NewDHKEMPublicKey`: wraps an ECDH public key for the DHKEM of
/// its curve.
pub fn dhkem_public_key(key: &ecdh::PublicKey) -> Result<Box<dyn PublicKey>, Error> {
    let kind = dh_kind_of(key.curve())?;
    kem_value(kind).public_key_from_bytes(&key.bytes())
}

/// Go's `hpke.NewMLKEMPrivateKey`. Reports an error (see the module
/// documentation).
pub fn mlkem_private_key(_decapsulator: &dyn Decapsulator) -> Result<Box<dyn PrivateKey>, Error> {
    Err(Error::unsupported("ML-KEM private keys"))
}

/// Go's `hpke.NewMLKEMPublicKey`. Reports an error.
pub fn mlkem_public_key(
    _encapsulator: &dyn crate::Encapsulator,
) -> Result<Box<dyn PublicKey>, Error> {
    Err(Error::unsupported("ML-KEM public keys"))
}

/// Go's `hpke.NewHybridPrivateKey`. Reports an error.
pub fn hybrid_private_key(
    _pq: &dyn Decapsulator,
    _traditional: &ecdh::PrivateKey,
    _kem: &dyn Kem,
) -> Result<Box<dyn PrivateKey>, Error> {
    Err(Error::unsupported("hybrid private keys"))
}

/// Go's `hpke.NewHybridPublicKey`. Reports an error.
pub fn hybrid_public_key(
    _pq: &dyn crate::Encapsulator,
    _traditional: &ecdh::PublicKey,
    _kem: &dyn Kem,
) -> Result<Box<dyn PublicKey>, Error> {
    Err(Error::unsupported("hybrid public keys"))
}

trait SenderContext {
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error>;
    fn export(&self, context: &[u8], length: usize) -> Result<Vec<u8>, Error>;
}

trait RecipientContext {
    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error>;
    fn export(&self, context: &[u8], length: usize) -> Result<Vec<u8>, Error>;
}

struct SenderImpl<A: hpke::aead::Aead, D: hpke::kdf::Kdf, K: hpke::Kem> {
    ctx: AeadCtxS<A, D, K>,
    export_only: bool,
}

struct RecipientImpl<A: hpke::aead::Aead, D: hpke::kdf::Kdf, K: hpke::Kem> {
    ctx: AeadCtxR<A, D, K>,
    export_only: bool,
}

impl<A: hpke::aead::Aead, D: hpke::kdf::Kdf, K: hpke::Kem> SenderContext for SenderImpl<A, D, K> {
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        if self.export_only {
            return Err(Error::new("export-only instantiation"));
        }
        Ok(self.ctx.seal(plaintext, aad)?)
    }

    fn export(&self, context: &[u8], length: usize) -> Result<Vec<u8>, Error> {
        let mut out = vec![0u8; length];
        self.ctx.export(context, &mut out)?;
        Ok(out)
    }
}

impl<A: hpke::aead::Aead, D: hpke::kdf::Kdf, K: hpke::Kem> RecipientContext
    for RecipientImpl<A, D, K>
{
    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        if self.export_only {
            return Err(Error::new("export-only instantiation"));
        }
        Ok(self.ctx.open(ciphertext, aad)?)
    }

    fn export(&self, context: &[u8], length: usize) -> Result<Vec<u8>, Error> {
        let mut out = vec![0u8; length];
        self.ctx.export(context, &mut out)?;
        Ok(out)
    }
}

fn setup_sender_generic<A, D, K>(
    public: &[u8],
    info: &[u8],
    export_only: bool,
    source: &mut Source<'_>,
) -> Result<(Vec<u8>, Box<dyn SenderContext>), Error>
where
    A: hpke::aead::Aead + 'static,
    D: hpke::kdf::Kdf + 'static,
    K: hpke::Kem + 'static,
{
    let public = <K::PublicKey as Deserializable>::from_bytes(public)?;
    let (enc, ctx) = hpke::setup_sender_with_rng::<A, D, K>(&OpModeS::Base, &public, info, source)?;
    Ok((
        enc.to_bytes().to_vec(),
        Box::new(SenderImpl { ctx, export_only }),
    ))
}

fn setup_recipient_generic<A, D, K>(
    enc: &[u8],
    private: &[u8],
    info: &[u8],
    export_only: bool,
) -> Result<Box<dyn RecipientContext>, Error>
where
    A: hpke::aead::Aead + 'static,
    D: hpke::kdf::Kdf + 'static,
    K: hpke::Kem + 'static,
{
    let private = <K::PrivateKey as Deserializable>::from_bytes(private)?;
    let enc = <K::EncappedKey as Deserializable>::from_bytes(enc)?;
    let ctx = hpke::setup_receiver::<A, D, K>(&OpModeR::Base, &private, &enc, info)?;
    Ok(Box::new(RecipientImpl { ctx, export_only }))
}

/// Dispatches on the runtime KEM, KDF and AEAD choices.
macro_rules! with_suite {
    ($dh:expr, $kdf:expr, $aead:expr, $a:ident, $d:ident, $k:ident => $body:expr) => {
        with_dh!($dh, $k => match $kdf {
            KdfKind::Sha256 => { type $d = HkdfSha256; with_aead!($aead, $a => $body) }
            KdfKind::Sha384 => { type $d = HkdfSha384; with_aead!($aead, $a => $body) }
            KdfKind::Sha512 => { type $d = HkdfSha512; with_aead!($aead, $a => $body) }
            KdfKind::Shake128 | KdfKind::Shake256 => unreachable!("rejected before dispatch"),
        })
    };
}

macro_rules! with_aead {
    ($aead:expr, $a:ident => $body:expr) => {
        match $aead {
            AeadKind::Aes128 => {
                type $a = AesGcm128;
                $body
            }
            AeadKind::Aes256 => {
                type $a = AesGcm256;
                $body
            }
            AeadKind::ChaCha20Poly1305 => {
                type $a = ChaCha20Poly1305;
                $body
            }
            AeadKind::ExportOnly => {
                type $a = ExportOnlyAead;
                $body
            }
        }
    };
}

fn suite(kdf: &dyn Kdf, aead: &dyn Aead) -> Result<(KdfKind, AeadKind), Error> {
    let kdf = kdf
        .kind()
        .ok_or_else(|| Error::unsupported("the SHAKE KDFs"))?;
    Ok((kdf.0, aead.kind().0))
}

/// Go's `hpke.Sender`: an HPKE sender context.
pub struct Sender {
    ctx: Box<dyn SenderContext>,
}

/// Go's `hpke.Recipient`: an HPKE recipient context.
pub struct Recipient {
    ctx: Box<dyn RecipientContext>,
}

impl fmt::Debug for Sender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sender")
    }
}

impl fmt::Debug for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Recipient")
    }
}

impl Sender {
    /// Go's `hpke.NewSender`: sets up a sender for the recipient `public_key`.
    /// Returns the encapsulated key to send to the recipient and the context.
    pub fn new(
        public_key: &dyn PublicKey,
        kdf: &dyn Kdf,
        aead: &dyn Aead,
        info: &[u8],
    ) -> Result<(Vec<u8>, Sender), Error> {
        Self::setup(public_key, kdf, aead, info, &mut Source::System)
    }

    /// [`Sender::new`] with the encapsulation randomness read from `rand`, for
    /// known-answer tests (Go's tests replace the key generator the same way): a
    /// DHKEM reads the key material `ikmE` of RFC 9180 section 7.1.3.
    #[doc(hidden)]
    pub fn with_rng(
        public_key: &dyn PublicKey,
        kdf: &dyn Kdf,
        aead: &dyn Aead,
        info: &[u8],
        rand: &mut dyn std::io::Read,
    ) -> Result<(Vec<u8>, Sender), Error> {
        let mut source = Source::explicit(Some(rand));
        let result = Self::setup(public_key, kdf, aead, info, &mut source);
        source
            .finish()
            .map_err(|error| Error::new(error.to_string()))?;
        result
    }

    fn setup(
        public_key: &dyn PublicKey,
        kdf: &dyn Kdf,
        aead: &dyn Aead,
        info: &[u8],
        source: &mut Source<'_>,
    ) -> Result<(Vec<u8>, Sender), Error> {
        let (kdf_kind, aead_kind) = suite(kdf, aead)?;
        let (dh, bytes) = public_key
            .dh()
            .ok_or_else(|| Error::unsupported("this KEM"))?;
        let export_only = aead_kind == AeadKind::ExportOnly;
        let (enc, ctx) = with_suite!(dh.0, kdf_kind, aead_kind, A, D, K =>
        setup_sender_generic::<A, D, K>(&bytes, info, export_only, source))?;
        Ok((enc, Self { ctx }))
    }
}

impl Recipient {
    /// Go's `hpke.NewRecipient`: sets up a recipient from an encapsulated key.
    pub fn new(
        enc: &[u8],
        private_key: &dyn PrivateKey,
        kdf: &dyn Kdf,
        aead: &dyn Aead,
        info: &[u8],
    ) -> Result<Recipient, Error> {
        let (kdf_kind, aead_kind) = suite(kdf, aead)?;
        let (dh, bytes) = private_key
            .dh()
            .ok_or_else(|| Error::unsupported("this KEM"))?;
        let export_only = aead_kind == AeadKind::ExportOnly;
        let ctx = with_suite!(dh.0, kdf_kind, aead_kind, A, D, K =>
        setup_recipient_generic::<A, D, K>(enc, &bytes, info, export_only))?;
        Ok(Self { ctx })
    }
}

impl Sender {
    /// Go's `Sender.Seal`: encrypts `plaintext` with additional data `aad`.
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.ctx.seal(aad, plaintext)
    }

    /// Go's `Sender.Export`: derives a secret from the context.
    pub fn export(&self, exporter_context: &str, length: usize) -> Result<Vec<u8>, Error> {
        self.export_bytes(exporter_context.as_bytes(), length)
    }

    /// [`Sender::export`] for an exporter context that is not UTF-8, which a
    /// Go string can hold.
    pub fn export_bytes(&self, exporter_context: &[u8], length: usize) -> Result<Vec<u8>, Error> {
        if length > 0xFFFF {
            return Err(Error::new("invalid length"));
        }
        self.ctx.export(exporter_context, length)
    }
}

impl Recipient {
    /// Go's `Recipient.Open`: decrypts `ciphertext` with additional data `aad`.
    pub fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        self.ctx.open(aad, ciphertext)
    }

    /// Go's `Recipient.Export`: derives a secret from the context.
    pub fn export(&self, exporter_context: &str, length: usize) -> Result<Vec<u8>, Error> {
        self.export_bytes(exporter_context.as_bytes(), length)
    }

    /// [`Recipient::export`] for an exporter context that is not UTF-8, which
    /// a Go string can hold.
    pub fn export_bytes(&self, exporter_context: &[u8], length: usize) -> Result<Vec<u8>, Error> {
        if length > 0xFFFF {
            return Err(Error::new("invalid length"));
        }
        self.ctx.export(exporter_context, length)
    }
}

/// Go's `hpke.Seal`: single-shot encryption; the result is the encapsulated
/// key followed by the ciphertext.
pub fn seal(
    public_key: &dyn PublicKey,
    kdf: &dyn Kdf,
    aead: &dyn Aead,
    info: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let (mut enc, mut sender) = Sender::new(public_key, kdf, aead, info)?;
    let ciphertext = sender.seal(&[], plaintext)?;
    enc.extend_from_slice(&ciphertext);
    Ok(enc)
}

/// Go's `hpke.Open`: single-shot decryption of the output of [`seal`].
pub fn open(
    private_key: &dyn PrivateKey,
    kdf: &dyn Kdf,
    aead: &dyn Aead,
    info: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    let enc_size = private_key.kem().id_enc_size();
    if ciphertext.len() < enc_size {
        return Err(Error::new("ciphertext too short"));
    }
    let (enc, ciphertext) = ciphertext.split_at(enc_size);
    let mut recipient = Recipient::new(enc, private_key, kdf, aead, info)?;
    recipient.open(&[], ciphertext)
}

trait EncSize {
    fn id_enc_size(&self) -> usize;
}

impl EncSize for Arc<dyn Kem> {
    fn id_enc_size(&self) -> usize {
        self.enc_size()
    }
}
