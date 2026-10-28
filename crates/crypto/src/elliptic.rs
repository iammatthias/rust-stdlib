//! Elliptic curves over prime fields, compatible with Go's `crypto/elliptic`.
//!
//! Go deprecated the [`Curve`] interface's point operations in favour of
//! `crypto/ecdh` and `crypto/ecdsa`, but the named NIST curves remain. P-224,
//! P-256, P-384 and P-521 are backed by the reviewed `p224`, `p256`, `p384`
//! and `p521` crates (see `crate::nistec`); their point addition, doubling
//! and scalar multiplication run there. Go's *generic* fallback, which performs
//! the same operations on a caller-supplied [`CurveParams`] with `math/big`,
//! is a first-party elliptic-curve implementation and is therefore not
//! provided (docs/adr/0003): the arithmetic methods of a [`CurveParams`] that
//! is not one of the four NIST curves panic with a message saying so.
//!
//! Like Go, the point operations panic on points that are not on the curve.

use std::io;
use std::sync::{Arc, OnceLock};

use crate::bigint::Int;
use crate::nistec::{self, Backend, Id};

/// Go's `elliptic.Curve`: a short-form Weierstrass curve with `a = -3`.
pub trait Curve: Send + Sync {
    /// The parameters of the curve.
    fn params(&self) -> &CurveParams;

    /// Reports whether the given `(x, y)` lies on the curve (deprecated in Go).
    fn is_on_curve(&self, x: &Int, y: &Int) -> bool;

    /// Returns the sum of `(x1, y1)` and `(x2, y2)` (deprecated in Go).
    fn add(&self, x1: &Int, y1: &Int, x2: &Int, y2: &Int) -> (Int, Int);

    /// Returns `2 * (x1, y1)` (deprecated in Go).
    fn double(&self, x1: &Int, y1: &Int) -> (Int, Int);

    /// Returns `k * (x1, y1)` where `k` is a big-endian number (deprecated in Go).
    fn scalar_mult(&self, x1: &Int, y1: &Int, k: &[u8]) -> (Int, Int);

    /// Returns `k * G` where `G` is the base point (deprecated in Go).
    fn scalar_base_mult(&self, k: &[u8]) -> (Int, Int);

    #[doc(hidden)]
    fn nist(&self) -> Option<Id> {
        self.params().named
    }
}

/// Go's `elliptic.CurveParams`: the parameters of a short Weierstrass curve
/// `y² = x³ - 3x + b` over the prime field of order `p`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CurveParams {
    /// The order of the underlying field.
    pub p: Int,
    /// The order of the base point.
    pub n: Int,
    /// The constant of the curve equation.
    pub b: Int,
    /// The x coordinate of the base point.
    pub gx: Int,
    /// The y coordinate of the base point.
    pub gy: Int,
    /// The size of the underlying field in bits.
    pub bit_size: usize,
    /// The canonical name of the curve.
    pub name: String,
    named: Option<Id>,
}

fn panic_custom(operation: &str) -> ! {
    panic!(
        "crypto/elliptic: {operation} on a custom CurveParams is not supported \
         (the reviewed crates implement only P-224, P-256, P-384 and P-521)"
    )
}

impl CurveParams {
    /// The reviewed backend, if these are the unmodified parameters of a NIST
    /// curve. A copy of `P256().Params()` whose fields were changed is a
    /// custom curve and gets no backend.
    fn backend(&self) -> Option<&'static dyn Backend> {
        let id = self.named?;
        (self == canonical(id)).then(|| nistec::backend(id))
    }

    fn byte_len(&self) -> usize {
        self.bit_size.div_ceil(8)
    }

    /// Go's `pointFromAffine`: the SEC 1 encoding of `(x, y)` or the identity
    /// for `(0, 0)`, or an error message.
    fn encode_affine(&self, x: &Int, y: &Int) -> Result<Vec<u8>, &'static str> {
        if x.is_zero() && y.is_zero() {
            return Ok(vec![0]);
        }
        if x.bit_len() > self.bit_size || y.bit_len() > self.bit_size {
            return Err("overflowing coordinate");
        }
        let len = self.byte_len();
        let mut buf = vec![4u8];
        buf.extend(x.fill_bytes(len).expect("fits"));
        buf.extend(y.fill_bytes(len).expect("fits"));
        Ok(buf)
    }

    /// Go's `pointToAffine`.
    fn decode_affine(&self, point: &[u8]) -> (Int, Int) {
        if point == [0] {
            return (Int::zero(), Int::zero());
        }
        let len = self.byte_len();
        (
            Int::from_be_bytes(&point[1..1 + len]),
            Int::from_be_bytes(&point[1 + len..]),
        )
    }

    fn valid_point(&self, backend: &dyn Backend, x: &Int, y: &Int, operation: &str) -> Vec<u8> {
        match self
            .encode_affine(x, y)
            .ok()
            .and_then(|encoded| backend.point(&encoded))
        {
            Some(point) => point,
            None => panic!("crypto/elliptic: {operation} was called on an invalid point"),
        }
    }
}

impl Curve for CurveParams {
    fn params(&self) -> &CurveParams {
        self
    }

    fn is_on_curve(&self, x: &Int, y: &Int) -> bool {
        let Some(backend) = self.backend() else {
            panic_custom("IsOnCurve")
        };
        if x.is_zero() && y.is_zero() {
            return false;
        }
        self.encode_affine(x, y)
            .ok()
            .and_then(|encoded| backend.point(&encoded))
            .is_some()
    }

    fn add(&self, x1: &Int, y1: &Int, x2: &Int, y2: &Int) -> (Int, Int) {
        let Some(backend) = self.backend() else {
            panic_custom("Add")
        };
        let a = self.valid_point(backend, x1, y1, "Add");
        let b = self.valid_point(backend, x2, y2, "Add");
        let sum = backend.add(&a, &b).expect("valid points");
        self.decode_affine(&sum)
    }

    fn double(&self, x1: &Int, y1: &Int) -> (Int, Int) {
        let Some(backend) = self.backend() else {
            panic_custom("Double")
        };
        let a = self.valid_point(backend, x1, y1, "Double");
        let doubled = backend.double(&a).expect("valid point");
        self.decode_affine(&doubled)
    }

    fn scalar_mult(&self, x1: &Int, y1: &Int, k: &[u8]) -> (Int, Int) {
        let Some(backend) = self.backend() else {
            panic_custom("ScalarMult")
        };
        let a = self.valid_point(backend, x1, y1, "ScalarMult");
        let product = backend.scalar_mult(&a, k).expect("valid point");
        self.decode_affine(&product)
    }

    fn scalar_base_mult(&self, k: &[u8]) -> (Int, Int) {
        let Some(backend) = self.backend() else {
            panic_custom("ScalarBaseMult")
        };
        self.decode_affine(&backend.scalar_base_mult(k))
    }
}

fn named_params(id: Id) -> CurveParams {
    let constants = nistec::backend(id).constants();
    let hex = |text: &str| Int::from_hex(text).expect("constant");
    CurveParams {
        p: hex(constants.p),
        n: hex(constants.n),
        b: hex(constants.b),
        gx: hex(constants.gx),
        gy: hex(constants.gy),
        bit_size: constants.bit_size,
        name: constants.name.to_string(),
        named: Some(id),
    }
}

fn canonical(id: Id) -> &'static CurveParams {
    static P224: OnceLock<CurveParams> = OnceLock::new();
    static P256: OnceLock<CurveParams> = OnceLock::new();
    static P384: OnceLock<CurveParams> = OnceLock::new();
    static P521: OnceLock<CurveParams> = OnceLock::new();
    let slot = match id {
        Id::P224 => &P224,
        Id::P256 => &P256,
        Id::P384 => &P384,
        Id::P521 => &P521,
    };
    slot.get_or_init(|| named_params(id))
}

/// A NIST curve, the value of Go's unexported `nistCurve`.
struct NistCurve(CurveParams);

impl Curve for NistCurve {
    fn params(&self) -> &CurveParams {
        &self.0
    }

    fn is_on_curve(&self, x: &Int, y: &Int) -> bool {
        self.0.is_on_curve(x, y)
    }

    fn add(&self, x1: &Int, y1: &Int, x2: &Int, y2: &Int) -> (Int, Int) {
        self.0.add(x1, y1, x2, y2)
    }

    fn double(&self, x1: &Int, y1: &Int) -> (Int, Int) {
        self.0.double(x1, y1)
    }

    fn scalar_mult(&self, x1: &Int, y1: &Int, k: &[u8]) -> (Int, Int) {
        self.0.scalar_mult(x1, y1, k)
    }

    fn scalar_base_mult(&self, k: &[u8]) -> (Int, Int) {
        self.0.scalar_base_mult(k)
    }
}

fn curve(slot: &'static OnceLock<Arc<dyn Curve>>, id: Id) -> Arc<dyn Curve> {
    slot.get_or_init(|| Arc::new(NistCurve(named_params(id))))
        .clone()
}

/// Go's `elliptic.P224`: the NIST curve P-224 (secp224r1).
pub fn p224() -> Arc<dyn Curve> {
    static CURVE: OnceLock<Arc<dyn Curve>> = OnceLock::new();
    curve(&CURVE, Id::P224)
}

/// Go's `elliptic.P256`: the NIST curve P-256 (secp256r1).
pub fn p256() -> Arc<dyn Curve> {
    static CURVE: OnceLock<Arc<dyn Curve>> = OnceLock::new();
    curve(&CURVE, Id::P256)
}

/// Go's `elliptic.P384`: the NIST curve P-384 (secp384r1).
pub fn p384() -> Arc<dyn Curve> {
    static CURVE: OnceLock<Arc<dyn Curve>> = OnceLock::new();
    curve(&CURVE, Id::P384)
}

/// Go's `elliptic.P521`: the NIST curve P-521 (secp521r1).
pub fn p521() -> Arc<dyn Curve> {
    static CURVE: OnceLock<Arc<dyn Curve>> = OnceLock::new();
    curve(&CURVE, Id::P521)
}

/// Reports whether two curve values are the same curve object, like Go's
/// `==` on `elliptic.Curve` interface values.
pub fn same_curve(a: &Arc<dyn Curve>, b: &Arc<dyn Curve>) -> bool {
    std::ptr::addr_eq(Arc::as_ptr(a), Arc::as_ptr(b))
}

/// Go's `elliptic.GenerateKey` with the system random source: a private key
/// (big-endian, one byte more than needed for the order is not used) and the
/// matching public point.
pub fn generate_key(curve: &dyn Curve) -> io::Result<(Vec<u8>, Int, Int)> {
    generate_key_with_rng(&mut crate::rand::Reader, curve)
}

/// [`generate_key`] reading from `rng`, like Go's `elliptic.GenerateKey`,
/// which always honours the reader.
pub fn generate_key_with_rng(
    rand: &mut dyn io::Read,
    curve: &dyn Curve,
) -> io::Result<(Vec<u8>, Int, Int)> {
    let n = &curve.params().n;
    let bit_size = n.bit_len();
    let byte_len = bit_size.div_ceil(8);
    const MASK: [u8; 8] = [0xff, 0x1, 0x3, 0x7, 0xf, 0x1f, 0x3f, 0x7f];
    let mut private = vec![0u8; byte_len];
    loop {
        rand.read_exact(&mut private)?;
        private[0] &= MASK[bit_size % 8];
        private[1] ^= 0x42;
        if &Int::from_be_bytes(&private) >= n {
            continue;
        }
        let (x, y) = curve.scalar_base_mult(&private);
        return Ok((private, x, y));
    }
}

fn panic_if_not_on_curve(curve: &dyn Curve, x: &Int, y: &Int) {
    if x.is_zero() && y.is_zero() {
        return;
    }
    if !curve.is_on_curve(x, y) {
        panic!("crypto/elliptic: attempted operation on invalid point");
    }
}

/// Go's `elliptic.Marshal`: the uncompressed SEC 1 encoding of a point.
///
/// # Panics
///
/// Panics if `(x, y)` is not on the curve, like Go.
pub fn marshal(curve: &dyn Curve, x: &Int, y: &Int) -> Vec<u8> {
    panic_if_not_on_curve(curve, x, y);
    let byte_len = curve.params().bit_size.div_ceil(8);
    let mut out = vec![4u8];
    out.extend(x.fill_bytes(byte_len).expect("on curve"));
    out.extend(y.fill_bytes(byte_len).expect("on curve"));
    out
}

/// Go's `elliptic.MarshalCompressed`: the compressed SEC 1 encoding of a point.
///
/// # Panics
///
/// Panics if `(x, y)` is not on the curve, like Go.
pub fn marshal_compressed(curve: &dyn Curve, x: &Int, y: &Int) -> Vec<u8> {
    panic_if_not_on_curve(curve, x, y);
    let byte_len = curve.params().bit_size.div_ceil(8);
    let mut out = vec![y.bit(0) | 2];
    out.extend(x.fill_bytes(byte_len).expect("on curve"));
    out
}

/// Go's `elliptic.Unmarshal`: converts an uncompressed point back to
/// coordinates, or `None` if the data is not a valid point.
pub fn unmarshal(curve: &dyn Curve, data: &[u8]) -> Option<(Int, Int)> {
    let backend = curve.params().backend();
    if data.is_empty() || data[0] != 4 {
        return None;
    }
    let byte_len = curve.params().bit_size.div_ceil(8);
    match backend {
        Some(backend) => {
            backend.point(data)?;
            Some((
                Int::from_be_bytes(&data[1..1 + byte_len]),
                Int::from_be_bytes(&data[1 + byte_len..]),
            ))
        }
        None => panic_custom("Unmarshal"),
    }
}

/// Go's `elliptic.UnmarshalCompressed`: converts a compressed point back to
/// coordinates, or `None` if the data is not a valid point.
pub fn unmarshal_compressed(curve: &dyn Curve, data: &[u8]) -> Option<(Int, Int)> {
    if data.is_empty() || (data[0] != 2 && data[0] != 3) {
        return None;
    }
    match curve.params().backend() {
        Some(backend) => {
            let point = backend.point(data)?;
            Some(curve.params().decode_affine(&point))
        }
        None => panic_custom("UnmarshalCompressed"),
    }
}

impl CurveParams {
    /// Parameters of a curve that is not one of the NIST curves. Its point
    /// operations panic (see the module documentation); the parameters are
    /// carried so that code that only inspects them keeps working.
    pub fn custom(
        p: Int,
        n: Int,
        b: Int,
        gx: Int,
        gy: Int,
        bit_size: usize,
        name: impl Into<String>,
    ) -> CurveParams {
        CurveParams {
            p,
            n,
            b,
            gx,
            gy,
            bit_size,
            name: name.into(),
            named: None,
        }
    }
}
