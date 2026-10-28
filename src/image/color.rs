//! Color values and models compatible with Go's `image/color` package.
//!
//! Every color reports alpha-premultiplied 16-bit components through
//! [`Color::rgba`], using exactly Go's `RGBA()` arithmetic. Model conversion
//! (`Model::convert` and each type's `from_color`) reproduces Go's integer
//! rounding and truncation, including for out-of-range premultiplied inputs.
//! YCbCr and CMYK colors, and models defined by a function ([`model_func`]),
//! follow Go's arithmetic as well. Standard palettes are in [`palette`].

use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

pub mod palette;

/// Alpha-premultiplied 32-bit color: 8 bits per channel.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Rgba {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

/// Alpha-premultiplied 64-bit color: 16 bits per channel.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Rgba64 {
    pub r: u16,
    pub g: u16,
    pub b: u16,
    pub a: u16,
}

/// Non-alpha-premultiplied 32-bit color.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Nrgba {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

/// Non-alpha-premultiplied 64-bit color.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Nrgba64 {
    pub r: u16,
    pub g: u16,
    pub b: u16,
    pub a: u16,
}

/// 8-bit grayscale color.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Gray {
    pub y: u8,
}

/// 16-bit grayscale color.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Gray16 {
    pub y: u16,
}

/// 8-bit alpha color.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Alpha {
    pub a: u8,
}

/// 16-bit alpha color.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Alpha16 {
    pub a: u16,
}

/// Opaque black (`color.Black`).
pub const BLACK: Gray16 = Gray16 { y: 0 };
/// Opaque white (`color.White`).
pub const WHITE: Gray16 = Gray16 { y: 0xffff };
/// Fully transparent (`color.Transparent`).
pub const TRANSPARENT: Alpha16 = Alpha16 { a: 0 };
/// Fully opaque (`color.Opaque`).
pub const OPAQUE: Alpha16 = Alpha16 { a: 0xffff };

fn widen(v: u8) -> u32 {
    let v = u32::from(v);
    v | (v << 8)
}

impl Rgba {
    /// Premultiplied 16-bit components in `[0, 0xffff]`.
    pub fn rgba(self) -> (u32, u32, u32, u32) {
        (widen(self.r), widen(self.g), widen(self.b), widen(self.a))
    }
    /// Go's `RGBAModel` conversion.
    pub fn from_color(c: Color) -> Self {
        if let Color::Rgba(c) = c {
            return c;
        }
        let (r, g, b, a) = c.rgba();
        Self {
            r: (r >> 8) as u8,
            g: (g >> 8) as u8,
            b: (b >> 8) as u8,
            a: (a >> 8) as u8,
        }
    }
}

impl Rgba64 {
    pub fn rgba(self) -> (u32, u32, u32, u32) {
        (
            u32::from(self.r),
            u32::from(self.g),
            u32::from(self.b),
            u32::from(self.a),
        )
    }
    /// Go's `RGBA64Model` conversion.
    pub fn from_color(c: Color) -> Self {
        if let Color::Rgba64(c) = c {
            return c;
        }
        let (r, g, b, a) = c.rgba();
        Self {
            r: r as u16,
            g: g as u16,
            b: b as u16,
            a: a as u16,
        }
    }
}

impl Nrgba {
    pub fn rgba(self) -> (u32, u32, u32, u32) {
        let a = u32::from(self.a);
        (
            widen(self.r) * a / 0xff,
            widen(self.g) * a / 0xff,
            widen(self.b) * a / 0xff,
            widen(self.a),
        )
    }
    /// Go's `NRGBAModel` conversion, including its truncating division.
    pub fn from_color(c: Color) -> Self {
        if let Color::Nrgba(c) = c {
            return c;
        }
        let (r, g, b, a) = c.rgba();
        if a == 0xffff {
            return Self {
                r: (r >> 8) as u8,
                g: (g >> 8) as u8,
                b: (b >> 8) as u8,
                a: 0xff,
            };
        }
        if a == 0 {
            return Self::default();
        }
        Self {
            r: ((r * 0xffff / a) >> 8) as u8,
            g: ((g * 0xffff / a) >> 8) as u8,
            b: ((b * 0xffff / a) >> 8) as u8,
            a: (a >> 8) as u8,
        }
    }
}

impl Nrgba64 {
    pub fn rgba(self) -> (u32, u32, u32, u32) {
        let a = u32::from(self.a);
        (
            u32::from(self.r) * a / 0xffff,
            u32::from(self.g) * a / 0xffff,
            u32::from(self.b) * a / 0xffff,
            a,
        )
    }
    /// Go's `NRGBA64Model` conversion.
    pub fn from_color(c: Color) -> Self {
        if let Color::Nrgba64(c) = c {
            return c;
        }
        let (r, g, b, a) = c.rgba();
        if a == 0xffff {
            return Self {
                r: r as u16,
                g: g as u16,
                b: b as u16,
                a: 0xffff,
            };
        }
        if a == 0 {
            return Self::default();
        }
        Self {
            r: (r * 0xffff / a) as u16,
            g: (g * 0xffff / a) as u16,
            b: (b * 0xffff / a) as u16,
            a: a as u16,
        }
    }
}

impl Gray {
    pub fn rgba(self) -> (u32, u32, u32, u32) {
        let y = widen(self.y);
        (y, y, y, 0xffff)
    }
    /// Go's `GrayModel` conversion (ITU-R BT.601 luma weights).
    pub fn from_color(c: Color) -> Self {
        if let Color::Gray(c) = c {
            return c;
        }
        let (r, g, b, _) = c.rgba();
        Self {
            y: ((19595 * r + 38470 * g + 7471 * b + (1 << 15)) >> 24) as u8,
        }
    }
}

impl Gray16 {
    pub fn rgba(self) -> (u32, u32, u32, u32) {
        let y = u32::from(self.y);
        (y, y, y, 0xffff)
    }
    /// Go's `Gray16Model` conversion.
    pub fn from_color(c: Color) -> Self {
        if let Color::Gray16(c) = c {
            return c;
        }
        let (r, g, b, _) = c.rgba();
        Self {
            y: ((19595 * r + 38470 * g + 7471 * b + (1 << 15)) >> 16) as u16,
        }
    }
}

impl Alpha {
    pub fn rgba(self) -> (u32, u32, u32, u32) {
        let a = widen(self.a);
        (a, a, a, a)
    }
    /// Go's `AlphaModel` conversion.
    pub fn from_color(c: Color) -> Self {
        if let Color::Alpha(c) = c {
            return c;
        }
        Self {
            a: (c.rgba().3 >> 8) as u8,
        }
    }
}

impl Alpha16 {
    pub fn rgba(self) -> (u32, u32, u32, u32) {
        let a = u32::from(self.a);
        (a, a, a, a)
    }
    /// Go's `Alpha16Model` conversion.
    pub fn from_color(c: Color) -> Self {
        if let Color::Alpha16(c) = c {
            return c;
        }
        Self {
            a: c.rgba().3 as u16,
        }
    }
}

/// Go's clamping of a fixed-point YCbCr channel: `v >> shift` when `v` is in
/// `[0, 1<<24)`, otherwise 0 below the range and `max` above it.
fn clamp_fixed(v: i32, shift: u32, max: u32) -> u32 {
    if (0..1 << 24).contains(&v) {
        (v >> shift) as u32
    } else if v < 0 {
        0
    } else {
        max
    }
}

/// Go's `RGBToYCbCr`: the BT.601 full-range conversion in fixed point.
pub fn rgb_to_ycbcr(r: u8, g: u8, b: u8) -> (u8, u8, u8) {
    let (r, g, b) = (i32::from(r), i32::from(g), i32::from(b));
    let y = (19595 * r + 38470 * g + 7471 * b + (1 << 15)) >> 16;
    let cb = -11056 * r - 21712 * g + 32768 * b + (257 << 15);
    let cr = 32768 * r - 27440 * g - 5328 * b + (257 << 15);
    (
        y as u8,
        clamp_fixed(cb, 16, 0xff) as u8,
        clamp_fixed(cr, 16, 0xff) as u8,
    )
}

/// The three fixed-point channel values of a YCbCr color, before shifting.
fn ycbcr_fixed(y: u8, cb: u8, cr: u8) -> (i32, i32, i32) {
    let yy = i32::from(y) * 0x10101;
    let cb = i32::from(cb) - 128;
    let cr = i32::from(cr) - 128;
    (
        yy + 91881 * cr,
        yy - 22554 * cb - 46802 * cr,
        yy + 116130 * cb,
    )
}

/// Go's `YCbCrToRGB`.
pub fn ycbcr_to_rgb(y: u8, cb: u8, cr: u8) -> (u8, u8, u8) {
    let (r, g, b) = ycbcr_fixed(y, cb, cr);
    (
        clamp_fixed(r, 16, 0xff) as u8,
        clamp_fixed(g, 16, 0xff) as u8,
        clamp_fixed(b, 16, 0xff) as u8,
    )
}

/// Go's `RGBToCMYK`: the minimal black channel and the complements of the rest.
pub fn rgb_to_cmyk(r: u8, g: u8, b: u8) -> (u8, u8, u8, u8) {
    let (rr, gg, bb) = (u32::from(r), u32::from(g), u32::from(b));
    let w = rr.max(gg).max(bb);
    if w == 0 {
        return (0, 0, 0, 0xff);
    }
    (
        ((w - rr) * 0xff / w) as u8,
        ((w - gg) * 0xff / w) as u8,
        ((w - bb) * 0xff / w) as u8,
        (0xff - w) as u8,
    )
}

/// The 16-bit channels of a CMYK color.
fn cmyk_wide(c: u8, m: u8, y: u8, k: u8) -> (u32, u32, u32) {
    let w = 0xffff - u32::from(k) * 0x101;
    let channel = |v: u8| (0xffff - u32::from(v) * 0x101) * w / 0xffff;
    (channel(c), channel(m), channel(y))
}

/// Go's `CMYKToRGB`.
pub fn cmyk_to_rgb(c: u8, m: u8, y: u8, k: u8) -> (u8, u8, u8) {
    let (r, g, b) = cmyk_wide(c, m, y, k);
    ((r >> 8) as u8, (g >> 8) as u8, (b >> 8) as u8)
}

/// YCbCr color (Go's `color.YCbCr`), with full-range BT.601 coefficients.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Ycbcr {
    pub y: u8,
    pub cb: u8,
    pub cr: u8,
}

impl Ycbcr {
    /// Alpha-premultiplied components; the color is opaque.
    pub fn rgba(self) -> (u32, u32, u32, u32) {
        let (r, g, b) = ycbcr_fixed(self.y, self.cb, self.cr);
        (
            clamp_fixed(r, 8, 0xffff),
            clamp_fixed(g, 8, 0xffff),
            clamp_fixed(b, 8, 0xffff),
            0xffff,
        )
    }
    /// Go's YCbCr model conversion.
    pub fn from_color(c: Color) -> Self {
        if let Color::Ycbcr(c) = c {
            return c;
        }
        let (r, g, b, _) = c.rgba();
        let (y, cb, cr) = rgb_to_ycbcr((r >> 8) as u8, (g >> 8) as u8, (b >> 8) as u8);
        Self { y, cb, cr }
    }
}

/// YCbCr with an alpha channel (Go's `color.NYCbCrA`), non-premultiplied.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Nycbcra {
    pub ycbcr: Ycbcr,
    pub a: u8,
}

impl Nycbcra {
    pub fn rgba(self) -> (u32, u32, u32, u32) {
        let (r, g, b, _) = self.ycbcr.rgba();
        let a = u32::from(self.a) * 0x101;
        (r * a / 0xffff, g * a / 0xffff, b * a / 0xffff, a)
    }
    /// Go's NYCbCrA model conversion, which un-premultiplies the input.
    pub fn from_color(c: Color) -> Self {
        match c {
            Color::Nycbcra(c) => return c,
            Color::Ycbcr(c) => return Self { ycbcr: c, a: 0xff },
            _ => {}
        }
        let (mut r, mut g, mut b, a) = c.rgba();
        if let Some(a) = std::num::NonZeroU32::new(a) {
            let a = a.get();
            r = r * 0xffff / a;
            g = g * 0xffff / a;
            b = b * 0xffff / a;
        }
        let (y, cb, cr) = rgb_to_ycbcr((r >> 8) as u8, (g >> 8) as u8, (b >> 8) as u8);
        Self {
            ycbcr: Ycbcr { y, cb, cr },
            a: (a >> 8) as u8,
        }
    }
}

/// CMYK color (Go's `color.CMYK`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Cmyk {
    pub c: u8,
    pub m: u8,
    pub y: u8,
    pub k: u8,
}

impl Cmyk {
    /// Alpha-premultiplied components; the color is opaque.
    pub fn rgba(self) -> (u32, u32, u32, u32) {
        let (r, g, b) = cmyk_wide(self.c, self.m, self.y, self.k);
        (r, g, b, 0xffff)
    }
    /// Go's CMYK model conversion.
    pub fn from_color(c: Color) -> Self {
        if let Color::Cmyk(c) = c {
            return c;
        }
        let (r, g, b, _) = c.rgba();
        let (c, m, y, k) = rgb_to_cmyk((r >> 8) as u8, (g >> 8) as u8, (b >> 8) as u8);
        Self { c, m, y, k }
    }
}

/// Any color value from this module, the counterpart of Go's `color.Color`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Color {
    Rgba(Rgba),
    Rgba64(Rgba64),
    Nrgba(Nrgba),
    Nrgba64(Nrgba64),
    Gray(Gray),
    Gray16(Gray16),
    Alpha(Alpha),
    Alpha16(Alpha16),
    Ycbcr(Ycbcr),
    Nycbcra(Nycbcra),
    Cmyk(Cmyk),
}

impl Color {
    /// Alpha-premultiplied red, green, blue and alpha in `[0, 0xffff]`,
    /// computed exactly as Go's `RGBA()` method for the underlying type.
    pub fn rgba(&self) -> (u32, u32, u32, u32) {
        match *self {
            Color::Rgba(c) => c.rgba(),
            Color::Rgba64(c) => c.rgba(),
            Color::Nrgba(c) => c.rgba(),
            Color::Nrgba64(c) => c.rgba(),
            Color::Gray(c) => c.rgba(),
            Color::Gray16(c) => c.rgba(),
            Color::Alpha(c) => c.rgba(),
            Color::Alpha16(c) => c.rgba(),
            Color::Ycbcr(c) => c.rgba(),
            Color::Nycbcra(c) => c.rgba(),
            Color::Cmyk(c) => c.rgba(),
        }
    }
}

macro_rules! color_from {
    ($($variant:ident),*) => {
        $(impl From<$variant> for Color {
            fn from(c: $variant) -> Self {
                Color::$variant(c)
            }
        })*
    };
}
color_from!(Rgba, Rgba64, Nrgba, Nrgba64, Gray, Gray16, Alpha, Alpha16, Ycbcr, Nycbcra, Cmyk);

/// An ordered color palette (`color.Palette`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Palette(pub Vec<Color>);

impl Palette {
    pub fn new(colors: Vec<Color>) -> Self {
        Self(colors)
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn get(&self, index: usize) -> Option<Color> {
        self.0.get(index).copied()
    }
    /// The palette color closest to `c` in Euclidean RGBA space; `None` for an
    /// empty palette (Go returns a nil color).
    pub fn convert(&self, c: Color) -> Option<Color> {
        self.0.get(self.index(c)).copied()
    }
    /// Index of the closest palette entry, using Go's wrapping 32-bit squared
    /// difference and first-minimum tie-break. Returns 0 for an empty palette.
    pub fn index(&self, c: Color) -> usize {
        let (cr, cg, cb, ca) = c.rgba();
        let mut best = 0;
        let mut best_sum = u32::MAX;
        for (i, v) in self.0.iter().enumerate() {
            let (vr, vg, vb, va) = v.rgba();
            let sum = sq_diff(cr, vr)
                .wrapping_add(sq_diff(cg, vg))
                .wrapping_add(sq_diff(cb, vb))
                .wrapping_add(sq_diff(ca, va));
            if sum < best_sum {
                if sum == 0 {
                    return i;
                }
                best = i;
                best_sum = sum;
            }
        }
        best
    }
}

fn sq_diff(x: u32, y: u32) -> u32 {
    let d = x.wrapping_sub(y);
    d.wrapping_mul(d) >> 2
}

/// A conversion function that defines a [`Model::Func`] (Go's `ModelFunc`).
/// Two models are equal when they share the same function.
#[derive(Clone)]
pub struct ModelFunc(Arc<dyn Fn(Color) -> Color + Send + Sync>);

impl fmt::Debug for ModelFunc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ModelFunc")
    }
}

impl PartialEq for ModelFunc {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for ModelFunc {}

impl Hash for ModelFunc {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (Arc::as_ptr(&self.0) as *const () as usize).hash(state);
    }
}

/// Go's `ModelFunc`: a model whose conversion is `f`. Unlike Go's function
/// values, the closure may capture state.
pub fn model_func(f: impl Fn(Color) -> Color + Send + Sync + 'static) -> Model {
    Model::Func(ModelFunc(Arc::new(f)))
}

/// A color model: Go's predefined models, palettes, model functions and
/// uniform images.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Model {
    Rgba,
    Rgba64,
    Nrgba,
    Nrgba64,
    Gray,
    Gray16,
    Alpha,
    Alpha16,
    Ycbcr,
    Nycbcra,
    Cmyk,
    Palette(Palette),
    Func(ModelFunc),
    /// A [`Uniform`](super::Uniform) image as a model (Go's `Uniform`
    /// implements `color.Model`): every color converts to this one.
    Uniform(Color),
}

impl Model {
    /// Convert `c` into this model. An empty palette yields
    /// [`TRANSPARENT`] where Go returns a nil color.
    pub fn convert(&self, c: Color) -> Color {
        match self {
            Model::Rgba => Rgba::from_color(c).into(),
            Model::Rgba64 => Rgba64::from_color(c).into(),
            Model::Nrgba => Nrgba::from_color(c).into(),
            Model::Nrgba64 => Nrgba64::from_color(c).into(),
            Model::Gray => Gray::from_color(c).into(),
            Model::Gray16 => Gray16::from_color(c).into(),
            Model::Alpha => Alpha::from_color(c).into(),
            Model::Alpha16 => Alpha16::from_color(c).into(),
            Model::Ycbcr => Ycbcr::from_color(c).into(),
            Model::Nycbcra => Nycbcra::from_color(c).into(),
            Model::Cmyk => Cmyk::from_color(c).into(),
            Model::Palette(p) => p.convert(c).unwrap_or(Color::Alpha16(TRANSPARENT)),
            Model::Func(f) => (f.0)(c),
            Model::Uniform(u) => *u,
        }
    }
}
