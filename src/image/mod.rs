//! Basic 2-D geometry and in-memory images compatible with Go's `image`.
//!
//! Coordinates are `i32` and geometry arithmetic wraps like Go's fixed-width
//! integers. Concrete images store pixels in `pix` with Go's layouts
//! (row-major, `stride` bytes per row, 16-bit samples big-endian) and report
//! colors with exactly Go's `At`/`RGBA64At` results. `pix` is a [`Pix`], a
//! buffer that is plain owned bytes until `sub_image(&mut self, ..)` shares it,
//! so `sub_image` shares pixels with its parent (writes through either are
//! visible through both), as Go's slices do; only shared buffers lock.
//! [`Uniform`] is an infinite single-color image, as in Go.
//!
//! ```
//! use rust_stdlib::image::{color, rect, Image, Nrgba};
//! let mut img = Nrgba::new(rect(0, 0, 2, 1));
//! img.set(1, 0, color::Rgba { r: 0x40, g: 0, b: 0, a: 0x80 }.into());
//! assert_eq!(img.pixel_at(1, 0), color::Nrgba { r: 0x7f, g: 0, b: 0, a: 0x80 });
//! assert_eq!(img.rgba64_at(1, 0).a, 0x8080);
//! ```
use std::any::Any;
use std::fmt;
use std::ops::{Add, Div, Mul, Sub};

pub mod color;
pub mod draw;
mod format;
pub mod gif;
pub mod jpeg;
mod pix;
pub mod png;
mod ycbcr;

pub use format::{decode, decode_config, register_format, DecodeError};
pub use pix::Pix;
pub use ycbcr::{Nycbcra, Ycbcr, YcbcrSubsampleRatio};

/// The error type of [`ERR_FORMAT`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error(&'static str);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for Error {}

/// Go's `image.ErrFormat`: the stream matches no registered format.
pub const ERR_FORMAT: Error = Error("image: unknown format");

/// Go's `image.Black`, `White`, `Transparent` and `Opaque`: infinite uniform
/// images of the color constants of [`color`].
pub const BLACK: Uniform = Uniform {
    c: Color::Gray16(color::BLACK),
};
pub const WHITE: Uniform = Uniform {
    c: Color::Gray16(color::WHITE),
};
pub const TRANSPARENT: Uniform = Uniform {
    c: Color::Alpha16(color::TRANSPARENT),
};
pub const OPAQUE: Uniform = Uniform {
    c: Color::Alpha16(color::OPAQUE),
};

/// Go's `image.ZP`, the zero point.
pub const ZP: Point = Point { x: 0, y: 0 };
/// Go's `image.ZR`, the zero rectangle.
pub const ZR: Rectangle = Rectangle { min: ZP, max: ZP };

use color::{Color, Model, Palette};

/// An (x, y) coordinate pair.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Point {
    pub x: i32,
    pub y: i32,
}

/// Shorthand for `Point { x, y }` (Go's `image.Pt`).
pub const fn pt(x: i32, y: i32) -> Point {
    Point { x, y }
}

impl Add for Point {
    type Output = Point;
    fn add(self, q: Point) -> Point {
        pt(self.x.wrapping_add(q.x), self.y.wrapping_add(q.y))
    }
}
impl Sub for Point {
    type Output = Point;
    fn sub(self, q: Point) -> Point {
        pt(self.x.wrapping_sub(q.x), self.y.wrapping_sub(q.y))
    }
}
impl Mul<i32> for Point {
    type Output = Point;
    fn mul(self, k: i32) -> Point {
        pt(self.x.wrapping_mul(k), self.y.wrapping_mul(k))
    }
}
/// Truncating division; panics when `k` is zero, as Go does.
impl Div<i32> for Point {
    type Output = Point;
    fn div(self, k: i32) -> Point {
        pt(self.x.wrapping_div(k), self.y.wrapping_div(k))
    }
}

impl Point {
    /// Whether the point lies within `r` (Go's `Point.In`).
    pub fn is_in(self, r: Rectangle) -> bool {
        r.min.x <= self.x && self.x < r.max.x && r.min.y <= self.y && self.y < r.max.y
    }
    /// The point in `r` congruent to `self` modulo `r`'s size (Go's `Mod`).
    /// Panics for an empty rectangle, as Go does.
    pub fn modulo(self, r: Rectangle) -> Point {
        let (w, h) = (r.dx(), r.dy());
        let mut p = self - r.min;
        p.x = p.x.wrapping_rem(w);
        if p.x < 0 {
            p.x = p.x.wrapping_add(w);
        }
        p.y = p.y.wrapping_rem(h);
        if p.y < 0 {
            p.y = p.y.wrapping_add(h);
        }
        p + r.min
    }
}

impl fmt::Display for Point {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({},{})", self.x, self.y)
    }
}

/// A half-open rectangle `[min.x, max.x) x [min.y, max.y)`. A rectangle is
/// well-formed when `min <= max` componentwise; [`rect`] canonicalizes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Rectangle {
    pub min: Point,
    pub max: Point,
}

/// Go's `image.Rect`: builds a rectangle, swapping coordinates if needed.
pub fn rect(x0: i32, y0: i32, x1: i32, y1: i32) -> Rectangle {
    let (x0, x1) = if x0 > x1 { (x1, x0) } else { (x0, x1) };
    let (y0, y1) = if y0 > y1 { (y1, y0) } else { (y0, y1) };
    Rectangle {
        min: pt(x0, y0),
        max: pt(x1, y1),
    }
}

impl Rectangle {
    pub fn dx(self) -> i32 {
        self.max.x.wrapping_sub(self.min.x)
    }
    pub fn dy(self) -> i32 {
        self.max.y.wrapping_sub(self.min.y)
    }
    pub fn size(self) -> Point {
        pt(self.dx(), self.dy())
    }
    /// Shrinks by `n` on every side (grows for negative `n`), collapsing to
    /// the midpoint along any axis that is too small.
    pub fn inset(mut self, n: i32) -> Rectangle {
        let twice = n.wrapping_mul(2);
        if self.dx() < twice {
            self.min.x = self.min.x.wrapping_add(self.max.x) / 2;
            self.max.x = self.min.x;
        } else {
            self.min.x = self.min.x.wrapping_add(n);
            self.max.x = self.max.x.wrapping_sub(n);
        }
        if self.dy() < twice {
            self.min.y = self.min.y.wrapping_add(self.max.y) / 2;
            self.max.y = self.min.y;
        } else {
            self.min.y = self.min.y.wrapping_add(n);
            self.max.y = self.max.y.wrapping_sub(n);
        }
        self
    }
    /// The largest rectangle inside both; the zero rectangle if disjoint.
    pub fn intersect(mut self, s: Rectangle) -> Rectangle {
        self.min.x = self.min.x.max(s.min.x);
        self.min.y = self.min.y.max(s.min.y);
        self.max.x = self.max.x.min(s.max.x);
        self.max.y = self.max.y.min(s.max.y);
        if self.is_empty() {
            return Rectangle::default();
        }
        self
    }
    /// The smallest rectangle containing both; empty inputs are ignored.
    pub fn union(mut self, s: Rectangle) -> Rectangle {
        if self.is_empty() {
            return s;
        }
        if s.is_empty() {
            return self;
        }
        self.min.x = self.min.x.min(s.min.x);
        self.min.y = self.min.y.min(s.min.y);
        self.max.x = self.max.x.max(s.max.x);
        self.max.y = self.max.y.max(s.max.y);
        self
    }
    pub fn is_empty(self) -> bool {
        self.min.x >= self.max.x || self.min.y >= self.max.y
    }
    /// Go's `Rectangle.Eq`: identical, or both empty.
    pub fn equals(self, s: Rectangle) -> bool {
        self == s || (self.is_empty() && s.is_empty())
    }
    pub fn overlaps(self, s: Rectangle) -> bool {
        !self.is_empty()
            && !s.is_empty()
            && self.min.x < s.max.x
            && s.min.x < self.max.x
            && self.min.y < s.max.y
            && s.min.y < self.max.y
    }
    /// Whether every point of `self` is in `s` (Go's `Rectangle.In`).
    pub fn is_in(self, s: Rectangle) -> bool {
        if self.is_empty() {
            return true;
        }
        s.min.x <= self.min.x
            && self.max.x <= s.max.x
            && s.min.y <= self.min.y
            && self.max.y <= s.max.y
    }
    /// The canonical version of the rectangle, with min <= max.
    pub fn canon(self) -> Rectangle {
        rect(self.min.x, self.min.y, self.max.x, self.max.y)
    }
}

impl Add<Point> for Rectangle {
    type Output = Rectangle;
    fn add(self, p: Point) -> Rectangle {
        Rectangle {
            min: self.min + p,
            max: self.max + p,
        }
    }
}
impl Sub<Point> for Rectangle {
    type Output = Rectangle;
    fn sub(self, p: Point) -> Rectangle {
        Rectangle {
            min: self.min - p,
            max: self.max - p,
        }
    }
}

impl fmt::Display for Rectangle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.min, self.max)
    }
}

/// A finite rectangular grid of colors (Go's `image.Image`).
pub trait Image {
    fn color_model(&self) -> Model;
    fn bounds(&self) -> Rectangle;
    /// The color at (x, y). Points outside the bounds yield the type's zero
    /// color (palette entry 0 for [`Paletted`]).
    fn at(&self, x: i32, y: i32) -> Color;
    /// The premultiplied 16-bit color at (x, y) (Go's `RGBA64At`).
    fn rgba64_at(&self, x: i32, y: i32) -> color::Rgba64 {
        let (r, g, b, a) = self.at(x, y).rgba();
        color::Rgba64 {
            r: r as u16,
            g: g as u16,
            b: b as u16,
            a: a as u16,
        }
    }
    /// Whether every pixel is fully opaque. The default scans all pixels.
    fn opaque(&self) -> bool {
        let b = self.bounds();
        (b.min.y..b.max.y).all(|y| (b.min.x..b.max.x).all(|x| self.at(x, y).rgba().3 == 0xffff))
    }
    /// Access to the color indexes of a paletted image, if this is one.
    fn as_paletted(&self) -> Option<&dyn PalettedImage> {
        None
    }
    /// The concrete image for downcasting, used by [`draw`] to select Go's
    /// type-specific code paths. Types from this module return themselves
    /// ([`AnyImage`] returns the wrapped image); the default is `None`.
    fn as_any(&self) -> Option<&dyn Any> {
        None
    }
}

/// An [`Image`] with a premultiplied 16-bit color accessor (Go's
/// `image.RGBA64Image`). [`Image::rgba64_at`] provides it for every image, so
/// the trait is implemented for all of them.
pub trait RGBA64Image: Image {}

impl<T: Image + ?Sized> RGBA64Image for T {}

/// An image whose colors come from a palette (Go's `image.PalettedImage`).
pub trait PalettedImage: Image {
    fn color_index_at(&self, x: i32, y: i32) -> u8;
}

/// Go's `image.Config`: dimensions and color model without pixel data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub color_model: Model,
    pub width: i32,
    pub height: i32,
}

/// Rectangles are images that are opaque inside and transparent outside.
impl Image for Rectangle {
    fn color_model(&self) -> Model {
        Model::Alpha16
    }
    fn bounds(&self) -> Rectangle {
        *self
    }
    fn at(&self, x: i32, y: i32) -> Color {
        if pt(x, y).is_in(*self) {
            color::OPAQUE.into()
        } else {
            color::TRANSPARENT.into()
        }
    }
    fn as_any(&self) -> Option<&dyn Any> {
        Some(self)
    }
}

/// An infinite-sized image of a single color (Go's `image.Uniform`).
///
/// Its bounds are Go's `(-1e9,-1e9)-(1e9,1e9)`. Go's `Uniform` is its own
/// color model, converting every color to `c`; `color_model` reports it as
/// [`Model::Uniform`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Uniform {
    pub c: Color,
}

impl Uniform {
    /// Go's `image.NewUniform`.
    pub fn new(c: Color) -> Self {
        Self { c }
    }
    /// Go's `Uniform.Convert`: every color converts to the uniform color.
    pub fn convert(&self, _c: Color) -> Color {
        self.c
    }
    /// Go's `Uniform.RGBA`: the premultiplied components of the uniform color.
    pub fn rgba(&self) -> (u32, u32, u32, u32) {
        self.c.rgba()
    }
}

impl Image for Uniform {
    fn color_model(&self) -> Model {
        Model::Uniform(self.c)
    }
    fn bounds(&self) -> Rectangle {
        rect(-1_000_000_000, -1_000_000_000, 1_000_000_000, 1_000_000_000)
    }
    fn at(&self, _x: i32, _y: i32) -> Color {
        self.c
    }
    fn opaque(&self) -> bool {
        self.c.rgba().3 == 0xffff
    }
    fn as_any(&self) -> Option<&dyn Any> {
        Some(self)
    }
}

/// Pixel-buffer length for `r` at `bpp` bytes per pixel, or `None` for
/// negative or overflowing dimensions.
fn buffer_len(r: Rectangle, bpp: usize) -> Option<(usize, usize)> {
    let w = usize::try_from(r.max.x.checked_sub(r.min.x)?).ok()?;
    let h = usize::try_from(r.max.y.checked_sub(r.min.y)?).ok()?;
    let stride = w.checked_mul(bpp)?;
    let len = stride.checked_mul(h)?;
    if len > isize::MAX as usize {
        return None;
    }
    Some((stride, len))
}

fn offset(r: Rectangle, stride: usize, bpp: usize, x: i32, y: i32) -> usize {
    (y - r.min.y) as usize * stride + (x - r.min.x) as usize * bpp
}

macro_rules! direct_image {
    (
        $(#[$doc:meta])*
        $name:ident, $color:ident, $bpp:expr, $model:ident,
        read: $read:expr, write: $write:expr, opaque: $opaque:expr,
        from_rgba64: $from64:expr
    ) => {
        $(#[$doc])*
        #[derive(Clone, Debug, Default, PartialEq, Eq)]
        pub struct $name {
            pub pix: Pix,
            pub stride: usize,
            pub rect: Rectangle,
        }

        impl $name {
            /// Bytes per pixel in `pix`.
            pub const BYTES_PER_PIXEL: usize = $bpp;

            /// A zeroed image with bounds `r`. Panics, as Go does, when the
            /// dimensions are negative or the buffer size overflows.
            pub fn new(r: Rectangle) -> Self {
                Self::try_new(r).unwrap_or_else(|| {
                    panic!(concat!("image: New", stringify!($name), " Rectangle has huge or negative dimensions"))
                })
            }

            /// A zeroed image with bounds `r`, or `None` for negative or
            /// overflowing dimensions.
            pub fn try_new(r: Rectangle) -> Option<Self> {
                let (stride, len) = buffer_len(r, $bpp)?;
                Some(Self { pix: vec![0; len].into(), stride, rect: r })
            }

            /// Index of the first byte of (x, y) in `pix`. Only meaningful
            /// for points inside `rect`.
            pub fn pix_offset(&self, x: i32, y: i32) -> usize {
                offset(self.rect, self.stride, $bpp, x, y)
            }

            /// The typed pixel at (x, y), or the zero color outside bounds.
            pub fn pixel_at(&self, x: i32, y: i32) -> color::$color {
                if !pt(x, y).is_in(self.rect) {
                    return color::$color::default();
                }
                let i = self.pix_offset(x, y);
                let read: fn(&[u8]) -> color::$color = $read;
                self.pix.with(|p| read(&p[i..i + $bpp]))
            }

            /// Store a typed pixel; points outside bounds are ignored.
            pub fn set_pixel(&mut self, x: i32, y: i32, c: color::$color) {
                if !pt(x, y).is_in(self.rect) {
                    return;
                }
                let i = self.pix_offset(x, y);
                let write: fn(&mut [u8], color::$color) = $write;
                self.pix.with_mut(|p| write(&mut p[i..i + $bpp], c));
            }

            /// Convert `c` with this image's color model and store it.
            pub fn set(&mut self, x: i32, y: i32, c: Color) {
                self.set_pixel(x, y, color::$color::from_color(c));
            }

            /// Store a premultiplied 16-bit color with exactly Go's
            /// `SetRGBA64` arithmetic, which for the non-premultiplied types
            /// differs from `set` when the alpha is zero.
            pub fn set_rgba64(&mut self, x: i32, y: i32, c: color::Rgba64) {
                let convert: fn(color::Rgba64) -> color::$color = $from64;
                self.set_pixel(x, y, convert(c));
            }

            /// The part of the image visible through `r`, sharing pixels with
            /// this image. An empty intersection yields an empty image with
            /// zero bounds.
            pub fn sub_image(&mut self, r: Rectangle) -> Self {
                let r = r.intersect(self.rect);
                if r.is_empty() {
                    return Self::default();
                }
                let i = offset(self.rect, self.stride, $bpp, r.min.x, r.min.y);
                Self { pix: self.pix.slice_from(i), stride: self.stride, rect: r }
            }

            /// Whether every pixel in bounds is fully opaque.
            pub fn opaque(&self) -> bool {
                let opaque: fn(color::$color) -> bool = $opaque;
                let b = self.rect;
                (b.min.y..b.max.y).all(|y| (b.min.x..b.max.x).all(|x| opaque(self.pixel_at(x, y))))
            }
        }

        impl Image for $name {
            fn color_model(&self) -> Model {
                Model::$model
            }
            fn bounds(&self) -> Rectangle {
                self.rect
            }
            fn at(&self, x: i32, y: i32) -> Color {
                self.pixel_at(x, y).into()
            }
            fn opaque(&self) -> bool {
                $name::opaque(self)
            }
            fn as_any(&self) -> Option<&dyn Any> {
                Some(self)
            }
        }
    };
}

/// Go's `NRGBA.SetRGBA64`/`NRGBA64.SetRGBA64` un-premultiplication: alpha 0
/// keeps the color channels, unlike the color-model conversion.
fn unpremultiply(c: color::Rgba64) -> (u32, u32, u32, u32) {
    let (mut r, mut g, mut b, a) = c.rgba();
    if a != 0 && a != 0xffff {
        r = r * 0xffff / a;
        g = g * 0xffff / a;
        b = b * 0xffff / a;
    }
    (r, g, b, a)
}

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

direct_image!(
    /// 8-bit CMYK pixels (Go's `image.CMYK`); always opaque.
    Cmyk, Cmyk, 4, Cmyk,
    read: |p| color::Cmyk { c: p[0], m: p[1], y: p[2], k: p[3] },
    write: |p, c| p.copy_from_slice(&[c.c, c.m, c.y, c.k]),
    opaque: |_| true,
    from_rgba64: |c| color::Cmyk::from_color(c.into())
);
direct_image!(
    /// Premultiplied 8-bit RGBA pixels (Go's `image.RGBA`).
    Rgba, Rgba, 4, Rgba,
    read: |p| color::Rgba { r: p[0], g: p[1], b: p[2], a: p[3] },
    write: |p, c| p.copy_from_slice(&[c.r, c.g, c.b, c.a]),
    opaque: |c| c.a == 0xff,
    from_rgba64: |c| color::Rgba::from_color(c.into())
);
direct_image!(
    /// Premultiplied 16-bit RGBA pixels (Go's `image.RGBA64`).
    Rgba64, Rgba64, 8, Rgba64,
    read: |p| color::Rgba64 { r: be16(&p[0..]), g: be16(&p[2..]), b: be16(&p[4..]), a: be16(&p[6..]) },
    write: |p, c| {
        for (i, v) in [c.r, c.g, c.b, c.a].into_iter().enumerate() {
            p[2 * i..2 * i + 2].copy_from_slice(&v.to_be_bytes());
        }
    },
    opaque: |c| c.a == 0xffff,
    from_rgba64: |c| c
);
direct_image!(
    /// Non-premultiplied 8-bit RGBA pixels (Go's `image.NRGBA`).
    Nrgba, Nrgba, 4, Nrgba,
    read: |p| color::Nrgba { r: p[0], g: p[1], b: p[2], a: p[3] },
    write: |p, c| p.copy_from_slice(&[c.r, c.g, c.b, c.a]),
    opaque: |c| c.a == 0xff,
    from_rgba64: |c| {
        let (r, g, b, a) = unpremultiply(c);
        color::Nrgba { r: (r >> 8) as u8, g: (g >> 8) as u8, b: (b >> 8) as u8, a: (a >> 8) as u8 }
    }
);
direct_image!(
    /// Non-premultiplied 16-bit RGBA pixels (Go's `image.NRGBA64`).
    Nrgba64, Nrgba64, 8, Nrgba64,
    read: |p| color::Nrgba64 { r: be16(&p[0..]), g: be16(&p[2..]), b: be16(&p[4..]), a: be16(&p[6..]) },
    write: |p, c| {
        for (i, v) in [c.r, c.g, c.b, c.a].into_iter().enumerate() {
            p[2 * i..2 * i + 2].copy_from_slice(&v.to_be_bytes());
        }
    },
    opaque: |c| c.a == 0xffff,
    from_rgba64: |c| {
        let (r, g, b, a) = unpremultiply(c);
        color::Nrgba64 { r: r as u16, g: g as u16, b: b as u16, a: a as u16 }
    }
);
direct_image!(
    /// 8-bit grayscale pixels (Go's `image.Gray`).
    Gray, Gray, 1, Gray,
    read: |p| color::Gray { y: p[0] },
    write: |p, c| p[0] = c.y,
    opaque: |_| true,
    from_rgba64: |c| color::Gray::from_color(c.into())
);
direct_image!(
    /// 16-bit grayscale pixels (Go's `image.Gray16`).
    Gray16, Gray16, 2, Gray16,
    read: |p| color::Gray16 { y: be16(p) },
    write: |p, c| p.copy_from_slice(&c.y.to_be_bytes()),
    opaque: |_| true,
    from_rgba64: |c| color::Gray16::from_color(c.into())
);
direct_image!(
    /// 8-bit alpha pixels (Go's `image.Alpha`).
    Alpha, Alpha, 1, Alpha,
    read: |p| color::Alpha { a: p[0] },
    write: |p, c| p[0] = c.a,
    opaque: |c| c.a == 0xff,
    from_rgba64: |c| color::Alpha::from_color(c.into())
);
direct_image!(
    /// 16-bit alpha pixels (Go's `image.Alpha16`).
    Alpha16, Alpha16, 2, Alpha16,
    read: |p| color::Alpha16 { a: be16(p) },
    write: |p, c| p.copy_from_slice(&c.a.to_be_bytes()),
    opaque: |c| c.a == 0xffff,
    from_rgba64: |c| color::Alpha16::from_color(c.into())
);

/// 8-bit palette indexes plus a palette (Go's `image.Paletted`).
///
/// Indexes may exceed the palette length; `at` then panics, as in Go.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Paletted {
    pub pix: Pix,
    pub stride: usize,
    pub rect: Rectangle,
    pub palette: Palette,
}

impl Paletted {
    /// A zero-index image with bounds `r`. Panics on negative or
    /// overflowing dimensions, as Go does.
    pub fn new(r: Rectangle, palette: Palette) -> Self {
        Self::try_new(r, palette).unwrap_or_else(|| {
            panic!("image: NewPaletted Rectangle has huge or negative dimensions")
        })
    }
    pub fn try_new(r: Rectangle, palette: Palette) -> Option<Self> {
        let (stride, len) = buffer_len(r, 1)?;
        Some(Self {
            pix: vec![0; len].into(),
            stride,
            rect: r,
            palette,
        })
    }
    pub fn pix_offset(&self, x: i32, y: i32) -> usize {
        offset(self.rect, self.stride, 1, x, y)
    }
    /// The palette index at (x, y), or 0 outside bounds.
    pub fn color_index_at(&self, x: i32, y: i32) -> u8 {
        if !pt(x, y).is_in(self.rect) {
            return 0;
        }
        self.pix.get(self.pix_offset(x, y))
    }
    pub fn set_color_index(&mut self, x: i32, y: i32, index: u8) {
        if !pt(x, y).is_in(self.rect) {
            return;
        }
        let i = self.pix_offset(x, y);
        self.pix.set(i, index);
    }
    /// Store the index of the palette entry closest to `c`.
    pub fn set(&mut self, x: i32, y: i32, c: Color) {
        let index = self.palette.index(c) as u8;
        self.set_color_index(x, y, index);
    }
    /// Go's `Paletted.SetRGBA64`: the same as [`Paletted::set`].
    pub fn set_rgba64(&mut self, x: i32, y: i32, c: color::Rgba64) {
        self.set(x, y, c.into());
    }
    /// The part of the image visible through `r`, sharing pixels with this
    /// image.
    pub fn sub_image(&mut self, r: Rectangle) -> Self {
        let r = r.intersect(self.rect);
        if r.is_empty() {
            return Self {
                palette: self.palette.clone(),
                ..Self::default()
            };
        }
        let i = offset(self.rect, self.stride, 1, r.min.x, r.min.y);
        Self {
            pix: self.pix.slice_from(i),
            stride: self.stride,
            rect: r,
            palette: self.palette.clone(),
        }
    }
    /// Whether every palette entry used by an in-bounds pixel is opaque.
    pub fn opaque(&self) -> bool {
        let mut present = [false; 256];
        let b = self.rect;
        for y in b.min.y..b.max.y {
            for x in b.min.x..b.max.x {
                present[usize::from(self.color_index_at(x, y))] = true;
            }
        }
        self.palette
            .0
            .iter()
            .enumerate()
            .all(|(i, c)| i >= 256 || !present[i] || c.rgba().3 == 0xffff)
    }
}

impl Image for Paletted {
    fn color_model(&self) -> Model {
        Model::Palette(self.palette.clone())
    }
    fn bounds(&self) -> Rectangle {
        self.rect
    }
    /// Go's `Paletted.At`. A pixel index outside the palette panics, as in
    /// Go; for an empty palette, where Go returns a nil color, this returns
    /// transparent black.
    fn at(&self, x: i32, y: i32) -> Color {
        if self.palette.is_empty() {
            return Color::Alpha16(color::TRANSPARENT);
        }
        if !pt(x, y).is_in(self.rect) {
            return self.palette.0[0];
        }
        self.palette.0[usize::from(self.color_index_at(x, y))]
    }
    fn opaque(&self) -> bool {
        Paletted::opaque(self)
    }
    fn as_paletted(&self) -> Option<&dyn PalettedImage> {
        Some(self)
    }
    fn as_any(&self) -> Option<&dyn Any> {
        Some(self)
    }
}

impl PalettedImage for Paletted {
    fn color_index_at(&self, x: i32, y: i32) -> u8 {
        Paletted::color_index_at(self, x, y)
    }
}

/// Any concrete image type from this module, as returned by decoders.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnyImage {
    Rgba(Rgba),
    Rgba64(Rgba64),
    Nrgba(Nrgba),
    Nrgba64(Nrgba64),
    Gray(Gray),
    Gray16(Gray16),
    Alpha(Alpha),
    Alpha16(Alpha16),
    Paletted(Paletted),
}

macro_rules! any_image {
    ($self:ident, $img:ident => $body:expr) => {
        match $self {
            AnyImage::Rgba($img) => $body,
            AnyImage::Rgba64($img) => $body,
            AnyImage::Nrgba($img) => $body,
            AnyImage::Nrgba64($img) => $body,
            AnyImage::Gray($img) => $body,
            AnyImage::Gray16($img) => $body,
            AnyImage::Alpha($img) => $body,
            AnyImage::Alpha16($img) => $body,
            AnyImage::Paletted($img) => $body,
        }
    };
}

impl Image for AnyImage {
    fn color_model(&self) -> Model {
        any_image!(self, i => i.color_model())
    }
    fn bounds(&self) -> Rectangle {
        any_image!(self, i => i.bounds())
    }
    fn at(&self, x: i32, y: i32) -> Color {
        any_image!(self, i => i.at(x, y))
    }
    fn opaque(&self) -> bool {
        any_image!(self, i => Image::opaque(i))
    }
    fn as_paletted(&self) -> Option<&dyn PalettedImage> {
        match self {
            AnyImage::Paletted(p) => Some(p),
            _ => None,
        }
    }
    fn as_any(&self) -> Option<&dyn Any> {
        any_image!(self, i => Some(i))
    }
}

macro_rules! any_from {
    ($($variant:ident),*) => {
        $(impl From<$variant> for AnyImage {
            fn from(i: $variant) -> Self {
                AnyImage::$variant(i)
            }
        })*
    };
}
any_from!(Rgba, Rgba64, Nrgba, Nrgba64, Gray, Gray16, Alpha, Alpha16, Paletted);
