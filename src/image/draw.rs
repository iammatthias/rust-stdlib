//! Image composition compatible with Go's `image/draw`.
//!
//! [`draw`] and [`draw_mask`] clip the rectangle exactly as Go does and then
//! reproduce, pixel for pixel, the result Go computes for the same image
//! types: the concrete-type fast paths Go selects (premultiplied RGBA
//! destinations, uniform sources, `Alpha` masks, paletted destinations and
//! same-type non-premultiplied copies) are ported with Go's integer
//! arithmetic, including its 32-bit wrap-around on out-of-range
//! premultiplied input, and every other combination uses Go's generic
//! `RGBA64At`/`SetRGBA64` path. [`FloydSteinberg`] is Go's error-diffusion
//! [`Drawer`].
//!
//! Rust borrowing forbids passing the destination as its own source, so Go's
//! `Draw(dst, r, dst, sp, op)` is spelled [`draw_within`] (and
//! [`draw_mask_within`]). These give Go's overlap-safe results: for the
//! image types of this module the source is a snapshot of the destination,
//! which is what Go's direction-aware loops compute; other destination types
//! use Go's generic loop with its backward iteration order.
//!
//! Deliberate differences from Go: a paletted pixel whose index is outside
//! its palette reads as transparent black where Go panics, and
//! [`FloydSteinberg`] into a paletted image with an empty palette writes
//! index 0 without diffusing error where Go panics. Go's `Quantizer`
//! communicates the wanted palette size through the slice capacity; here it
//! is an explicit argument.
//!
//! ```
//! use rust_stdlib::image::{color, draw, pt, rect, Image, Rgba, Uniform};
//! let mut dst = Rgba::new(rect(0, 0, 4, 4));
//! let red = Uniform::new(color::Rgba { r: 0xff, g: 0, b: 0, a: 0xff }.into());
//! draw::draw(&mut dst, rect(1, 1, 3, 3), &red, pt(0, 0), draw::Op::Src);
//! assert_eq!(dst.pixel_at(1, 2), color::Rgba { r: 0xff, g: 0, b: 0, a: 0xff });
//! assert_eq!(dst.pixel_at(0, 0), color::Rgba::default());
//! ```
use std::any::Any;

use super::color::{self, Color, Palette};
use super::{
    Alpha, Alpha16, AnyImage, Gray, Gray16, Nrgba, Nrgba64, Paletted, Pix, Point, Rectangle, Rgba,
    Rgba64, Uniform,
};

/// The maximum color value returned by `Color::rgba`.
const M: u32 = 0xffff;

/// An image whose pixels can be changed (Go's `draw.Image` together with
/// `draw.RGBA64Image`).
pub trait Image: super::Image {
    /// Convert `c` with the image's color model and store it; points outside
    /// the bounds are ignored.
    fn set(&mut self, x: i32, y: i32, c: Color);
    /// Store a premultiplied 16-bit color (Go's `SetRGBA64`). The default
    /// calls [`Image::set`].
    fn set_rgba64(&mut self, x: i32, y: i32, c: color::Rgba64) {
        self.set(x, y, c.into());
    }
    /// The concrete image for downcasting, used to select Go's type-specific
    /// code paths. Types from [`crate::image`] return themselves; the
    /// default is `None`.
    fn as_any_mut(&mut self) -> Option<&mut dyn Any> {
        None
    }
}

/// Go's `draw.RGBA64Image`: a drawable image that is also an
/// [`image::RGBA64Image`](super::RGBA64Image). [`Image::set_rgba64`] is its
/// `SetRGBA64`.
pub trait RGBA64Image: Image + super::RGBA64Image {}

impl<T: Image + super::RGBA64Image + ?Sized> RGBA64Image for T {}

macro_rules! drawable {
    ($($t:ident),*) => {
        $(impl Image for $t {
            fn set(&mut self, x: i32, y: i32, c: Color) {
                $t::set(self, x, y, c);
            }
            fn set_rgba64(&mut self, x: i32, y: i32, c: color::Rgba64) {
                $t::set_rgba64(self, x, y, c);
            }
            fn as_any_mut(&mut self) -> Option<&mut dyn Any> {
                Some(self)
            }
        })*
    };
}
drawable!(Rgba, Rgba64, Nrgba, Nrgba64, Gray, Gray16, Alpha, Alpha16, Paletted);

macro_rules! any_drawable {
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
    fn set(&mut self, x: i32, y: i32, c: Color) {
        any_drawable!(self, i => i.set(x, y, c))
    }
    fn set_rgba64(&mut self, x: i32, y: i32, c: color::Rgba64) {
        any_drawable!(self, i => i.set_rgba64(x, y, c))
    }
    fn as_any_mut(&mut self) -> Option<&mut dyn Any> {
        any_drawable!(self, i => Some(i))
    }
}

/// A Porter-Duff compositing operator.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Op {
    /// `(src in mask) over dst`.
    #[default]
    Over,
    /// `src in mask`.
    Src,
}

impl Op {
    /// Go's `Op.Draw`: [`draw_mask`] with no mask.
    pub fn draw(self, dst: &mut dyn Image, r: Rectangle, src: &dyn super::Image, sp: Point) {
        draw_mask(dst, r, src, sp, None, Point::default(), self);
    }
}

/// Something that can draw one image onto another (Go's `draw.Drawer`).
pub trait Drawer {
    /// Align `r.min` in `dst` with `sp` in `src` and replace the rectangle
    /// `r` in `dst` with the result of drawing `src` on it.
    fn draw(&self, dst: &mut dyn Image, r: Rectangle, src: &dyn super::Image, sp: Point);
}

impl Drawer for Op {
    fn draw(&self, dst: &mut dyn Image, r: Rectangle, src: &dyn super::Image, sp: Point) {
        Op::draw(*self, dst, r, src, sp);
    }
}

/// Produces a palette for an image (Go's `draw.Quantizer`).
pub trait Quantizer {
    /// Append up to `capacity - palette.len()` colors to `palette` and return
    /// the result, suitable for converting `m` to a paletted image. Go passes
    /// the capacity as the slice's capacity.
    fn quantize(&self, palette: Palette, capacity: usize, m: &dyn super::Image) -> Palette;
}

/// The [`Op::Src`] operator with Floyd-Steinberg error diffusion (Go's
/// `draw.FloydSteinberg`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct FloydSteinberg;

impl Drawer for FloydSteinberg {
    fn draw(&self, dst: &mut dyn Image, r: Rectangle, src: &dyn super::Image, sp: Point) {
        let mut r = r;
        let mut sp = sp;
        let mut mp = Point::default();
        clip(dst.bounds(), &mut r, src.bounds(), &mut sp, None, &mut mp);
        if r.is_empty() {
            return;
        }
        draw_paletted(dst, r, src, sp, true);
    }
}

/// [`draw_mask`] with no mask.
pub fn draw(dst: &mut dyn Image, r: Rectangle, src: &dyn super::Image, sp: Point, op: Op) {
    draw_mask(dst, r, src, sp, None, Point::default(), op);
}

/// Align `r.min` in `dst` with `sp` in `src` and `mp` in `mask`, then replace
/// the rectangle `r` in `dst` with the Porter-Duff composition `op`. A `None`
/// mask is fully opaque.
pub fn draw_mask(
    dst: &mut dyn Image,
    r: Rectangle,
    src: &dyn super::Image,
    sp: Point,
    mask: Option<&dyn super::Image>,
    mp: Point,
    op: Op,
) {
    draw_source(dst, r, Source::Other(src), sp, mask, mp, op);
}

/// [`draw`] with `dst` as its own source (Go's `Draw(dst, r, dst, sp, op)`).
pub fn draw_within(dst: &mut dyn Image, r: Rectangle, sp: Point, op: Op) {
    draw_mask_within(dst, r, sp, None, Point::default(), op);
}

/// [`draw_mask`] with `dst` as its own source. Overlapping regions behave as
/// in Go: every source pixel is read before it is overwritten.
pub fn draw_mask_within(
    dst: &mut dyn Image,
    r: Rectangle,
    sp: Point,
    mask: Option<&dyn super::Image>,
    mp: Point,
    op: Op,
) {
    draw_source(dst, r, Source::Dst, sp, mask, mp, op);
}

#[derive(Clone, Copy)]
enum Source<'a> {
    Other(&'a dyn super::Image),
    /// The destination itself.
    Dst,
}

/// Go's clip, computed in 64-bit arithmetic like Go's `int`.
fn clip(
    dst: Rectangle,
    r: &mut Rectangle,
    src: Rectangle,
    sp: &mut Point,
    mask: Option<Rectangle>,
    mp: &mut Point,
) {
    type R = (i64, i64, i64, i64);
    fn wide(r: Rectangle) -> R {
        (
            i64::from(r.min.x),
            i64::from(r.min.y),
            i64::from(r.max.x),
            i64::from(r.max.y),
        )
    }
    fn intersect(a: R, b: R) -> R {
        let out = (a.0.max(b.0), a.1.max(b.1), a.2.min(b.2), a.3.min(b.3));
        if out.0 >= out.2 || out.1 >= out.3 {
            return (0, 0, 0, 0);
        }
        out
    }
    fn shift(b: Rectangle, dx: i64, dy: i64) -> R {
        let b = wide(b);
        (b.0 + dx, b.1 + dy, b.2 + dx, b.3 + dy)
    }
    let (ox, oy) = (i64::from(r.min.x), i64::from(r.min.y));
    let mut out = intersect(wide(*r), wide(dst));
    out = intersect(out, shift(src, ox - i64::from(sp.x), oy - i64::from(sp.y)));
    if let Some(m) = mask {
        out = intersect(out, shift(m, ox - i64::from(mp.x), oy - i64::from(mp.y)));
    }
    // `out` lies within `dst`'s bounds, so it fits in i32.
    *r = Rectangle {
        min: Point {
            x: out.0 as i32,
            y: out.1 as i32,
        },
        max: Point {
            x: out.2 as i32,
            y: out.3 as i32,
        },
    };
    let (dx, dy) = (out.0 - ox, out.1 - oy);
    if dx == 0 && dy == 0 {
        return;
    }
    sp.x = (i64::from(sp.x) + dx) as i32;
    sp.y = (i64::from(sp.y) + dy) as i32;
    if mask.is_some() {
        mp.x = (i64::from(mp.x) + dx) as i32;
        mp.y = (i64::from(mp.y) + dy) as i32;
    }
}

/// Go's `processBackward` for a source that is the destination itself.
fn process_backward(r: Rectangle, sp: Point) -> bool {
    r.overlaps(r + (sp - r.min)) && (sp.y < r.min.y || (sp.y == r.min.y && sp.x < r.min.x))
}

/// A copy of a destination of a concrete type from this module.
fn snapshot(dst: &dyn super::Image) -> Option<Box<dyn super::Image>> {
    let any = dst.as_any()?;
    macro_rules! try_clone {
        ($($t:ident),*) => {
            $(if let Some(i) = any.downcast_ref::<$t>() {
                return Some(Box::new(i.clone()));
            })*
        };
    }
    try_clone!(Rgba, Rgba64, Nrgba, Nrgba64, Gray, Gray16, Alpha, Alpha16, Paletted);
    None
}

/// A handle on the pixel buffer of a concrete image from this module.
fn pix_of(i: &dyn super::Image) -> Option<&Pix> {
    let any = i.as_any()?;
    macro_rules! try_pix {
        ($($t:ident),*) => {
            $(if let Some(i) = any.downcast_ref::<$t>() {
                return Some(&i.pix);
            })*
        };
    }
    try_pix!(Rgba, Rgba64, Nrgba, Nrgba64, Gray, Gray16, Alpha, Alpha16, Paletted);
    None
}

fn downcast<T: 'static>(i: &dyn super::Image) -> Option<&T> {
    i.as_any()?.downcast_ref::<T>()
}

fn draw_source(
    dst: &mut dyn Image,
    r: Rectangle,
    src: Source<'_>,
    sp: Point,
    mask: Option<&dyn super::Image>,
    mp: Point,
    op: Op,
) {
    let (mut r, mut sp, mut mp) = (r, sp, mp);
    let src_bounds = match src {
        Source::Other(s) => s.bounds(),
        Source::Dst => dst.bounds(),
    };
    clip(
        dst.bounds(),
        &mut r,
        src_bounds,
        &mut sp,
        mask.map(|m| m.bounds()),
        &mut mp,
    );
    if r.is_empty() {
        return;
    }
    let src = match src {
        Source::Other(s) => s,
        Source::Dst => {
            // Go's loops for `dst == src` never read a source pixel after
            // writing it, so a snapshot gives the same pixels.
            match snapshot(dst) {
                Some(copy) => return draw_clipped(dst, r, copy.as_ref(), sp, mask, mp, op),
                None => {
                    return generic(dst, r, Source::Dst, sp, mask, mp, op);
                }
            }
        }
    };
    // A source or mask that shares pixels with the destination (a SubImage of
    // it, say) is read from a snapshot, so reads never wait on the lock held
    // for writing.
    if let Some(dp) = pix_of(dst) {
        let aliased = |i: &dyn super::Image| pix_of(i).is_some_and(|p| p.shares_with(dp));
        let src_copy = if aliased(src) { snapshot(src) } else { None };
        let mask_copy = match mask {
            Some(m) if aliased(m) => snapshot(m),
            _ => None,
        };
        if src_copy.is_some() || mask_copy.is_some() {
            let src = src_copy.as_deref().unwrap_or(src);
            let mask = mask_copy.as_deref().or(mask);
            return draw_clipped(dst, r, src, sp, mask, mp, op);
        }
    }
    draw_clipped(dst, r, src, sp, mask, mp, op);
}

/// Go's `DrawMask` after clipping, for a source distinct from `dst`.
fn draw_clipped(
    dst: &mut dyn Image,
    r: Rectangle,
    src: &dyn super::Image,
    sp: Point,
    mask: Option<&dyn super::Image>,
    mp: Point,
    op: Op,
) {
    let uniform = downcast::<Uniform>(src);
    if let Some(d) = dst.as_any_mut().and_then(|a| a.downcast_mut::<Rgba>()) {
        rgba_fast_paths(d, r, src, uniform, sp, mask, mp, op);
        return;
    }
    if op == Op::Src && mask.is_none() {
        if let Some(d) = dst.as_any_mut().and_then(|a| a.downcast_mut::<Paletted>()) {
            if let Some(u) = uniform {
                let index = d.palette.index(u.c) as u8;
                for y in r.min.y..r.max.y {
                    let i = d.pix_offset(r.min.x, y);
                    d.pix.with_mut(|p| p[i..i + r.dx() as usize].fill(index));
                }
                return;
            }
            draw_paletted(dst, r, src, sp, false);
            return;
        }
        if let Some(d) = dst.as_any_mut().and_then(|a| a.downcast_mut::<Nrgba>()) {
            if let Some(s) = downcast::<Nrgba>(src) {
                let d0 = d.pix_offset(r.min.x, r.min.y);
                copy_rows(
                    &mut d.pix,
                    d.stride,
                    d0,
                    &s.pix,
                    s.stride,
                    s.pix_offset(sp.x, sp.y),
                    r.dy(),
                    4 * r.dx() as usize,
                );
                return;
            }
        }
        if let Some(d) = dst.as_any_mut().and_then(|a| a.downcast_mut::<Nrgba64>()) {
            if let Some(s) = downcast::<Nrgba64>(src) {
                let d0 = d.pix_offset(r.min.x, r.min.y);
                copy_rows(
                    &mut d.pix,
                    d.stride,
                    d0,
                    &s.pix,
                    s.stride,
                    s.pix_offset(sp.x, sp.y),
                    r.dy(),
                    8 * r.dx() as usize,
                );
                return;
            }
        }
    }
    generic(dst, r, Source::Other(src), sp, mask, mp, op);
}

#[allow(clippy::too_many_arguments)]
fn copy_rows(
    dst: &mut Pix,
    dst_stride: usize,
    d0: usize,
    src: &Pix,
    src_stride: usize,
    s0: usize,
    rows: i32,
    bytes_per_row: usize,
) {
    // Draw detaches a source that shares a buffer with the destination, so
    // the two locks are never taken on the same buffer.
    dst.with_mut(|dst| {
        src.with(|src| {
            for row in 0..rows as usize {
                let (d, s) = (d0 + row * dst_stride, s0 + row * src_stride);
                dst[d..d + bytes_per_row].copy_from_slice(&src[s..s + bytes_per_row]);
            }
        })
    });
}

/// Go's FALLBACK1.17 loop: `RGBA64At` reads and `SetRGBA64` writes, walking
/// backward when the source is the destination and lies before it.
fn generic(
    dst: &mut dyn Image,
    r: Rectangle,
    src: Source<'_>,
    sp: Point,
    mask: Option<&dyn super::Image>,
    mp: Point,
    op: Op,
) {
    let (mut x0, mut x1, mut dx) = (r.min.x, r.max.x, 1);
    let (mut y0, mut y1, mut dy) = (r.min.y, r.max.y, 1);
    if matches!(src, Source::Dst) && process_backward(r, sp) {
        (x0, x1, dx) = (x1 - 1, x0 - 1, -1);
        (y0, y1, dy) = (y1 - 1, y0 - 1, -1);
    }
    let read = |dst: &dyn Image, x: i32, y: i32| match src {
        Source::Other(s) => s.rgba64_at(x, y),
        Source::Dst => dst.rgba64_at(x, y),
    };
    let mut y = y0;
    let mut sy = sp.y + y0 - r.min.y;
    let mut my = mp.y + y0 - r.min.y;
    while y != y1 {
        let mut x = x0;
        let mut sx = sp.x + x0 - r.min.x;
        let mut mx = mp.x + x0 - r.min.x;
        while x != x1 {
            match mask {
                None => {
                    let s = read(dst, sx, sy);
                    if op == Op::Src {
                        dst.set_rgba64(x, y, s);
                    } else {
                        let a = M - u32::from(s.a);
                        let d = dst.rgba64_at(x, y);
                        let f = |dc: u16, sc: u16| {
                            ((u32::from(dc).wrapping_mul(a) / M) as u16).wrapping_add(sc)
                        };
                        dst.set_rgba64(
                            x,
                            y,
                            color::Rgba64 {
                                r: f(d.r, s.r),
                                g: f(d.g, s.g),
                                b: f(d.b, s.b),
                                a: f(d.a, s.a),
                            },
                        );
                    }
                }
                Some(m) => {
                    let ma = u32::from(m.rgba64_at(mx, my).a);
                    if ma == 0 {
                        if op == Op::Src {
                            dst.set_rgba64(x, y, color::Rgba64::default());
                        }
                    } else if ma == M && op == Op::Src {
                        let s = read(dst, sx, sy);
                        dst.set_rgba64(x, y, s);
                    } else {
                        let s = read(dst, sx, sy);
                        let out = if op == Op::Over {
                            let d = dst.rgba64_at(x, y);
                            let a = M - u32::from(s.a) * ma / M;
                            let f = |dc: u16, sc: u16| {
                                (u32::from(dc)
                                    .wrapping_mul(a)
                                    .wrapping_add(u32::from(sc).wrapping_mul(ma))
                                    / M) as u16
                            };
                            color::Rgba64 {
                                r: f(d.r, s.r),
                                g: f(d.g, s.g),
                                b: f(d.b, s.b),
                                a: f(d.a, s.a),
                            }
                        } else {
                            let f = |sc: u16| (u32::from(sc) * ma / M) as u16;
                            color::Rgba64 {
                                r: f(s.r),
                                g: f(s.g),
                                b: f(s.b),
                                a: f(s.a),
                            }
                        };
                        dst.set_rgba64(x, y, out);
                    }
                }
            }
            x += dx;
            sx += dx;
            mx += dx;
        }
        y += dy;
        sy += dy;
        my += dy;
    }
}

/// Iterate over the clipped rectangle, yielding the destination byte offset
/// and the source and mask points for each pixel in Go's forward order.
fn for_each(r: Rectangle, sp: Point, mp: Point, mut f: impl FnMut(i32, i32, Point, Point)) {
    for y in r.min.y..r.max.y {
        for x in r.min.x..r.max.x {
            let s = Point {
                x: sp.x + x - r.min.x,
                y: sp.y + y - r.min.y,
            };
            let m = Point {
                x: mp.x + x - r.min.x,
                y: mp.y + y - r.min.y,
            };
            f(x, y, s, m);
        }
    }
}

fn widen(v: u8) -> u32 {
    u32::from(v) * 0x101
}

/// Go's `(d*a + s*ma) / m >> 8` with 32-bit wrap-around.
fn blend(d: u8, a: u32, s: u32, ma: u32) -> u8 {
    ((u32::from(d)
        .wrapping_mul(a)
        .wrapping_add(s.wrapping_mul(ma))
        / M)
        >> 8) as u8
}

/// Go's `(d*a/m + s) >> 8` with 32-bit wrap-around.
fn over(d: u8, a: u32, s: u32) -> u8 {
    ((u32::from(d).wrapping_mul(a) / M).wrapping_add(s) >> 8) as u8
}

/// Go's `*image.RGBA` destination cases of `DrawMask`.
#[allow(clippy::too_many_arguments)]
fn rgba_fast_paths(
    dst: &mut Rgba,
    r: Rectangle,
    src: &dyn super::Image,
    uniform: Option<&Uniform>,
    sp: Point,
    mask: Option<&dyn super::Image>,
    mp: Point,
    op: Op,
) {
    let alpha_mask = mask.and_then(downcast::<Alpha>);
    match (op, mask) {
        (Op::Over, None) => {
            if let Some(u) = uniform {
                let s = u.c.rgba();
                if s.3 == 0xffff {
                    fill_src(dst, r, s);
                } else {
                    fill_over(dst, r, s);
                }
                return;
            }
            if let Some(s) = downcast::<Rgba>(src) {
                return pixel_loop(dst, r, sp, mp, |d, sp, _| {
                    let p = s.pixel_at(sp.x, sp.y);
                    let sa = widen(p.a);
                    let a = (M - sa) * 0x101;
                    [
                        over(d[0], a, widen(p.r)),
                        over(d[1], a, widen(p.g)),
                        over(d[2], a, widen(p.b)),
                        over(d[3], a, sa),
                    ]
                });
            }
            if let Some(s) = downcast::<Nrgba>(src) {
                return pixel_loop(dst, r, sp, mp, |d, sp, _| {
                    let p = s.pixel_at(sp.x, sp.y);
                    let sa = widen(p.a);
                    let a = (M - sa) * 0x101;
                    [
                        over(d[0], a, u32::from(p.r) * sa / 0xff),
                        over(d[1], a, u32::from(p.g) * sa / 0xff),
                        over(d[2], a, u32::from(p.b) * sa / 0xff),
                        over(d[3], a, sa),
                    ]
                });
            }
            if let Some(s) = downcast::<Gray>(src) {
                return draw_gray(dst, r, s, sp);
            }
        }
        (Op::Over, Some(_)) => {
            if let Some(m) = alpha_mask {
                let ma_at = |p: Point| {
                    let v = u32::from(m.pixel_at(p.x, p.y).a);
                    v | (v << 8)
                };
                if let Some(u) = uniform {
                    let (sr, sg, sb, sa) = u.c.rgba();
                    return pixel_loop(dst, r, sp, mp, |d, _, mp| {
                        let ma = ma_at(mp);
                        if ma == 0 {
                            return d;
                        }
                        let a = (M - sa * ma / M) * 0x101;
                        [
                            blend(d[0], a, sr, ma),
                            blend(d[1], a, sg, ma),
                            blend(d[2], a, sb, ma),
                            blend(d[3], a, sa, ma),
                        ]
                    });
                }
                if let Some(s) = downcast::<Rgba>(src) {
                    return pixel_loop(dst, r, sp, mp, |d, sp, mp| {
                        let ma = ma_at(mp);
                        let p = s.pixel_at(sp.x, sp.y);
                        let sa = widen(p.a);
                        let a = (M - sa * ma / M) * 0x101;
                        [
                            blend(d[0], a, widen(p.r), ma),
                            blend(d[1], a, widen(p.g), ma),
                            blend(d[2], a, widen(p.b), ma),
                            blend(d[3], a, sa, ma),
                        ]
                    });
                }
                if let Some(s) = downcast::<Gray>(src) {
                    return pixel_loop(dst, r, sp, mp, |d, sp, mp| {
                        let ma = ma_at(mp);
                        let y = widen(s.pixel_at(sp.x, sp.y).y);
                        let a = (M - M * ma / M) * 0x101;
                        [
                            blend(d[0], a, y, ma),
                            blend(d[1], a, y, ma),
                            blend(d[2], a, y, ma),
                            blend(d[3], a, M, ma),
                        ]
                    });
                }
                // Every source implements Go's image.RGBA64Image.
                return pixel_loop(dst, r, sp, mp, |d, sp, mp| {
                    let ma = ma_at(mp);
                    let s = src.rgba64_at(sp.x, sp.y);
                    let sa = u32::from(s.a);
                    let a = (M - sa * ma / M) * 0x101;
                    [
                        blend(d[0], a, u32::from(s.r), ma),
                        blend(d[1], a, u32::from(s.g), ma),
                        blend(d[2], a, u32::from(s.b), ma),
                        blend(d[3], a, sa, ma),
                    ]
                });
            }
        }
        (Op::Src, None) => {
            if let Some(u) = uniform {
                return fill_src(dst, r, u.c.rgba());
            }
            if let Some(s) = downcast::<Rgba>(src) {
                let (d0, s0) = (dst.pix_offset(r.min.x, r.min.y), s.pix_offset(sp.x, sp.y));
                return copy_rows(
                    &mut dst.pix,
                    dst.stride,
                    d0,
                    &s.pix,
                    s.stride,
                    s0,
                    r.dy(),
                    4 * r.dx() as usize,
                );
            }
            if let Some(s) = downcast::<Nrgba>(src) {
                return pixel_loop(dst, r, sp, mp, |_, sp, _| {
                    let p = s.pixel_at(sp.x, sp.y);
                    let sa = widen(p.a);
                    [
                        ((u32::from(p.r) * sa / 0xff) >> 8) as u8,
                        ((u32::from(p.g) * sa / 0xff) >> 8) as u8,
                        ((u32::from(p.b) * sa / 0xff) >> 8) as u8,
                        (sa >> 8) as u8,
                    ]
                });
            }
            if let Some(s) = downcast::<Gray>(src) {
                return draw_gray(dst, r, s, sp);
            }
        }
        (Op::Src, Some(_)) => {}
    }
    draw_rgba(dst, r, src, sp, mask, mp, op);
}

/// Replace each pixel of `r` in `dst` with `f(old pixel, source point,
/// mask point)`.
fn pixel_loop(
    dst: &mut Rgba,
    r: Rectangle,
    sp: Point,
    mp: Point,
    mut f: impl FnMut([u8; 4], Point, Point) -> [u8; 4],
) {
    for_each(r, sp, mp, |x, y, s, m| {
        let i = dst.pix_offset(x, y);
        dst.pix.with_mut(|p| {
            let d = &mut p[i..i + 4];
            let out = f([d[0], d[1], d[2], d[3]], s, m);
            d.copy_from_slice(&out);
        });
    });
}

fn fill_src(dst: &mut Rgba, r: Rectangle, (sr, sg, sb, sa): (u32, u32, u32, u32)) {
    let px = [
        (sr >> 8) as u8,
        (sg >> 8) as u8,
        (sb >> 8) as u8,
        (sa >> 8) as u8,
    ];
    pixel_loop(dst, r, Point::default(), Point::default(), |_, _, _| px);
}

fn fill_over(dst: &mut Rgba, r: Rectangle, (sr, sg, sb, sa): (u32, u32, u32, u32)) {
    let a = (M - sa) * 0x101;
    pixel_loop(dst, r, Point::default(), Point::default(), |d, _, _| {
        [
            over(d[0], a, sr),
            over(d[1], a, sg),
            over(d[2], a, sb),
            over(d[3], a, sa),
        ]
    });
}

fn draw_gray(dst: &mut Rgba, r: Rectangle, src: &Gray, sp: Point) {
    pixel_loop(dst, r, sp, Point::default(), |_, sp, _| {
        let y = src.pixel_at(sp.x, sp.y).y;
        [y, y, y, 0xff]
    });
}

/// Go's `drawRGBA`: the generic loop specialized to an RGBA destination.
fn draw_rgba(
    dst: &mut Rgba,
    r: Rectangle,
    src: &dyn super::Image,
    sp: Point,
    mask: Option<&dyn super::Image>,
    mp: Point,
    op: Op,
) {
    pixel_loop(dst, r, sp, mp, |d, sp, mp| {
        let s = src.rgba64_at(sp.x, sp.y);
        let (sr, sg, sb, sa) = s.rgba();
        match (mask, op) {
            (None, Op::Over) => {
                let a = (M - sa) * 0x101;
                [
                    over(d[0], a, sr),
                    over(d[1], a, sg),
                    over(d[2], a, sb),
                    over(d[3], a, sa),
                ]
            }
            (None, Op::Src) => [
                (sr >> 8) as u8,
                (sg >> 8) as u8,
                (sb >> 8) as u8,
                (sa >> 8) as u8,
            ],
            (Some(m), Op::Over) => {
                let ma = u32::from(m.rgba64_at(mp.x, mp.y).a);
                let a = (M - sa * ma / M) * 0x101;
                [
                    blend(d[0], a, sr, ma),
                    blend(d[1], a, sg, ma),
                    blend(d[2], a, sb, ma),
                    blend(d[3], a, sa, ma),
                ]
            }
            (Some(m), Op::Src) => {
                let ma = u32::from(m.rgba64_at(mp.x, mp.y).a);
                let f = |c: u32| ((c * ma / M) >> 8) as u8;
                [f(sr), f(sg), f(sb), f(sa)]
            }
        }
    });
}

/// Go's `drawPaletted`: nearest-palette-color conversion into a paletted
/// destination (or `set` into any other), optionally with Floyd-Steinberg
/// error diffusion.
fn draw_paletted(
    dst: &mut dyn Image,
    r: Rectangle,
    src: &dyn super::Image,
    sp: Point,
    floyd_steinberg: bool,
) {
    let mut diffusion = Diffusion::new(floyd_steinberg, r.dx() as usize);
    let source = |x: i32, y: i32| {
        let (sr, sg, sb, sa) = src.at(sp.x + x, sp.y + y).rgba();
        [sr as i32, sg as i32, sb as i32, sa as i32]
    };
    if let Some(p) = dst.as_any_mut().and_then(|a| a.downcast_mut::<Paletted>()) {
        let palette: Vec<[i32; 4]> = p
            .palette
            .0
            .iter()
            .map(|c| {
                let (r, g, b, a) = c.rgba();
                [r as i32, g as i32, b as i32, a as i32]
            })
            .collect();
        for y in 0..r.dy() {
            for x in 0..r.dx() {
                let mut e = diffusion.adjust(x as usize, source(x, y));
                let mut best = 0;
                let mut best_sum = u32::MAX;
                for (index, q) in palette.iter().enumerate() {
                    let sum = (0..4).fold(0u32, |acc, k| acc.wrapping_add(sq_diff(e[k], q[k])));
                    if sum < best_sum {
                        best = index;
                        best_sum = sum;
                        if sum == 0 {
                            break;
                        }
                    }
                }
                let i = p.pix_offset(r.min.x + x, r.min.y + y);
                p.pix.set(i, best as u8);
                if !floyd_steinberg {
                    continue;
                }
                // An empty palette panics here, as in Go.
                let chosen = palette[best];
                for k in 0..4 {
                    e[k] = e[k].wrapping_sub(chosen[k]);
                }
                diffusion.propagate(x as usize, e);
            }
            diffusion.next_row();
        }
        return;
    }
    for y in 0..r.dy() {
        for x in 0..r.dx() {
            let mut e = diffusion.adjust(x as usize, source(x, y));
            let (px, py) = (r.min.x + x, r.min.y + y);
            let out = color::Rgba64 {
                r: e[0] as u16,
                g: e[1] as u16,
                b: e[2] as u16,
                a: e[3] as u16,
            };
            dst.set(px, py, out.into());
            if !floyd_steinberg {
                continue;
            }
            let (qr, qg, qb, qa) = dst.at(px, py).rgba();
            for (k, q) in [qr, qg, qb, qa].into_iter().enumerate() {
                e[k] = e[k].wrapping_sub(q as i32);
            }
            diffusion.propagate(x as usize, e);
        }
        diffusion.next_row();
    }
}

/// Floyd-Steinberg quantization errors for the current and next rows; the
/// two extra entries simplify the edges, as in Go.
struct Diffusion {
    enabled: bool,
    curr: Vec<[i32; 4]>,
    next: Vec<[i32; 4]>,
}

impl Diffusion {
    fn new(enabled: bool, width: usize) -> Self {
        let len = if enabled { width + 2 } else { 0 };
        Self {
            enabled,
            curr: vec![[0; 4]; len],
            next: vec![[0; 4]; len],
        }
    }
    /// The source value plus the error propagated to column `x`, clamped.
    fn adjust(&self, x: usize, mut e: [i32; 4]) -> [i32; 4] {
        if self.enabled {
            for (k, v) in e.iter_mut().enumerate() {
                *v = v.wrapping_add(self.curr[x + 1][k] / 16).clamp(0, 0xffff);
            }
        }
        e
    }
    fn propagate(&mut self, x: usize, e: [i32; 4]) {
        for (k, &v) in e.iter().enumerate() {
            self.next[x][k] = self.next[x][k].wrapping_add(v.wrapping_mul(3));
            self.next[x + 1][k] = self.next[x + 1][k].wrapping_add(v.wrapping_mul(5));
            self.next[x + 2][k] = self.next[x + 2][k].wrapping_add(v);
            self.curr[x + 2][k] = self.curr[x + 2][k].wrapping_add(v.wrapping_mul(7));
        }
    }
    fn next_row(&mut self) {
        if self.enabled {
            std::mem::swap(&mut self.curr, &mut self.next);
            self.next.iter_mut().for_each(|q| *q = [0; 4]);
        }
    }
}

/// Go's `sqDiff`: squared difference shifted right by 2, with wrap-around.
fn sq_diff(x: i32, y: i32) -> u32 {
    let d = x.wrapping_sub(y) as u32;
    d.wrapping_mul(d) >> 2
}
