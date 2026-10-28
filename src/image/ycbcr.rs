//! YCbCr images with chroma subsampling (Go's `image.YCbCr` and
//! `image.NYCbCrA`). Planes use Go's layout: the luma plane has one byte per
//! pixel, and each chroma plane has one byte per subsampled block.
use std::fmt;

use super::color::{self, Color, Model};
use super::{pt, Image, Pix, Rectangle};

/// Go's `image.YCbCrSubsampleRatio`: how many luma pixels share a chroma sample.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum YcbcrSubsampleRatio {
    #[default]
    Ratio444 = 0,
    Ratio422 = 1,
    Ratio420 = 2,
    Ratio440 = 3,
    Ratio411 = 4,
    Ratio410 = 5,
}

impl fmt::Display for YcbcrSubsampleRatio {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            YcbcrSubsampleRatio::Ratio444 => "YCbCrSubsampleRatio444",
            YcbcrSubsampleRatio::Ratio422 => "YCbCrSubsampleRatio422",
            YcbcrSubsampleRatio::Ratio420 => "YCbCrSubsampleRatio420",
            YcbcrSubsampleRatio::Ratio440 => "YCbCrSubsampleRatio440",
            YcbcrSubsampleRatio::Ratio411 => "YCbCrSubsampleRatio411",
            YcbcrSubsampleRatio::Ratio410 => "YCbCrSubsampleRatio410",
        })
    }
}

/// Chroma plane size (width, height) for `r`, computed with Go's truncating
/// integer division.
fn chroma_size(r: Rectangle, ratio: YcbcrSubsampleRatio) -> (i64, i64) {
    let (w, h) = (i64::from(r.dx()), i64::from(r.dy()));
    let (x0, y0) = (i64::from(r.min.x), i64::from(r.min.y));
    let (x1, y1) = (i64::from(r.max.x), i64::from(r.max.y));
    match ratio {
        YcbcrSubsampleRatio::Ratio422 => ((x1 + 1) / 2 - x0 / 2, h),
        YcbcrSubsampleRatio::Ratio420 => ((x1 + 1) / 2 - x0 / 2, (y1 + 1) / 2 - y0 / 2),
        YcbcrSubsampleRatio::Ratio440 => (w, (y1 + 1) / 2 - y0 / 2),
        YcbcrSubsampleRatio::Ratio411 => ((x1 + 3) / 4 - x0 / 4, h),
        YcbcrSubsampleRatio::Ratio410 => ((x1 + 3) / 4 - x0 / 4, (y1 + 1) / 2 - y0 / 2),
        YcbcrSubsampleRatio::Ratio444 => (w, h),
    }
}

/// Luma and chroma plane sizes `(luma_width, luma_height, chroma_width,
/// chroma_height)` for `r`, or `None` for negative or overflowing dimensions.
pub(crate) fn plane_sizes(
    r: Rectangle,
    ratio: YcbcrSubsampleRatio,
) -> Option<(usize, usize, usize, usize)> {
    let (cw, ch) = chroma_size(r, ratio);
    let (w, h) = (i64::from(r.dx()), i64::from(r.dy()));
    if w < 0 || h < 0 || cw < 0 || ch < 0 {
        return None;
    }
    let (w, h) = (usize::try_from(w).ok()?, usize::try_from(h).ok()?);
    let (cw, ch) = (usize::try_from(cw).ok()?, usize::try_from(ch).ok()?);
    let luma = w.checked_mul(h)?;
    let chroma = cw.checked_mul(ch)?;
    if luma.checked_add(chroma.checked_mul(2)?)? > isize::MAX as usize {
        return None;
    }
    Some((w, h, cw, ch))
}

/// Index of the chroma sample for (x, y), as Go's `COffset`.
fn c_offset(rect: Rectangle, ratio: YcbcrSubsampleRatio, stride: usize, x: i32, y: i32) -> usize {
    let (min_x, min_y) = (rect.min.x, rect.min.y);
    let (row, col) = match ratio {
        YcbcrSubsampleRatio::Ratio422 => (y - min_y, x / 2 - min_x / 2),
        YcbcrSubsampleRatio::Ratio420 => (y / 2 - min_y / 2, x / 2 - min_x / 2),
        YcbcrSubsampleRatio::Ratio440 => (y / 2 - min_y / 2, x - min_x),
        YcbcrSubsampleRatio::Ratio411 => (y - min_y, x / 4 - min_x / 4),
        YcbcrSubsampleRatio::Ratio410 => (y / 2 - min_y / 2, x / 4 - min_x / 4),
        YcbcrSubsampleRatio::Ratio444 => (y - min_y, x - min_x),
    };
    row as usize * stride + col as usize
}

/// Index of the luma sample for (x, y), as Go's `YOffset`.
fn y_offset(rect: Rectangle, stride: usize, x: i32, y: i32) -> usize {
    (y - rect.min.y) as usize * stride + (x - rect.min.x) as usize
}

/// Index of the alpha sample for (x, y), as Go's `AOffset`.
fn a_offset(rect: Rectangle, stride: usize, x: i32, y: i32) -> usize {
    y_offset(rect, stride, x, y)
}

/// A YCbCr image (Go's `image.YCbCr`). Its color model is [`Model::Ycbcr`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ycbcr {
    pub y: Pix,
    pub cb: Pix,
    pub cr: Pix,
    pub y_stride: usize,
    pub c_stride: usize,
    pub subsample_ratio: YcbcrSubsampleRatio,
    pub rect: Rectangle,
}

impl Ycbcr {
    /// A zeroed image with bounds `r`. Panics, as Go does, when the
    /// dimensions are negative or the buffer size overflows.
    pub fn new(r: Rectangle, ratio: YcbcrSubsampleRatio) -> Self {
        Self::try_new(r, ratio)
            .unwrap_or_else(|| panic!("image: NewYCbCr Rectangle has huge or negative dimensions"))
    }

    /// A zeroed image with bounds `r`, or `None` for negative or overflowing
    /// dimensions.
    pub fn try_new(r: Rectangle, ratio: YcbcrSubsampleRatio) -> Option<Self> {
        let (w, h, cw, ch) = plane_sizes(r, ratio)?;
        Some(Self {
            y: vec![0; w * h].into(),
            cb: vec![0; cw * ch].into(),
            cr: vec![0; cw * ch].into(),
            y_stride: w,
            c_stride: cw,
            subsample_ratio: ratio,
            rect: r,
        })
    }

    /// Index of the luma sample for (x, y), as Go's `YOffset`.
    pub fn y_offset(&self, x: i32, y: i32) -> usize {
        y_offset(self.rect, self.y_stride, x, y)
    }

    /// Index of the chroma samples for (x, y), as Go's `COffset`.
    pub fn c_offset(&self, x: i32, y: i32) -> usize {
        c_offset(self.rect, self.subsample_ratio, self.c_stride, x, y)
    }

    /// The YCbCr color at (x, y), or the zero color outside bounds.
    pub fn ycbcr_at(&self, x: i32, y: i32) -> color::Ycbcr {
        if !pt(x, y).is_in(self.rect) {
            return color::Ycbcr::default();
        }
        let (yi, ci) = (self.y_offset(x, y), self.c_offset(x, y));
        color::Ycbcr {
            y: self.y.get(yi),
            cb: self.cb.get(ci),
            cr: self.cr.get(ci),
        }
    }

    /// The part of the image visible through `r`, with the same strides and
    /// subsampling, sharing the planes with this image (Go's `SubImage`).
    pub fn sub_image(&mut self, r: Rectangle) -> Self {
        let r = r.intersect(self.rect);
        if r.is_empty() {
            return Self {
                subsample_ratio: self.subsample_ratio,
                ..Self::default()
            };
        }
        let yi = self.y_offset(r.min.x, r.min.y);
        let ci = self.c_offset(r.min.x, r.min.y);
        Self {
            y: self.y.slice_from(yi),
            cb: self.cb.slice_from(ci),
            cr: self.cr.slice_from(ci),
            y_stride: self.y_stride,
            c_stride: self.c_stride,
            subsample_ratio: self.subsample_ratio,
            rect: r,
        }
    }
}

impl Image for Ycbcr {
    fn color_model(&self) -> Model {
        Model::Ycbcr
    }
    fn bounds(&self) -> Rectangle {
        self.rect
    }
    fn at(&self, x: i32, y: i32) -> Color {
        self.ycbcr_at(x, y).into()
    }
    /// Go's YCbCr images are always opaque.
    fn opaque(&self) -> bool {
        true
    }
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
}

/// A YCbCr image with an alpha plane (Go's `image.NYCbCrA`). Its color model
/// is [`Model::Nycbcra`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Nycbcra {
    pub ycbcr: Ycbcr,
    pub a: Pix,
    pub a_stride: usize,
}

impl Nycbcra {
    /// A zeroed image with bounds `r`. Panics, as Go does, when the
    /// dimensions are negative or the buffer size overflows.
    pub fn new(r: Rectangle, ratio: YcbcrSubsampleRatio) -> Self {
        Self::try_new(r, ratio)
            .unwrap_or_else(|| panic!("image: NewNYCbCrA Rectangle has huge or negative dimension"))
    }

    /// A zeroed image with bounds `r`, or `None` for negative or overflowing
    /// dimensions.
    pub fn try_new(r: Rectangle, ratio: YcbcrSubsampleRatio) -> Option<Self> {
        let (w, h, _, _) = plane_sizes(r, ratio)?;
        let ycbcr = Ycbcr::try_new(r, ratio)?;
        Some(Self {
            ycbcr,
            a: vec![0; w * h].into(),
            a_stride: w,
        })
    }

    /// Index of the alpha sample for (x, y), as Go's `AOffset`.
    pub fn a_offset(&self, x: i32, y: i32) -> usize {
        a_offset(self.ycbcr.rect, self.a_stride, x, y)
    }

    /// The NYCbCrA color at (x, y), or the zero color outside bounds.
    pub fn nycbcra_at(&self, x: i32, y: i32) -> color::Nycbcra {
        if !pt(x, y).is_in(self.ycbcr.rect) {
            return color::Nycbcra::default();
        }
        color::Nycbcra {
            ycbcr: self.ycbcr.ycbcr_at(x, y),
            a: self.a.get(self.a_offset(x, y)),
        }
    }

    /// The part of the image visible through `r`, sharing pixels with this
    /// image (Go's `SubImage`).
    pub fn sub_image(&mut self, r: Rectangle) -> Self {
        let rect = r.intersect(self.ycbcr.rect);
        if rect.is_empty() {
            return Self {
                ycbcr: Ycbcr {
                    subsample_ratio: self.ycbcr.subsample_ratio,
                    ..Ycbcr::default()
                },
                ..Self::default()
            };
        }
        let ai = self.a_offset(rect.min.x, rect.min.y);
        Self {
            ycbcr: self.ycbcr.sub_image(rect),
            a: self.a.slice_from(ai),
            a_stride: self.a_stride,
        }
    }
}

impl Image for Nycbcra {
    fn color_model(&self) -> Model {
        Model::Nycbcra
    }
    fn bounds(&self) -> Rectangle {
        self.ycbcr.rect
    }
    fn at(&self, x: i32, y: i32) -> Color {
        self.nycbcra_at(x, y).into()
    }
    /// Whether every alpha sample in bounds is 0xff.
    fn opaque(&self) -> bool {
        let r = self.ycbcr.rect;
        if r.is_empty() {
            return true;
        }
        (r.min.y..r.max.y).all(|y| {
            let start = self.a_offset(r.min.x, y);
            self.a
                .with(|a| a[start..start + r.dx() as usize].iter().all(|&a| a == 0xff))
        })
    }
}
