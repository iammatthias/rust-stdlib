use rust_stdlib::image::color::{self, Color, Model, Palette};
use rust_stdlib::image::draw::{self, Drawer, FloydSteinberg, Op};
use rust_stdlib::image::{
    pt, rect, Alpha, AnyImage, Gray, Image, Nrgba, Nrgba64, Paletted, Point, Rectangle, Rgba,
    Rgba64, Uniform,
};

fn rgba(r: u8, g: u8, b: u8, a: u8) -> color::Rgba {
    color::Rgba { r, g, b, a }
}

/// An image type the draw package cannot downcast, so it takes Go's generic
/// path (including in-place overlap handling) like a user-defined Go image.
#[derive(Clone)]
struct Opaque<T>(T);

impl<T: Image> Image for Opaque<T> {
    fn color_model(&self) -> Model {
        self.0.color_model()
    }
    fn bounds(&self) -> Rectangle {
        self.0.bounds()
    }
    fn at(&self, x: i32, y: i32) -> Color {
        self.0.at(x, y)
    }
}

impl<T: draw::Image> draw::Image for Opaque<T> {
    fn set(&mut self, x: i32, y: i32, c: Color) {
        self.0.set(x, y, c);
    }
    fn set_rgba64(&mut self, x: i32, y: i32, c: color::Rgba64) {
        self.0.set_rgba64(x, y, c);
    }
}

fn gradient(r: Rectangle) -> Rgba {
    let mut m = Rgba::new(r);
    for y in r.min.y..r.max.y {
        for x in r.min.x..r.max.x {
            let a = (x * 7 + y * 13) as u8 | 0x80;
            m.set_pixel(
                x,
                y,
                rgba((x * 9) as u8 % a, (y * 11) as u8 % a, 0x10.min(a), a),
            );
        }
    }
    m
}

#[test]
fn overlapping_draws_read_every_source_pixel_before_writing_it() {
    for op in [Op::Over, Op::Src] {
        for yoff in -2..=2 {
            for xoff in -2..=2 {
                let base = gradient(rect(0, 0, 16, 16));
                let r = rect(5, 5, 10, 10);
                let sp = pt(5 + xoff, 5 + yoff);
                // Golden: draw from an unrelated copy of the image.
                let mut golden = base.clone();
                draw::draw(&mut golden, r, &base.clone(), sp, op);

                let mut fast = base.clone();
                draw::draw_within(&mut fast, r, sp, op);
                assert_eq!(fast, golden, "op {op:?} offset ({xoff},{yoff})");

                let mut generic = Opaque(Rgba64::new(base.rect));
                draw::draw(&mut generic, base.rect, &base, base.rect.min, Op::Src);
                let mut golden64 = generic.clone();
                let snapshot = generic.0.clone();
                draw::draw(&mut golden64, r, &snapshot, sp, op);
                draw::draw_within(&mut generic, r, sp, op);
                assert_eq!(
                    generic.0, golden64.0,
                    "generic op {op:?} offset ({xoff},{yoff})"
                );
            }
        }
    }
}

#[test]
fn non_zero_source_point() {
    let mut a = Rgba::new(rect(0, 0, 1, 1));
    let mut b = Rgba::new(rect(0, 0, 2, 2));
    b.set_pixel(0, 0, rgba(0, 0, 0, 5));
    b.set_pixel(1, 0, rgba(0, 0, 5, 5));
    b.set_pixel(0, 1, rgba(0, 5, 0, 5));
    b.set_pixel(1, 1, rgba(5, 0, 0, 5));
    draw::draw(&mut a, rect(0, 0, 1, 1), &b, pt(1, 1), Op::Over);
    assert_eq!(a.pixel_at(0, 0), rgba(5, 0, 0, 5));
}

#[test]
fn uniform_fills_pixels_rows_columns_and_wholes() {
    let rects = [
        rect(0, 0, 0, 0),
        rect(0, 0, 40, 30),
        rect(10, 20, 15, 25),
        rect(0, 15, 40, 16),
        rect(20, 20, 29, 29),
    ];
    for r in rects {
        let mut m = Rgba::new(r);
        let b = m.rect;
        let check = |m: &Rgba, c: color::Rgba| {
            for y in b.min.y..b.max.y {
                for x in b.min.x..b.max.x {
                    assert_eq!(m.pixel_at(x, y), c, "{r} at ({x},{y})");
                }
            }
        };
        let c = rgba(11, 0, 0, 255);
        for y in b.min.y..b.max.y {
            for x in b.min.x..b.max.x {
                draw::draw(
                    &mut m,
                    rect(x, y, x + 1, y + 1),
                    &Uniform::new(c.into()),
                    Point::default(),
                    Op::Src,
                );
            }
        }
        check(&m, c);
        let c = rgba(0, 22, 0, 255);
        for y in b.min.y..b.max.y {
            draw::draw(
                &mut m,
                rect(b.min.x, y, b.max.x, y + 1),
                &Uniform::new(c.into()),
                Point::default(),
                Op::Src,
            );
        }
        check(&m, c);
        let c = rgba(44, 55, 66, 77);
        draw::draw(
            &mut m,
            b,
            &Uniform::new(c.into()),
            Point::default(),
            Op::Src,
        );
        check(&m, c);
    }
}

#[test]
fn src_between_non_premultiplied_images_is_lossless() {
    let opaque_gray = color::Nrgba {
        r: 0x99,
        g: 0x99,
        b: 0x99,
        a: 0xff,
    };
    let blue = color::Nrgba {
        r: 0,
        g: 0,
        b: 0xff,
        a: 0,
    };
    let green = color::Nrgba {
        r: 0,
        g: 0xff,
        b: 0,
        a: 0,
    };
    let red = color::Nrgba {
        r: 0xff,
        g: 0,
        b: 0,
        a: 0,
    };
    let mut dst = Nrgba::new(rect(0, 10, 3, 11));
    dst.set_pixel(0, 10, opaque_gray);
    let mut src = Nrgba::new(rect(1, 20, 4, 21));
    src.set_pixel(1, 20, blue);
    src.set_pixel(2, 20, green);
    src.set_pixel(3, 20, red);
    draw::draw(&mut dst, rect(1, 10, 3, 11), &src, pt(1, 20), Op::Src);
    assert_eq!(dst.pixel_at(0, 10), opaque_gray);
    assert_eq!(dst.pixel_at(1, 10), blue);
    assert_eq!(dst.pixel_at(2, 10), green);

    let purple = color::Nrgba64 {
        r: 0xfedc,
        g: 0,
        b: 0x7654,
        a: 0,
    };
    let mut dst = Nrgba64::new(rect(0, 0, 1, 1));
    let mut src = Nrgba64::new(rect(0, 0, 1, 1));
    src.set_pixel(0, 0, purple);
    draw::draw(&mut dst, rect(0, 0, 1, 1), &src, pt(0, 0), Op::Src);
    assert_eq!(dst.pixel_at(0, 0), purple);

    // Through Go's generic SetRGBA64 path the color channels of an
    // alpha-zero premultiplied value survive, unlike the model conversion.
    let mut n = Nrgba::new(rect(0, 0, 1, 1));
    n.set_rgba64(
        0,
        0,
        color::Rgba64 {
            r: 0x1234,
            g: 0,
            b: 0xff00,
            a: 0,
        },
    );
    assert_eq!(
        n.pixel_at(0, 0),
        color::Nrgba {
            r: 0x12,
            g: 0,
            b: 0xff,
            a: 0
        }
    );
    n.set(
        0,
        0,
        color::Rgba64 {
            r: 0x1234,
            g: 0,
            b: 0xff00,
            a: 0,
        }
        .into(),
    );
    assert_eq!(n.pixel_at(0, 0), color::Nrgba::default());
}

#[test]
fn floyd_steinberg_dithers_mid_gray_to_a_checkerboard() {
    let b = rect(0, 0, 640, 480);
    let src = Uniform::new(color::Gray16 { y: 0x7fff }.into());
    let mut dst = Paletted::new(b, Palette(vec![color::BLACK.into(), color::WHITE.into()]));
    FloydSteinberg.draw(&mut dst, b, &src, Point::default());
    for y in b.min.y..b.max.y {
        for x in b.min.x..b.max.x {
            assert_eq!(dst.color_index_at(x, y), ((x + y) % 2) as u8, "({x},{y})");
        }
    }
}

#[test]
fn paletted_fast_path_matches_the_generic_path() {
    let b = rect(0, 0, 37, 23);
    let cga = Palette(vec![
        rgba(0, 0, 0, 0xff).into(),
        rgba(0x55, 0xff, 0xff, 0xff).into(),
        rgba(0xff, 0x55, 0xff, 0xff).into(),
        rgba(0xff, 0xff, 0xff, 0xff).into(),
    ]);
    let uniform = Uniform::new(rgba(0xff, 0x7f, 0xff, 0xff).into());
    let picture = gradient(b);
    let sources: [&dyn Image; 2] = [&uniform, &picture];
    let drawers: [&dyn Drawer; 2] = [&Op::Src, &FloydSteinberg];
    for d in drawers {
        for src in sources {
            let mut fast = Paletted::new(b, cga.clone());
            let mut generic = Opaque(Paletted::new(b, cga.clone()));
            d.draw(&mut fast, b, src, Point::default());
            d.draw(&mut generic, b, src, Point::default());
            assert_eq!(fast.pix, generic.0.pix);
        }
    }
}

#[test]
fn clipping_limits_the_drawn_region() {
    // dst (0,0)-(4,4), src (2,2)-(5,5), mask (0,0)-(3,10): only the
    // intersection after alignment changes.
    let mut dst = Gray::new(rect(0, 0, 4, 4));
    let mut src = Gray::new(rect(2, 2, 5, 5));
    src.pix.fill(200);
    let mut mask = Alpha::new(rect(0, 0, 3, 10));
    mask.pix.fill(0xff);
    draw::draw_mask(
        &mut dst,
        rect(-5, -5, 10, 10),
        &src,
        pt(-3, -3),
        Some(&mask),
        pt(-4, -4),
        Op::Src,
    );
    // Aligned: dst p <-> src p + (2,2) <-> mask p + (1,1).
    for y in 0..4 {
        for x in 0..4 {
            let inside = (0..=2).contains(&x) && (0..=2).contains(&y) && x + 1 < 3;
            let want = if inside { 200 } else { 0 };
            assert_eq!(dst.pixel_at(x, y).y, want, "({x},{y})");
        }
    }
    // Empty and inverted rectangles draw nothing.
    let before = dst.clone();
    draw::draw(&mut dst, rect(10, 10, 20, 20), &src, pt(0, 0), Op::Src);
    draw::draw(
        &mut dst,
        Rectangle {
            min: pt(3, 3),
            max: pt(1, 1),
        },
        &src,
        pt(0, 0),
        Op::Src,
    );
    assert_eq!(dst, before);
}

#[test]
fn masks_and_operators_use_go_arithmetic() {
    // Uniform opaque red over transparent black through a 0x80 glyph mask.
    let mut dst = Rgba::new(rect(0, 0, 1, 1));
    let mut mask = Alpha::new(rect(0, 0, 1, 1));
    mask.pix.set(0, 0x80);
    let red = Uniform::new(rgba(0xff, 0, 0, 0xff).into());
    draw::draw_mask(
        &mut dst,
        rect(0, 0, 1, 1),
        &red,
        Point::default(),
        Some(&mask),
        Point::default(),
        Op::Over,
    );
    assert_eq!(dst.pixel_at(0, 0), rgba(0x80, 0, 0, 0x80));

    // Src with a zero mask clears; Over with a zero mask leaves the pixel.
    let mut g = Rgba64::new(rect(0, 0, 1, 1));
    g.set_pixel(
        0,
        0,
        color::Rgba64 {
            r: 1,
            g: 2,
            b: 3,
            a: 4,
        },
    );
    let zero = Uniform::new(color::TRANSPARENT.into());
    draw::draw_mask(
        &mut g,
        rect(0, 0, 1, 1),
        &red,
        Point::default(),
        Some(&zero),
        Point::default(),
        Op::Over,
    );
    assert_eq!(
        g.pixel_at(0, 0),
        color::Rgba64 {
            r: 1,
            g: 2,
            b: 3,
            a: 4
        }
    );
    draw::draw_mask(
        &mut g,
        rect(0, 0, 1, 1),
        &red,
        Point::default(),
        Some(&zero),
        Point::default(),
        Op::Src,
    );
    assert_eq!(g.pixel_at(0, 0), color::Rgba64::default());

    // Drawing into an AnyImage reaches the same concrete-type code.
    let mut any = AnyImage::Rgba(Rgba::new(rect(0, 0, 1, 1)));
    draw::draw_mask(
        &mut any,
        rect(0, 0, 1, 1),
        &red,
        Point::default(),
        Some(&mask),
        Point::default(),
        Op::Over,
    );
    assert_eq!(any.at(0, 0), rgba(0x80, 0, 0, 0x80).into());
}

#[test]
fn uniform_is_an_infinite_image() {
    let u = Uniform::new(color::Gray { y: 7 }.into());
    assert_eq!(
        u.bounds(),
        rect(-1_000_000_000, -1_000_000_000, 1_000_000_000, 1_000_000_000)
    );
    assert_eq!(u.at(-999, 12345), color::Gray { y: 7 }.into());
    assert!(u.opaque());
    assert!(!Uniform::new(color::Alpha { a: 3 }.into()).opaque());
    // Go's Uniform is its own color model.
    assert_eq!(u.color_model(), Model::Uniform(color::Gray { y: 7 }.into()));
}
