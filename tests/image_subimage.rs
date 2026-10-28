//! SubImage shares pixels with its parent, as Go's `Pix[i:]` slices do.
use rust_stdlib::image::color::{self, Palette};
use rust_stdlib::image::{
    rect, Alpha, Alpha16, Cmyk, Gray, Gray16, Image, Nrgba, Nrgba64, Nycbcra, Paletted, Rgba,
    Rgba64, Ycbcr, YcbcrSubsampleRatio,
};

macro_rules! shares {
    ($name:ident, $t:ident, $c:expr) => {
        #[test]
        fn $name() {
            let mut parent = $t::new(rect(0, 0, 4, 4));
            let mut sub = parent.sub_image(rect(1, 1, 3, 3));
            assert_eq!(sub.rect, rect(1, 1, 3, 3));
            assert_eq!(sub.stride, parent.stride);
            // A write through the parent is visible in the child...
            parent.set(2, 2, $c);
            assert_eq!(sub.at(2, 2), parent.at(2, 2));
            assert_ne!(sub.at(2, 2), $t::new(rect(0, 0, 1, 1)).at(0, 0));
            // ...and the reverse.
            sub.set(1, 1, $c);
            assert_eq!(parent.at(1, 1), sub.at(1, 1));
            assert_ne!(parent.at(1, 1), $t::new(rect(0, 0, 1, 1)).at(0, 0));
            // Points outside the child's bounds read as zero.
            assert_eq!(sub.at(0, 0), $t::new(rect(0, 0, 1, 1)).at(0, 0));
            // Cloning copies.
            let mut copy = parent.clone();
            copy.set(0, 0, $c);
            assert_ne!(parent.at(0, 0), copy.at(0, 0));
        }
    };
}

shares!(
    rgba,
    Rgba,
    color::Rgba {
        r: 9,
        g: 8,
        b: 7,
        a: 255
    }
    .into()
);
shares!(
    rgba64,
    Rgba64,
    color::Rgba64 {
        r: 9,
        g: 8,
        b: 7,
        a: 0xffff
    }
    .into()
);
shares!(
    nrgba,
    Nrgba,
    color::Nrgba {
        r: 9,
        g: 8,
        b: 7,
        a: 255
    }
    .into()
);
shares!(
    nrgba64,
    Nrgba64,
    color::Nrgba64 {
        r: 9,
        g: 8,
        b: 7,
        a: 0xffff
    }
    .into()
);
shares!(gray, Gray, color::Gray { y: 77 }.into());
shares!(gray16, Gray16, color::Gray16 { y: 7777 }.into());
shares!(alpha, Alpha, color::Alpha { a: 77 }.into());
shares!(alpha16, Alpha16, color::Alpha16 { a: 7777 }.into());
shares!(
    cmyk,
    Cmyk,
    color::Cmyk {
        c: 1,
        m: 2,
        y: 3,
        k: 4
    }
    .into()
);

#[test]
fn paletted_shares_indexes() {
    let pal = Palette(vec![color::BLACK.into(), color::WHITE.into()]);
    let mut parent = Paletted::new(rect(0, 0, 4, 4), pal);
    let mut sub = parent.sub_image(rect(2, 2, 4, 4));
    parent.set_color_index(3, 3, 1);
    assert_eq!(sub.color_index_at(3, 3), 1);
    sub.set_color_index(2, 2, 1);
    assert_eq!(parent.color_index_at(2, 2), 1);
}

#[test]
fn ycbcr_planes_are_shared() {
    let mut parent = Ycbcr::new(rect(0, 0, 4, 4), YcbcrSubsampleRatio::Ratio420);
    let mut sub = parent.sub_image(rect(2, 2, 4, 4));
    let ci = parent.c_offset(3, 3);
    let yi = parent.y_offset(3, 3);
    parent.y.set(yi, 11);
    parent.cb.set(ci, 22);
    parent.cr.set(ci, 33);
    let c = sub.ycbcr_at(3, 3);
    assert_eq!((c.y, c.cb, c.cr), (11, 22, 33));
    sub.y.set(sub.y_offset(2, 2), 99);
    assert_eq!(parent.ycbcr_at(2, 2).y, 99);

    let mut parent = Nycbcra::new(rect(0, 0, 4, 4), YcbcrSubsampleRatio::Ratio444);
    let sub = parent.sub_image(rect(1, 1, 3, 3));
    parent.a.set(parent.a_offset(2, 2), 200);
    assert_eq!(sub.nycbcra_at(2, 2).a, 200);
}

#[test]
fn draw_onto_a_region_of_its_own_source_does_not_deadlock() {
    use rust_stdlib::image::draw::{self, Op};
    let mut m = Rgba::new(rect(0, 0, 4, 4));
    m.set(
        0,
        0,
        color::Rgba {
            r: 1,
            g: 2,
            b: 3,
            a: 255,
        }
        .into(),
    );
    let src = m.sub_image(rect(0, 0, 2, 2));
    draw::draw(
        &mut m,
        rect(2, 2, 4, 4),
        &src,
        rust_stdlib::image::pt(0, 0),
        Op::Src,
    );
    assert_eq!(m.at(2, 2), m.at(0, 0));
}

#[test]
#[should_panic]
fn paletted_at_panics_on_an_index_outside_the_palette() {
    let mut p = Paletted::new(rect(0, 0, 1, 1), Palette(vec![color::BLACK.into()]));
    p.set_color_index(0, 0, 5);
    let _ = p.at(0, 0);
}
