//! Values taken from Go's image/color (go1.27) for the YCbCr and CMYK
//! conversions and models; the exhaustive comparison lives in tools/color_check.py.
use rust_stdlib::image::color::{
    self, Alpha, Cmyk, Color, Gray16, Model, Nrgba, Nycbcra, Rgba64, Ycbcr,
};

#[test]
fn ycbcr_and_cmyk_conversions_match_go() {
    assert_eq!(color::rgb_to_ycbcr(255, 0, 0), (76, 85, 255));
    assert_eq!(color::rgb_to_ycbcr(12, 200, 99), (132, 109, 42));
    assert_eq!(color::ycbcr_to_rgb(76, 85, 255), (254, 0, 0));
    assert_eq!(
        Ycbcr {
            y: 76,
            cb: 85,
            cr: 255
        }
        .rgba(),
        (65113, 102, 26, 65535)
    );
    assert_eq!(color::rgb_to_cmyk(10, 200, 30), (242, 0, 216, 55));
    assert_eq!(color::rgb_to_cmyk(0, 0, 0), (0, 0, 0, 0xff));
    assert_eq!(color::cmyk_to_rgb(10, 20, 30, 40), (207, 198, 190));
    assert_eq!(
        Cmyk {
            c: 0,
            m: 0,
            y: 0,
            k: 0
        }
        .rgba(),
        (0xffff, 0xffff, 0xffff, 0xffff)
    );
}

#[test]
fn ycbcr_and_cmyk_models_match_go() {
    assert_eq!(
        Model::Ycbcr.convert(Gray16 { y: 0x8000 }.into()),
        Ycbcr {
            y: 128,
            cb: 128,
            cr: 128
        }
        .into()
    );
    assert_eq!(
        Model::Nycbcra.convert(
            Nrgba {
                r: 10,
                g: 200,
                b: 30,
                a: 128
            }
            .into()
        ),
        Nycbcra {
            ycbcr: Ycbcr {
                y: 124,
                cb: 75,
                cr: 47
            },
            a: 128
        }
        .into()
    );
    assert_eq!(
        Model::Cmyk.convert(
            Rgba64 {
                r: 0x1000,
                g: 0x8000,
                b: 0xf000,
                a: 0xffff
            }
            .into()
        ),
        Cmyk {
            c: 238,
            m: 119,
            y: 0,
            k: 15
        }
        .into()
    );
    assert_eq!(
        Model::Cmyk.convert(Gray16 { y: 0 }.into()),
        Cmyk {
            c: 0,
            m: 0,
            y: 0,
            k: 255
        }
        .into()
    );
    assert_eq!(
        Model::Nycbcra.convert(Ycbcr { y: 1, cb: 2, cr: 3 }.into()),
        Nycbcra {
            ycbcr: Ycbcr { y: 1, cb: 2, cr: 3 },
            a: 255
        }
        .into()
    );
    assert_eq!(
        Model::Ycbcr.convert(
            Nycbcra {
                ycbcr: Ycbcr { y: 1, cb: 2, cr: 3 },
                a: 9
            }
            .into()
        ),
        Ycbcr {
            y: 2,
            cb: 127,
            cr: 126
        }
        .into()
    );
}

#[test]
fn model_func_converts_with_its_closure_and_compares_by_identity() {
    let offset = 7u8;
    let shifted = color::model_func(move |_| {
        Color::Gray16(Gray16 {
            y: u16::from(offset),
        })
    });
    assert_eq!(
        shifted.convert(Alpha { a: 1 }.into()),
        Color::Gray16(Gray16 { y: 7 })
    );
    let same = shifted.clone();
    assert_eq!(shifted, same);
    assert_ne!(shifted, color::model_func(|c| c));
}
