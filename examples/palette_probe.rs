//! Prints the standard palettes in the line format of `tools/palette_oracle.go`
//! for the `tools/palette_check.py` differential.
use rust_stdlib::image::color::{palette, Rgba};

fn line(table: &str, index: usize, c: &Rgba) -> String {
    format!(
        "{table} {index} {:02x}{:02x}{:02x}{:02x}",
        c.r, c.g, c.b, c.a
    )
}

fn main() {
    for (i, c) in palette::PLAN9.iter().enumerate() {
        println!("{}", line("plan9", i, c));
    }
    for (i, c) in palette::WEB_SAFE.iter().enumerate() {
        println!("{}", line("websafe", i, c));
    }
}
