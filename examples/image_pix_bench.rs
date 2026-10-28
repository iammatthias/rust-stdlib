//! Times `Paletted::set_color_index` and `color_index_at` over a 1000x1000
//! image: `cargo run --release --example image_pix_bench`.
use rust_stdlib::image::color::Palette;
use rust_stdlib::image::{rect, Paletted};
use std::time::Instant;

fn main() {
    let mut m = Paletted::new(rect(0, 0, 1000, 1000), Palette::default());
    let start = Instant::now();
    for y in 0..1000 {
        for x in 0..1000 {
            m.set_color_index(x, y, (x ^ y) as u8);
        }
    }
    let set = start.elapsed();
    let start = Instant::now();
    let mut sum = 0u64;
    for y in 0..1000 {
        for x in 0..1000 {
            sum += u64::from(m.color_index_at(x, y));
        }
    }
    let get = start.elapsed();
    // After `sub_image` the buffer is shared and every access takes a lock.
    let _sub = m.sub_image(rect(0, 0, 1000, 1000));
    let start = Instant::now();
    for y in 0..1000 {
        for x in 0..1000 {
            m.set_color_index(x, y, (x ^ y) as u8);
        }
    }
    let shared = start.elapsed();
    println!("set_color_index 1000x1000: {set:?}");
    println!("set_color_index, shared:   {shared:?}");
    println!("color_index_at  1000x1000: {get:?} (sum {sum})");
}
