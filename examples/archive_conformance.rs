//! File-based compression/archive interoperability driver.
use rust_stdlib::{
    archive::{tar, zip},
    compress,
};
use std::{
    fs,
    io::{self, Write},
};
/// Compress `input` at flate `level` as a raw DEFLATE, zlib or gzip stream.
fn compress_with(format: &str, level: i32, input: &[u8], output: &mut Vec<u8>) -> io::Result<()> {
    match format {
        "deflate" => {
            let mut w = compress::flate::Writer::new(output, level)?;
            w.write_all(input)?;
            w.close()
        }
        "zlib" => {
            let mut w = compress::zlib::Writer::with_level(output, level)?;
            w.write_all(input)?;
            w.close()
        }
        _ => {
            let mut w = compress::gzip::Writer::with_level(output, level)?;
            w.write_all(input)?;
            w.close()
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        return Err(
            "usage: archive_conformance encode|decode deflate|zlib|gzip|tar|zip input output"
                .into(),
        );
    }
    let input = fs::read(&args[3])?;
    let mut output = Vec::new();
    match (args[1].as_str(), args[2].as_str()) {
        ("encode-stream", "deflate" | "zlib" | "gzip") => {
            compress_with(&args[2], 0, &input, &mut output)?
        }
        ("encode-stream", "tar") => tar::write_stream(
            &[tar::Entry {
                path: "file.bin".into(),
                mode: 0o644,
                uid: 0,
                gid: 0,
                modified: 0,
                kind: tar::Kind::File,
                link: String::new(),
                data: input,
            }],
            &mut output,
            tar::Limits::default(),
        )?,

        ("encode", "deflate" | "zlib" | "gzip") => {
            compress_with(&args[2], -1, &input, &mut output)?
        }
        ("decode", "deflate") => {
            compress::decode_deflate(&input[..], &mut output, compress::Limits::default())?
        }
        ("decode", "zlib") => {
            compress::decode_zlib(&input[..], &mut output, compress::Limits::default())?
        }
        ("decode", "gzip") => {
            compress::decode_gzip(&input[..], &mut output, compress::Limits::default())?
        }
        ("encode", "zip") => zip::write(
            &[zip::Entry {
                name: "file.bin".into(),
                data: input,
                directory: false,
            }],
            &mut output,
            zip::Limits::default(),
        )?,
        ("decode", "zip") => {
            let entries = zip::read(&input[..], zip::Limits::default())?;
            if entries.len() != 1 || entries[0].name != "file.bin" {
                return Err("unexpected ZIP corpus shape".into());
            }
            output = entries[0].data.clone();
        }
        ("encode", "tar") => tar::write(
            &[tar::Entry {
                path: "file.bin".into(),
                mode: 0o644,
                uid: 0,
                gid: 0,
                modified: 0,
                kind: tar::Kind::File,
                link: String::new(),
                data: input,
            }],
            &mut output,
            tar::Limits::default(),
        )?,
        ("decode", "tar") => {
            let entries = tar::read(&input[..], tar::Limits::default())?;
            if entries.len() != 1 || entries[0].path != "file.bin" {
                return Err("unexpected tar corpus shape".into());
            }
            output = entries[0].data.clone();
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported operation or format",
            )
            .into())
        }
    }
    fs::write(&args[4], output)?;
    Ok(())
}
