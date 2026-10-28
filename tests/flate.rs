//! Tests for `compress::{flate, gzip, zlib}`, ported from Go's `*_test.go`
//! tables (fixtures extracted by `tools/gen_flate_fixtures.py`) plus round-trip,
//! flush, reset, dictionary and error-text tests. Go differential coverage is in
//! `tools/flate_check.py`.
use rust_stdlib::compress::flate::{
    self, CorruptInputError, InternalError, ReadError, Resetter, WriteError,
};
use rust_stdlib::compress::{gzip, zlib};
use std::io::{self, Read, Write};

fn unhex(text: &str) -> Vec<u8> {
    if text == "-" {
        return Vec::new();
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn read_all(r: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0u8; 40];
    loop {
        match r.read(&mut buf)? {
            0 => return Ok(out),
            n => out.extend_from_slice(&buf[..n]),
        }
    }
}

/// Bytes delivered even when the stream ends in an error.
fn read_partial(r: &mut impl Read) -> (Vec<u8>, Option<io::Error>) {
    let mut out = Vec::new();
    let mut buf = [0u8; 7];
    loop {
        match r.read(&mut buf) {
            Ok(0) => return (out, None),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) => return (out, Some(e)),
        }
    }
}

fn text(n: usize) -> Vec<u8> {
    let words: [&str; 9] = [
        "the", "quick", "brown", "fox", "jumps", "over", "lazy", "dog", "and",
    ];
    let mut state = 12345u32;
    let mut out = Vec::new();
    while out.len() < n {
        state = state.wrapping_mul(1664525).wrapping_add(1013904223);
        out.extend_from_slice(words[(state >> 24) as usize % words.len()].as_bytes());
        out.push(if state & 0x100 != 0 { b' ' } else { b'\n' });
    }
    out.truncate(n);
    out
}

fn noise(n: usize, seed: u32) -> Vec<u8> {
    let mut state = seed;
    (0..n)
        .map(|_| {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            (state >> 24) as u8
        })
        .collect()
}

fn downcast<T: std::error::Error + 'static>(e: &io::Error) -> Option<&T> {
    e.get_ref().and_then(|inner| inner.downcast_ref::<T>())
}

fn assert_unexpected_eof(e: &io::Error) {
    assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(e.to_string(), "unexpected EOF");
}

#[test]
fn constants_and_error_texts_match_go() {
    assert_eq!(flate::NO_COMPRESSION, 0);
    assert_eq!(flate::BEST_SPEED, 1);
    assert_eq!(flate::BEST_COMPRESSION, 9);
    assert_eq!(flate::DEFAULT_COMPRESSION, -1);
    assert_eq!(flate::HUFFMAN_ONLY, -2);
    assert_eq!(gzip::HUFFMAN_ONLY, -2);
    assert_eq!(zlib::BEST_SPEED, 1);
    assert_eq!(
        CorruptInputError(17).to_string(),
        "flate: corrupt input before offset 17"
    );
    assert_eq!(
        InternalError("boom".into()).to_string(),
        "flate: internal error: boom"
    );
    let read = ReadError {
        offset: 3,
        err: io::Error::other("bad read"),
    };
    assert_eq!(read.to_string(), "flate: read error at offset 3: bad read");
    let write = WriteError {
        offset: 9,
        err: io::Error::other("bad write"),
    };
    assert_eq!(
        write.to_string(),
        "flate: write error at offset 9: bad write"
    );
    assert_eq!(gzip::ERR_CHECKSUM.to_string(), "gzip: invalid checksum");
    assert_eq!(gzip::ERR_HEADER.to_string(), "gzip: invalid header");
    assert_eq!(zlib::ERR_CHECKSUM.to_string(), "zlib: invalid checksum");
    assert_eq!(zlib::ERR_DICTIONARY.to_string(), "zlib: invalid dictionary");
    assert_eq!(zlib::ERR_HEADER.to_string(), "zlib: invalid header");
    for bad in [-3, 10, 42] {
        assert_eq!(
            flate::Writer::new(Vec::new(), bad)
                .err()
                .unwrap()
                .to_string(),
            format!("flate: invalid compression level {bad}: want value in range [-2, 9]")
        );
        assert_eq!(
            gzip::Writer::with_level(Vec::new(), bad)
                .err()
                .unwrap()
                .to_string(),
            format!("gzip: invalid compression level: {bad}")
        );
        assert_eq!(
            zlib::Writer::with_level(Vec::new(), bad)
                .err()
                .unwrap()
                .to_string(),
            format!("zlib: invalid compression level: {bad}")
        );
    }
}

/// Go's `TestStreams`: valid and invalid DEFLATE streams from the C zlib corpus.
#[test]
fn go_flate_streams_table() {
    let table = include_str!("fixtures/compress/flate_streams.tsv");
    let mut count = 0;
    for line in table.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        let (desc, stream, want) = (f[0], unhex(f[1]), f[2]);
        let mut r = flate::Decompressor::from_buf_read(&stream[..]);
        let result = read_all(&mut r);
        if want == "fail" {
            assert!(result.is_err(), "{desc}: got Ok, want error");
        } else {
            assert_eq!(result.unwrap(), unhex(want), "{desc}");
        }
        count += 1;
    }
    assert_eq!(count, 28);
}

#[test]
fn go_truncated_flate_streams() {
    let data = b"\x00\x0c\x00\xf3\xffhello, world\x01\x00\x00\xff\xff";
    for i in 0..data.len() - 1 {
        let mut r = flate::Decompressor::new(&data[..i]);
        let err = read_all(&mut r).unwrap_err();
        assert_unexpected_eof(&err);
    }
    assert_eq!(
        read_all(&mut flate::Decompressor::new(&data[..])).unwrap(),
        b"hello, world"
    );
}

/// Go's `TestNlitOutOfRange`: a table with nlit=288 must not panic.
#[test]
fn nlit_out_of_range_is_corrupt_input() {
    let data = b"\xfc\xfe\x36\xe7\x5e\x1c\xef\xb3\x55\x58\x77\xb6\x56\xb5\x43\xf4\
\x6f\xf2\xd2\xe6\x3d\x99\xa0\x85\x8c\x48\xeb\xf8\xda\x83\x04\x2a\
\x75\xc4\xf8\x0f\x12\x11\xb9\xb4\x4b\x09\xa0\xbe\x8b\x91\x4c";
    let err = read_all(&mut flate::Decompressor::new(&data[..])).unwrap_err();
    assert!(downcast::<CorruptInputError>(&err).is_some(), "{err}");
}

#[test]
fn corrupt_input_error_carries_go_offsets() {
    // Reserved block type 3 after three header bits: one byte consumed.
    let err = read_all(&mut flate::Decompressor::new(&[0x07u8][..])).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert_eq!(err.to_string(), "flate: corrupt input before offset 1");
    assert_eq!(
        downcast::<CorruptInputError>(&err),
        Some(&CorruptInputError(1))
    );
    // Stored block whose length complement is wrong.
    let err = read_all(&mut flate::Decompressor::new(&[0x01u8, 1, 0, 0, 0][..])).unwrap_err();
    assert_eq!(err.to_string(), "flate: corrupt input before offset 5");
    // Errors are sticky and keep their type.
    let mut r = flate::Decompressor::new(&[0x07u8][..]);
    let first = read_all(&mut r).unwrap_err();
    let second = read_all(&mut r).unwrap_err();
    assert_eq!(first.to_string(), second.to_string());
    assert!(downcast::<CorruptInputError>(&second).is_some());
    assert!(r.close().is_err());
}

#[test]
fn bytes_before_an_error_are_delivered() {
    // "hello" in a stored block, then a bad block type.
    let mut stream = b"\x00\x05\x00\xfa\xffhello".to_vec();
    stream.push(0x07);
    let (out, err) = read_partial(&mut flate::Decompressor::new(&stream[..]));
    assert_eq!(out, b"hello");
    assert_eq!(
        err.unwrap().to_string(),
        "flate: corrupt input before offset 11"
    );
}

#[test]
fn trailing_data_after_final_block_is_left_unread() {
    let mut stream = Vec::new();
    {
        let mut w = flate::Writer::new(&mut stream, 6).unwrap();
        w.write_all(b"payload payload payload").unwrap();
        w.close().unwrap();
    }
    stream.extend_from_slice(b"TAIL");
    let mut src = &stream[..];
    let mut r = flate::Decompressor::from_buf_read(&mut src);
    assert_eq!(read_all(&mut r).unwrap(), b"payload payload payload");
    drop(r);
    assert_eq!(src, b"TAIL");
}

#[test]
fn gunzip_table_from_go() {
    let table = include_str!("fixtures/compress/gunzip_tests.tsv");
    let mut count = 0;
    for line in table.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        let (name, desc, raw, data, want_err) = (unhex(f[0]), f[1], unhex(f[2]), unhex(f[3]), f[4]);
        let mut r =
            gzip::Reader::from_buf_read(&data[..]).unwrap_or_else(|e| panic!("{desc}: {e}"));
        assert_eq!(r.header.name.as_bytes(), &name[..], "{desc}");
        let (out, err) = read_partial(&mut r);
        match want_err {
            "nil" => {
                assert!(err.is_none(), "{desc}: {err:?}");
                assert_eq!(out, raw, "{desc}");
            }
            "ErrHeader" => assert_eq!(
                downcast::<gzip::Error>(&err.expect(desc)),
                Some(&gzip::ERR_HEADER),
                "{desc}"
            ),
            "ErrChecksum" => assert_eq!(
                downcast::<gzip::Error>(&err.expect(desc)),
                Some(&gzip::ERR_CHECKSUM),
                "{desc}"
            ),
            "io.ErrUnexpectedEOF" => assert_unexpected_eof(&err.expect(desc)),
            other => panic!("unknown expectation {other}"),
        }
        // Errors and EOF are sticky.
        let mut one = [0u8; 1];
        match want_err {
            "nil" => assert_eq!(r.read(&mut one).unwrap(), 0, "{desc}"),
            _ => assert!(r.read(&mut one).is_err(), "{desc}"),
        }
        count += 1;
    }
    assert_eq!(count, 15);
}

#[test]
fn gunzip_header_fields_from_go_vectors() {
    let table = include_str!("fixtures/compress/gunzip_tests.tsv");
    let line = table
        .lines()
        .find(|l| l.contains("header with all fields used"))
        .unwrap();
    let f: Vec<&str> = line.split('\t').collect();
    let data = unhex(f[3]);
    let r = gzip::Reader::from_buf_read(&data[..]).unwrap();
    assert_eq!(r.header.name, "f1l3n4m3.tXt");
    // The comment holds the bytes 1..=255, decoded as Latin-1.
    assert_eq!(
        r.header.comment,
        (1u8..=255).map(char::from).collect::<String>()
    );
    assert_eq!(r.header.os, 170);
}

#[test]
fn gzip_multistream_and_reset() {
    let member = |payload: &[u8]| {
        let mut z = gzip::Writer::new(Vec::new());
        z.write_all(payload).unwrap();
        z.close().unwrap();
        z.into_inner()
    };
    let one = member(b"first member\n");
    let two = member(b"second member\n");
    let both = [one.clone(), two.clone()].concat();

    let mut r = gzip::Reader::from_buf_read(&both[..]).unwrap();
    assert_eq!(read_all(&mut r).unwrap(), b"first member\nsecond member\n");

    // Multistream(false): one member at a time, source left at the next header.
    let mut src = &both[..];
    let mut r = gzip::Reader::from_buf_read(&mut src).unwrap();
    r.multistream(false);
    assert_eq!(read_all(&mut r).unwrap(), b"first member\n");
    drop(r);
    assert_eq!(src, &two[..]);
    let mut r = gzip::Reader::from_buf_read(&both[..]).unwrap();
    r.multistream(false);
    assert_eq!(read_all(&mut r).unwrap(), b"first member\n");
    r.reset(&two[..]).unwrap();
    assert_eq!(read_all(&mut r).unwrap(), b"second member\n");

    // An empty stream is Go's EOF at construction; garbage after a member is a header error.
    let err = gzip::Reader::new(&b""[..]).err().unwrap();
    assert_eq!(err.to_string(), "EOF");
    let junk = [one.clone(), b"junk, not a gzip header".to_vec()].concat();
    let (out, err) = read_partial(&mut gzip::Reader::new(&junk[..]).unwrap());
    assert_eq!(out, b"first member\n");
    assert_eq!(
        downcast::<gzip::Error>(&err.unwrap()),
        Some(&gzip::ERR_HEADER)
    );
    let cut = [one.clone(), one[..5].to_vec()].concat();
    let (_, err) = read_partial(&mut gzip::Reader::new(&cut[..]).unwrap());
    assert_unexpected_eof(&err.unwrap());
}

#[test]
fn zlib_table_from_go() {
    let table = include_str!("fixtures/compress/zlib_tests.tsv");
    let mut count = 0;
    for line in table.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        let (desc, raw, data, dict, want_err) = (f[0], unhex(f[1]), unhex(f[2]), unhex(f[3]), f[4]);
        let reader = zlib::Reader::from_buf_read_with_dictionary(&data[..], &dict);
        let check = |err: &io::Error| match want_err {
            "ErrHeader" => assert_eq!(
                downcast::<zlib::Error>(err),
                Some(&zlib::ERR_HEADER),
                "{desc}"
            ),
            "ErrChecksum" => assert_eq!(
                downcast::<zlib::Error>(err),
                Some(&zlib::ERR_CHECKSUM),
                "{desc}"
            ),
            "ErrDictionary" => assert_eq!(
                downcast::<zlib::Error>(err),
                Some(&zlib::ERR_DICTIONARY),
                "{desc}"
            ),
            "io.ErrUnexpectedEOF" => assert_unexpected_eof(err),
            other => panic!("{desc}: unexpected error {other}: {err}"),
        };
        let mut r = match reader {
            Ok(r) => r,
            Err(e) => {
                check(&e);
                count += 1;
                continue;
            }
        };
        match read_all(&mut r) {
            Err(e) => check(&e),
            Ok(out) => {
                assert_eq!(want_err, "nil", "{desc}");
                assert_eq!(out, raw, "{desc}");
                let mut one = [0u8; 1];
                assert_eq!(r.read(&mut one).unwrap(), 0, "{desc}");
                r.close().unwrap();
            }
        }
        count += 1;
    }
    assert_eq!(count, 14);
}

#[test]
fn every_level_round_trips_in_all_formats() {
    let inputs: Vec<Vec<u8>> = vec![
        Vec::new(),
        b"a".to_vec(),
        b"abcabcabcabcabcabcabcabc".to_vec(),
        text(100_000),
        noise(70_000, 1),
        vec![0; 200_000],
        [text(40_000), noise(3_000, 2), vec![7; 70_000], text(5_000)].concat(),
    ];
    for level in -2..=9 {
        for input in &inputs {
            let mut w = flate::Writer::new(Vec::new(), level).unwrap();
            w.write_all(input).unwrap();
            w.close().unwrap();
            let packed = w.into_inner();
            assert_eq!(
                read_all(&mut flate::Decompressor::new(&packed[..])).unwrap(),
                *input,
                "flate level {level} len {}",
                input.len()
            );
            let mut w = zlib::Writer::with_level(Vec::new(), level).unwrap();
            w.write_all(input).unwrap();
            w.close().unwrap();
            let packed = w.into_inner();
            assert_eq!(
                read_all(&mut zlib::Reader::new(&packed[..]).unwrap()).unwrap(),
                *input,
                "zlib level {level}"
            );
            let mut w = gzip::Writer::with_level(Vec::new(), level).unwrap();
            w.write_all(input).unwrap();
            w.close().unwrap();
            let packed = w.into_inner();
            assert_eq!(
                read_all(&mut gzip::Reader::new(&packed[..]).unwrap()).unwrap(),
                *input,
                "gzip level {level}"
            );
        }
    }
}

fn compressed_len(level: i32, data: &[u8]) -> usize {
    let mut w = flate::Writer::new(Vec::new(), level).unwrap();
    w.write_all(data).unwrap();
    w.close().unwrap();
    w.into_inner().len()
}

#[test]
fn levels_trade_effort_for_size() {
    let data = text(300_000);
    let sizes: Vec<usize> = (-2..=9).map(|l| compressed_len(l, &data)).collect();
    let size = |level: i32| sizes[(level + 2) as usize];
    // Stored output is the input plus five bytes per 65535 bytes plus the 2-byte final block.
    assert_eq!(size(0), data.len() + 5 * data.len().div_ceil(65535) + 2);
    assert!(size(-2) < size(0), "Huffman-only must beat stored on text");
    assert!(size(1) < size(-2), "matching must beat Huffman-only");
    assert!(size(6) < size(1));
    assert!(size(9) <= size(6));
    assert_eq!(size(-1), size(6), "the default level is 6");
    assert!(size(6) * 3 < data.len(), "text must compress well");
    // Incompressible data stays within stored-block overhead at every level:
    // five bytes per 32 KiB (Go's Huffman-only and level 7-9 blocks) and the
    // final block. Go's own output on this input is 200022 or 200037 bytes.
    let random = noise(200_000, 9);
    for level in -2..=9 {
        let bound = random.len() + 5 * random.len().div_ceil(32_768) + 5;
        assert!(compressed_len(level, &random) <= bound, "level {level}");
    }
}

#[test]
fn compression_is_deterministic_and_chunking_independent() {
    let data = text(200_000);
    for level in [1, 4, 6, 9] {
        let whole = {
            let mut w = flate::Writer::new(Vec::new(), level).unwrap();
            w.write_all(&data).unwrap();
            w.close().unwrap();
            w.into_inner()
        };
        let again = {
            let mut w = flate::Writer::new(Vec::new(), level).unwrap();
            w.write_all(&data).unwrap();
            w.close().unwrap();
            w.into_inner()
        };
        assert_eq!(whole, again);
        let mut w = flate::Writer::new(Vec::new(), level).unwrap();
        for piece in data.chunks(1237) {
            w.write_all(piece).unwrap();
        }
        w.close().unwrap();
        let pieces = w.into_inner();
        assert_eq!(
            read_all(&mut flate::Decompressor::new(&pieces[..])).unwrap(),
            data
        );
    }
}

#[test]
fn flush_makes_all_written_data_decodable() {
    let data = text(120_000);
    for level in [-2, 0, 1, 6, 9] {
        let mut w = flate::Writer::new(Vec::new(), level).unwrap();
        let mut written = 0;
        for size in [0usize, 1, 100, 33_000, 70_000, 5, 0] {
            w.write_all(&data[written..written + size]).unwrap();
            written += size;
            w.flush().unwrap();
            let so_far = w.get_ref().clone();
            // Sync flush ends on an empty stored block: 00 00 ff ff.
            assert_eq!(
                &so_far[so_far.len() - 4..],
                &[0, 0, 0xff, 0xff],
                "level {level}"
            );
            let (out, err) = read_partial(&mut flate::Decompressor::new(&so_far[..]));
            assert_eq!(out, &data[..written], "level {level} after {written}");
            assert_unexpected_eof(&err.unwrap());
        }
        w.close().unwrap();
        let all = w.into_inner();
        assert_eq!(
            read_all(&mut flate::Decompressor::new(&all[..])).unwrap(),
            &data[..written]
        );
    }
}

#[test]
fn flush_with_nothing_pending_still_writes_a_marker() {
    let mut w = flate::Writer::new(Vec::new(), 6).unwrap();
    w.flush().unwrap();
    assert_eq!(w.get_ref(), &[0, 0, 0, 0xff, 0xff]);
    w.flush().unwrap();
    assert_eq!(w.get_ref().len(), 10);
    w.close().unwrap();
    assert_eq!(&w.get_ref()[10..], &[3, 0]);
}

#[test]
fn close_semantics_match_go() {
    let mut w = flate::Writer::new(Vec::new(), 6).unwrap();
    w.write_all(b"abc").unwrap();
    w.close().unwrap();
    let len = w.get_ref().len();
    w.close().unwrap();
    assert_eq!(w.get_ref().len(), len, "second Close is a no-op");
    assert_eq!(
        w.write(b"x").unwrap_err().to_string(),
        "flate: closed writer"
    );
    assert_eq!(w.flush().unwrap_err().to_string(), "flate: closed writer");
    // Reset revives a closed writer.
    w.reset(Vec::new());
    w.write_all(b"again").unwrap();
    w.close().unwrap();
    assert_eq!(
        read_all(&mut flate::Decompressor::new(&w.get_ref()[..])).unwrap(),
        b"again"
    );
}

struct FailAfter {
    left: usize,
}

impl Write for FailAfter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.left == 0 {
            return Err(io::Error::other("sink failed"));
        }
        let n = buf.len().min(self.left);
        self.left -= n;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn write_errors_are_persistent() {
    let data = noise(300_000, 4);
    for level in [0, 1, 6, 9] {
        let mut w = flate::Writer::new(FailAfter { left: 1000 }, level).unwrap();
        let first = w.write_all(&data).and_then(|()| w.flush()).unwrap_err();
        assert_eq!(first.to_string(), "sink failed");
        assert_eq!(w.write(b"x").unwrap_err().to_string(), "sink failed");
        assert_eq!(w.flush().unwrap_err().to_string(), "sink failed");
        assert_eq!(w.close().unwrap_err().to_string(), "sink failed");
    }
}

#[test]
fn preset_dictionaries_work_in_both_directions() {
    let dictionary = noise(20_000, 6);
    let data = [
        &dictionary[5_000..9_000],
        &b" tail "[..],
        &dictionary[..3_000],
    ]
    .concat();
    for level in [1, 3, 6, 9] {
        let mut with = flate::Writer::with_dictionary(Vec::new(), level, &dictionary).unwrap();
        with.write_all(&data).unwrap();
        with.close().unwrap();
        let with = with.into_inner();
        let without = {
            let mut w = flate::Writer::new(Vec::new(), level).unwrap();
            w.write_all(&data).unwrap();
            w.close().unwrap();
            w.into_inner()
        };
        assert!(
            with.len() * 4 < without.len(),
            "level {level} must use the dictionary"
        );
        let mut r = flate::Decompressor::with_dictionary(&with[..], &dictionary);
        assert_eq!(read_all(&mut r).unwrap(), data);
        // Without the dictionary the back references reach too far.
        let (_, err) = read_partial(&mut flate::Decompressor::new(&with[..]));
        assert!(err.is_some());
    }
    // A dictionary longer than the window only contributes its last 32 KiB.
    let long = text(100_000);
    let mut w = flate::Writer::with_dictionary(Vec::new(), 6, &long).unwrap();
    w.write_all(&long[long.len() - 2000..]).unwrap();
    w.close().unwrap();
    let packed = w.into_inner();
    assert_eq!(
        read_all(&mut flate::Decompressor::with_dictionary(
            &packed[..],
            &long
        ))
        .unwrap(),
        &long[long.len() - 2000..]
    );
    // Levels 0 and -2 ignore the dictionary, so the output decodes without it.
    for level in [0, -2] {
        let mut w = flate::Writer::with_dictionary(Vec::new(), level, &dictionary).unwrap();
        w.write_all(&data).unwrap();
        w.close().unwrap();
        let packed = w.into_inner();
        assert_eq!(
            read_all(&mut flate::Decompressor::new(&packed[..])).unwrap(),
            data
        );
    }
}

#[test]
fn writer_reset_reproduces_output_and_keeps_dictionary() {
    let data = text(150_000);
    for level in -2..=9 {
        for dict_len in [0, 3000, 40_000] {
            let dictionary = text(dict_len);
            let mut w = flate::Writer::with_dictionary(Vec::new(), level, &dictionary).unwrap();
            w.write_all(&data[..30_000]).unwrap();
            w.flush().unwrap();
            w.write_all(&data[30_000..]).unwrap();
            w.close().unwrap();
            let first = w.get_ref().clone();
            // Reset after a finished stream and after an abandoned one.
            for abandon in [false, true] {
                if abandon {
                    w.reset(Vec::new());
                    w.write_all(&noise(100_000, 4)).unwrap();
                }
                w.reset(Vec::new());
                w.write_all(&data[..30_000]).unwrap();
                w.flush().unwrap();
                w.write_all(&data[30_000..]).unwrap();
                w.close().unwrap();
                assert_eq!(
                    *w.get_ref(),
                    first,
                    "level {level} dictionary {dict_len} abandon {abandon}"
                );
            }
        }
    }
}

/// Go's `TestResetDict`: one reader reused with different dictionaries.
#[test]
fn reader_reset_with_dictionaries() {
    let dicts: [&[u8]; 3] = [b"", b"the lazy dog jumps", b"over and over and over"];
    let sample = b"the quick brown fox jumps over the lazy dog and the quick brown fox";
    let mut streams = Vec::new();
    for d in &dicts {
        let mut w = flate::Writer::with_dictionary(Vec::new(), 6, d).unwrap();
        w.write_all(sample).unwrap();
        w.close().unwrap();
        streams.push(w.into_inner());
    }
    let mut r = flate::Decompressor::from_buf_read_with_dictionary(&streams[0][..], dicts[0]);
    for round in 0..3 {
        for (i, d) in dicts.iter().enumerate() {
            r.reset(&streams[i][..], d).unwrap();
            assert_eq!(read_all(&mut r).unwrap(), sample, "round {round} dict {i}");
            r.close().unwrap();
        }
    }
}

#[test]
fn gzip_writer_header_roundtrip() {
    let mut z = gzip::Writer::with_level(Vec::new(), gzip::BEST_COMPRESSION).unwrap();
    z.header.name = "caf\u{e9}.txt".into();
    z.header.comment = "a comment".into();
    z.header.extra = Some(vec![1, 2, 3]);
    z.header.os = 3;
    z.header.mod_time = Some(rust_stdlib::time::DateTime::from_unix(1_234_567_890, 0, 0).unwrap());
    z.write_all(b"hello gzip").unwrap();
    z.close().unwrap();
    let packed = z.into_inner();
    assert_eq!(&packed[..4], &[0x1f, 0x8b, 8, 0x1c]);
    assert_eq!(&packed[4..8], &1_234_567_890u32.to_le_bytes());
    assert_eq!(packed[8], 2, "XFL for best compression");
    assert_eq!(packed[9], 3);
    // The name is stored as Latin-1.
    assert!(packed.windows(8).any(|w| w == b"caf\xe9.txt"));
    let mut r = gzip::Reader::new(&packed[..]).unwrap();
    assert_eq!(r.header.name, "caf\u{e9}.txt");
    assert_eq!(r.header.comment, "a comment");
    assert_eq!(r.header.extra, Some(vec![1, 2, 3]));
    assert_eq!(r.header.os, 3);
    assert_eq!(r.header.mod_time.unwrap().unix_seconds(), 1_234_567_890);
    assert_eq!(read_all(&mut r).unwrap(), b"hello gzip");

    // Defaults: OS unknown, no time, XFL by level.
    let mut z = gzip::Writer::with_level(Vec::new(), gzip::BEST_SPEED).unwrap();
    z.close().unwrap();
    let packed = z.into_inner();
    assert_eq!(&packed[..10], &[0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 4, 255]);
    // A present but empty Extra still sets FEXTRA.
    let mut z = gzip::Writer::new(Vec::new());
    z.header.extra = Some(Vec::new());
    z.close().unwrap();
    let packed = z.into_inner();
    assert_eq!(packed[3], 4);
    assert_eq!(&packed[10..12], &[0, 0]);
    let r = gzip::Reader::new(&packed[..]).unwrap();
    assert_eq!(r.header.extra, Some(Vec::new()));
}

#[test]
fn gzip_writer_rejects_bad_headers_like_go() {
    let mut z = gzip::Writer::new(Vec::new());
    z.header.name = "no\u{4e16}".into();
    let err = z.write(b"x").unwrap_err();
    assert_eq!(err.to_string(), "gzip.Write: non-Latin-1 header string");
    assert_eq!(z.close().unwrap_err().to_string(), err.to_string());
    let mut z = gzip::Writer::new(Vec::new());
    z.header.comment = "a\0b".into();
    assert_eq!(
        z.flush().unwrap_err().to_string(),
        "gzip.Write: non-Latin-1 header string"
    );
    let mut z = gzip::Writer::new(Vec::new());
    z.header.extra = Some(vec![0; 0x1_0000]);
    assert_eq!(
        z.write(b"x").unwrap_err().to_string(),
        "gzip.Write: Extra data is too large"
    );
}

#[test]
fn gzip_writer_flush_reset_and_close() {
    let data = text(40_000);
    let mut z = gzip::Writer::new(Vec::new());
    z.write_all(&data[..1000]).unwrap();
    z.flush().unwrap();
    let (out, err) = read_partial(&mut gzip::Reader::new(&z.get_ref()[..]).unwrap());
    assert_eq!(out, &data[..1000]);
    assert_unexpected_eof(&err.unwrap());
    z.write_all(&data[1000..]).unwrap();
    z.close().unwrap();
    z.close().unwrap();
    let first = z.get_ref().clone();
    assert_eq!(
        read_all(&mut gzip::Reader::new(&first[..]).unwrap()).unwrap(),
        data
    );
    // Reset restores the default header and reproduces the stream.
    z.header.name = "ignored".into();
    z.reset(Vec::new());
    assert_eq!(z.header.name, "");
    assert_eq!(z.header.os, 255);
    z.write_all(&data[..1000]).unwrap();
    z.flush().unwrap();
    z.write_all(&data[1000..]).unwrap();
    z.close().unwrap();
    assert_eq!(*z.get_ref(), first);
    // Flush and Close on an untouched writer still write a header.
    let mut z = gzip::Writer::new(Vec::new());
    z.flush().unwrap();
    assert_eq!(&z.get_ref()[..3], &[0x1f, 0x8b, 8]);
}

#[test]
fn zlib_writer_headers_dictionaries_and_reset() {
    let expected = [
        (-2, [0x78, 0x01]),
        (0, [0x78, 0x01]),
        (1, [0x78, 0x01]),
        (2, [0x78, 0x5e]),
        (5, [0x78, 0x5e]),
        (6, [0x78, 0x9c]),
        (-1, [0x78, 0x9c]),
        (7, [0x78, 0xda]),
        (9, [0x78, 0xda]),
    ];
    for (level, header) in expected {
        let mut z = zlib::Writer::with_level(Vec::new(), level).unwrap();
        z.write_all(b"x").unwrap();
        z.close().unwrap();
        assert_eq!(&z.get_ref()[..2], &header, "level {level}");
    }
    let dictionary = b"hello world";
    let mut z = zlib::Writer::with_level_and_dictionary(Vec::new(), 6, Some(dictionary)).unwrap();
    z.write_all(b"hello world hello").unwrap();
    z.close().unwrap();
    let packed = z.get_ref().clone();
    assert_eq!(packed[1] & 0x20, 0x20);
    assert_eq!(
        &packed[2..6],
        &rust_stdlib::hash::adler32::checksum(dictionary).to_be_bytes()
    );
    let out =
        read_all(&mut zlib::Reader::with_dictionary(&packed[..], dictionary).unwrap()).unwrap();
    assert_eq!(out, b"hello world hello");
    let err = zlib::Reader::with_dictionary(&packed[..], b"other")
        .err()
        .unwrap();
    assert_eq!(downcast::<zlib::Error>(&err), Some(&zlib::ERR_DICTIONARY));
    assert_eq!(err.to_string(), "zlib: invalid dictionary");
    // Reset reuses level and dictionary.
    z.reset(Vec::new());
    z.write_all(b"hello world hello").unwrap();
    z.close().unwrap();
    assert_eq!(*z.get_ref(), packed);
    // Present-but-empty dictionary still sets the flag, as a non-nil slice does in Go.
    let mut z = zlib::Writer::with_level_and_dictionary(Vec::new(), 6, Some(&[])).unwrap();
    z.close().unwrap();
    assert_eq!(z.get_ref()[1] & 0x20, 0x20);
}

/// Go quirk, checked against go1.27: a second zlib Close appends the Adler-32 again.
#[test]
fn zlib_double_close_repeats_trailer_and_gzip_does_not() {
    let mut z = zlib::Writer::new(Vec::new());
    z.write_all(b"abc").unwrap();
    z.close().unwrap();
    let first = z.get_ref().len();
    let adler = 0x024d_0127u32.to_be_bytes();
    assert_eq!(&z.get_ref()[first - 4..], &adler);
    z.close().unwrap();
    assert_eq!(z.get_ref().len(), first + 4);
    assert_eq!(&z.get_ref()[first..], &adler);
    assert_eq!(
        z.write(b"x").unwrap_err().to_string(),
        "flate: closed writer"
    );
    assert_eq!(z.flush().unwrap_err().to_string(), "flate: closed writer");
    let mut g = gzip::Writer::new(Vec::new());
    g.write_all(b"abc").unwrap();
    g.close().unwrap();
    let gzip_len = g.get_ref().len();
    g.close().unwrap();
    assert_eq!(
        g.get_ref().len(),
        gzip_len,
        "gzip does not repeat its trailer"
    );
    assert_eq!(
        g.write(b"x").unwrap_err().to_string(),
        "flate: closed writer"
    );
    assert_eq!(g.flush().unwrap_err().to_string(), "flate: closed writer");
}

#[test]
fn zlib_reader_resetter_and_close() {
    let make = |payload: &[u8]| {
        let mut z = zlib::Writer::new(Vec::new());
        z.write_all(payload).unwrap();
        z.close().unwrap();
        z.into_inner()
    };
    let a = make(b"alpha alpha alpha");
    let b = make(b"beta");
    let mut r = zlib::Reader::from_buf_read(&a[..]).unwrap();
    assert_eq!(read_all(&mut r).unwrap(), b"alpha alpha alpha");
    r.reset(&b[..], &[]).unwrap();
    assert_eq!(read_all(&mut r).unwrap(), b"beta");
    let mut bad = b.clone();
    let n = bad.len();
    bad[n - 1] ^= 1;
    r.reset(&bad[..], &[]).unwrap();
    let err = read_all(&mut r).unwrap_err();
    assert_eq!(err.to_string(), "zlib: invalid checksum");
    assert_eq!(r.close().unwrap_err().to_string(), "zlib: invalid checksum");
    let err = r.reset(&b"\x00\x00"[..], &[]).unwrap_err();
    assert_eq!(err.to_string(), "zlib: invalid header");
}

#[test]
fn randomized_write_flush_schedules_round_trip() {
    let data = [
        text(80_000),
        noise(20_000, 5),
        vec![1; 50_000],
        text(60_000),
    ]
    .concat();
    let mut state = 99u64;
    let mut next = move || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (state >> 33) as usize
    };
    for level in [-2, 0, 1, 2, 4, 6, 7, 9] {
        let mut w = flate::Writer::new(Vec::new(), level).unwrap();
        let mut at = 0;
        let mut marks = Vec::new();
        while at < data.len() {
            let n = match next() % 4 {
                0 => next() % 10,
                1 => next() % 1000,
                2 => next() % 40_000,
                _ => next() % 100_000,
            }
            .min(data.len() - at);
            w.write_all(&data[at..at + n]).unwrap();
            at += n;
            if next() % 3 == 0 {
                w.flush().unwrap();
                marks.push((w.get_ref().len(), at));
            }
        }
        w.close().unwrap();
        let packed = w.into_inner();
        assert_eq!(
            read_all(&mut flate::Decompressor::new(&packed[..])).unwrap(),
            data,
            "level {level}"
        );
        for (len, written) in marks {
            let (out, _) = read_partial(&mut flate::Decompressor::new(&packed[..len]));
            assert_eq!(out, &data[..written], "level {level} flush at {len}");
        }
    }
}

#[test]
fn matches_at_window_edges_round_trip() {
    // Repeats at distances around 32768 and with maximum-length matches.
    let block = noise(32_768, 3);
    let data = [
        block.clone(),
        block.clone(),
        block[..32_767].to_vec(),
        block[100..30_000].to_vec(),
        noise(1, 8),
        block[..258].to_vec(),
        vec![b'z'; 1000],
    ]
    .concat();
    for level in 1..=9 {
        let mut w = flate::Writer::new(Vec::new(), level).unwrap();
        w.write_all(&data).unwrap();
        w.close().unwrap();
        let packed = w.into_inner();
        assert_eq!(
            read_all(&mut flate::Decompressor::new(&packed[..])).unwrap(),
            data,
            "level {level}"
        );
        // The fast levels (1-6) only match at distances below 32768, like Go's,
        // so they cannot use the repeat at exactly 32768; levels 7-9 do.
        let bound = if level >= 7 {
            40_000
        } else {
            data.len() + data.len() / 100
        };
        assert!(packed.len() < bound, "level {level}: {}", packed.len());
    }
}

#[test]
fn reader_buffers_unbuffered_sources() {
    struct OneByte<'a>(&'a [u8]);
    impl Read for OneByte<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.0.is_empty() || buf.is_empty() {
                return Ok(0);
            }
            buf[0] = self.0[0];
            self.0 = &self.0[1..];
            Ok(1)
        }
    }
    let data = text(30_000);
    let mut w = gzip::Writer::new(Vec::new());
    w.write_all(&data).unwrap();
    w.close().unwrap();
    let packed = w.into_inner();
    let mut r = gzip::Reader::new(OneByte(&packed)).unwrap();
    assert_eq!(read_all(&mut r).unwrap(), data);
    let mut r = flate::Decompressor::new(OneByte(b"\x01\x01\x00\xfe\xff\x11"));
    assert_eq!(read_all(&mut r).unwrap(), [0x11]);
}

#[test]
fn degenerate_huffman_inputs_behave_like_go() {
    // Only Huffman-coded literals of a single value: a one-symbol tree needs two symbols
    // in our encoder, so the data decodes through a complete code.
    let data = vec![b'a'; 5000];
    let mut w = flate::Writer::new(Vec::new(), flate::HUFFMAN_ONLY).unwrap();
    w.write_all(&data).unwrap();
    w.close().unwrap();
    let packed = w.into_inner();
    assert!(packed.len() < 700, "{}", packed.len());
    assert_eq!(
        read_all(&mut flate::Decompressor::new(&packed[..])).unwrap(),
        data
    );
}

#[test]
fn resetter_trait_is_object_safe_enough_for_generic_use() {
    fn reuse<T: Resetter<&'static [u8]>>(r: &mut T, input: &'static [u8]) {
        r.reset(input, &[]).unwrap();
    }
    let mut r = flate::Decompressor::from_buf_read(&b"\x01\x00\x00\xff\xff"[..]);
    reuse(&mut r, b"\x01\x01\x00\xfe\xff\x07");
    assert_eq!(read_all(&mut r).unwrap(), [7]);
}
