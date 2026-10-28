use rust_stdlib::{
    archive::{tar, zip},
    compress,
};
use std::io::{self, Read};
struct Bits {
    b: Vec<u8>,
    bit: u8,
}
impl Bits {
    fn new() -> Self {
        Self { b: vec![], bit: 0 }
    }
    fn put(&mut self, value: usize, width: u8) {
        for i in 0..width {
            if self.bit == 0 {
                self.b.push(0)
            }
            let last = self.b.len() - 1;
            self.b[last] |= (((value >> i) & 1) as u8) << self.bit;
            self.bit = (self.bit + 1) % 8
        }
    }
    fn code(&mut self, value: usize, width: u8) {
        let mut reverse = 0;
        for i in 0..width {
            reverse = (reverse << 1) | ((value >> i) & 1)
        }
        self.put(reverse, width)
    }
}
#[test]
fn malformed_huffman_trees_and_reserved_symbols_reject_without_output() {
    let mut oversubscribed = Bits::new();
    oversubscribed.put(5, 3);
    oversubscribed.put(0, 5);
    oversubscribed.put(0, 5);
    oversubscribed.put(0, 4);
    for _ in 0..4 {
        oversubscribed.put(1, 3)
    }
    let mut empty = Bits::new();
    empty.put(5, 3);
    empty.put(0, 5);
    empty.put(0, 5);
    empty.put(0, 4);
    for _ in 0..4 {
        empty.put(0, 3)
    }
    let mut reserved = Bits::new();
    reserved.put(3, 3);
    reserved.code(0xc6, 8); // fixed symbol 286
    let mut backref = Bits::new();
    backref.put(3, 3);
    backref.code(1, 7);
    backref.code(0, 5); // length3 distance1 before any output
    for input in [oversubscribed.b, empty.b, reserved.b, backref.b] {
        let mut output = vec![42];
        assert!(compress::decode_deflate(&input[..], &mut output, Default::default()).is_err());
        assert_eq!(output, vec![42]);
    }
}
#[test]
fn independent_gzip_zip_bombs_enforce_decoded_budgets() {
    let input = include_bytes!("fixtures/compress/review-bomb.gzip");
    let mut output = vec![42];
    assert!(compress::decode_gzip(
        &input[..],
        &mut output,
        compress::Limits {
            max_input: input.len(),
            max_output: 1024
        }
    )
    .is_err());
    assert_eq!(output, vec![42]);
    let input = include_bytes!("fixtures/compress/review-bomb.zip");
    assert!(zip::read(
        &input[..],
        zip::Limits {
            max_file: 1024,
            ..Default::default()
        }
    )
    .is_err());
    assert!(zip::read(
        &input[..],
        zip::Limits {
            max_total: 1024,
            ..Default::default()
        }
    )
    .is_err());
    let entries = zip::read(&input[..], Default::default()).unwrap();
    assert_eq!(entries[0].data.len(), 1048576);
    assert!(entries[0].data.iter().all(|b| *b == b'A'));
}
#[test]
fn gzip_corrupt_second_member_and_trailing_bytes_are_atomic() {
    let input = include_bytes!("fixtures/compress/python.gzip");
    let mut corrupt = input.to_vec();
    corrupt.extend_from_slice(input);
    let len = corrupt.len();
    corrupt[len - 8] ^= 1;
    for input in [corrupt, [input.as_slice(), b"garbage"].concat()] {
        let mut output = vec![42];
        assert!(compress::decode_gzip(&input[..], &mut output, Default::default()).is_err());
        assert_eq!(output, vec![42]);
    }
}
fn stored_zip() -> Vec<u8> {
    let mut out = vec![];
    zip::write(
        &[
            zip::Entry {
                name: "first".into(),
                data: b"one".to_vec(),
                directory: false,
            },
            zip::Entry {
                name: "second".into(),
                data: b"two".to_vec(),
                directory: false,
            },
        ],
        &mut out,
        Default::default(),
    )
    .unwrap();
    out
}
#[test]
fn zip_metadata_tampering_overlaps_and_bombs_reject() {
    let bytes = stored_zip();
    let central = bytes.windows(4).position(|b| b == [80, 75, 1, 2]).unwrap();
    for (offset, value) in [
        (central + 24, 0xff),
        (central + 42, 1),
        (central + 8, 1),
        (central + 10, 99),
        (30, b'X'),
    ] {
        let mut bad = bytes.clone();
        bad[offset] = value;
        assert!(
            zip::read(&bad[..], Default::default()).is_err(),
            "offset {offset}"
        );
    }
    let mut bad = bytes.clone();
    let second = central + 46 + "first".len();
    bad[second + 42..second + 46].copy_from_slice(&0u32.to_le_bytes());
    assert!(zip::read(&bad[..], Default::default()).is_err());
    let mut bad = bytes.clone();
    bad[central + 24..central + 28].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(zip::read(&bad[..], Default::default()).is_err());
}
struct InterruptAtEnd<'a> {
    input: &'a [u8],
    position: usize,
    interrupted: bool,
}
impl Read for InterruptAtEnd<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.position == self.input.len() && !self.interrupted {
            self.interrupted = true;
            return Err(io::ErrorKind::Interrupted.into());
        }
        let n = out.len().min(self.input.len() - self.position);
        out[..n].copy_from_slice(&self.input[self.position..self.position + n]);
        self.position += n;
        Ok(n)
    }
}
#[test]
fn tar_retries_interrupt_after_end_markers() {
    let bytes = [0u8; 1024];
    let reader = InterruptAtEnd {
        input: &bytes,
        position: 0,
        interrupted: false,
    };
    assert!(tar::read(reader, Default::default()).unwrap().is_empty());
}
#[test]
fn archive_arbitrary_data_and_mutations_stay_bounded() {
    let original = stored_zip();
    let mut state = 714u64;
    for i in 0..3000 {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let mut input = original.clone();
        let at = state as usize % input.len();
        input[at] ^= (state >> 32) as u8;
        if i % 7 == 0 {
            input.truncate(at)
        }
        let _ = zip::read(
            &input[..],
            zip::Limits {
                max_archive: 4096,
                max_file: 4096,
                max_total: 8192,
                max_entries: 16,
            },
        );
        let _ = tar::read(
            &input[..],
            tar::Limits {
                max_archive: 4096,
                max_file: 4096,
                max_total: 8192,
                max_entries: 16,
            },
        );
    }
}
