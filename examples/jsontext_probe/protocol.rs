//! The request/response protocol shared by the Go differential
//! (`tools/jsontext_check.py`) and the golden vectors in `tests/jsontext.rs`.
//! `tools/jsontext_oracle.go` answers the same requests with Go's package.
//! Binary fields are hex (`-` is empty).
use rust_stdlib::encoding::json::jsontext::{
    self as jt, Decoder, Encoder, Error, Options, Pointer, Token, Value,
};
use std::io::{self, Read};
use std::panic::{catch_unwind, AssertUnwindSafe};

fn dec(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex field"))
        .collect()
}

fn enc(b: &[u8]) -> String {
    if b.is_empty() {
        return "-".into();
    }
    b.iter().map(|c| format!("{c:02x}")).collect()
}

fn encs(s: &str) -> String {
    enc(s.as_bytes())
}

fn err_text(err: &Option<Error>) -> String {
    match err {
        None => "nil".into(),
        Some(Error::Eof) => "EOF".into(),
        Some(e @ Error::Syntactic(se)) => format!(
            "E{}@{}@{}",
            encs(&e.to_string()),
            se.byte_offset,
            encs(se.json_pointer.as_str())
        ),
        Some(e) => format!("E{}", encs(&e.to_string())),
    }
}

fn options(letters: &str) -> Vec<Options> {
    if letters == "-" {
        return Vec::new();
    }
    letters
        .chars()
        .map(|c| match c {
            'd' => jt::allow_duplicate_names(true),
            'u' => jt::allow_invalid_utf8(true),
            'h' => jt::escape_for_html(true),
            'j' => jt::escape_for_js(true),
            'p' => jt::preserve_raw_strings(true),
            'i' => jt::canonicalize_raw_ints(true),
            'f' => jt::canonicalize_raw_floats(true),
            'r' => jt::reorder_raw_objects(true),
            'm' => jt::multiline(true),
            ':' => jt::space_after_colon(true),
            ',' => jt::space_after_comma(true),
            'I' => jt::with_indent("  "),
            'T' => jt::with_indent("\t"),
            'P' => jt::with_indent_prefix("> "),
            'X' => jt::with_indent(""),
            'D' => jt::allow_duplicate_names(false),
            'U' => jt::allow_invalid_utf8(false),
            'c' => jt::space_after_colon(false),
            'k' => jt::space_after_comma(false),
            'n' => jt::multiline(false),
            'e' => jt::escape_for_html(false),
            'q' => jt::preserve_raw_strings(false),
            other => panic!("unknown option letter {other}"),
        })
        .collect()
}

struct ChunkReader {
    data: Vec<u8>,
    pos: usize,
    n: usize,
}

impl Read for ChunkReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let mut want = out.len().min(self.data.len() - self.pos);
        if self.n > 0 {
            want = want.min(self.n);
        }
        out[..want].copy_from_slice(&self.data[self.pos..self.pos + want]);
        self.pos += want;
        Ok(want)
    }
}

fn kind_char(k: jt::Kind) -> String {
    if k.0 == 0 {
        "_".into()
    } else {
        (k.0 as char).to_string()
    }
}

fn try_<F: FnOnce() -> String>(f: F) -> String {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(s) => s,
        Err(p) => {
            let msg = p
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default();
            format!("P{}", encs(&msg))
        }
    }
}

fn tok_text(t: &Token) -> String {
    let k = t.kind();
    let mut s = format!("{}:{}:b", kind_char(k), enc(&t.string_bytes()));
    s += &try_(|| t.bool().to_string());
    s += ":f";
    s += &try_(|| {
        let (f, e) = t.float();
        format!("{:x}/{}", f.to_bits(), err_text(&e))
    });
    s += ":g";
    s += &try_(|| {
        let (f, e) = t.float32();
        format!("{:x}/{}", f.to_bits(), err_text(&e))
    });
    s += ":i";
    s += &try_(|| {
        let (i, e) = t.int();
        format!("{i}/{}", err_text(&e))
    });
    s += ":u";
    s += &try_(|| {
        let (u, e) = t.uint();
        format!("{u}/{}", err_text(&e))
    });
    s
}

fn stack_text(depth: usize, index: impl Fn(usize) -> (jt::Kind, i64)) -> String {
    (0..=depth)
        .map(|i| {
            let (k, n) = index(i);
            format!("{}{n}", kind_char(k))
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn decode_op(chunk: &str, opt_letters: &str, ops: &str, doc: Vec<u8>) -> String {
    let opts = options(opt_letters);
    let mut d = if chunk == "b" {
        Decoder::from_buffer(doc, &opts)
    } else {
        let n = chunk.parse().unwrap_or(0);
        Decoder::new(
            ChunkReader {
                data: doc,
                pos: 0,
                n,
            },
            &opts,
        )
    };
    let ops = ops.as_bytes();
    let mut recs = Vec::new();
    for step in 0..400 {
        let op = ops[step % ops.len()];
        let mut res = String::new();
        let mut err: Option<Error> = None;
        match op {
            b'T' => match d.read_token() {
                Ok(t) => res = format!("t{}", tok_text(&t)),
                Err(e) => err = Some(e),
            },
            b'V' => match d.read_value() {
                Ok(v) => res = format!("v{}", enc(&v.0)),
                Err(e) => err = Some(e),
            },
            b'D' => loop {
                if let Err(e) = d.read_token() {
                    err = Some(e);
                    break;
                }
            },
            b'K' => res = format!("k{}", kind_char(d.peek_kind())),
            b'S' => match d.skip_value() {
                Ok(()) => res = "s".into(),
                Err(e) => err = Some(e),
            },
            _ => unreachable!(),
        }
        let stop = err.is_some();
        if err.is_some() {
            res = format!("x{}", err_text(&err));
        }
        let offset = d.input_offset();
        let depth = d.stack_depth();
        let ptr = encs(d.stack_pointer().as_str());
        let idx = stack_text(depth, |i| d.stack_index(i));
        let unread = enc(d.unread_buffer());
        recs.push(format!(
            "{}:{res}|o{offset}|d{depth}|p{ptr}|i{idx}|u{unread}",
            op as char
        ));
        if stop {
            break;
        }
    }
    recs.join(" ")
}

fn parse_token(op: &str) -> Token {
    let rest = &op[1..];
    match op.as_bytes()[0] {
        b'n' => jt::null(),
        b'f' => jt::false_(),
        b't' => jt::true_(),
        b'{' => jt::begin_object(),
        b'}' => jt::end_object(),
        b'[' => jt::begin_array(),
        b']' => jt::end_array(),
        b's' => jt::string_bytes(&dec(rest)),
        b'i' => jt::int(rest.parse().unwrap_or(0)),
        b'u' => jt::uint(rest.parse().unwrap_or(0)),
        b'F' => jt::float(f64::from_bits(u64::from_str_radix(rest, 16).unwrap_or(0))),
        b'G' => jt::float32(f32::from_bits(u32::from_str_radix(rest, 16).unwrap_or(0))),
        b'b' => jt::bool(rest == "1"),
        b'x' => Token::default(),
        _ => panic!("unknown token op"),
    }
}

fn encode_op(opt_letters: &str, ops: &[&str]) -> String {
    let opts = options(opt_letters);
    let mut buf: Vec<u8> = Vec::new();
    let mut recs = Vec::new();
    let final_;
    {
        let mut e = Encoder::new(&mut buf, &opts);
        for op in ops {
            let res = match op.as_bytes()[0] {
                b't' => {
                    let tok = parse_token(&op[1..]);
                    try_(|| err_text(&e.write_token(&tok).err()))
                }
                b'v' => try_(|| err_text(&e.write_value(&Value(dec(&op[1..]))).err())),
                _ => "q".into(),
            };
            let depth = e.stack_depth();
            let ptr = encs(e.stack_pointer().as_str());
            let idx = stack_text(depth, |i| e.stack_index(i));
            recs.push(format!(
                "{res}|o{}|d{depth}|p{ptr}|i{idx}",
                e.output_offset()
            ));
        }
        final_ = e.stack_depth() == 0;
    }
    let w = if final_ { enc(&buf) } else { "-".into() };
    format!("{} w={w}", recs.join(" "))
}

fn value_op(op: &str, opt_letters: &str, doc: Vec<u8>) -> String {
    let opts = options(opt_letters);
    let mut v = Value(doc);
    match op {
        "valid" => return v.is_valid(&opts).to_string(),
        "kind" => return kind_char(v.kind()),
        "string" => return encs(&v.to_string()),
        "clone" => return enc(&v.clone().0),
        "marshal" => return format!("{} nil", enc(&v.marshal_json())),
        "appendformat" => {
            let mut dst = b"pre".to_vec();
            let r = jt::append_format(&mut dst, &v.0, &opts);
            return format!("{} {}", enc(&dst), err_text(&r.err()));
        }
        _ => {}
    }
    let r = match op {
        "format" => v.format(&opts),
        "compact" => v.compact(&opts),
        "indent" => v.indent(&opts),
        "canon" => v.canonicalize(&opts),
        other => panic!("unknown value op {other}"),
    };
    format!("{} {}", enc(&v.0), err_text(&r.err()))
}

/// Builds a Token with one of the constructors and describes the results of
/// all its accessors.
fn tok_acc_op(ctor: &str, arg: &str) -> String {
    let tok = match ctor {
        "zero" => Token::default(),
        "null" => jt::null(),
        "false" => jt::false_(),
        "true" => jt::true_(),
        "bo" => jt::begin_object(),
        "eo" => jt::end_object(),
        "ba" => jt::begin_array(),
        "ea" => jt::end_array(),
        "bool" => jt::bool(arg == "1"),
        "string" => jt::string_bytes(&dec(arg)),
        "f32" => jt::float32(f32::from_bits(u32::from_str_radix(arg, 16).unwrap_or(0))),
        "f64" => jt::float(f64::from_bits(u64::from_str_radix(arg, 16).unwrap_or(0))),
        "int" => jt::int(arg.parse().unwrap_or(0)),
        "uint" => jt::uint(arg.parse().unwrap_or(0)),
        "raw" => {
            let mut d = Decoder::from_buffer(dec(arg), &[]);
            match d.read_token() {
                Ok(t) => t,
                Err(e) => return format!("decode error {}", err_text(&Some(e))),
            }
        }
        other => panic!("unknown token constructor {other}"),
    };
    format!("{} clone={}", tok_text(&tok), tok_text(&tok.clone_token()))
}

fn pointer_op(op: &str, p: Pointer, arg: &str) -> String {
    match op {
        "valid" => p.is_valid().to_string(),
        "parent" => encs(p.parent().as_str()),
        "last" => encs(&p.last_token()),
        "append" => encs(p.append_token(arg).as_str()),
        "contains" => p.contains(&Pointer::from(arg)).to_string(),
        "tokens" => {
            let toks: Vec<String> = p.tokens().map(|t| encs(&t)).collect();
            format!("{} {}", toks.len(), toks.join(","))
        }
        other => panic!("unknown pointer op {other}"),
    }
}

pub fn respond(line: &str) -> String {
    let f: Vec<&str> = line.split(' ').collect();
    match f[0] {
        "decode" => decode_op(f[1], f[2], f[3], dec(f[4])),
        "encode" => encode_op(f[2], &f[3..]),
        "value" => value_op(f[1], f[2], dec(f[3])),
        "quote" => {
            let mut dst = b"pre".to_vec();
            let r = jt::append_quote(&mut dst, &dec(f[1]));
            format!("{} {}", enc(&dst), err_text(&r.err()))
        }
        "unquote" => {
            let mut dst = b"pre".to_vec();
            let r = jt::append_unquote(&mut dst, &dec(f[1]));
            format!("{} {}", enc(&dst), err_text(&r.err()))
        }
        "float" => {
            let bits: i32 = f[1].parse().expect("bits");
            let n = u64::from_str_radix(f[2], 16).expect("float bits");
            let v = if bits == 32 {
                f64::from(f32::from_bits(n as u32))
            } else {
                f64::from_bits(n)
            };
            let mut dst = b"pre".to_vec();
            jt::append_float(&mut dst, v, bits);
            enc(&dst)
        }
        "pointer" => pointer_op(
            f[1],
            Pointer::from(String::from_utf8_lossy(&dec(f[2])).into_owned()),
            &String::from_utf8_lossy(&dec(f[3])),
        ),
        "tokacc" => tok_acc_op(f[1], f[2]),
        "options" => {
            let s = String::from_utf8_lossy(&dec(f[2])).into_owned();
            match f[1] {
                "indent" => try_(|| {
                    let _ = jt::with_indent(&s);
                    "ok".into()
                }),
                _ => try_(|| {
                    let _ = jt::with_indent_prefix(&s);
                    "ok".into()
                }),
            }
        }
        other => format!("unknown op {other}"),
    }
}

/// Answers a request, turning a panic into a `panic <hex message>` record.
pub fn respond_safely(line: &str) -> String {
    match catch_unwind(AssertUnwindSafe(|| respond(line))) {
        Ok(t) => t,
        Err(p) => {
            let msg = p
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default();
            format!("panic {}", encs(&msg))
        }
    }
}
