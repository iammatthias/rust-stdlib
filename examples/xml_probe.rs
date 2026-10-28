//! Line protocol used by `tools/xml_check.py` for Go differential checks of the
//! tokenizer, escaping and `Encoder::encode_token`.
use rust_stdlib::encoding::xml::{
    self, Attr, CharData, Comment, Decoder, Directive, EndElement, Name, ProcInst, StartElement,
    Token,
};
use std::{
    cell::RefCell,
    io::{self, BufRead, Write},
    rc::Rc,
};

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

fn hx(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hs(text: &str) -> String {
    hx(text.as_bytes())
}

fn rec_name(n: &Name) -> String {
    format!("{}/{}", hs(&n.space), hs(&n.local))
}

fn record(t: &Token) -> String {
    match t {
        Token::StartElement(t) => {
            let mut parts = vec!["S".to_string(), rec_name(&t.name)];
            for a in &t.attr {
                parts.push(format!("{}={}", rec_name(&a.name), hs(&a.value)));
            }
            parts.join(" ")
        }
        Token::EndElement(t) => format!("E {}", rec_name(&t.name)),
        Token::CharData(t) => format!("C {}", hx(&t.0)),
        Token::Comment(t) => format!("M {}", hx(&t.0)),
        Token::ProcInst(t) => format!("P {} {}", hs(&t.target), hx(&t.inst)),
        Token::Directive(t) => format!("D {}", hx(&t.0)),
    }
}

fn pos(d: &Decoder) -> String {
    let (line, col) = d.input_pos();
    format!(" @{},{},{}", d.input_offset(), line, col)
}

fn decode_mode(flags: &str, input: &[u8]) -> String {
    let f = flags.as_bytes();
    let out: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let mut d = Decoder::new(input);
    d.strict = f[0] == b'1';
    if f[1] == b'1' {
        d.auto_close = xml::html_auto_close();
    }
    match f[2] {
        b'1' => d.entity = xml::html_entity(),
        b'2' => {
            for (k, v) in [
                ("foo", "bar"),
                ("x", "<&>"),
                ("e", ""),
                ("amp", "NOT"),
                ("lt", "NOT"),
            ] {
                d.entity.insert(k.to_string(), v.to_string());
            }
        }
        _ => {}
    }
    if f[3] == b'1' {
        d.default_space = "urn:default".into();
    }
    let log = out.clone();
    d.charset_reader = Some(Box::new(move |charset, r| {
        log.borrow_mut().push(format!("charset {}", hs(charset)));
        if charset == "fail" {
            return Err("boom".into());
        }
        Ok(r)
    }));
    let mode = f[4];
    for i in 0..4000 {
        let res = if mode == b'1' {
            d.raw_token()
        } else {
            d.token()
        };
        let p = pos(&d);
        match res {
            Err(e) => {
                if e.is_eof() {
                    out.borrow_mut().push(format!("EOF{p}"));
                } else {
                    out.borrow_mut()
                        .push(format!("ERR {}{p}", hs(&e.to_string())));
                }
                break;
            }
            Ok(t) => out.borrow_mut().push(format!("{}{p}", record(&t))),
        }
        if mode == b'2' && i % 3 == 2 {
            let r = d.skip();
            let p = pos(&d);
            match r {
                Err(e) => {
                    if e.is_eof() {
                        out.borrow_mut().push(format!("SKIP-EOF{p}"));
                    } else {
                        out.borrow_mut()
                            .push(format!("SKIP-ERR {}{p}", hs(&e.to_string())));
                    }
                    break;
                }
                Ok(()) => out.borrow_mut().push(format!("SKIP{p}")),
            }
        }
    }
    let joined = out.borrow().join("|");
    joined
}

fn escape_mode(input: &[u8]) -> String {
    let mut a = Vec::new();
    xml::escape_text(&mut a, input).unwrap();
    let mut b = Vec::new();
    xml::escape(&mut b, input);
    format!("{} {}", hx(&a), hx(&b))
}

fn parse_token(s: &str) -> Token {
    let f: Vec<&str> = s.split(':').collect();
    let s = |i: usize| String::from_utf8(unhex(f[i])).expect("utf8 test string");
    let name = |i: usize| Name {
        space: s(i),
        local: s(i + 1),
    };
    match f[0] {
        "S" => {
            let mut st = StartElement {
                name: name(1),
                attr: Vec::new(),
            };
            let mut i = 3;
            while i + 2 < f.len() {
                st.attr.push(Attr {
                    name: name(i),
                    value: s(i + 2),
                });
                i += 3;
            }
            Token::StartElement(st)
        }
        "E" => Token::EndElement(EndElement { name: name(1) }),
        "C" => Token::CharData(CharData(unhex(f[1]))),
        "M" => Token::Comment(Comment(unhex(f[1]))),
        "P" => Token::ProcInst(ProcInst {
            target: s(1),
            inst: unhex(f[2]),
        }),
        "D" => Token::Directive(Directive(unhex(f[1]))),
        other => panic!("bad token kind {other}"),
    }
}

fn encode_tokens(prefix: &[u8], indent: &[u8], ops: &[&str]) -> String {
    let mut buf = Vec::new();
    let mut out = Vec::new();
    {
        let mut e = xml::Encoder::new(&mut buf);
        e.indent(
            std::str::from_utf8(prefix).unwrap(),
            std::str::from_utf8(indent).unwrap(),
        );
        for op in ops {
            let r = if *op == "FLUSH" {
                e.flush()
            } else {
                e.encode_token(parse_token(op))
            };
            match r {
                Ok(()) => out.push("ok".to_string()),
                Err(err) => out.push(format!("err {}", hs(&err.to_string()))),
            }
        }
        match e.close() {
            Ok(()) => out.push("close-ok".to_string()),
            Err(err) => out.push(format!("close-err {}", hs(&err.to_string()))),
        }
    }
    format!("{} {}", out.join("|"), hx(&buf))
}

fn main() {
    let stdout = io::stdout();
    let mut w = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let f: Vec<&str> = line.split('\t').collect();
        let resp = match f[0] {
            "T" => decode_mode(f[1], &unhex(f[2])),
            "E" => escape_mode(&unhex(f[1])),
            "K" => {
                let ops: Vec<&str> = if f.len() > 3 && !f[3].is_empty() {
                    f[3].split(' ').collect()
                } else {
                    Vec::new()
                };
                encode_tokens(&unhex(f[1]), &unhex(f[2]), &ops)
            }
            other => format!("bad request {other:?}"),
        };
        writeln!(w, "{resp}").unwrap();
    }
}
