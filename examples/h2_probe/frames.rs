//! Frame section of the Rust HTTP/2 probe; mirrors `tools/h2_frame_oracle.go`.
use super::{hex, unhex};
use rust_stdlib::net::http::h2::frame::*;
use rust_stdlib::net::http::h2::hpack::{Decoder, HeaderField};
use std::io::Cursor;

fn fields_text(fs: &[HeaderField]) -> String {
    fs.iter()
        .map(|f| {
            format!(
                "{}/{}/{}",
                hex(&f.name),
                hex(&f.value),
                u8::from(f.sensitive)
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn header(h: &FrameHeader) -> String {
    format!("t{} f{} l{} s{}", h.ftype, h.flags, h.length, h.stream_id)
}

fn prio(p: &PriorityParam) -> String {
    format!("{}/{}/{}", p.stream_dep, u8::from(p.exclusive), p.weight)
}

fn has_duplicates(s: &[Setting]) -> bool {
    (0..s.len()).any(|i| (i + 1..s.len()).any(|j| s[i].id == s[j].id))
}

fn summarize(f: &Frame) -> String {
    let h = header(&f.header());
    match f {
        Frame::Data { data, .. } => format!("{h} DATA {}", hex(data)),
        Frame::Headers {
            priority, fragment, ..
        } => format!("{h} HEADERS {} {}", prio(priority), hex(fragment)),
        Frame::Priority { priority, .. } => format!("{h} PRIORITY {}", prio(priority)),
        Frame::RstStream { code, .. } => format!("{h} RST {code}"),
        Frame::Settings {
            header, settings, ..
        } => {
            let parts: Vec<String> = settings
                .iter()
                .map(|s| format!("{}={}", s.id, s.val))
                .collect();
            format!(
                "{h} SETTINGS {} dups={} ack={}",
                parts.join(","),
                u8::from(has_duplicates(settings)),
                u8::from(header.has(FLAG_SETTINGS_ACK))
            )
        }
        Frame::PushPromise {
            promise_id,
            fragment,
            ..
        } => format!("{h} PUSH {promise_id} {}", hex(fragment)),
        Frame::Ping { data, .. } => format!("{h} PING {}", hex(data)),
        Frame::GoAway {
            last_stream_id,
            code,
            debug_data,
            ..
        } => format!("{h} GOAWAY {last_stream_id} {code} {}", hex(debug_data)),
        Frame::WindowUpdate { increment, .. } => format!("{h} WU {increment}"),
        Frame::Continuation { fragment, .. } => format!("{h} CONT {}", hex(fragment)),
        Frame::PriorityUpdate {
            priority,
            prioritized_stream_id,
            ..
        } => {
            let (p, ok) = parse_rfc9218_priority(&String::from_utf8_lossy(priority), true);
            format!(
                "{h} PU {prioritized_stream_id} {} {}/{}/{}",
                hex(priority),
                p.urgency(),
                p.incremental(),
                u8::from(ok)
            )
        }
        Frame::Unknown { payload, .. } => format!("{h} UNKNOWN {}", hex(payload)),
        Frame::Meta(m) => {
            let (p, aware, inter) = m.rfc9218_priority(false);
            format!(
                "{h} META {} trunc={} fields={} r9218={}/{}/{}/{}",
                prio(&m.priority),
                u8::from(m.truncated),
                fields_text(&m.fields),
                p.urgency(),
                p.incremental(),
                u8::from(aware),
                u8::from(inter)
            )
        }
    }
}

fn frame_read(head: &str, rest: &str) -> String {
    let p: Vec<&str> = head.split(',').collect();
    let mut fr = FrameReader::new(Cursor::new(unhex(rest)));
    fr.set_max_read_frame_size(p[0].parse().unwrap());
    if p[1] == "1" {
        fr.set_meta_headers_decoder(Some(Decoder::new(4096)));
    }
    fr.set_max_header_list_size(p[2].parse().unwrap());
    fr.set_max_header_value_count(p[3].parse().unwrap());
    fr.allow_illegal_reads = p[4] == "1";
    let mut out = Vec::new();
    for _ in 0..200 {
        match fr.read_frame() {
            Ok(f) => out.push(summarize(&f)),
            Err(e) => {
                let detail = fr.error_detail().unwrap_or("").to_owned();
                out.push(format!("E:{e}|{detail}"));
                if matches!(e, FrameError::Stream { .. }) {
                    continue;
                }
                break;
            }
        }
    }
    out.join(";")
}

fn write_op(illegal: bool, op: &str) -> String {
    let a: Vec<&str> = op.split(',').collect();
    let u32_at = |i: usize| -> u32 { a[i].parse().unwrap() };
    let mut fr = FrameWriter::new(Vec::new());
    fr.allow_illegal_writes = illegal;
    let r = match a[0] {
        "data" => {
            let pad = if a[4] == "n" { None } else { Some(unhex(a[4])) };
            fr.write_data_padded(u32_at(1), a[2] == "1", &unhex(a[3]), pad.as_deref())
        }
        "settings" => {
            let ss: Vec<Setting> = a[1..]
                .iter()
                .filter(|s| !s.is_empty())
                .map(|s| {
                    let (k, v) = s.split_once('=').unwrap();
                    Setting {
                        id: k.parse().unwrap(),
                        val: v.parse().unwrap(),
                    }
                })
                .collect();
            fr.write_settings(&ss)
        }
        "settingsack" => fr.write_settings_ack(),
        "ping" => {
            let mut d = [0u8; 8];
            let b = unhex(a[2]);
            d[..b.len().min(8)].copy_from_slice(&b[..b.len().min(8)]);
            fr.write_ping(a[1] == "1", d)
        }
        "goaway" => fr.write_goaway(u32_at(1), u32_at(2), &unhex(a[3])),
        "wu" => fr.write_window_update(u32_at(1), u32_at(2)),
        "headers" => fr.write_headers(&HeadersParam {
            stream_id: u32_at(1),
            end_stream: a[2] == "1",
            end_headers: a[3] == "1",
            pad_length: a[4].parse().unwrap(),
            priority: PriorityParam::new(u32_at(5), a[6] == "1", a[7].parse().unwrap()),
            block_fragment: &unhex(a[8]),
        }),
        "priority" => fr.write_priority(
            u32_at(1),
            PriorityParam::new(u32_at(2), a[3] == "1", a[4].parse().unwrap()),
        ),
        "pu" => fr.write_priority_update(u32_at(1), &String::from_utf8_lossy(&unhex(a[2]))),
        "rst" => fr.write_rst_stream(u32_at(1), u32_at(2)),
        "cont" => fr.write_continuation(u32_at(1), a[2] == "1", &unhex(a[3])),
        "pp" => fr.write_push_promise(&PushPromiseParam {
            stream_id: u32_at(1),
            promise_id: u32_at(2),
            end_headers: a[3] == "1",
            pad_length: a[4].parse().unwrap(),
            block_fragment: &unhex(a[5]),
        }),
        "raw" => fr.write_raw_frame(
            a[1].parse().unwrap(),
            a[2].parse().unwrap(),
            u32_at(3),
            &unhex(a[4]),
        ),
        _ => return "unknown op".into(),
    };
    match r {
        Err(e) => format!("err:{e}"),
        Ok(()) => hex(fr.get_ref()),
    }
}

pub fn frame_request(head: &str, rest: &str) -> String {
    match head.as_bytes()[0] {
        b'R' => frame_read(&head[1..], rest),
        b'W' => rest
            .split(';')
            .map(|op| write_op(&head[1..] == "1", op))
            .collect::<Vec<_>>()
            .join(";"),
        b'Q' => {
            let p: Vec<&str> = rest.split(',').collect();
            let (pp, ok) =
                parse_rfc9218_priority(&String::from_utf8_lossy(&unhex(p[0])), p[1] == "1");
            format!("{}/{}/{}", pp.urgency(), pp.incremental(), u8::from(ok))
        }
        _ => format!("unsupported request {head}"),
    }
}
