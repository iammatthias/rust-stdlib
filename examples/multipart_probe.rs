//! Line protocol used by `tools/multipart_check.py` for Go differential checks.
//! Requests are `MODE:hex`; responses match `tools/multipart_oracle.go`.
use rust_stdlib::multipart::{
    file_content_disposition, Form, Reader, Writer, ERR_MESSAGE_TOO_LARGE,
};
use rust_stdlib::net::textproto::MIMEHeader;
use std::error::Error;
use std::io::{self, BufRead, Write};

fn from_hex(text: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if !text.len().is_multiple_of(2) {
        return Err("odd-length hex input".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| Ok(u8::from_str_radix(&text[i..i + 2], 16)?))
        .collect()
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

fn header_fields(header: &MIMEHeader) -> String {
    let parts: Vec<String> = header
        .iter()
        .map(|(key, values)| {
            let values: Vec<String> = values.iter().map(hex).collect();
            format!("{}={}", hex(key), values.join(","))
        })
        .collect();
    parts.join(";")
}

fn is_too_large(error: &io::Error) -> bool {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rust_stdlib::multipart::Error>())
        .is_some_and(|inner| inner.0 == ERR_MESSAGE_TOO_LARGE.0)
}

fn read_parts(boundary: &str, body: &[u8], raw: bool) -> String {
    let mut reader = Reader::new(body, boundary);
    let mut out = Vec::new();
    loop {
        let next = if raw {
            reader.next_raw_part()
        } else {
            reader.next_part()
        };
        match next {
            Ok(None) => break,
            Ok(Some(mut part)) => {
                let mut data = Vec::new();
                if io::Read::read_to_end(&mut part, &mut data).is_err() {
                    return "err".into();
                }
                out.push(format!(
                    "{},{},{},{}",
                    hex(part.form_name()),
                    hex(part.file_name()),
                    header_fields(&part.header),
                    hex(&data)
                ))
            }
            Err(_) => return "err".into(),
        }
    }
    format!("ok\t{}", out.join("\t"))
}

fn read_form(boundary: &str, max_memory: i64, body: &[u8]) -> String {
    let mut reader = Reader::new(body, boundary);
    let form: Form = match reader.read_form(max_memory) {
        Ok(form) => form,
        Err(error) if is_too_large(&error) => return "toolarge".into(),
        Err(_) => return "err".into(),
    };
    let mut out = Vec::new();
    for (name, values) in &form.value {
        for value in values {
            out.push(format!("v:{},{}", hex(name), hex(value)));
        }
    }
    for (name, files) in &form.file {
        for file in files {
            let mut content = Vec::new();
            let mut opened = match file.open() {
                Ok(opened) => opened,
                Err(_) => return "err".into(),
            };
            if io::Read::read_to_end(&mut opened, &mut content).is_err() {
                return "err".into();
            }
            out.push(format!(
                "f:{},{},{},{},{}",
                hex(name),
                hex(&file.filename),
                file.size,
                hex(&content),
                header_fields(&file.header)
            ));
        }
    }
    format!("ok\t{}", out.join("\t"))
}

/// The sizes of the `multipart-*` files in `$TMPDIR`, sorted, as `n:size,size`.
fn tmp_sizes() -> String {
    let mut sizes: Vec<u64> = std::fs::read_dir(std::env::temp_dir())
        .expect("read TMPDIR")
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with("multipart-"))
        .map(|e| e.metadata().expect("stat").len())
        .collect();
    sizes.sort_unstable();
    let list: Vec<String> = sizes.iter().map(u64::to_string).collect();
    format!("{}:{}", sizes.len(), list.join(","))
}

fn clear_tmp() {
    for entry in std::fs::read_dir(std::env::temp_dir())
        .expect("read TMPDIR")
        .filter_map(Result::ok)
    {
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with("multipart-")
        {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Mode `T`: `read_form`, then the temporary files left, the contents read
/// back, and the files left after `Form::remove_all`.
fn read_form_tmp(boundary: &str, max_memory: i64, body: &[u8]) -> String {
    use rust_stdlib::io::ReadAt;
    use std::io::Seek;
    clear_tmp();
    let mut reader = Reader::new(body, boundary);
    let result = reader.read_form(max_memory);
    let left = tmp_sizes();
    let form: Form = match result {
        Ok(form) => form,
        Err(error) if is_too_large(&error) => return format!("toolarge\t{left}"),
        Err(_) => return format!("err\t{left}"),
    };
    let mut out = Vec::new();
    for (name, files) in &form.file {
        for file in files {
            let mut opened = match file.open() {
                Ok(opened) => opened,
                Err(_) => return "err".into(),
            };
            let mut content = Vec::new();
            if io::Read::read_to_end(&mut opened, &mut content).is_err() {
                return "err".into();
            }
            let mut buf = [0u8; 3];
            let n = match opened.read_at(&mut buf, 1) {
                Ok(n) => n,
                Err(e) => e.read(),
            };
            let pos = opened.seek(io::SeekFrom::End(-2)).unwrap_or(0);
            out.push(format!("{},{},{},{}", hex(name), n, pos, hex(&content)));
        }
    }
    let removed = form.remove_all().is_ok();
    let after = tmp_sizes();
    clear_tmp();
    format!("ok\t{left}\t{}\t{after}\t{removed}", out.join(";"))
}

fn write_script(boundary: &str, items: &[&[u8]]) -> Result<String, Box<dyn Error>> {
    let mut bytes = Vec::new();
    let mut writer = Writer::new(&mut bytes);
    if writer.set_boundary(boundary).is_err() {
        return Ok("err".into());
    }
    for item in items.iter().filter(|item| !item.is_empty()) {
        let text = std::str::from_utf8(item)?;
        let fields: Vec<&str> = text.splitn(4, '\u{1f}').collect();
        let result = match fields[0] {
            "F" => writer.write_field(fields[1], fields[2]),
            "C" => writer
                .create_form_file(fields[1], fields[2])
                .and_then(|mut part| part.write_all(fields[3].as_bytes())),
            "H" => writer
                .create_form_field(fields[1])
                .and_then(|mut part| part.write_all(fields[2].as_bytes())),
            "P" => {
                let mut header = std::collections::BTreeMap::new();
                header.insert(fields[1].to_owned(), vec![fields[2].to_owned()]);
                writer
                    .create_part_map(&header)
                    .and_then(|mut part| part.write_all(fields[3].as_bytes()))
            }
            other => return Err(format!("unknown script item {other}").into()),
        };
        if result.is_err() {
            return Ok("err".into());
        }
    }
    if writer.close().is_err() {
        return Ok("err".into());
    }
    drop(writer);
    Ok(hex(bytes))
}

fn handle(mode: &str, data: &[u8]) -> Result<String, Box<dyn Error>> {
    let fields: Vec<&[u8]> = data.split(|b| *b == 0).collect();
    Ok(match mode {
        "R" => read_parts(std::str::from_utf8(fields[0])?, fields[1], false),
        "W" => read_parts(std::str::from_utf8(fields[0])?, fields[1], true),
        "F" => read_form(
            std::str::from_utf8(fields[0])?,
            std::str::from_utf8(fields[1])?.parse()?,
            fields[2],
        ),
        "T" => read_form_tmp(
            std::str::from_utf8(fields[0])?,
            std::str::from_utf8(fields[1])?.parse()?,
            fields[2],
        ),
        "D" => hex(file_content_disposition(
            std::str::from_utf8(fields[0])?,
            std::str::from_utf8(fields[1])?,
        )),
        "B" => write_script(std::str::from_utf8(fields[0])?, &fields[1..])?,
        "S" => match Writer::new(Vec::new()).set_boundary(std::str::from_utf8(data)?) {
            Ok(()) => "ok".into(),
            Err(_) => "err".into(),
        },
        "M" => {
            let mut writer = Writer::new(Vec::new());
            match writer.set_boundary(std::str::from_utf8(data)?) {
                Ok(()) => hex(writer.form_data_content_type()),
                Err(_) => "err".into(),
            }
        }
        _ => return Err(format!("unknown mode {mode}").into()),
    })
}

fn main() -> Result<(), Box<dyn Error>> {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        let line = line?;
        let (mode, payload) = line.split_once(':').ok_or("bad request")?;
        writeln!(out, "{}", handle(mode, &from_hex(payload)?)?)?;
    }
    out.flush()?;
    Ok(())
}
