use rust_stdlib::hash::{adler32, crc32, crc64, fnv};
use std::io::{self, BufRead, Write};

fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) {
        return Err("hex input must contain pairs of digits".to_owned());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

macro_rules! result {
    ($new:expr, $bytes:expr) => {{
        let mut h = $new;
        for chunk in $bytes.chunks(7) {
            h.write_all(chunk).expect("in-memory hash writer");
        }
        let mut digest = Vec::new();
        h.sum(&mut digest);
        (to_hex(&digest), to_hex(&h.marshal_binary()))
    }};
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    for line in io::stdin().lock().lines() {
        let bytes = decode_hex(&line?)?;
        let mut values = Vec::new();
        let mut states = Vec::new();
        macro_rules! append_hash {
            ($hasher:expr) => {{
                let (digest, state) = result!($hasher, &bytes);
                values.push(digest);
                states.push(state);
            }};
        }
        append_hash!(fnv::new32());
        append_hash!(fnv::new32a());
        append_hash!(fnv::new64());
        append_hash!(fnv::new64a());
        append_hash!(fnv::new128());
        append_hash!(fnv::new128a());
        append_hash!(crc64::Crc64::new(&crc64::Table::iso()));
        append_hash!(crc64::Crc64::new(&crc64::Table::ecma()));
        let custom64 = crc64::Table::new(0x95ac_9329_ac4b_c9b5);
        append_hash!(crc64::Crc64::new(&custom64));
        values.push(format!(
            "{:016x}",
            crc64::update(0x1234_5678_9abc_def0, &custom64, &bytes)
        ));
        for table in [
            crc32::Table::ieee().clone(),
            crc32::Table::castagnoli(),
            crc32::Table::koopman(),
            crc32::Table::new(0x741b_8cd7),
        ] {
            append_hash!(crc32::Crc32::new(&table));
        }
        values.push(format!(
            "{:08x}",
            crc32::update(0x89ab_cdef, &crc32::Table::new(0x741b_8cd7), &bytes)
        ));
        append_hash!(adler32::Adler32::new());
        let mut arbitrary_adler = adler32::Adler32::new();
        arbitrary_adler.unmarshal_binary(b"adl\x01\xff\xff\xff\xff")?;
        arbitrary_adler.update(&bytes);
        values.push(format!("{:08x}", arbitrary_adler.sum32()));
        values.push(format!("{:08x}", adler32::checksum(&bytes)));
        values.push(format!("{:08x}", crc32::checksum_ieee(&bytes)));
        values.push(format!(
            "{:08x}",
            crc32::checksum(&bytes, crc32::Table::ieee())
        ));
        values.push(format!(
            "{:08x}",
            crc32::checksum(&bytes, &crc32::Table::new(0x741b_8cd7))
        ));
        values.push(format!(
            "{:08x}",
            crc32::update(0, crc32::Table::ieee(), &bytes)
        ));
        values.push(format!(
            "{:016x}",
            crc64::checksum(&bytes, &crc64::Table::iso())
        ));
        states.push(to_hex(&arbitrary_adler.marshal_binary()));

        let json_values = values
            .iter()
            .map(|value| format!("\"{value}\""))
            .collect::<Vec<_>>()
            .join(",");
        let json_states = states
            .iter()
            .map(|value| format!("\"{value}\""))
            .collect::<Vec<_>>()
            .join(",");
        writeln!(io::stdout().lock(), "[[{json_values}],[{json_states}]]")?;
    }
    Ok(())
}
