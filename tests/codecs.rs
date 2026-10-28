use rust_stdlib::encoding::{
    base64, hex,
    json::{self, Deserialize, Number, Serialize, Value},
};
use std::{
    collections::BTreeMap,
    io::{self, Read, Write},
};

#[test]
fn hex_vectors_and_errors() {
    assert_eq!(hex::encode(b"\x00\x01\xffhello"), "0001ff68656c6c6f");
    assert_eq!(
        hex::decode("0001FF68656C6C6F").unwrap(),
        b"\x00\x01\xffhello"
    );
    assert_eq!(hex::decode("").unwrap(), b"");
    assert_eq!(hex::decode("f"), Err(hex::Error::Length));
    assert_eq!(
        hex::decode("fg"),
        Err(hex::Error::InvalidByte(hex::InvalidByteError(b'g')))
    );
    assert!(hex::decode("\u{00e9}").is_err());
}
#[test]
fn rfc4648_vectors() {
    for (plain, encoded) in [
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ] {
        assert_eq!(base64::STANDARD.encode(plain.as_bytes()), encoded);
        assert_eq!(base64::STANDARD.decode(encoded).unwrap(), plain.as_bytes());
        assert_eq!(
            base64::STANDARD_NO_PAD.encode(plain.as_bytes()),
            encoded.trim_end_matches('=')
        );
    }
}
#[test]
fn base64_strict_rejections() {
    for text in [
        "A", "AA", "AAA", "A===", "====", "Zg=", "Zh==", "Zm9=", "Z g==", "Z=g=", "AA-_",
        "\u{00e9}",
    ] {
        assert!(base64::STANDARD.strict().decode(text).is_err(), "{text:?}");
    }
    for text in ["A", "AA=", "Zh", "Zm9", "AA+/"] {
        assert!(
            base64::URL_SAFE_NO_PAD.strict().decode(text).is_err(),
            "{text:?}"
        );
    }
}
#[test]
fn base64_alphabets() {
    assert_eq!(base64::STANDARD.encode([251, 255, 255]), "+///");
    assert_eq!(base64::URL_SAFE.encode([251, 255, 255]), "-___");
    assert_eq!(
        base64::URL_SAFE_NO_PAD.decode("-___").unwrap(),
        [251, 255, 255]
    );
}
#[test]
fn codec_roundtrips_deterministic_binary_corpus() {
    let mut state = 0x5eed_u64;
    for length in 0..512 {
        let bytes: Vec<_> = (0..length)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect();
        assert_eq!(hex::decode(hex::encode(&bytes)).unwrap(), bytes);
        for encoding in [
            base64::STANDARD,
            base64::URL_SAFE,
            base64::STANDARD_NO_PAD,
            base64::URL_SAFE_NO_PAD,
        ] {
            assert_eq!(encoding.decode(encoding.encode(&bytes)).unwrap(), bytes);
        }
    }
}
#[test]
fn json_valid_values() {
    for text in [
        "null",
        "true",
        "false",
        "0",
        "-0",
        "10",
        "-2.35e+12",
        "[]",
        "{}",
        r#"[1,"two",null,{"a":true}]"#,
        " \r\n\t123 \r\n",
    ] {
        let value = text.parse::<json::Value>().unwrap();
        assert_eq!(value.to_string().parse::<json::Value>().unwrap(), value);
    }
}
#[test]
fn json_rejects_malformed_values() {
    for text in [
        "",
        " ",
        "+1",
        "01",
        "-",
        "1.",
        "1e",
        "1e+",
        "NaN",
        "Infinity",
        "[1,]",
        "{\"a\":1,}",
        "[",
        "{",
        "nul",
        "true false",
        "\"a\nb\"",
        "\"\\x00\"",
        "\u{feff}null",
        "\"unterminated",
    ] {
        assert!(text.parse::<json::Value>().is_err(), "{text:?}");
    }
}
#[test]
fn json_unicode_surrogates_and_controls() {
    assert_eq!(
        (r#""\uD83D\uDE00""#)
            .parse::<json::Value>()
            .unwrap()
            .as_str(),
        Some("😀")
    );
    assert_eq!(
        r#""\u0000\b\f\n\r\t\\\/\"""#.parse::<json::Value>().unwrap().as_str(),
        Some("\0\u{8}\u{c}\n\r\t\\/\"")
    );
    assert_eq!(
        ("\"日本語😀\"").parse::<json::Value>().unwrap().as_str(),
        Some("日本語😀")
    );
}
#[test]
fn json_exact_number_lexemes() {
    for text in [
        "9007199254740993",
        "18446744073709551615",
        "-0.000e+12",
        "1e9999",
    ] {
        assert_eq!(text.parse::<json::Value>().unwrap().to_string(), text);
        assert_eq!(text.parse::<Number>().unwrap().as_str(), text);
    }
    assert_eq!(
        "9007199254740993".parse::<Number>().unwrap().as_u64(),
        Some(9007199254740993)
    );
    assert_eq!("1e9999".parse::<Number>().unwrap().as_f64(), None);
    assert!(" 1".parse::<Number>().is_err());
    assert!("01".parse::<Number>().is_err());
}
fn encode<T: Serialize + ?Sized>(value: &T) -> Result<String, json::Error> {
    Ok(String::from_utf8(json::marshal(value)?).unwrap())
}
fn decode<T: Deserialize>(text: &str) -> Result<T, json::Error> {
    json::unmarshal(text.as_bytes())
}
#[test]
fn json_output_and_typed_traits() {
    let mut map = BTreeMap::new();
    map.insert("z".to_owned(), vec![1u64, 2, 9007199254740993]);
    assert_eq!(
        String::from_utf8(json::marshal(&map).unwrap()).unwrap(),
        r#"{"z":[1,2,9007199254740993]}"#
    );
    assert_eq!(
        json::unmarshal::<BTreeMap<String, Vec<u64>>>(&json::marshal(&map).unwrap()).unwrap(),
        map
    );
    assert_eq!(
        json::unmarshal::<Option<String>>("null".as_bytes()).unwrap(),
        None
    );
    assert_eq!(
        decode::<Option<String>>(r#""yes""#).unwrap(),
        Some("yes".to_owned())
    );
    assert!(json::unmarshal::<u8>("256".as_bytes()).is_err());
    assert!(json::unmarshal::<u64>("-1".as_bytes()).is_err());
    assert!(json::unmarshal::<u64>("1.0".as_bytes()).is_err());
    assert!(f64::NAN.to_json().is_err());
    assert!(f64::INFINITY.to_json().is_err());
    assert!(bool::from_json(&Value::Bool(true)).unwrap());
}
struct ShortReader<'a>(&'a [u8]);
impl Read for ShortReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.0.is_empty() || buf.is_empty() {
            return Ok(0);
        }
        buf[0] = self.0[0];
        self.0 = &self.0[1..];
        Ok(1)
    }
}
struct BrokenWriter;
impl Write for BrokenWriter {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::BrokenPipe, "test"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn json_io_handles_short_reads_and_write_failures() {
    let v = json::Decoder::new(ShortReader(br#"{"hello":"world"}"#))
        .decode::<Value>()
        .unwrap();
    assert_eq!(v.get("hello").and_then(Value::as_str), Some("world"));
    assert!(json::Encoder::new(BrokenWriter).encode(&v).is_err());
}
#[test]
fn json_arbitrary_bytes_do_not_panic() {
    let mut state = 19u64;
    for length in 0..512 {
        let bytes: Vec<_> = (0..length)
            .map(|_| {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                (state >> 32) as u8
            })
            .collect();
        let _ = json::Value::try_from(&bytes[..]);
    }
}

#[test]
fn json_fixed_arrays_float32_and_number_traits() {
    assert_eq!(encode(&[1u16, 2, 3]).unwrap(), "[1,2,3]");
    assert_eq!(
        json::unmarshal::<[u16; 3]>("[1,2,3]".as_bytes()).unwrap(),
        [1, 2, 3]
    );
    assert_eq!(json::unmarshal::<[u16; 0]>("[]".as_bytes()).unwrap(), []);
    assert!(json::unmarshal::<f32>("1e9999".as_bytes()).is_err());
    assert!(f32::INFINITY.to_json().is_err());
    assert_eq!(json::unmarshal::<f32>("1.5".as_bytes()).unwrap(), 1.5);
    assert_eq!(encode(&Box::new(32)).unwrap(), "32");
    assert_eq!(
        json::unmarshal::<Box<u64>>("32".as_bytes()).unwrap(),
        Box::new(32)
    );
    assert_eq!(
        json::unmarshal::<Number>("1.00e+3".as_bytes())
            .unwrap()
            .as_str(),
        "1.00e+3"
    );
}

#[test]
fn json_reference_slice_and_box_traits_preserve_bounds() {
    let values = [1u8, 2, 255];
    let slice = &values[..];
    assert_eq!(encode(&slice).unwrap(), "[1,2,255]");
    let borrowed = "雪";
    assert_eq!(encode(&borrowed).unwrap(), "\"雪\"");
    let nested = Box::new(vec![Some(255u8), None]);
    assert_eq!(
        decode::<Box<Vec<Option<u8>>>>(&encode(&nested).unwrap()).unwrap(),
        nested
    );
    assert!(json::unmarshal::<Box<[u8; 2]>>("[1,256]".as_bytes()).is_err());
    let invalid: f32 = f32::NEG_INFINITY;
    assert!(encode(&&invalid).is_err());
}
