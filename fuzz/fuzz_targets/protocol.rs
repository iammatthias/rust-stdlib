#![no_main]
#![forbid(unsafe_code)]
use libfuzzer_sys::fuzz_target;
use rust_stdlib::{
    mime, multipart,
    net::{http, url},
};
fuzz_target!(|data: &[u8]| {
    if data.len() > 8192 {
        return;
    }
    let reader = || http::BufioReader::new(std::io::Cursor::new(data.to_vec()));
    let _ = http::request::read_request(&reader());
    let _ = http::response::read_response(&reader(), None);
    let mut reader = multipart::Reader::new(std::io::BufReader::with_capacity(1, data), "boundary");
    for _ in 0..64 {
        if !matches!(reader.next_part(), Ok(Some(_))) {
            break;
        }
    }
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(value) = mime::MediaType::parse(text) {
            assert_eq!(
                mime::MediaType::parse(&value.encode().unwrap()).unwrap(),
                value
            );
        }
        let _ = mime::parse_parameters(text, mime::Limits::default());
        let _ = http::parse_cookie(text);
        if let Ok(cookie) = http::parse_set_cookie(text) {
            let origin = url::parse("https://example.com/account/login").unwrap();
            let jar = http::cookiejar::Jar::new(None).unwrap();
            jar.set_cookies(&origin, &[cookie]);
            let _ = jar.cookies(&origin);
        }
        if let Ok(parsed) = url::parse(text) {
            let _ = parsed.to_string();
            let _ = parsed.resolve_reference(&parsed);
        }
        let _ = url::parse_query(text);
        let _ = url::query_unescape(text);
        assert_eq!(url::path_unescape(&url::path_escape(text)).unwrap(), text);
    }
});
