//! Local time follows `TZ` as in Go, and `LUTC` prints UTC. Go resolves
//! `time.Local` once per process, so each case runs in a child process with
//! `TZ` and `ZONEINFO` set.
use rust_stdlib::{
    log::{self, Logger},
    time::{self, DateTime},
};
use std::{
    io,
    process::Command,
    sync::{Arc, Mutex},
};

const CHILD: &str = "RUST_STDLIB_LOG_LOCAL_CHILD";
const ZONEINFO: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/time/tzdata/zoneinfo.zip");

#[derive(Clone, Default)]
struct Shared(Arc<Mutex<Vec<u8>>>);
impl io::Write for Shared {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Shared {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

/// 2023-11-14T22:13:20Z. In America/New_York that is 17:13:20 (EST).
fn instant() -> DateTime {
    DateTime::from_unix(1_700_000_000, 0, 0).unwrap()
}

#[test]
fn log_header_and_slog_time_follow_tz() {
    let Ok(expected) = std::env::var(CHILD) else {
        // Parent: run this test again in a child process for each zone.
        for (tz, expected) in [
            ("America/New_York", "ny"),
            ("Asia/Kolkata", "kolkata"),
            ("UTC", "utc"),
        ] {
            let status = Command::new(std::env::current_exe().unwrap())
                .args(["log_header_and_slog_time_follow_tz", "--exact"])
                .env(CHILD, expected)
                .env("TZ", tz)
                .env("ZONEINFO", ZONEINFO)
                .status()
                .unwrap();
            assert!(status.success(), "{tz}");
        }
        return;
    };
    // Expected header clock for the instant in each zone.
    let (date, clock) = match expected.as_str() {
        "ny" => ("2023/11/14", "17:13:20"),
        "kolkata" => ("2023/11/15", "03:43:20"),
        _ => ("2023/11/14", "22:13:20"),
    };
    let utc_clock = "22:13:20";

    let out = Shared::default();
    let logger = Logger::new(out.clone(), "", log::LDATE | log::LTIME);
    logger.output_at(&instant(), None, "local").unwrap();
    assert_eq!(out.text(), format!("{date} {clock} local\n"));

    let out = Shared::default();
    let logger = Logger::new(out.clone(), "", log::LDATE | log::LTIME | log::LUTC);
    logger.output_at(&instant(), None, "utc").unwrap();
    assert_eq!(out.text(), format!("2023/11/14 {utc_clock} utc\n"));

    // slog stamps records with the current time in Local, so the live offset must match.
    let now = time::now();
    let (_, offset) = now.zone();
    let live_zone = if offset == 0 {
        "Z".to_owned()
    } else {
        format!(
            "{}{:02}:{:02}",
            if offset < 0 { '-' } else { '+' },
            offset.abs() / 3600,
            (offset.abs() % 3600) / 60
        )
    };
    let out = Shared::default();
    let logger = rust_stdlib::log::slog::Logger::new(Arc::new(
        rust_stdlib::log::slog::TextHandler::new(out.clone(), None),
    ));
    logger.info("hello", &[]);
    let text = out.text();
    assert!(text.contains(&format!("{live_zone} level=INFO")), "{text}");
}
