//! Tests for `database/sql` and `database/sql/driver`, ported from Go's
//! `convert_test.go`, `driver/types_test.go` and the applicable parts of
//! `sql_test.go`, run against the fake driver of `fakedb_test.go`.
#[path = "../examples/common/fakedb.rs"]
mod fakedb;

use rust_stdlib::context::Context;
use rust_stdlib::database::sql::driver::{self, Arg, Decimal, Form, Value, ValueConverter};
use rust_stdlib::database::sql::{
    self, convert_assign, Error, Null, NullBool, NullByte, NullFloat64, NullInt16, NullInt32,
    NullInt64, NullString, NullTime, RawBytes, Scanner, ERR_CONN_DONE, ERR_NO_ROWS, ERR_TX_DONE,
};
use rust_stdlib::time::{self, Time};
use rust_stdlib::uuid;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn setup() {
    fakedb::register_drivers();
}

static DB_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// A database with a fresh fakedb name holding the `people` table.
fn new_db() -> sql::DB {
    setup();
    let n = DB_COUNTER.fetch_add(1, Ordering::SeqCst);
    let db = sql::DB::open("test", &format!("tests{n}")).unwrap();
    exec(&db, "WIPE", &[]);
    exec(
        &db,
        "CREATE|people|name=string,age=int32,photo=blob,dead=bool,bdate=datetime",
        &[],
    );
    exec(
        &db,
        "INSERT|people|name=Alice,age=?,photo=APHOTO",
        &[1i32.into()],
    );
    exec(
        &db,
        "INSERT|people|name=Bob,age=?,photo=BPHOTO",
        &[2i32.into()],
    );
    exec(
        &db,
        "INSERT|people|name=Chris,age=?,photo=CPHOTO",
        &[3i32.into()],
    );
    db
}

fn exec(db: &sql::DB, q: &str, args: &[Arg]) -> Box<dyn sql::Result> {
    db.exec(q, args).unwrap_or_else(|e| panic!("{q}: {e}"))
}

fn err_text<T>(r: Result<T, Error>) -> String {
    match r {
        Ok(_) => "<no error>".to_string(),
        Err(e) => e.to_string(),
    }
}

// ------------------------------------------------------------ conversions

fn time_value(sec: i64, nsec: i64) -> Value {
    Value::Time(time::unix(sec, nsec).utc())
}

fn check<D: Scanner>(src: Value, mut d: D, want: impl FnOnce(&D) -> bool, label: &str) {
    convert_assign(driver::ScanContext::default(), &mut d, &src)
        .unwrap_or_else(|e| panic!("{label}: {e}"));
    assert!(want(&d), "{label}: unexpected value");
}

fn fails<D: Scanner + Default>(src: Value, want: &str) {
    let mut d = D::default();
    let err = convert_assign(driver::ScanContext::default(), &mut d, &src)
        .expect_err("conversion should fail");
    assert_eq!(err.to_string(), want);
}

/// `*uuid.UUID` destinations, with the texts of Go 1.27's convertAssign.
#[test]
fn uuid_destination() {
    use rust_stdlib::uuid::{self, UUID};
    let text = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6";
    let want = uuid::parse(text).unwrap();
    let s = |x: &str| Value::String(x.to_string());
    let b = |x: &[u8]| Value::Bytes(x.to_vec());
    check(s(text), UUID::default(), |d| *d == want, "string");
    check(
        s(&format!("urn:uuid:{text}")),
        UUID::default(),
        |d| *d == want,
        "urn",
    );
    check(
        b(b"f81d4fae7dec11d0a76500a0c91e6bf6"),
        UUID::default(),
        |d| *d == want,
        "text bytes",
    );
    // Sixteen bytes are the UUID itself, not text.
    check(
        b(b"0123456789abcdef"),
        UUID::default(),
        |d| d.0 == *b"0123456789abcdef",
        "raw bytes",
    );
    fails::<UUID>(
        s("bad"),
        "converting driver.Value type string (\"bad\") to a UUID: invalid uuid",
    );
    fails::<UUID>(
        b(b"bad"),
        "converting driver.Value type []byte (\"bad\") to a UUID: invalid uuid",
    );
    fails::<UUID>(
        b(b""),
        "converting driver.Value type []byte (\"\") to a UUID: invalid uuid",
    );
    fails::<UUID>(
        Value::Int64(5),
        "unsupported Scan, storing driver.Value type int64 into type *uuid.UUID",
    );
    fails::<UUID>(
        Value::Null,
        "unsupported Scan, storing driver.Value type <nil> into type *uuid.UUID",
    );
    check(Value::Null, Some(want), |d| d.is_none(), "nil into *UUID");
    check(
        s(text),
        None::<UUID>,
        |d| *d == Some(want),
        "string into *UUID",
    );
}

/// Go's `TestConversions` table, for the destinations Rust has.
#[test]
fn conversions_table() {
    let s = |x: &str| Value::String(x.to_string());
    let b = |x: &str| Value::Bytes(x.as_bytes().to_vec());
    let i = Value::Int64;
    // Exact conversions.
    check(s("foo"), String::new(), |d| d == "foo", "string");
    check(i(123), 0i64, |d| *d == 123, "int");
    let some_time = time::unix(123, 0);
    check(
        Value::Time(some_time.clone()),
        Time::default(),
        |d| d.equal(&some_time),
        "time",
    );
    // To strings.
    check(b("byteslice"), String::new(), |d| d == "byteslice", "bytes");
    check(i(123), String::new(), |d| d == "123", "int to string");
    check(
        Value::Float64(1.5),
        String::new(),
        |d| d == "1.5",
        "float to string",
    );
    // From time.Time.
    check(
        time_value(1, 0),
        String::new(),
        |d| d == "1970-01-01T00:00:01Z",
        "time to string",
    );
    check(
        Value::Time(
            time::unix(1453874597, 0).in_location(&time::Location::fixed("here", -3600 * 8)),
        ),
        String::new(),
        |d| d == "2016-01-26T22:03:17-08:00",
        "zone time to string",
    );
    check(
        time_value(1, 2),
        String::new(),
        |d| d == "1970-01-01T00:00:01.000000002Z",
        "nanos",
    );
    check(
        Value::Time(Time::default()),
        String::new(),
        |d| d == "0001-01-01T00:00:00Z",
        "zero time",
    );
    check(
        time_value(1, 2),
        Vec::<u8>::new(),
        |d| d == b"1970-01-01T00:00:01.000000002Z",
        "time to bytes",
    );
    check(
        time_value(1, 2),
        Value::Null,
        |d| *d == time_value(1, 2),
        "time to any",
    );
    // To []byte.
    check(Value::Null, b"x".to_vec(), |d| d.is_empty(), "nil to bytes");
    check(
        s("string"),
        Vec::<u8>::new(),
        |d| d == b"string",
        "string to bytes",
    );
    check(i(123), Vec::<u8>::new(), |d| d == b"123", "int to bytes");
    check(
        Value::Float64(1.5),
        Vec::<u8>::new(),
        |d| d == b"1.5",
        "float to bytes",
    );
    // To RawBytes.
    check(
        Value::Null,
        RawBytes(b"x".to_vec()),
        |d| d.0.is_empty(),
        "nil to raw",
    );
    check(i(123), RawBytes::default(), |d| d.0 == b"123", "int to raw");
    check(
        time_value(2, 5),
        RawBytes::default(),
        |d| d.0 == b"1970-01-01T00:00:02.000000005Z",
        "time to raw",
    );
    // Strings to integers.
    check(s("255"), 0u8, |d| *d == 255, "255 to u8");
    fails::<u8>(
        s("256"),
        "converting driver.Value type string (\"256\") to a uint8: value out of range",
    );
    check(s("256"), 0u16, |d| *d == 256, "256 to u16");
    check(s("-1"), 0isize, |d| *d == -1, "-1 to int");
    fails::<isize>(
        s("foo"),
        "converting driver.Value type string (\"foo\") to a int: invalid syntax",
    );
    // int64 to smaller integers.
    check(i(5), 0u8, |d| *d == 5, "5 to u8");
    fails::<u8>(
        i(256),
        "converting driver.Value type int64 (\"256\") to a uint8: value out of range",
    );
    check(i(256), 0u16, |d| *d == 256, "256 to u16");
    fails::<u16>(
        i(65536),
        "converting driver.Value type int64 (\"65536\") to a uint16: value out of range",
    );
    // True and false bools.
    for v in [
        Value::Bool(true),
        s("True"),
        s("TRUE"),
        s("1"),
        i(1),
        b("t"),
    ] {
        check(v, false, |d| *d, "true bool");
    }
    for v in [Value::Bool(false), s("false"), s("FALSE"), s("0"), i(0)] {
        check(v, true, |d| !*d, "false bool");
    }
    fails::<bool>(
        s("yup"),
        "sql/driver: couldn't convert \"yup\" into type bool",
    );
    fails::<bool>(i(2), "sql/driver: couldn't convert 2 into type bool");
    // Floats.
    check(Value::Float64(1.5), 0f64, |d| *d == 1.5, "f64");
    check(i(1), 0f64, |d| *d == 1.0, "int to f64");
    check(Value::Float64(1.5), 0f32, |d| *d == 1.5, "f32");
    check(s("1.5"), 0f32, |d| *d == 1.5, "string to f32");
    check(s("1.5"), 0f64, |d| *d == 1.5, "string to f64");
    // Pointers.
    check(Value::Null, Some(7i64), |d| d.is_none(), "nil pointer");
    check(i(42), None::<i64>, |d| *d == Some(42), "pointer");
    // To interface{}.
    for v in [
        Value::Float64(1.5),
        i(1),
        s("str"),
        b("byteslice"),
        Value::Bool(true),
        Value::Null,
    ] {
        let want = v.clone();
        check(v, Value::String("x".into()), |d| *d == want, "any");
    }
    // Other errors.
    fails::<Time>(
        s("2020"),
        "unsupported Scan, storing driver.Value type string into type *time.Time",
    );
    fails::<i64>(Value::Null, "converting NULL to int64 is unsupported");
    fails::<bool>(
        Value::Null,
        "sql/driver: couldn't convert <nil> (<nil>) into type bool",
    );
}

#[test]
fn null_string_scan_and_value() {
    let mut ns = NullString::default();
    ns.scan(&Value::Bytes(b"foo".to_vec())).unwrap();
    assert!(ns.valid);
    assert_eq!(ns.string, "foo");
    ns.scan(&Value::Null).unwrap();
    assert!(!ns.valid);
    assert_eq!(ns.string, "");
    assert_eq!(
        driver::Valuer::value(&NullString {
            string: "hi".into(),
            valid: true
        })
        .unwrap(),
        Value::String("hi".into())
    );
}

#[test]
fn null_types_follow_go() {
    let mut n = NullInt64::default();
    assert!(n.scan(&Value::String("12x".into())).is_err());
    assert!(!n.valid, "a failed conversion leaves the value invalid");
    n.scan(&Value::Int64(7)).unwrap();
    assert_eq!((n.int64, n.valid), (7, true));
    assert_eq!(driver::Valuer::value(&n).unwrap(), Value::Int64(7));
    n.scan(&Value::Null).unwrap();
    assert_eq!(driver::Valuer::value(&n).unwrap(), Value::Null);

    let mut b = NullBool::default();
    b.scan(&Value::String("true".into())).unwrap();
    assert!(b.bool && b.valid);
    let mut f = NullFloat64::default();
    f.scan(&Value::String("2.5".into())).unwrap();
    assert_eq!(f.float64, 2.5);
    let mut i32v = NullInt32::default();
    assert!(i32v.scan(&Value::Int64(1 << 40)).is_err());
    i32v.scan(&Value::Int64(-5)).unwrap();
    assert_eq!(driver::Valuer::value(&i32v).unwrap(), Value::Int64(-5));
    let mut i16v = NullInt16::default();
    i16v.scan(&Value::Int64(300)).unwrap();
    assert_eq!(i16v.int16, 300);
    let mut by = NullByte::default();
    assert!(by.scan(&Value::Int64(300)).is_err());
    by.scan(&Value::Int64(200)).unwrap();
    assert_eq!(driver::Valuer::value(&by).unwrap(), Value::Int64(200));
    let mut t = NullTime::default();
    t.scan(&time_value(5, 0)).unwrap();
    assert!(t.valid);
    assert_eq!(driver::Valuer::value(&t).unwrap(), time_value(5, 0));

    let mut g: Null<String> = Null::default();
    g.scan(&Value::Int64(5)).unwrap();
    assert_eq!((g.v.as_str(), g.valid), ("5", true));
    assert_eq!(
        driver::Valuer::value(&g).unwrap(),
        Value::String("5".into())
    );
    g.scan(&Value::Null).unwrap();
    assert_eq!((g.v.as_str(), g.valid), ("", false));
}

// ------------------------------------------------------------- converters

fn convert(c: &dyn ValueConverter, a: Arg) -> Result<Value, String> {
    c.convert_value(&a).map_err(|e| e.to_string())
}

/// Go's `driver.TestValueConverters`.
#[test]
fn driver_value_converters() {
    let now = time::now();
    let bool_cases: [(Arg, bool); 14] = [
        ("true".into(), true),
        ("True".into(), true),
        (b"t".as_slice().into(), true),
        (true.into(), true),
        ("1".into(), true),
        (1isize.into(), true),
        (1i64.into(), true),
        (1u16.into(), true),
        ("false".into(), false),
        (false.into(), false),
        ("0".into(), false),
        (0isize.into(), false),
        (0i64.into(), false),
        (0u16.into(), false),
    ];
    for (arg, want) in bool_cases {
        assert_eq!(convert(&driver::BOOL, arg), Ok(Value::Bool(want)));
    }
    assert_eq!(
        convert(&driver::BOOL, "foo".into()),
        Err("sql/driver: couldn't convert \"foo\" into type bool".into())
    );
    assert_eq!(
        convert(&driver::BOOL, 2isize.into()),
        Err("sql/driver: couldn't convert 2 into type bool".into())
    );
    let d = &driver::DEFAULT_PARAMETER_CONVERTER;
    assert_eq!(
        convert(d, Arg::Time(now.clone())),
        Ok(Value::Time(now.clone()))
    );
    assert_eq!(convert(d, Arg::Pointer(None)), Ok(Value::Null));
    assert_eq!(
        convert(d, Arg::Pointer(Some(Box::new(Arg::Int64(42))))),
        Ok(Value::Int64(42))
    );
    assert_eq!(
        convert(d, Arg::Pointer(Some(Box::new(Arg::Time(now.clone()))))),
        Ok(Value::Time(now))
    );
    assert_eq!(convert(d, Arg::Float64(0.1)), Ok(Value::Float64(0.1)));
    assert_eq!(convert(d, Arg::Bytes(vec![1])), Ok(Value::Bytes(vec![1])));
    assert_eq!(
        convert(
            d,
            Arg::Unsupported {
                type_name: "driver.t".into(),
                kind: "struct".into(),
                repr: String::new()
            }
        ),
        Err("unsupported type driver.t, a struct".into())
    );
    assert_eq!(
        convert(
            d,
            Arg::UnsupportedSlice {
                type_name: "driver.is".into(),
                elem_kind: "int".into(),
                repr: String::new()
            }
        ),
        Err("unsupported type driver.is, a slice of int".into())
    );
    assert_eq!(
        convert(d, Arg::Uint64(1 << 63)),
        Err("uint64 values with high bit set are not supported".into())
    );
    assert_eq!(convert(d, Arg::Uint(u64::MAX)), Ok(Value::Int64(-1)));
    // Valuers are called, and sql's Null types are Valuers.
    assert_eq!(
        convert(
            d,
            NullString {
                string: "hi".into(),
                valid: true
            }
            .into()
        ),
        Ok(Value::String("hi".into()))
    );
    assert_eq!(convert(d, NullString::default().into()), Ok(Value::Null));
    // Int32, String, Null and NotNull.
    assert_eq!(convert(&driver::INT32, 5i8.into()), Ok(Value::Int64(5)));
    assert_eq!(
        convert(&driver::INT32, 1i64.wrapping_shl(31).into()),
        Err("sql/driver: value 2147483648 overflows int32".into())
    );
    assert_eq!(convert(&driver::INT32, "12".into()), Ok(Value::Int64(12)));
    assert_eq!(
        convert(&driver::INT32, "x".into()),
        Err("sql/driver: value \"x\" can't be converted to int32".into())
    );
    assert_eq!(
        convert(&driver::STRING, 12i32.into()),
        Ok(Value::String("12".into()))
    );
    let null = driver::Null {
        converter: Box::new(driver::BOOL),
    };
    assert_eq!(convert(&null, Arg::Nil), Ok(Value::Null));
    assert_eq!(convert(&null, true.into()), Ok(Value::Bool(true)));
    let not_null = driver::NotNull {
        converter: Box::new(driver::BOOL),
    };
    assert_eq!(
        convert(&not_null, Arg::Nil),
        Err("nil value not allowed".into())
    );
    assert!(driver::is_value(&Arg::Bytes(vec![])));
    assert!(!driver::is_value(&Arg::Int32(1)));
    assert!(driver::is_scan_value(&Arg::Nil));
    assert_eq!(driver::BOOL.to_string(), "Bool");
}

#[test]
fn driver_results_and_isolation() {
    use driver::Result as _;
    let r = driver::RowsAffected(5);
    assert_eq!(r.rows_affected().unwrap(), 5);
    assert_eq!(
        r.last_insert_id().unwrap_err().to_string(),
        "LastInsertId is not supported by this driver"
    );
    let n = driver::RESULT_NO_ROWS;
    assert_eq!(
        n.last_insert_id().unwrap_err().to_string(),
        "no LastInsertId available after DDL statement"
    );
    assert_eq!(
        n.rows_affected().unwrap_err().to_string(),
        "no RowsAffected available after DDL statement"
    );
    assert_eq!(sql::LEVEL_DEFAULT.to_string(), "Default");
    assert_eq!(sql::LEVEL_SNAPSHOT.to_string(), "Snapshot");
    assert_eq!(sql::LEVEL_LINEARIZABLE.to_string(), "Linearizable");
    assert_eq!(sql::IsolationLevel(42).to_string(), "IsolationLevel(42)");
    assert!(driver::ERR_BAD_CONN.is(&driver::ERR_BAD_CONN));
    let wrapped = Error::wrap("outer", driver::ERR_BAD_CONN);
    assert!(wrapped.is(&driver::ERR_BAD_CONN));
    assert!(!wrapped.is(&driver::ERR_SKIP));
    assert_ne!(Error::new("x"), Error::new("x"));
}

// ------------------------------------------------------------- registry

#[test]
fn drivers_are_sorted_and_register_rejects_duplicates() {
    setup();
    let all = sql::drivers();
    assert!(all.windows(2).all(|w| w[0] <= w[1]), "{all:?}");
    assert!(all.contains(&"test".to_string()) && all.contains(&"testctx".to_string()));
    let dup = std::panic::catch_unwind(|| {
        sql::register("test", Arc::new(fakedb::fdriver(false).clone()));
    });
    assert!(dup.is_err());
    assert_eq!(
        err_text(sql::DB::open("nope", "")),
        "sql: unknown driver \"nope\" (forgotten import?)"
    );
}

// ---------------------------------------------------------------- queries

#[test]
fn query_and_scan() {
    let db = new_db();
    let mut rows = db.query("SELECT|people|age,name|", &[]).unwrap();
    assert_eq!(rows.columns().unwrap(), ["age", "name"]);
    let mut got = Vec::new();
    while let Some(mut row) = rows.next_row().unwrap() {
        let (mut age, mut name) = (0i64, String::new());
        row.scan(&mut [&mut age, &mut name]).unwrap();
        got.push((age, name));
    }
    assert_eq!(
        got,
        [
            (1, "Alice".to_string()),
            (2, "Bob".to_string()),
            (3, "Chris".to_string())
        ]
    );
    // Rows close themselves at the end; Columns then reports it.
    assert_eq!(err_text(rows.columns()), "sql: Rows are closed");
    rows.close().unwrap();
    assert_eq!(db.stats().in_use, 0);
}

#[test]
fn scan_errors_and_destination_counts() {
    let db = new_db();
    let mut rows = db.query("SELECT|people|age,name|", &[]).unwrap();
    let (mut age, mut name) = (0i64, String::new());
    // Scan before Next cannot be written: a row comes only from next_row.
    let mut row = rows.next_row().unwrap().unwrap();
    assert_eq!(
        err_text(row.scan(&mut [&mut age])),
        "sql: expected 2 destination arguments in Scan, not 1"
    );
    // name is not a number: Go names the column in the error.
    let mut name_num = 0i64;
    assert_eq!(
        err_text(row.scan(&mut [&mut age, &mut name_num])),
        "sql: Scan error on column index 1, name \"name\": converting driver.Value type []uint8 (\"Alice\") to a int64: invalid syntax"
    );
    row.scan(&mut [&mut age, &mut name]).unwrap();
    assert_eq!((age, name.as_str()), (1, "Alice"));
    rows.close().unwrap();
    assert_eq!(
        err_text(row.scan(&mut [&mut age, &mut name])),
        "sql: Rows are closed"
    );
}

#[test]
fn query_row_and_err_no_rows() {
    let db = new_db();
    let mut name = String::new();
    db.query_row("SELECT|people|name|age=?", &[2i32.into()])
        .scan(&mut [&mut name])
        .unwrap();
    assert_eq!(name, "Bob");
    let mut row = db.query_row("SELECT|people|name|age=?", &[99i32.into()]);
    assert_eq!(row.scan(&mut [&mut name]).unwrap_err(), ERR_NO_ROWS);
    assert!(row.err().is_ok());
    let mut raw = RawBytes::default();
    assert_eq!(
        err_text(
            db.query_row("SELECT|people|name|age=?", &[1i32.into()])
                .scan(&mut [&mut raw])
        ),
        "sql: RawBytes isn't allowed on Row.Scan"
    );
    let mut bad = db.query_row("SELECT|nope|name|", &[]);
    assert_eq!(
        bad.scan(&mut [&mut name]).unwrap_err().to_string(),
        "fakedb: table \"nope\" doesn't exist"
    );
    assert!(bad.err().is_err());
    // QueryRow takes the first row and leaves no connection busy.
    assert_eq!(db.stats().in_use, 0);
}

#[test]
fn raw_bytes_scan_is_an_independent_copy() {
    let db = new_db();
    let mut rows = db.query("SELECT|people|photo|", &[]).unwrap();
    let mut first = RawBytes::default();
    let mut row = rows.next_row().unwrap().unwrap();
    row.scan(&mut [&mut first]).unwrap();
    // Go forbids a second Scan before Next while a RawBytes is held.
    let mut again = RawBytes::default();
    assert_eq!(
        err_text(row.scan(&mut [&mut again])),
        "sql: Scan called without calling Next (closemuScanHold)"
    );
    assert!(rows.next_row().unwrap().is_some());
    assert_eq!(first.0, b"APHOTO", "the copy outlives the next row");
    rows.close().unwrap();
}

#[test]
fn multiple_result_sets_and_column_types() {
    let db = new_db();
    let mut rows = db
        .query("SELECT|people|name|;SELECT|people|age,dead|", &[])
        .unwrap();
    let cts = rows.column_types().unwrap();
    assert_eq!(cts.len(), 1);
    assert_eq!(cts[0].name(), "name");
    assert_eq!(cts[0].scan_type().name(), "string");
    assert_eq!(cts[0].nullable(), None);
    assert_eq!(cts[0].length(), None);
    assert_eq!(cts[0].database_type_name(), "");
    let mut n = 0;
    while rows.next_row().unwrap().is_some() {
        n += 1;
    }
    assert_eq!(n, 3);
    assert!(rows.next_result_set());
    let cts = rows.column_types().unwrap();
    assert_eq!(
        cts.iter()
            .map(|c| c.scan_type().to_string())
            .collect::<Vec<_>>(),
        ["int32", "bool"]
    );
    assert_eq!(rows.columns().unwrap(), ["age", "dead"]);
    assert!(!rows.next_result_set());
}

#[test]
fn exec_results() {
    let db = new_db();
    let r = exec(&db, "INSERT|people|name=Dan,age=?", &[4i32.into()]);
    assert_eq!(r.rows_affected().unwrap(), 1);
    assert!(r.last_insert_id().is_err());
    assert_eq!(
        err_text(db.exec("INSERT|people|name=Eve,age=?", &[])),
        "sql: expected 1 arguments, got 0"
    );
    assert_eq!(
        err_text(db.exec("INSERT|people|name=Eve,age=?", &["not a number".into()])),
        "sql: converting argument $1 type: sql/driver: value \"not a number\" can't be converted to int32"
    );
    let ddl = exec(&db, "WIPE", &[]);
    assert_eq!(
        ddl.rows_affected().unwrap_err().to_string(),
        "no RowsAffected available after DDL statement"
    );
    assert_eq!(
        err_text(db.exec("BOGUS|x", &[])),
        "fakedb: unsupported command type \"BOGUS\""
    );
}

#[test]
fn named_and_valuer_arguments() {
    let db = new_db();
    exec(
        &db,
        "INSERT|people|name=?name,age=?age",
        &[
            sql::named("name", "Dana").into(),
            sql::named("age", 9i32).into(),
        ],
    );
    let mut age = 0i64;
    db.query_row(
        "SELECT|people|age|name=?name",
        &[sql::named("name", "Dana").into()],
    )
    .scan(&mut [&mut age])
    .unwrap();
    assert_eq!(age, 9);
    assert_eq!(
        err_text(db.exec(
            "INSERT|people|name=?,age=?",
            &[sql::named("1bad", "x").into(), 1i32.into()]
        )),
        "name \"1bad\" does not begin with a letter"
    );
    // A Valuer is converted by the column converter: NullString -> string/nil.
    exec(
        &db,
        "INSERT|people|name=?,age=?",
        &[
            NullString {
                string: "Evan".into(),
                valid: true,
            }
            .into(),
            1i32.into(),
        ],
    );
    let mut name = String::new();
    db.query_row(
        "SELECT|people|name|name=?",
        &[NullString {
            string: "Evan".into(),
            valid: true,
        }
        .into()],
    )
    .scan(&mut [&mut name])
    .unwrap();
    assert_eq!(name, "Evan");
    // A nil pointer argument is NULL.
    exec(
        &db,
        "INSERT|people|name=?,age=?",
        &[Arg::from(None::<String>), 7i32.into()],
    );
}

// ----------------------------------------------------------- transactions

fn tx_status(q: impl Fn(&str, &[Arg]) -> sql::Row) -> String {
    let mut s = String::new();
    q("SELECT|tx_status|tx_status|", &[])
        .scan(&mut [&mut s])
        .unwrap();
    s
}

#[test]
fn commit_rollback_and_err_tx_done() {
    let db = new_db();
    exec(&db, "CREATE|tx_status|tx_status=string", &[]);
    let tx = db.begin().unwrap();
    assert_eq!(tx_status(|q, a| tx.query_row(q, a)), "transaction");
    tx.exec("INSERT|people|name=Tx,age=?", &[9i32.into()])
        .unwrap();
    tx.commit().unwrap();
    assert_eq!(tx.commit().unwrap_err(), ERR_TX_DONE);
    assert_eq!(tx.rollback().unwrap_err(), ERR_TX_DONE);
    assert_eq!(err_text(tx.exec("WIPE", &[])), ERR_TX_DONE.to_string());
    assert_eq!(err_text(tx.query("WIPE", &[])), ERR_TX_DONE.to_string());
    assert_eq!(err_text(tx.prepare("WIPE")), ERR_TX_DONE.to_string());
    let mut n = 0i64;
    db.query_row("SELECT|people|age|name=Tx", &[])
        .scan(&mut [&mut n])
        .unwrap_err();
    db.query_row("SELECT|people|age|name=?", &["Tx".into()])
        .scan(&mut [&mut n])
        .unwrap();
    assert_eq!(n, 9);
    assert_eq!(tx_status(|q, a| db.query_row(q, a)), "autocommit");

    let tx = db.begin().unwrap();
    tx.rollback().unwrap();
    assert_eq!(tx.rollback().unwrap_err(), ERR_TX_DONE);
    assert_eq!(db.stats().in_use, 0);
}

#[test]
fn dropped_tx_rolls_back_and_releases_the_connection() {
    let db = new_db();
    exec(&db, "CREATE|tx_status|tx_status=string", &[]);
    db.set_max_open_conns(1);
    {
        let _tx = db.begin().unwrap();
        assert_eq!(db.stats().in_use, 1);
    }
    assert_eq!(db.stats().in_use, 0);
    assert_eq!(tx_status(|q, a| db.query_row(q, a)), "autocommit");
}

#[test]
fn tx_options_need_driver_support() {
    let db = new_db();
    let ctx = Context::background();
    let opts = sql::TxOptions {
        isolation: sql::LEVEL_SERIALIZABLE,
        read_only: false,
    };
    assert_eq!(
        err_text(db.begin_tx(&ctx, Some(opts))),
        "sql: driver does not support non-default isolation level"
    );
    let ro = sql::TxOptions {
        isolation: sql::LEVEL_DEFAULT,
        read_only: true,
    };
    assert_eq!(
        err_text(db.begin_tx(&ctx, Some(ro))),
        "sql: driver does not support read-only transactions"
    );
    db.begin_tx(&ctx, Some(sql::TxOptions::default()))
        .unwrap()
        .rollback()
        .unwrap();
    assert_eq!(db.stats().in_use, 0);
}

#[test]
fn tx_prepared_statements_end_with_the_transaction() {
    let db = new_db();
    let tx = db.begin().unwrap();
    let stmt = tx.prepare("SELECT|people|name|age=?").unwrap();
    let mut name = String::new();
    stmt.query_row(&[3i32.into()])
        .scan(&mut [&mut name])
        .unwrap();
    assert_eq!(name, "Chris");
    tx.commit().unwrap();
    assert_eq!(
        err_text(stmt.query(&[1i32.into()])),
        "sql: statement is closed"
    );
    // Tx::stmt re-prepares a database statement on the transaction.
    let dbstmt = db.prepare("SELECT|people|name|age=?").unwrap();
    let tx = db.begin().unwrap();
    let txstmt = tx.stmt(&dbstmt);
    txstmt
        .query_row(&[2i32.into()])
        .scan(&mut [&mut name])
        .unwrap();
    assert_eq!(name, "Bob");
    tx.rollback().unwrap();
    assert!(txstmt.query(&[1i32.into()]).is_err());
    // The database statement survives the transaction.
    dbstmt
        .query_row(&[1i32.into()])
        .scan(&mut [&mut name])
        .unwrap();
    assert_eq!(name, "Alice");
    // A statement of another database is refused.
    let other = new_db();
    let tx = other.begin().unwrap();
    assert_eq!(
        err_text(tx.stmt(&dbstmt).query(&[])),
        "sql: Tx.Stmt: statement from different database used"
    );
    tx.rollback().unwrap();
}

#[test]
fn commit_closes_open_rows_with_a_context_error() {
    let db = new_db();
    let tx = db.begin().unwrap();
    let mut rows = tx.query("SELECT|people|name|", &[]).unwrap();
    assert!(rows.next_row().unwrap().is_some());
    tx.commit().unwrap();
    assert_eq!(err_text(rows.next_row().map(|_| ())), "context canceled");
}

#[test]
fn context_cancel_rolls_back_the_transaction() {
    let db = new_db();
    exec(&db, "CREATE|tx_status|tx_status=string", &[]);
    let (ctx, cancel) = Context::background().with_cancel();
    let tx = db.begin_tx(&ctx, None).unwrap();
    tx.exec("INSERT|people|name=Gone,age=?", &[5i32.into()])
        .unwrap();
    cancel();
    // The rollback runs on the transaction's own thread.
    let deadline = Instant::now() + Duration::from_secs(5);
    while db.stats().in_use > 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(db.stats().in_use, 0);
    assert_eq!(tx.commit().unwrap_err(), ERR_TX_DONE);
    assert_eq!(err_text(tx.exec("WIPE", &[])), ERR_TX_DONE.to_string());
}

// ------------------------------------------------------ connections, stmts

#[test]
fn conn_lifecycle() {
    let db = new_db();
    let ctx = Context::background();
    let conn = db.conn(&ctx).unwrap();
    assert_eq!(db.stats().in_use, 1);
    conn.raw(|ci| {
        fakedb::with_fake_conn(ci, |fc| fc.set_skip_dirty_session(true));
        Ok(())
    })
    .unwrap();
    let mut n = 0i64;
    conn.query_row_context(&ctx, "SELECT|people|age|name=Alice", &[])
        .scan(&mut [&mut n])
        .unwrap_err();
    conn.query_row_context(&ctx, "SELECT|people|age|name=?", &["Alice".into()])
        .scan(&mut [&mut n])
        .unwrap();
    assert_eq!(n, 1);
    conn.exec_context(&ctx, "INSERT|people|name=Zed,age=?", &[8i32.into()])
        .unwrap();
    conn.ping_context(&ctx).unwrap();
    let stmt = conn
        .prepare_context(&ctx, "SELECT|people|age|name=?")
        .unwrap();
    stmt.query_row(&["Zed".into()]).scan(&mut [&mut n]).unwrap();
    assert_eq!(n, 8);
    let tx = conn.begin_tx(&ctx, None).unwrap();
    assert_eq!(
        err_text(conn.begin_tx(&ctx, None)),
        "fakedb: already in a transaction"
    );
    tx.commit().unwrap();
    conn.close().unwrap();
    assert_eq!(conn.close().unwrap_err(), ERR_CONN_DONE);
    assert_eq!(err_text(conn.ping_context(&ctx)), ERR_CONN_DONE.to_string());
    assert_eq!(
        err_text(conn.exec_context(&ctx, "WIPE", &[])),
        ERR_CONN_DONE.to_string()
    );
    assert_eq!(
        err_text(conn.query_context(&ctx, "WIPE", &[])),
        ERR_CONN_DONE.to_string()
    );
    assert_eq!(
        err_text(conn.prepare_context(&ctx, "WIPE")),
        ERR_CONN_DONE.to_string()
    );
    assert_eq!(
        err_text(conn.begin_tx(&ctx, None)),
        ERR_CONN_DONE.to_string()
    );
    assert_eq!(err_text(conn.raw(|_| Ok(()))), ERR_CONN_DONE.to_string());
    assert_eq!(db.stats().in_use, 0);
    // The statement reports its connection is gone only on use.
    drop(stmt);
}

#[test]
fn conn_raw_panic_discards_the_connection() {
    let db = new_db();
    let ctx = Context::background();
    let conn = db.conn(&ctx).unwrap();
    let before = db.stats().open_connections;
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = conn.raw(|_| panic!("boom"));
    }));
    assert!(r.is_err());
    assert_eq!(conn.close().unwrap_err(), ERR_CONN_DONE);
    assert_eq!(db.stats().open_connections, before - 1);
}

#[test]
fn prepared_statements_move_between_connections() {
    let db = new_db();
    let stmt = db.prepare("SELECT|people|name|age=?").unwrap();
    assert_eq!(db.stats().open_connections, 1);
    // Hold the cached connection so the statement needs a second one.
    let ctx = Context::background();
    let held = db.conn(&ctx).unwrap();
    let mut name = String::new();
    stmt.query_row(&[2i32.into()])
        .scan(&mut [&mut name])
        .unwrap();
    assert_eq!(name, "Bob");
    assert_eq!(
        db.stats().open_connections,
        2,
        "re-prepared on a new connection"
    );
    held.close().unwrap();
    // Both connections now have the statement; closing it closes both.
    stmt.query_row(&[3i32.into()])
        .scan(&mut [&mut name])
        .unwrap();
    stmt.close().unwrap();
    assert_eq!(
        err_text(stmt.query(&[1i32.into()])),
        "sql: statement is closed"
    );
    stmt.close().unwrap();
    assert_eq!(db.stats().in_use, 0);
    db.close().unwrap();
}

#[test]
fn closing_the_database_closes_idle_connections() {
    let db = new_db();
    let stmt = db.prepare("SELECT|people|name|").unwrap();
    let mut rows = stmt.query(&[]).unwrap();
    // The connection is busy; it closes when the rows do.
    db.close().unwrap();
    db.close().unwrap();
    assert_eq!(err_text(db.ping()), "sql: database is closed");
    while rows.next_row().unwrap().is_some() {}
    rows.close().unwrap();
    stmt.close().unwrap();
    let st = db.stats();
    assert_eq!((st.open_connections, st.idle), (0, 0));
}

// --------------------------------------------------------------- the pool

#[test]
fn pool_limits_and_stats() {
    let db = new_db();
    db.set_max_open_conns(2);
    db.set_max_idle_conns(1);
    let ctx = Context::background();
    let a = db.conn(&ctx).unwrap();
    let b = db.conn(&ctx).unwrap();
    let st = db.stats();
    assert_eq!(
        (st.max_open_connections, st.open_connections, st.in_use),
        (2, 2, 2)
    );
    // A third connection waits; a short deadline gives up.
    let (short, _cancel) = Context::background().with_timeout(Duration::from_millis(30).into());
    assert_eq!(err_text(db.conn(&short)), "context deadline exceeded");
    assert_eq!(db.stats().wait_count, 1);
    assert!(db.stats().wait_duration.as_nanos() > 0);
    a.close().unwrap();
    b.close().unwrap();
    let st = db.stats();
    assert_eq!(
        (st.idle, st.open_connections, st.max_idle_closed),
        (1, 1, 1)
    );
    db.set_max_idle_conns(-1);
    let st = db.stats();
    assert_eq!(
        (st.idle, st.open_connections, st.max_idle_closed),
        (0, 0, 2)
    );
    db.set_max_idle_conns(5);
    db.set_max_open_conns(1);
    assert_eq!(db.stats().max_open_connections, 1);
    db.set_max_open_conns(-3);
    assert_eq!(db.stats().max_open_connections, 0);
}

#[test]
fn a_waiter_receives_a_released_connection() {
    let db = new_db();
    db.set_max_open_conns(1);
    let ctx = Context::background();
    let held = db.conn(&ctx).unwrap();
    let db2 = db.clone();
    let waiter = std::thread::spawn(move || {
        let c = db2.conn(&Context::background()).unwrap();
        c.close().unwrap();
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while db.stats().wait_count == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(2));
    }
    held.close().unwrap();
    waiter.join().unwrap();
    let st = db.stats();
    assert_eq!((st.wait_count, st.open_connections, st.in_use), (1, 1, 0));
}

#[test]
fn context_cancel_wakes_a_blocked_waiter() {
    let db = new_db();
    db.set_max_open_conns(1);
    let held = db.conn(&Context::background()).unwrap();
    let (ctx, cancel) = Context::background().with_cancel();
    let db2 = db.clone();
    let c2 = ctx.clone();
    let waiter = std::thread::spawn(move || err_text(db2.conn(&c2)));
    let deadline = Instant::now() + Duration::from_secs(5);
    while db.stats().wait_count == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(2));
    }
    cancel();
    assert_eq!(waiter.join().unwrap(), "context canceled");
    held.close().unwrap();
    // The pool still works and the abandoned request left nothing behind.
    db.conn(&Context::background()).unwrap().close().unwrap();
}

#[test]
fn concurrent_queries_respect_the_open_limit() {
    let db = new_db();
    db.set_max_open_conns(3);
    let handles: Vec<_> = (0..8)
        .map(|t| {
            let db = db.clone();
            std::thread::spawn(move || {
                for i in 0..40 {
                    let age = 1 + (t + i) % 3;
                    let mut name = String::new();
                    db.query_row("SELECT|people|name|age=?", &[Arg::Int32(age)])
                        .scan(&mut [&mut name])
                        .unwrap();
                    assert!(!name.is_empty());
                    assert!(db.stats().open_connections <= 3);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    let st = db.stats();
    assert_eq!(st.in_use, 0);
    assert!(st.open_connections <= 3);
}

#[test]
fn connection_lifetime_and_idle_time_close_connections() {
    let db = new_db();
    db.set_conn_max_lifetime(time::MILLISECOND * 40);
    let mut n = 0i64;
    db.query_row("SELECT|people|age|name=?", &["Alice".into()])
        .scan(&mut [&mut n])
        .unwrap();
    std::thread::sleep(Duration::from_millis(80));
    // The expired connection is closed at checkout and replaced.
    db.query_row("SELECT|people|age|name=?", &["Bob".into()])
        .scan(&mut [&mut n])
        .unwrap();
    assert_eq!(n, 2);
    assert!(db.stats().max_lifetime_closed >= 1);

    let db = new_db();
    db.set_conn_max_idle_time(time::MILLISECOND * 30);
    db.query_row("SELECT|people|age|name=?", &["Alice".into()])
        .scan(&mut [&mut n])
        .unwrap();
    assert_eq!(db.stats().idle, 1);
    // The cleaner thread wakes at least once a second.
    let deadline = Instant::now() + Duration::from_secs(5);
    while db.stats().open_connections > 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    let st = db.stats();
    assert_eq!((st.open_connections, st.max_idle_time_closed), (0, 1));
    db.close().unwrap();
}

#[test]
fn bad_connections_are_retried() {
    setup();
    let n = DB_COUNTER.fetch_add(1, Ordering::SeqCst);
    let db = sql::DB::open("test", &format!("tests{n};badConn")).unwrap();
    exec(&db, "WIPE", &[]);
    exec(&db, "CREATE|t|a=string", &[]);
    for i in 0..10 {
        exec(&db, "INSERT|t|a=?", &[format!("v{i}").into()]);
    }
    let mut rows = db.query("SELECT|t|a|", &[]).unwrap();
    let mut count = 0;
    while rows.next_row().unwrap().is_some() {
        count += 1;
    }
    assert_eq!(count, 10);
}

#[test]
fn sticky_bad_connection_is_discarded() {
    let db = new_db();
    let ctx = Context::background();
    let conn = db.conn(&ctx).unwrap();
    conn.raw(|ci| {
        fakedb::with_fake_conn(ci, |fc| {
            fc.set_skip_dirty_session(true);
            fc.set_sticky_bad(true);
        });
        Ok(())
    })
    .unwrap();
    let e = conn
        .prepare_context(&ctx, "SELECT|people|name|")
        .map(|_| ())
        .unwrap_err();
    assert!(e.is(&driver::ERR_BAD_CONN));
    // The Conn closed itself and the pool dropped the connection.
    assert_eq!(conn.close().unwrap_err(), ERR_CONN_DONE);
    assert_eq!(db.stats().in_use, 0);
    exec(&db, "WIPE", &[]);
}

#[test]
fn context_cancel_closes_rows() {
    let db = new_db();
    let (ctx, cancel) = Context::background().with_cancel();
    let mut rows = db.query_context(&ctx, "SELECT|people|name|", &[]).unwrap();
    assert!(rows.next_row().unwrap().is_some());
    cancel();
    let deadline = Instant::now() + Duration::from_secs(5);
    while db.stats().in_use > 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(db.stats().in_use, 0);
    assert_eq!(err_text(rows.next_row().map(|_| ())), "context canceled");
    // A cancelled context fails the call itself.
    assert_eq!(
        err_text(db.query_context(&ctx, "SELECT|people|name|", &[])),
        "context canceled"
    );
    assert_eq!(
        err_text(db.exec_context(&ctx, "WIPE", &[])),
        "context canceled"
    );
    assert_eq!(err_text(db.ping_context(&ctx)), "context canceled");
}

#[test]
fn connector_drivers_are_closed_with_the_database() {
    setup();
    let db = sql::DB::open("testctx", "connector-db").unwrap();
    exec(&db, "WIPE", &[]);
    db.ping().unwrap();
    assert!(Arc::strong_count(&db.driver()) >= 1);
    db.close().unwrap();
}

// ------------------------------------------------- driver capability paths

#[derive(Default)]
struct Log(Mutex<Vec<String>>);

impl Log {
    fn add(&self, s: impl Into<String>) {
        self.0.lock().unwrap().push(s.into());
    }
    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }
}

struct MockDriver {
    log: Arc<Log>,
    flavor: &'static str,
}

struct MockConn {
    log: Arc<Log>,
    flavor: &'static str,
}

struct MockStmt {
    log: Arc<Log>,
    inputs: i64,
}

struct MockTx(Arc<Log>);

struct MockRows {
    scanner: bool,
    row: usize,
}

impl driver::Driver for MockDriver {
    fn open(&self, _name: &str) -> Result<Box<dyn driver::Conn>, Error> {
        self.log.add("open");
        Ok(Box::new(MockConn {
            log: self.log.clone(),
            flavor: self.flavor,
        }))
    }
}

impl driver::Conn for MockConn {
    fn prepare(&mut self, query: &str) -> Result<Box<dyn driver::Stmt>, Error> {
        self.log.add(format!("prepare {query}"));
        Ok(Box::new(MockStmt {
            log: self.log.clone(),
            inputs: query.matches('?').count() as i64,
        }))
    }
    fn close(&mut self) -> Result<(), Error> {
        self.log.add("close");
        Ok(())
    }
    fn begin(&mut self) -> Result<Box<dyn driver::Tx>, Error> {
        self.log.add("begin");
        Ok(Box::new(MockTx(self.log.clone())))
    }
    fn as_execer(&mut self) -> Option<&mut dyn driver::Execer> {
        (self.flavor == "execer").then_some(self as &mut dyn driver::Execer)
    }
    fn as_queryer(&mut self) -> Option<&mut dyn driver::Queryer> {
        (self.flavor == "execer").then_some(self as &mut dyn driver::Queryer)
    }
    fn as_conn_begin_tx(&mut self) -> Option<&mut dyn driver::ConnBeginTx> {
        (self.flavor == "full").then_some(self as &mut dyn driver::ConnBeginTx)
    }
    fn as_pinger(&mut self) -> Option<&mut dyn driver::Pinger> {
        (self.flavor == "full").then_some(self as &mut dyn driver::Pinger)
    }
    fn as_named_value_checker(&mut self) -> Option<&mut dyn driver::NamedValueChecker> {
        (self.flavor == "full").then_some(self as &mut dyn driver::NamedValueChecker)
    }
}

impl driver::Execer for MockConn {
    fn exec(&mut self, query: &str, args: &[Value]) -> Result<Box<dyn driver::Result>, Error> {
        self.log.add(format!("Execer.exec {query} {args:?}"));
        if query == "skip" {
            return Err(driver::ERR_SKIP);
        }
        Ok(Box::new(driver::RowsAffected(7)))
    }
}

impl driver::Queryer for MockConn {
    fn query(&mut self, query: &str, args: &[Value]) -> Result<Box<dyn driver::Rows>, Error> {
        self.log.add(format!("Queryer.query {query} {args:?}"));
        Ok(Box::new(MockRows {
            scanner: false,
            row: 0,
        }))
    }
}

impl driver::ConnBeginTx for MockConn {
    fn begin_tx(
        &mut self,
        _ctx: &Context,
        opts: driver::TxOptions,
    ) -> Result<Box<dyn driver::Tx>, Error> {
        self.log.add(format!(
            "begin_tx iso={} ro={}",
            opts.isolation.0, opts.read_only
        ));
        Ok(Box::new(MockTx(self.log.clone())))
    }
}

impl driver::Pinger for MockConn {
    fn ping(&mut self, _ctx: &Context) -> Result<(), Error> {
        self.log.add("ping");
        Ok(())
    }
}

impl driver::NamedValueChecker for MockConn {
    fn check_named_value(&mut self, nv: &mut driver::NamedValue, arg: &Arg) -> Result<(), Error> {
        match arg {
            Arg::String(s) if s == "drop" => Err(driver::ERR_REMOVE_ARGUMENT),
            Arg::Int32(v) => {
                nv.value = Value::String(format!("i32:{v}"));
                Ok(())
            }
            _ => Err(driver::ERR_SKIP),
        }
    }
}

impl driver::Stmt for MockStmt {
    fn close(&mut self) -> Result<(), Error> {
        self.log.add("stmt close");
        Ok(())
    }
    fn num_input(&mut self) -> i64 {
        self.inputs
    }
    fn exec(&mut self, args: &[Value]) -> Result<Box<dyn driver::Result>, Error> {
        self.log.add(format!("stmt exec {args:?}"));
        Ok(Box::new(driver::RowsAffected(args.len() as i64)))
    }
    fn query(&mut self, args: &[Value]) -> Result<Box<dyn driver::Rows>, Error> {
        self.log.add(format!("stmt query {args:?}"));
        Ok(Box::new(MockRows {
            scanner: true,
            row: 0,
        }))
    }
}

impl driver::Tx for MockTx {
    fn commit(&mut self) -> Result<(), Error> {
        self.0.add("commit");
        Ok(())
    }
    fn rollback(&mut self) -> Result<(), Error> {
        self.0.add("rollback");
        Ok(())
    }
}

impl driver::Rows for MockRows {
    fn columns(&self) -> Vec<String> {
        vec!["a".into(), "b".into()]
    }
    fn close(&mut self) -> Result<(), Error> {
        Ok(())
    }
    fn next(&mut self, dest: &mut [Value]) -> Result<(), Error> {
        if self.row == 2 {
            return Err(driver::EOF);
        }
        self.row += 1;
        dest[0] = Value::Int64(self.row as i64);
        dest[1] = Value::String("x".into());
        Ok(())
    }
    fn as_rows_column_scanner(&mut self) -> Option<&mut dyn driver::RowsColumnScanner> {
        self.scanner
            .then_some(self as &mut dyn driver::RowsColumnScanner)
    }
    fn as_rows_column_type_database_type_name(
        &self,
    ) -> Option<&dyn driver::RowsColumnTypeDatabaseTypeName> {
        Some(self)
    }
    fn as_rows_column_type_length(&self) -> Option<&dyn driver::RowsColumnTypeLength> {
        Some(self)
    }
    fn as_rows_column_type_nullable(&self) -> Option<&dyn driver::RowsColumnTypeNullable> {
        Some(self)
    }
    fn as_rows_column_type_precision_scale(
        &self,
    ) -> Option<&dyn driver::RowsColumnTypePrecisionScale> {
        Some(self)
    }
    fn as_rows_column_type_scan_type(&self) -> Option<&dyn driver::RowsColumnTypeScanType> {
        Some(self)
    }
}

impl driver::RowsColumnScanner for MockRows {
    fn next_row(&mut self) -> Result<(), Error> {
        if self.row == 2 {
            return Err(driver::EOF);
        }
        self.row += 1;
        Ok(())
    }
    fn scan_column(
        &mut self,
        scan_ctx: driver::ScanContext,
        index: usize,
        dest: &mut dyn Scanner,
    ) -> Result<(), Error> {
        let v = if index == 0 {
            Value::Int64(100 + self.row as i64)
        } else {
            Value::String("scanned".into())
        };
        convert_assign(scan_ctx, dest, &v)
    }
}

impl driver::RowsColumnTypeDatabaseTypeName for MockRows {
    fn column_type_database_type_name(&self, index: usize) -> String {
        ["INT", "VARCHAR"][index].to_string()
    }
}
impl driver::RowsColumnTypeLength for MockRows {
    fn column_type_length(&self, index: usize) -> Option<i64> {
        (index == 1).then_some(32)
    }
}
impl driver::RowsColumnTypeNullable for MockRows {
    fn column_type_nullable(&self, index: usize) -> Option<bool> {
        Some(index == 1)
    }
}
impl driver::RowsColumnTypePrecisionScale for MockRows {
    fn column_type_precision_scale(&self, index: usize) -> Option<(i64, i64)> {
        (index == 0).then_some((10, 2))
    }
}
impl driver::RowsColumnTypeScanType for MockRows {
    fn column_type_scan_type(&self, index: usize) -> driver::ScanType {
        [driver::ScanType::INT64, driver::ScanType::STRING][index].clone()
    }
}

fn mock_db(flavor: &'static str) -> (sql::DB, Arc<Log>) {
    let log = Arc::new(Log::default());
    struct Connect(Arc<Log>, &'static str);
    impl driver::Connector for Connect {
        fn connect(&self, _ctx: &Context) -> Result<Box<dyn driver::Conn>, Error> {
            Ok(Box::new(MockConn {
                log: self.0.clone(),
                flavor: self.1,
            }))
        }
        fn driver(&self) -> Arc<dyn driver::Driver> {
            Arc::new(MockDriver {
                log: self.0.clone(),
                flavor: self.1,
            })
        }
    }
    (
        sql::DB::from_connector(Box::new(Connect(log.clone(), flavor))),
        log,
    )
}

#[test]
fn optional_interfaces_are_used_when_present() {
    let (db, log) = mock_db("execer");
    // Execer (deprecated, no context) with ErrSkip falling back to a Stmt.
    let r = db.exec("run", &[5i64.into(), "a".into()]).unwrap();
    assert_eq!(r.rows_affected().unwrap(), 7);
    assert_eq!(log.take(), ["Execer.exec run [Int64(5), String(\"a\")]"]);
    let r = db.exec("skip", &[]).unwrap();
    assert_eq!(r.rows_affected().unwrap(), 0);
    assert_eq!(
        log.take(),
        [
            "Execer.exec skip []",
            "prepare skip",
            "stmt exec []",
            "stmt close"
        ]
    );
    // A cancelled context stops before a non-context Execer is called.
    let (ctx, cancel) = Context::background().with_cancel();
    cancel();
    assert_eq!(
        err_text(db.exec_context(&ctx, "run", &[])),
        "context canceled"
    );
    assert!(log.take().is_empty());
    // Queryer, then rows without a column scanner use Next + convert_assign.
    let mut rows = db.query("q", &[]).unwrap();
    let (mut a, mut b) = (0i64, String::new());
    let mut row = rows.next_row().unwrap().unwrap();
    row.scan(&mut [&mut a, &mut b]).unwrap();
    assert_eq!((a, b.as_str()), (1, "x"));
    // Non-context Begin; options other than the default are refused.
    drop(rows);
    let tx = db.begin().unwrap();
    tx.commit().unwrap();
    assert_eq!(
        err_text(db.begin_tx(
            &ctx_ok(),
            Some(sql::TxOptions {
                isolation: sql::LEVEL_SNAPSHOT,
                read_only: false
            })
        )),
        "sql: driver does not support non-default isolation level"
    );
    assert!(log.take().contains(&"commit".to_string()));
    // Named parameters need a context-aware or named-value-aware driver.
    assert_eq!(
        err_text(db.exec("run", &[sql::named("x", 1i64).into()])),
        "sql: driver does not support the use of Named Parameters"
    );
}

fn ctx_ok() -> Context {
    Context::background()
}

#[test]
fn full_featured_driver_paths() {
    let (db, log) = mock_db("full");
    db.ping().unwrap();
    assert!(log.take().contains(&"ping".to_string()));
    let tx = db
        .begin_tx(
            &ctx_ok(),
            Some(sql::TxOptions {
                isolation: sql::LEVEL_SERIALIZABLE,
                read_only: true,
            }),
        )
        .unwrap();
    assert!(log.take().contains(&"begin_tx iso=6 ro=true".to_string()));
    tx.rollback().unwrap();
    // NamedValueChecker routes: handled, removed, skipped to the default.
    let stmt = db.prepare("insert ? ?").unwrap();
    let r = stmt.exec(&[Arg::Int32(4), 9i64.into()]).unwrap();
    assert_eq!(r.rows_affected().unwrap(), 2);
    assert!(log
        .take()
        .iter()
        .any(|l| l == "stmt exec [String(\"i32:4\"), Int64(9)]"));
    // ErrRemoveArgument drops the argument before the count is checked.
    let r = stmt
        .exec(&["drop".into(), Arg::Int32(1), 2i64.into()])
        .unwrap();
    assert_eq!(r.rows_affected().unwrap(), 2);
    assert_eq!(
        err_text(stmt.exec(&[1i64.into()])),
        "sql: expected 2 arguments, got 1"
    );
    drop(stmt);
    // Rows with a column scanner and full column metadata.
    let stmt = db.prepare("select").unwrap();
    let mut rows = stmt.query(&[]).unwrap();
    let cts = rows.column_types().unwrap();
    assert_eq!(cts[0].database_type_name(), "INT");
    assert_eq!(cts[1].database_type_name(), "VARCHAR");
    assert_eq!((cts[0].length(), cts[1].length()), (None, Some(32)));
    assert_eq!(
        (cts[0].nullable(), cts[1].nullable()),
        (Some(false), Some(true))
    );
    assert_eq!(
        (cts[0].decimal_size(), cts[1].decimal_size()),
        (Some((10, 2)), None)
    );
    assert_eq!(cts[0].scan_type().name(), "int64");
    let mut row = rows.next_row().unwrap().unwrap();
    let (mut a, mut b) = (0i64, String::new());
    row.scan(&mut [&mut a, &mut b]).unwrap();
    assert_eq!((a, b.as_str()), (101, "scanned"));
    let mut bad = 0u8;
    let mut text = 0i64;
    assert_eq!(
        err_text(row.scan(&mut [&mut bad, &mut text])),
        "sql: Scan error on column index 1, name \"b\": converting driver.Value type string (\"scanned\") to a int64: invalid syntax"
    );
    while rows.next_row().unwrap().is_some() {}
}

#[test]
fn errors_unwrap_on_boxed_results_and_handles() {
    let db = new_db();
    assert!(!db.exec("BOGUS|x", &[]).unwrap_err().to_string().is_empty());
    db.query("BOGUS|x", &[]).unwrap_err();
    db.prepare("BOGUS|x").unwrap_err();
    let tx = db.begin().unwrap();
    tx.commit().unwrap();
    assert_eq!(format!("{:?}", exec(&db, "WIPE", &[])), "dyn sql::Result");
    let dres: Box<dyn driver::Result> = Box::new(driver::RowsAffected(1));
    assert_eq!(format!("{dres:?}"), "dyn driver::Result");
    db.close().unwrap();
    db.begin().unwrap_err();
    db.conn(&Context::background()).unwrap_err();
}

#[test]
fn buffered_rows_stream_in_order_with_column_info() {
    use driver::{BufferedRows, ColumnInfo, Rows};
    let r = BufferedRows::new(
        vec!["a".into(), "b".into()],
        vec![
            vec![Value::Int64(1), Value::Null],
            vec![Value::Int64(2), Value::String("x".into())],
        ],
    );
    assert!(r.as_rows_column_type_nullable().is_none());
    let mut r = r.with_column_info(vec![
        ColumnInfo {
            nullable: Some(false),
            ..ColumnInfo::default()
        },
        ColumnInfo {
            database_type_name: "TEXT".into(),
            nullable: Some(true),
            ..ColumnInfo::default()
        },
    ]);
    assert_eq!(r.columns(), ["a", "b"]);
    assert_eq!(
        r.as_rows_column_type_database_type_name()
            .unwrap()
            .column_type_database_type_name(1),
        "TEXT"
    );
    let mut dest = [Value::Null, Value::Null];
    r.next(&mut dest).unwrap();
    assert_eq!(dest, [Value::Int64(1), Value::Null]);
    r.next(&mut dest).unwrap();
    assert_eq!(dest[1], Value::String("x".into()));
    assert_eq!(r.next(&mut dest).unwrap_err(), driver::EOF);
    assert!(r.next(&mut [Value::Null]).is_err());
}

#[test]
fn args_are_clone() {
    use rust_stdlib::database::sql::named;
    let args = vec![
        Arg::Int(1),
        Arg::String("x".into()),
        Arg::valuer(Value::Int64(9)),
        Arg::Pointer(Some(Box::new(Arg::Bool(true)))),
        Arg::Named(Box::new(named("n", Arg::valuer(Value::Int64(3))))),
    ];
    let copy = args.clone();
    assert_eq!(format!("{args:?}"), format!("{copy:?}"));
    let a = named("k", 5i64);
    assert_eq!(format!("{:?}", a.clone()), format!("{a:?}"));
    let Arg::Valuer(v) = &copy[2] else { panic!() };
    assert_eq!(v.value().unwrap(), Value::Int64(9));
}

/// A money amount in cents: an application decimal type.
#[derive(Debug, Default, PartialEq)]
struct Cents(i64);

impl driver::Decompose for Cents {
    fn decompose(&self) -> Decimal {
        let mag = self.0.unsigned_abs().to_be_bytes();
        let start = mag.iter().position(|&b| b != 0).unwrap_or(mag.len());
        Decimal {
            form: Form::Finite,
            negative: self.0 < 0,
            coefficient: mag[start..].to_vec(),
            exponent: -2,
        }
    }
}

impl driver::Compose for Cents {
    fn compose(&mut self, d: &Decimal) -> Result<(), Error> {
        if d.form != Form::Finite || d.exponent != -2 || d.coefficient.len() > 7 {
            return Err(Error::new(format!("cannot represent {d} in cents")));
        }
        let mag = d
            .coefficient
            .iter()
            .fold(0i64, |acc, &b| acc << 8 | i64::from(b));
        self.0 = if d.negative { -mag } else { mag };
        Ok(())
    }
}

#[test]
fn decimal_and_uuid_arguments_reach_the_driver() {
    let (db, log) = mock_db("plain");
    let u = uuid::must_parse("6ba7b810-9dad-11d1-80b4-00c04fd430c8");
    let cents = Arg::decimal(&Cents(-256));
    db.exec(
        "ins ? ? ? ?",
        &[cents.clone(), u.into(), Some(cents).into(), Some(u).into()],
    )
    .unwrap();
    let dec =
        "Decimal(Decimal { form: Finite, negative: true, coefficient: [1, 0], exponent: -2 })";
    let id = "String(\"6ba7b810-9dad-11d1-80b4-00c04fd430c8\")";
    assert_eq!(
        log.take(),
        [
            "prepare ins ? ? ? ?".to_string(),
            format!("stmt exec [{dec}, {id}, {dec}, {id}]"),
            "stmt close".to_string(),
        ]
    );
}

/// An application Scanner beside the blanket Scanner for Compose types.
#[derive(Default)]
struct Kind(&'static str);

impl Scanner for Kind {
    fn scan(&mut self, src: &Value) -> Result<(), Error> {
        self.0 = src.type_name();
        Ok(())
    }
}

#[test]
fn decimal_converts_like_go() {
    let d = |form, negative, coefficient: &[u8], exponent| Decimal {
        form,
        negative,
        coefficient: coefficient.to_vec(),
        exponent,
    };
    assert!(driver::is_value(&Arg::Decimal(Decimal::default())));
    assert!(!driver::is_value(&Arg::Uuid(Default::default())));
    let texts: Vec<String> = [
        d(Form::Finite, true, &[1, 0], -2),
        d(Form::Finite, false, &[0x30, 0x39], 3),
        d(Form::Finite, false, &[1], -7),
        d(Form::Finite, false, &[], -3),
        d(Form::Infinite, true, &[], 0),
        d(Form::NaN, false, &[], 0),
    ]
    .iter()
    .map(Decimal::to_string)
    .collect();
    assert_eq!(
        texts,
        ["-2.56", "1.2345E+7", "1E-7", "0.000", "-Infinity", "NaN"]
    );

    let src = Value::Decimal(d(Form::Finite, true, &[1, 0], -2));
    let ctx = driver::ScanContext::default;
    let mut cents = Cents(0);
    convert_assign(ctx(), &mut cents, &src).unwrap();
    assert_eq!(cents, Cents(-256));
    let mut copy = Decimal::default();
    convert_assign(ctx(), &mut copy, &src).unwrap();
    assert_eq!(Value::Decimal(copy), src);
    let mut kind = Kind::default();
    convert_assign(ctx(), &mut kind, &src).unwrap();
    assert_eq!(kind.0, "driver.Decimal");
    let mut f = 0f64;
    convert_assign(ctx(), &mut f, &src).unwrap();
    assert_eq!(f, -2.56);
    let mut s = String::new();
    assert_eq!(
        convert_assign(ctx(), &mut s, &src).unwrap_err().to_string(),
        "unsupported Scan, storing driver.Value type driver.Decimal into type *string"
    );
    // std::any::type_name names the destination and Rust does not guarantee
    // its exact text, so only the part this crate writes is asserted.
    let message = convert_assign(ctx(), &mut cents, &Value::Int64(5))
        .unwrap_err()
        .to_string();
    assert!(
        message.starts_with("unsupported Scan, storing driver.Value type int64 into type *")
            && message.ends_with("Cents"),
        "{message}"
    );
    assert_eq!(
        convert_assign(
            ctx(),
            &mut cents,
            &Value::Decimal(d(Form::NaN, false, &[], 0))
        )
        .unwrap_err()
        .to_string(),
        "cannot represent NaN in cents"
    );
}
