//! Nullable column types (Go's `NullString`, `NullInt64`, ..., `Null[T]`).
//!
//! Each implements [`Scanner`] and [`Valuer`] exactly as in Go: scanning `nil`
//! clears `valid`; scanning anything else converts like the underlying type
//! and sets `valid` to whether the conversion succeeded.
use super::convert::Scanner;
use super::driver::{Arg, Value, ValueConverter, Valuer, DEFAULT_PARAMETER_CONVERTER};
use super::error::Res;
use crate::time::Time;

macro_rules! null_type {
    ($(#[$doc:meta])* $name:ident, $field:ident: $ty:ty, $zero:expr, |$v:ident| $to_value:expr) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Default)]
        pub struct $name {
            pub $field: $ty,
            /// `valid` is true if the value is not NULL.
            pub valid: bool,
        }

        impl Scanner for $name {
            fn scan(&mut self, value: &Value) -> Res<()> {
                if matches!(value, Value::Null) {
                    self.$field = $zero;
                    self.valid = false;
                    return Ok(());
                }
                let result = self.$field.scan(value);
                self.valid = result.is_ok();
                result
            }
        }

        impl Valuer for $name {
            fn value(&self) -> Res<Value> {
                if !self.valid {
                    return Ok(Value::Null);
                }
                let $v = &self.$field;
                Ok($to_value)
            }
        }

        impl From<$name> for Arg {
            fn from(x: $name) -> Arg {
                Arg::valuer(x)
            }
        }
    };
}

null_type!(
    /// Go's `sql.NullString`.
    NullString, string: String, String::new(), |v| Value::String(v.clone())
);
null_type!(
    /// Go's `sql.NullInt64`.
    NullInt64, int64: i64, 0, |v| Value::Int64(*v)
);
null_type!(
    /// Go's `sql.NullInt32`.
    NullInt32, int32: i32, 0, |v| Value::Int64(i64::from(*v))
);
null_type!(
    /// Go's `sql.NullInt16`.
    NullInt16, int16: i16, 0, |v| Value::Int64(i64::from(*v))
);
null_type!(
    /// Go's `sql.NullByte`.
    NullByte, byte: u8, 0, |v| Value::Int64(i64::from(*v))
);
null_type!(
    /// Go's `sql.NullFloat64`.
    NullFloat64, float64: f64, 0.0, |v| Value::Float64(*v)
);
null_type!(
    /// Go's `sql.NullBool`.
    NullBool, bool: bool, false, |v| Value::Bool(*v)
);
null_type!(
    /// Go's `sql.NullTime`.
    NullTime, time: Time, Time::default(), |v| Value::Time(v.clone())
);

/// Go's `sql.Null[T]`: a value of any scannable type that may be NULL.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Null<T> {
    pub v: T,
    /// `valid` is true if `v` is not NULL.
    pub valid: bool,
}

impl<T: Scanner + Default> Scanner for Null<T> {
    fn scan(&mut self, value: &Value) -> Res<()> {
        if matches!(value, Value::Null) {
            self.v = T::default();
            self.valid = false;
            return Ok(());
        }
        let result = self.v.scan(value);
        self.valid = result.is_ok();
        result
    }
}

impl<T: Clone + Into<Arg> + Send + Sync> Valuer for Null<T> {
    fn value(&self) -> Res<Value> {
        if !self.valid {
            return Ok(Value::Null);
        }
        DEFAULT_PARAMETER_CONVERTER.convert_value(&self.v.clone().into())
    }
}
