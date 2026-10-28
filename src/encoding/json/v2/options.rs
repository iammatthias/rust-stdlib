//! The options of `encoding/json/v2`.
//!
//! They share the [`Options`] type with `jsontext`: a set of settings in
//! which later settings take precedence. See `jsontext` for the options
//! that apply to the syntax of the JSON text.
use std::sync::Arc;

use super::funcs::{Marshalers, Unmarshalers};
use crate::encoding::json::jsontext::flags::{self};
pub use crate::encoding::json::jsontext::Options;

/// Go's `JoinOptions`: combines the options in order, later ones winning.
pub fn join_options(srcs: &[Options]) -> Options {
    let mut dst = Options::default();
    dst.join_all(srcs);
    dst
}

/// Go's `DefaultOptionsV2`: the options that are the default of this package
/// (every v1 compatibility flag unspecified but set to the v2 behaviour).
pub fn default_options_v2() -> Options {
    let mut o = Options::default();
    o.flags.presence = flags::DEFAULT_V1_FLAGS;
    o.flags.values = 0;
    o
}

macro_rules! bool_options {
    ($($(#[$doc:meta])* $name:ident => $flag:ident),+ $(,)?) => { $(
        $(#[$doc])*
        pub fn $name(v: bool) -> Options {
            Options::from_bool(flags::$flag, v)
        }
    )+ };
}

bool_options!(
    /// Go's `StringifyNumbers`: marshal and unmarshal JSON numbers as quoted
    /// JSON strings.
    stringify_numbers => STRINGIFY_NUMBERS,
    /// Go's `Deterministic`: sort the members of Go maps when marshaling.
    deterministic => DETERMINISTIC,
    /// Go's `FormatNilSliceAsNull`: marshal a nil Go slice as JSON null
    /// instead of an empty array. Rust has no nil slice, so it has no effect
    /// on `Vec`.
    format_nil_slice_as_null => FORMAT_NIL_SLICE_AS_NULL,
    /// Go's `FormatNilMapAsNull`: marshal a nil Go map as JSON null instead
    /// of an empty object. Rust has no nil map, so it has no effect.
    format_nil_map_as_null => FORMAT_NIL_MAP_AS_NULL,
    /// Go's `OmitZeroStructFields`: omit every zero struct field when
    /// marshaling, as if it had the `omitzero` tag option.
    omit_zero_struct_fields => OMIT_ZERO_STRUCT_FIELDS,
    /// Go's `MatchCaseInsensitiveNames`: match JSON object member names to
    /// struct fields ignoring case when unmarshaling.
    match_case_insensitive_names => MATCH_CASE_INSENSITIVE_NAMES,
    /// Go's `RejectUnknownMembers`: fail when unmarshaling a JSON object
    /// member that no struct field matches.
    reject_unknown_members => REJECT_UNKNOWN_MEMBERS,
);

/// The experimental support for the `format` tag option. Go's v2 package
/// rejects `format` unless built with an experiment; this Rust-only option
/// turns the support on (it is what Go's internal `FormatTagSupported` flag
/// does).
pub fn experimental_support_format_tag(v: bool) -> Options {
    Options::from_bool(flags::FORMAT_TAG_SUPPORTED, v)
}

/// Go's `WithMarshalers`: the marshal functions to use before the default.
pub fn with_marshalers(v: Marshalers) -> Options {
    let mut o = Options::default();
    o.flags.set(flags::MARSHALERS, true);
    o.marshalers = Some(Arc::new(v));
    o
}

/// Go's `WithUnmarshalers`: the unmarshal functions to use before the
/// default.
pub fn with_unmarshalers(v: Unmarshalers) -> Options {
    let mut o = Options::default();
    o.flags.set(flags::UNMARSHALERS, true);
    o.unmarshalers = Some(Arc::new(v));
    o
}

/// A function that builds one [`Options`] setting, as `GetOption` takes:
/// [`deterministic`], [`with_marshalers`], `jsontext::with_indent`, ...
pub trait OptionSetter {
    /// The type of the option's value.
    type Value;
    /// The option's value in `opts` and whether `opts` specifies it.
    fn get(&self, opts: &Options) -> (Self::Value, bool);
}

fn probe_flag(setter: &Options) -> u64 {
    setter.flags.presence & !(flags::MULTILINE)
}

impl OptionSetter for fn(bool) -> Options {
    type Value = bool;
    fn get(&self, opts: &Options) -> (bool, bool) {
        let bit = probe_flag(&self(false));
        let (v, ok) = opts.bool_option(bit);
        if !ok && bit == flags::STRINGIFY_NUMBERS && opts.flags.get(flags::STRING_TAG) {
            return (true, true);
        }
        (v, ok)
    }
}

impl OptionSetter for fn(&str) -> Options {
    type Value = String;
    fn get(&self, opts: &Options) -> (String, bool) {
        let probe = self("");
        let bit = probe_flag(&probe);
        if bit == flags::INDENT {
            if !opts.flags.has(flags::INDENT) {
                return (String::new(), false);
            }
            (opts.indent.clone(), true)
        } else {
            if !opts.flags.has(flags::INDENT_PREFIX) {
                return (String::new(), false);
            }
            (opts.indent_prefix.clone(), true)
        }
    }
}

impl OptionSetter for fn(Marshalers) -> Options {
    type Value = Option<Marshalers>;
    fn get(&self, opts: &Options) -> (Option<Marshalers>, bool) {
        if !opts.flags.has(flags::MARSHALERS) {
            return (None, false);
        }
        (opts.marshalers.as_deref().cloned(), true)
    }
}

impl OptionSetter for fn(Unmarshalers) -> Options {
    type Value = Option<Unmarshalers>;
    fn get(&self, opts: &Options) -> (Option<Unmarshalers>, bool) {
        if !opts.flags.has(flags::UNMARSHALERS) {
            return (None, false);
        }
        (opts.unmarshalers.as_deref().cloned(), true)
    }
}

/// Go's `GetOption`: the value of the option that `setter` builds, and
/// whether `opts` specifies it.
///
/// ```
/// use rust_stdlib::encoding::json::v2;
/// let opts = v2::join_options(&[v2::deterministic(true)]);
/// assert_eq!(v2::get_option(&opts, v2::deterministic as fn(bool) -> _), (true, true));
/// ```
pub fn get_option<S: OptionSetter>(opts: &Options, setter: S) -> (S::Value, bool) {
    setter.get(opts)
}
