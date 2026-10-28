//! Go's `json.Options`: the v1-compatibility switches that Go 1.27 exposes so
//! that `encoding/json/v2` can be asked for (or away from) v1 behaviour.
//!
//! [`marshal_with_options`](super::marshal_with_options) and
//! [`unmarshal_with_options`](super::unmarshal_with_options) start from
//! [`default_options_v1`], exactly like `jsonv2.Marshal(v, json.DefaultOptionsV1(), opts...)`.
//! Options whose behaviour depends on Go-only concepts (method addressability,
//! `time.Time`, reflection-time struct validation, in-place merging) are
//! recorded but cannot change anything here; see the notes in
//! `docs/api/encoding_json.json`.

/// A set of option settings. Settings made later override earlier ones when
/// sets are combined with [`join`](Self::join).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Options {
    specified: u16,
    enabled: u16,
}

#[derive(Clone, Copy)]
pub(crate) enum Flag {
    CallMethodsWithLegacySemantics,
    FormatByteArrayAsArray,
    FormatBytesWithLegacySemantics,
    FormatDurationAsNano,
    MatchCaseSensitiveDelimiter,
    MergeWithLegacySemantics,
    OmitEmptyWithLegacySemantics,
    ParseBytesWithLooseRFC4648,
    ParseTimeWithLooseRFC3339,
    ReportErrorsWithLegacySemantics,
    StringifyWithLegacySemantics,
    UnmarshalArrayFromAnyLength,
}

const ALL_FLAGS: u16 = (1 << 12) - 1;

impl Options {
    fn with(flag: Flag, on: bool) -> Self {
        let bit = 1 << flag as u16;
        Self {
            specified: bit,
            enabled: if on { bit } else { 0 },
        }
    }
    /// Combines two sets; settings in `later` take precedence.
    #[must_use]
    pub fn join(self, later: Options) -> Options {
        Options {
            specified: self.specified | later.specified,
            enabled: (self.enabled & !later.specified) | later.enabled,
        }
    }
    /// The setting of an option, if this set specifies it.
    pub(crate) fn get(self, flag: Flag) -> Option<bool> {
        let bit = 1 << flag as u16;
        (self.specified & bit != 0).then_some(self.enabled & bit != 0)
    }
}

/// The options under which Go's v1 `Marshal` and `Unmarshal` run: all of the
/// v1-compatibility switches are on.
pub fn default_options_v1() -> Options {
    Options {
        specified: ALL_FLAGS,
        enabled: ALL_FLAGS,
    }
}

macro_rules! option_constructors {
    ($($(#[$doc:meta])* $name:ident => $flag:ident),+ $(,)?) => { $(
        $(#[$doc])*
        pub fn $name(on: bool) -> Options {
            Options::with(Flag::$flag, on)
        }
    )+ };
}

option_constructors!(
    /// Go's `CallMethodsWithLegacySemantics`. Rust has no addressability
    /// rules for methods, so this setting is recorded and has no effect.
    call_methods_with_legacy_semantics => CallMethodsWithLegacySemantics,
    /// Go's `FormatByteArrayAsArray`. Fixed-size byte arrays encode as arrays
    /// of numbers (the v1 behaviour); the setting has no effect.
    format_byte_array_as_array => FormatByteArrayAsArray,
    /// Go's `FormatBytesWithLegacySemantics`. [`Bytes`](super::Bytes) is
    /// base64 either way; when off, decoding a JSON array into it is an
    /// error (Rust has no named byte types or marshal methods on bytes for the
    /// other effects).
    format_bytes_with_legacy_semantics => FormatBytesWithLegacySemantics,
    /// Go's `FormatDurationAsNano`. `std::time::Duration` encodes as
    /// nanoseconds; when off it has no JSON form and both directions report
    /// "no default representation", as Go's v2 default does.
    format_duration_as_nano => FormatDurationAsNano,
    /// Go's `MatchCaseSensitiveDelimiter`. When off, `-` and `_` are ignored
    /// in addition to case when matching object keys to struct fields.
    match_case_sensitive_delimiter => MatchCaseSensitiveDelimiter,
    /// Go's `MergeWithLegacySemantics`. Decoding always builds a fresh value,
    /// so there is nothing to merge into; the setting has no effect.
    merge_with_legacy_semantics => MergeWithLegacySemantics,
    /// Go's `OmitEmptyWithLegacySemantics`. When off, `omitempty` omits a
    /// field whose encoding is `null`, `""`, `[]` or `{}` instead of Go's v1
    /// "empty" values.
    omit_empty_with_legacy_semantics => OmitEmptyWithLegacySemantics,
    /// Go's `ParseBytesWithLooseRFC4648`. When off, `\r` and `\n` in the
    /// base64 text of [`Bytes`](super::Bytes) are errors instead of ignored.
    parse_bytes_with_loose_rfc4648 => ParseBytesWithLooseRFC4648,
    /// Go's `ParseTimeWithLooseRFC3339`. There is no time type in this API;
    /// the setting has no effect.
    parse_time_with_loose_rfc3339 => ParseTimeWithLooseRFC3339,
    /// Go's `ReportErrorsWithLegacySemantics`. Errors always have the v1
    /// shape; the setting has no effect.
    report_errors_with_legacy_semantics => ReportErrorsWithLegacySemantics,
    /// Go's `StringifyWithLegacySemantics`. When off, the `string` tag option
    /// only quotes values that encode as JSON numbers.
    stringify_with_legacy_semantics => StringifyWithLegacySemantics,
    /// Go's `UnmarshalArrayFromAnyLength`. When off, a JSON array must have
    /// exactly as many elements as the Rust array it is decoded into.
    unmarshal_array_from_any_length => UnmarshalArrayFromAnyLength,
);
