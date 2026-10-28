//! Go's `encoding/json/internal/jsonflags`: the boolean option bits shared by
//! `jsontext` and `json/v2`, with presence tracking so that an unspecified
//! option differs from one set to false.
#![allow(dead_code)]

// Encoder and decoder flags.
pub(crate) const ALLOW_DUPLICATE_NAMES: u64 = 1 << 1;
pub(crate) const ALLOW_INVALID_UTF8: u64 = 1 << 2;
pub(crate) const WITHIN_ARSHAL_CALL: u64 = 1 << 3;
pub(crate) const OMIT_TOP_LEVEL_NEWLINE: u64 = 1 << 4;
pub(crate) const PRESERVE_RAW_STRINGS: u64 = 1 << 5;
pub(crate) const CANONICALIZE_RAW_INTS: u64 = 1 << 6;
pub(crate) const CANONICALIZE_RAW_FLOATS: u64 = 1 << 7;
pub(crate) const REORDER_RAW_OBJECTS: u64 = 1 << 8;
pub(crate) const ESCAPE_FOR_HTML: u64 = 1 << 9;
pub(crate) const ESCAPE_FOR_JS: u64 = 1 << 10;
pub(crate) const MULTILINE: u64 = 1 << 11;
pub(crate) const SPACE_AFTER_COLON: u64 = 1 << 12;
pub(crate) const SPACE_AFTER_COMMA: u64 = 1 << 13;
pub(crate) const INDENT: u64 = 1 << 14;
pub(crate) const INDENT_PREFIX: u64 = 1 << 15;
pub(crate) const BYTE_LIMIT: u64 = 1 << 16;
pub(crate) const DEPTH_LIMIT: u64 = 1 << 17;
const MAX_CODER_FLAG: u64 = 1 << 18;

// Marshal and Unmarshal flags (v2).
pub(crate) const STRINGIFY_NUMBERS: u64 = MAX_CODER_FLAG;
pub(crate) const DETERMINISTIC: u64 = STRINGIFY_NUMBERS << 1;
pub(crate) const FORMAT_NIL_MAP_AS_NULL: u64 = DETERMINISTIC << 1;
pub(crate) const FORMAT_NIL_SLICE_AS_NULL: u64 = FORMAT_NIL_MAP_AS_NULL << 1;
pub(crate) const OMIT_ZERO_STRUCT_FIELDS: u64 = FORMAT_NIL_SLICE_AS_NULL << 1;
pub(crate) const MATCH_CASE_INSENSITIVE_NAMES: u64 = OMIT_ZERO_STRUCT_FIELDS << 1;
pub(crate) const REJECT_UNKNOWN_MEMBERS: u64 = MATCH_CASE_INSENSITIVE_NAMES << 1;
pub(crate) const MARSHALERS: u64 = REJECT_UNKNOWN_MEMBERS << 1;
pub(crate) const UNMARSHALERS: u64 = MARSHALERS << 1;
pub(crate) const STRING_TAG: u64 = UNMARSHALERS << 1;
pub(crate) const FORMAT_TAG: u64 = STRING_TAG << 1;
pub(crate) const FORMAT_TAG_SUPPORTED: u64 = FORMAT_TAG << 1;
const MAX_ARSHAL_V2_FLAG: u64 = FORMAT_TAG_SUPPORTED << 1;

// Marshal and Unmarshal flags (v1 compatibility).
pub(crate) const CALL_METHODS_WITH_LEGACY_SEMANTICS: u64 = MAX_ARSHAL_V2_FLAG;
pub(crate) const FORMAT_BYTE_ARRAY_AS_ARRAY: u64 = CALL_METHODS_WITH_LEGACY_SEMANTICS << 1;
pub(crate) const FORMAT_BYTES_WITH_LEGACY_SEMANTICS: u64 = FORMAT_BYTE_ARRAY_AS_ARRAY << 1;
pub(crate) const FORMAT_DURATION_AS_NANO: u64 = FORMAT_BYTES_WITH_LEGACY_SEMANTICS << 1;
pub(crate) const MATCH_CASE_SENSITIVE_DELIMITER: u64 = FORMAT_DURATION_AS_NANO << 1;
pub(crate) const MERGE_WITH_LEGACY_SEMANTICS: u64 = MATCH_CASE_SENSITIVE_DELIMITER << 1;
pub(crate) const OMIT_EMPTY_WITH_LEGACY_SEMANTICS: u64 = MERGE_WITH_LEGACY_SEMANTICS << 1;
pub(crate) const PARSE_BYTES_WITH_LOOSE_RFC4648: u64 = OMIT_EMPTY_WITH_LEGACY_SEMANTICS << 1;
pub(crate) const PARSE_TIME_WITH_LOOSE_RFC3339: u64 = PARSE_BYTES_WITH_LOOSE_RFC4648 << 1;
pub(crate) const REPORT_ERRORS_WITH_LEGACY_SEMANTICS: u64 = PARSE_TIME_WITH_LOOSE_RFC3339 << 1;
pub(crate) const STRINGIFY_WITH_LEGACY_SEMANTICS: u64 = REPORT_ERRORS_WITH_LEGACY_SEMANTICS << 1;
pub(crate) const UNMARSHAL_ANY_WITH_RAW_NUMBER: u64 = STRINGIFY_WITH_LEGACY_SEMANTICS << 1;
pub(crate) const UNMARSHAL_ARRAY_FROM_ANY_LENGTH: u64 = UNMARSHAL_ANY_WITH_RAW_NUMBER << 1;

pub(crate) const NON_BOOLEAN_FLAGS: u64 =
    INDENT | INDENT_PREFIX | BYTE_LIMIT | DEPTH_LIMIT | MARSHALERS | UNMARSHALERS | FORMAT_TAG;

/// The flags that default to true under v1 semantics.
pub(crate) const DEFAULT_V1_FLAGS: u64 = ALLOW_DUPLICATE_NAMES
    | ALLOW_INVALID_UTF8
    | ESCAPE_FOR_HTML
    | ESCAPE_FOR_JS
    | PRESERVE_RAW_STRINGS
    | DETERMINISTIC
    | FORMAT_NIL_MAP_AS_NULL
    | FORMAT_NIL_SLICE_AS_NULL
    | MATCH_CASE_INSENSITIVE_NAMES
    | CALL_METHODS_WITH_LEGACY_SEMANTICS
    | FORMAT_BYTE_ARRAY_AS_ARRAY
    | FORMAT_BYTES_WITH_LEGACY_SEMANTICS
    | FORMAT_DURATION_AS_NANO
    | MATCH_CASE_SENSITIVE_DELIMITER
    | MERGE_WITH_LEGACY_SEMANTICS
    | OMIT_EMPTY_WITH_LEGACY_SEMANTICS
    | PARSE_BYTES_WITH_LOOSE_RFC4648
    | PARSE_TIME_WITH_LOOSE_RFC3339
    | REPORT_ERRORS_WITH_LEGACY_SEMANTICS
    | STRINGIFY_WITH_LEGACY_SEMANTICS
    | UNMARSHAL_ARRAY_FROM_ANY_LENGTH;

pub(crate) const ANY_WHITESPACE: u64 = MULTILINE | SPACE_AFTER_COLON | SPACE_AFTER_COMMA;
pub(crate) const ANY_ESCAPE: u64 = ESCAPE_FOR_HTML | ESCAPE_FOR_JS;
pub(crate) const CANONICALIZE_NUMBERS: u64 = CANONICALIZE_RAW_INTS | CANONICALIZE_RAW_FLOATS;
pub(crate) const TAG_FLAGS: u64 = STRING_TAG | FORMAT_TAG;

/// A set of boolean flags, each individually true, false or unspecified.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Flags {
    pub(crate) presence: u64,
    pub(crate) values: u64,
}

impl Flags {
    /// Joins two sets such that the latter takes precedence.
    pub(crate) fn join(&mut self, src: Flags) {
        self.presence |= src.presence;
        self.values &= !src.presence;
        self.values |= src.values;
    }
    /// Sets the presence and value of the flag bits `f` to `on`.
    pub(crate) fn set(&mut self, f: u64, on: bool) {
        self.presence |= f;
        self.values &= !f;
        if on {
            self.values |= f;
        }
    }
    /// Reports whether the flag (or any of the flags) is true.
    pub(crate) fn get(&self, f: u64) -> bool {
        self.values & f > 0
    }
    /// Reports whether the flag (or any of the flags) is specified.
    pub(crate) fn has(&self, f: u64) -> bool {
        self.presence & f > 0
    }
    /// Clears both the presence and the value of the flags.
    pub(crate) fn clear(&mut self, f: u64) {
        self.presence &= !f;
        self.values &= !f;
    }
}
