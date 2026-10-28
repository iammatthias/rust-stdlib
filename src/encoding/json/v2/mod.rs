//! Go's `encoding/json/v2`: a JSON library built on [`jsontext`] that maps
//! typed values to JSON and back.
//!
//! [`marshal`] writes a value that implements [`MarshalTo`] as JSON and
//! [`unmarshal`] reads JSON into a value that implements [`UnmarshalFrom`],
//! updating it in place (so existing struct fields, map entries and pointees
//! are merged with, as Go's rules say). Both take [`Options`], shared with
//! `jsontext`; the options of this package are [`deterministic`],
//! [`stringify_numbers`], [`omit_zero_struct_fields`],
//! [`match_case_insensitive_names`], [`reject_unknown_members`] and the rest
//! listed here.
//!
//! Go finds the conversion of a value with `reflect`. Here the standard
//! types implement the two traits and the `Serialize` and `Deserialize`
//! derives of `rust-stdlib-derive` implement them for structs, reading the
//! same `#[json(...)]` field options as Go's struct tags: `omitempty`,
//! `omitzero`, `string`, `case:ignore`, `case:strict`, `embed` (the derive
//! spells it `inline` or `unknown`), and `format:...`. A type that wants to
//! write its own JSON implements [`Marshaler`] or [`MarshalerTo`] and
//! returns it from [`MarshalTo::as_marshaler`] or
//! [`MarshalTo::as_marshaler_to`]; the unmarshaling hooks work alike.
//!
//! Differences from Go: Rust has no nil slice or map, so an empty `Vec` or
//! map stands for both Go's nil and its empty value; Go's interface-typed
//! `MarshalFunc` and `UnmarshalFunc` arguments become exact types; the
//! `reflect.Type` in a [`SemanticError`] is a [`TypeInfo`] naming the Go
//! type; `any` is [`Any`]; the result of [`marshal`] is only the error when
//! it fails; the experimental `format` tag option is rejected unless
//! [`experimental_support_format_tag`] is set, as in Go; and
//! `time.Time`/`time.Duration` formats and the v1 compatibility flags are
//! not supported.
mod any;
mod arshal;
mod containers;
mod errors;
mod fold;
mod funcs;
mod methods;
mod options;
mod scalars;
mod structs;
mod typeinfo;

pub use super::jsontext;
pub use any::Any;
pub use arshal::{
    marshal, marshal_encode, marshal_value, marshal_write, unmarshal, unmarshal_decode,
    unmarshal_read, unmarshal_value, MarshalTo, UnmarshalFrom,
};
pub use errors::{SemanticError, ERR_UNKNOWN_NAME};
pub use funcs::{
    join_marshalers, join_unmarshalers, marshal_func, marshal_to_func, unmarshal_from_func,
    unmarshal_func, Marshalers, Unmarshalers,
};
pub use methods::{
    Marshaler, MarshalerTo, TextAppender, TextMarshaler, TextUnmarshaler, Unmarshaler,
    UnmarshalerFrom,
};
pub use options::{
    default_options_v2, deterministic, experimental_support_format_tag, format_nil_map_as_null,
    format_nil_slice_as_null, get_option, join_options, match_case_insensitive_names,
    omit_zero_struct_fields, reject_unknown_members, stringify_numbers, with_marshalers,
    with_unmarshalers, OptionSetter, Options,
};
pub use structs::{
    marshal_struct, unmarshal_struct, EmbedAccess, EmbedAccessMut, FallbackMarshal,
    FallbackUnmarshal, FieldDesc, FieldValue, FieldValueMut, InsertName, StructDesc, StructMarshal,
    StructUnmarshal,
};
pub use typeinfo::{TypeInfo, TypeKind};
