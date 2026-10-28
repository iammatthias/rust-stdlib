//! Go structs: the fields a struct exposes in JSON, and the arshalers that
//! marshal and unmarshal them, ported from Go's `fields.go`,
//! `arshal_embedded.go` and the struct parts of `arshal_default.go`.
//!
//! Go reads the fields and their `json` tags from the type with `reflect`.
//! Here the `Serialize` and `Deserialize` derives describe a struct with a
//! [`StructDesc`] and give access to its fields by index path, and the code
//! in this module does the rest exactly as Go does.
use std::any::{Any, TypeId};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock, Mutex};

use super::arshal::{marshal_value, unmarshal_value, MarshalTo, UnmarshalFrom};
use super::errors::{
    duplicate_name_error_at, err_invalid_string_tag, err_nil_field, err_no_exported_fields,
    err_raw_embed_not_object, marshal_error_before, unmarshal_error_after, unmarshal_error_before,
    SemanticError,
};
use super::fold::fold_name;
use super::scalars::invalid_format_error_dec;
use super::scalars::invalid_format_error_enc;
use super::typeinfo::{TypeInfo, TypeKind};
use crate::encoding::json::jsontext::flags;
use crate::encoding::json::jsontext::{
    self, wire, Decoder, Encoder, Error, Pointer, Value, ValueFlags, KIND_BEGIN_OBJECT, KIND_NULL,
};
use crate::strconv;

// ------------------------------------------------------------ descriptions

/// The description of one field of a Go struct, as the derives give it.
#[derive(Clone, Debug)]
pub struct FieldDesc {
    /// The Go field name (`reflect.StructField.Name`).
    pub name: &'static str,
    /// The value of the field's `json` struct tag (empty if none).
    pub tag: &'static str,
    /// Whether the struct field has a `json` struct tag at all.
    pub has_tag: bool,
    /// Whether the field is a Go embedded (anonymous) field.
    pub anonymous: bool,
    /// Whether Go would export the field (an unexported one is ignored).
    pub exported: bool,
    /// The type of the field.
    pub type_info: TypeInfo,
    /// The description of the field's type, if it is a struct (possibly
    /// behind a pointer). Computed lazily; types may be recursive.
    pub struct_desc: fn() -> Option<StructDesc>,
}

impl FieldDesc {
    /// A field that JSON ignores (`json:"-"`, or unexported without a tag):
    /// it has no type to describe.
    pub fn ignored(name: &'static str, tag: &'static str, exported: bool) -> FieldDesc {
        FieldDesc {
            name,
            tag,
            has_tag: !tag.is_empty(),
            anonymous: false,
            exported,
            type_info: TypeInfo {
                name: String::new(),
                kind: TypeKind::Invalid,
                id: None,
                elem: None,
                key: None,
            },
            struct_desc: || None,
        }
    }
}

/// The description of a Go struct type, as the derives give it.
#[derive(Clone, Debug)]
pub struct StructDesc {
    /// The struct type.
    pub type_info: TypeInfo,
    /// Its fields, in declaration order.
    pub fields: Vec<FieldDesc>,
}

/// An object-safe view of a field value for marshaling.
pub trait FieldValue {
    /// Marshals the value (through the user's marshalers, if any).
    fn marshal(&self, enc: &mut Encoder<'_>) -> Result<(), Error>;
    /// Whether the value is zero (for `omitzero`).
    fn is_zero(&self) -> bool;
    /// Whether the value is an empty string, map, array, slice or a nil
    /// pointer; `None` for other kinds.
    fn is_empty(&self) -> Option<bool>;
    /// Whether the value's type has methods or a user marshaler replacing the
    /// default marshaling.
    fn non_default(&self, enc: &Encoder<'_>) -> bool;
    /// The embedded-fallback view of the value.
    fn fallback(&self) -> Option<&dyn FallbackMarshal>;
}

impl<T: MarshalTo> FieldValue for T {
    fn marshal(&self, enc: &mut Encoder<'_>) -> Result<(), Error> {
        marshal_value(enc, self)
    }
    fn is_zero(&self) -> bool {
        self.is_zero_value()
    }
    fn is_empty(&self) -> Option<bool> {
        self.is_empty_value()
    }
    fn non_default(&self, enc: &Encoder<'_>) -> bool {
        self.has_methods()
            || enc
                .s
                .opts
                .marshalers
                .as_ref()
                .is_some_and(|m| !m.lookup(TypeId::of::<T>()).is_empty())
    }
    fn fallback(&self) -> Option<&dyn FallbackMarshal> {
        self.as_fallback()
    }
}

/// An object-safe view of a field value for unmarshaling.
pub trait FieldValueMut {
    /// Unmarshals one value into the field (through the user's unmarshalers,
    /// if any).
    fn unmarshal(&mut self, dec: &mut Decoder<'_>) -> Result<(), Error>;
    /// The embedded-fallback view of the value.
    fn fallback_mut(&mut self) -> Option<&mut dyn FallbackUnmarshal>;
}

impl<T: UnmarshalFrom> FieldValueMut for T {
    fn unmarshal(&mut self, dec: &mut Decoder<'_>) -> Result<(), Error> {
        unmarshal_value(dec, self)
    }
    fn fallback_mut(&mut self) -> Option<&mut dyn FallbackUnmarshal> {
        self.as_fallback_mut()
    }
}

/// A struct whose fields can be reached by index path for marshaling. The
/// `Serialize` derive implements it.
pub trait StructMarshal: MarshalTo + Sized {
    /// Calls `f` with the field at the index `path` (which may go through
    /// embedded structs), or returns `None` if an embedded pointer on the
    /// path is nil.
    fn with_field<R>(&self, path: &[usize], f: impl FnOnce(&dyn FieldValue) -> R) -> Option<R>;
}

/// A struct whose fields can be reached by index path for unmarshaling. The
/// `Deserialize` derive implements it.
pub trait StructUnmarshal: UnmarshalFrom {
    /// Calls `f` with the field at the index `path`, allocating nil embedded
    /// pointers on the way if `may_alloc`. Returns `None` if one cannot be
    /// reached.
    fn with_field_mut<R>(
        &mut self,
        path: &[usize],
        may_alloc: bool,
        f: impl FnOnce(&mut dyn FieldValueMut) -> R,
    ) -> Option<R>;
}

/// Reaching through an embedded struct, possibly behind a pointer, to one of
/// its fields.
pub trait EmbedAccess {
    /// Calls `f` with the field at `path` of the embedded struct.
    fn with_embedded<R>(&self, path: &[usize], f: impl FnOnce(&dyn FieldValue) -> R) -> Option<R>;
}

/// The mutable counterpart of [`EmbedAccess`].
pub trait EmbedAccessMut {
    /// Calls `f` with the field at `path` of the embedded struct, allocating
    /// the struct if it is behind a nil pointer and `may_alloc`.
    fn with_embedded_mut<R>(
        &mut self,
        path: &[usize],
        may_alloc: bool,
        f: impl FnOnce(&mut dyn FieldValueMut) -> R,
    ) -> Option<R>;
}

impl<T: EmbedAccess> EmbedAccess for Option<T> {
    fn with_embedded<R>(&self, path: &[usize], f: impl FnOnce(&dyn FieldValue) -> R) -> Option<R> {
        self.as_ref()?.with_embedded(path, f)
    }
}

impl<T: EmbedAccess> EmbedAccess for Box<T> {
    fn with_embedded<R>(&self, path: &[usize], f: impl FnOnce(&dyn FieldValue) -> R) -> Option<R> {
        (**self).with_embedded(path, f)
    }
}

impl<T: EmbedAccessMut + UnmarshalFrom> EmbedAccessMut for Option<T> {
    fn with_embedded_mut<R>(
        &mut self,
        path: &[usize],
        may_alloc: bool,
        f: impl FnOnce(&mut dyn FieldValueMut) -> R,
    ) -> Option<R> {
        if self.is_none() {
            if !may_alloc {
                return None;
            }
            *self = Some(T::zero());
        }
        self.as_mut()?.with_embedded_mut(path, may_alloc, f)
    }
}

impl<T: EmbedAccessMut> EmbedAccessMut for Box<T> {
    fn with_embedded_mut<R>(
        &mut self,
        path: &[usize],
        may_alloc: bool,
        f: impl FnOnce(&mut dyn FieldValueMut) -> R,
    ) -> Option<R> {
        (**self).with_embedded_mut(path, may_alloc, f)
    }
}

/// Reports whether a member name has not been used in an object yet.
pub type InsertName<'a> = &'a mut dyn FnMut(&mut Encoder<'_>, &[u8]) -> bool;

/// An embedded fallback (a map with string keys, or `jsontext::Value`) as it
/// is marshaled: every member it holds is written into the parent object.
pub trait FallbackMarshal {
    /// Writes every member. `insert` reports whether a member name has not
    /// been used in the object yet (when duplicate names are checked).
    fn marshal_all(
        &self,
        enc: &mut Encoder<'_>,
        insert: Option<InsertName<'_>>,
    ) -> Result<(), Error>;
}

/// An embedded fallback as it is unmarshaled: unknown members are stored in
/// it one at a time.
pub trait FallbackUnmarshal {
    /// Reads the value of the member `quoted_name` (`unquoted_name` is its
    /// decoded text) and stores it.
    fn unmarshal_next(
        &mut self,
        dec: &mut Decoder<'_>,
        quoted_name: &[u8],
        unquoted_name: &[u8],
    ) -> Result<(), Error>;
}

// --------------------------------------------------------- field options

const CASE_IGNORE: i8 = 1;
const CASE_STRICT: i8 = 2;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct FieldOptions {
    name: String,
    quoted_name: Vec<u8>,
    has_name: bool,
    name_need_escape: bool,
    casing: i8,
    embed: bool,
    omitzero: bool,
    omitempty: bool,
    string: bool,
    format: String,
}

fn is_letter_or_digit(r: i32) -> bool {
    r == '_' as i32 || crate::unicode::is_letter(r) || crate::unicode::is_number(r)
}

/// `consumeTagOption`: the option at the start of `input`, how many bytes it
/// used, and what is wrong with it.
fn consume_tag_option(input: &str, allow_quoted: bool) -> (String, usize, Option<String>) {
    let i = input.find(',').unwrap_or(input.len());
    let (r, _) = crate::unicode::rune::decode_rune(input.as_bytes());
    if r == '_' as i32 || crate::unicode::is_letter(r) {
        let mut n = 0;
        for c in input.chars() {
            if !is_letter_or_digit(c as i32) {
                break;
            }
            n += c.len_utf8();
        }
        return (input[..n].to_string(), n, None);
    }
    if r == '\'' as i32 {
        if !allow_quoted {
            return (
                input[..i].to_string(),
                i,
                Some(format!(
                    "invalid character {} at start of option (expecting Unicode letter)",
                    strconv::quote_rune(r)
                )),
            );
        }
        let mut in_escape = false;
        let mut b: Vec<u8> = vec![b'"'];
        let mut n = 1;
        let bytes = input.as_bytes();
        while bytes.len() > n {
            let (r, rn) = crate::unicode::rune::decode_rune(&bytes[n..]);
            if in_escape {
                if r == '\'' as i32 {
                    b.pop();
                }
                in_escape = false;
            } else if r == '\\' as i32 {
                in_escape = true;
            } else if r == '"' as i32 {
                b.push(b'\\');
            } else if r == '\'' as i32 {
                b.push(b'"');
                n += 1;
                return match strconv::unquote(&b) {
                    Ok(out) => (String::from_utf8_lossy(&out).into_owned(), n, None),
                    Err(_) => (
                        input[..i].to_string(),
                        i,
                        Some(format!("invalid single-quoted string: {}", &input[..n])),
                    ),
                };
            }
            b.extend_from_slice(&bytes[n..n + rn]);
            n += rn;
        }
        let mut shown = n;
        if shown > 10 {
            shown = 10;
        }
        while !input.is_char_boundary(shown) {
            shown -= 1;
        }
        return (
            input[..i].to_string(),
            i,
            Some(format!(
                "single-quoted string not terminated: {}...",
                &input[..shown]
            )),
        );
    }
    if input.is_empty() {
        return (
            input[..i].to_string(),
            i,
            Some("unexpected EOF".to_string()),
        );
    }
    let what = if allow_quoted {
        "expecting Unicode letter or single quote"
    } else {
        "expecting Unicode letter"
    };
    (
        input[..i].to_string(),
        i,
        Some(format!(
            "invalid character {} at start of option ({what})",
            strconv::quote_rune(r)
        )),
    )
}

/// `parseFieldOptions`: the options in a field's `json` tag, whether the
/// field is ignored, and the first problem with the tag.
fn parse_field_options(sf: &FieldDesc) -> (FieldOptions, bool, Option<String>) {
    let mut out = FieldOptions::default();
    let mut err: Option<String> = None;
    let or_err = |e: Option<String>, text: String| e.or(Some(text));
    let mut tag: &str = sf.tag;
    if tag == "-" {
        return (FieldOptions::default(), true, None);
    }
    if !sf.exported && !sf.anonymous {
        if sf.has_tag {
            err = or_err(
                err,
                format!(
                    "unexported Go struct field {} cannot have non-ignored `json:{}` tag",
                    sf.name,
                    strconv::quote(tag)
                ),
            );
        }
        return (FieldOptions::default(), true, err);
    }
    out.name = sf.name.to_string();
    if !tag.is_empty() && !tag.starts_with(',') {
        let mut n = 0;
        for c in tag.chars() {
            if ",\\'\"`".contains(c) {
                break;
            }
            n += c.len_utf8();
        }
        let mut name = tag[..n].to_string();
        let mut err2: Option<String> = None;
        if !tag[n..].starts_with(',') && name.len() != tag.len() {
            let (nm, nn, e2) = consume_tag_option(tag, false);
            name = nm;
            n = nn;
            err2 = e2;
            if let Some(e2) = &err2 {
                err = or_err(
                    err,
                    format!("Go struct field {} has malformed `json` tag: {e2}", sf.name),
                );
            }
        }
        if err2.is_none() {
            out.has_name = true;
            out.name = name;
        }
        tag = &tag[n..];
    }
    let mut quoted = Vec::new();
    let _ = wire::append_quote(&mut quoted, out.name.as_bytes(), &flags::Flags::default());
    out.quoted_name = quoted;
    out.name_need_escape = wire::need_escape(out.name.as_bytes());

    let mut was_format = false;
    let mut seen_opts: HashSet<String> = HashSet::new();
    while !tag.is_empty() {
        if !tag.starts_with(',') {
            err = or_err(
                err,
                format!(
                    "Go struct field {} has malformed `json` tag: invalid character {} before next option (expecting ',')",
                    sf.name,
                    strconv::quote_rune(tag.chars().next().map_or(0, |c| c as i32))
                ),
            );
        } else {
            tag = &tag[1..];
            if tag.is_empty() {
                err = or_err(
                    err,
                    format!(
                        "Go struct field {} has malformed `json` tag: invalid trailing ',' character",
                        sf.name
                    ),
                );
                break;
            }
        }
        let (opt, n, err2) = consume_tag_option(tag, false);
        if let Some(e2) = &err2 {
            err = or_err(
                err,
                format!("Go struct field {} has malformed `json` tag: {e2}", sf.name),
            );
        }
        let raw_opt = tag[..n].to_string();
        tag = &tag[n..];
        if was_format {
            err = or_err(
                err,
                format!(
                    "Go struct field {} has `format` tag option that was not specified last",
                    sf.name
                ),
            );
        } else if raw_opt.starts_with('\'') && opt.chars().all(|c| is_letter_or_digit(c as i32)) {
            err = or_err(
                err,
                format!(
                    "Go struct field {} has unnecessarily quoted appearance of `{raw_opt}` tag option; specify `{opt}` instead",
                    sf.name
                ),
            );
        }
        match opt.as_str() {
            "case" => 'case: {
                if !tag.starts_with(':') {
                    err = or_err(
                        err,
                        format!(
                            "Go struct field {} is missing value for `case` tag option; specify `case:ignore` or `case:strict` instead",
                            sf.name
                        ),
                    );
                    break 'case;
                }
                tag = &tag[1..];
                let (opt, n, err2) = consume_tag_option(tag, false);
                if let Some(e2) = err2 {
                    err = or_err(
                        err,
                        format!(
                            "Go struct field {} has malformed value for `case` tag option: {e2}",
                            sf.name
                        ),
                    );
                    break 'case;
                }
                let raw_opt = tag[..n].to_string();
                tag = &tag[n..];
                if raw_opt.starts_with('\'') {
                    err = or_err(
                        err,
                        format!(
                            "Go struct field {} has unnecessarily quoted appearance of `case:{raw_opt}` tag option; specify `case:{opt}` instead",
                            sf.name
                        ),
                    );
                }
                match opt.as_str() {
                    "ignore" => out.casing |= CASE_IGNORE,
                    "strict" => out.casing |= CASE_STRICT,
                    _ => {
                        err = or_err(
                            err,
                            format!(
                                "Go struct field {} has unknown `case:{raw_opt}` tag value",
                                sf.name
                            ),
                        )
                    }
                }
            }
            "embed" => out.embed = true,
            "omitzero" => out.omitzero = true,
            "omitempty" => out.omitempty = true,
            "string" => out.string = true,
            "format" => 'format: {
                if !tag.starts_with(':') {
                    err = or_err(
                        err,
                        format!(
                            "Go struct field {} is missing value for `format` tag option",
                            sf.name
                        ),
                    );
                    break 'format;
                }
                tag = &tag[1..];
                let (opt, n, err2) = consume_tag_option(tag, true);
                if let Some(e2) = err2 {
                    err = or_err(
                        err,
                        format!(
                            "Go struct field {} has malformed value for `format` tag option: {e2}",
                            sf.name
                        ),
                    );
                    break 'format;
                } else if opt.is_empty() {
                    err = or_err(
                        err,
                        format!(
                            "Go struct field {} cannot have empty value for `format` tag option",
                            sf.name
                        ),
                    );
                    break 'format;
                }
                tag = &tag[n..];
                out.format = opt;
                was_format = true;
            }
            _ => {
                let norm = opt.to_lowercase().replace('_', "");
                if matches!(
                    norm.as_str(),
                    "case" | "embed" | "omitzero" | "omitempty" | "string" | "format"
                ) {
                    err = or_err(
                        err,
                        format!(
                            "Go struct field {} has invalid appearance of `{opt}` tag option; specify `{norm}` instead",
                            sf.name
                        ),
                    );
                }
            }
        }
        if out.casing == CASE_IGNORE | CASE_STRICT {
            err = or_err(
                err,
                format!(
                    "Go struct field {} cannot have both `case:ignore` and `case:strict` tag options",
                    sf.name
                ),
            );
        } else if seen_opts.contains(&opt) {
            err = or_err(
                err,
                format!(
                    "Go struct field {} has duplicate appearance of `{raw_opt}` tag option",
                    sf.name
                ),
            );
        }
        seen_opts.insert(opt);
    }
    (out, false, err)
}

// ------------------------------------------------------------ resolution

#[derive(Clone, Debug)]
struct StructField {
    /// Unique numeric ID in breadth-first order.
    id: usize,
    /// The index path from the root struct.
    index: Vec<usize>,
    opts: FieldOptions,
}

impl StructField {
    /// `matchFoldedName`.
    fn match_folded_name(&self, flags: &flags::Flags) -> bool {
        self.opts.casing == CASE_IGNORE
            || (flags.get(flags::MATCH_CASE_INSENSITIVE_NAMES) && self.opts.casing != CASE_STRICT)
    }
}

struct StructFields {
    flattened: Vec<StructField>,
    by_actual_name: HashMap<String, usize>,
    by_folded_name: HashMap<Vec<u8>, Vec<usize>>,
    embedded_fallback: Option<StructField>,
    err_unsupported_format: Option<SemanticError>,
}

struct Resolved {
    fields: StructFields,
    err_init: Option<SemanticError>,
}

fn semantic(t: &TypeInfo, text: String) -> SemanticError {
    SemanticError {
        type_info: Some(t.clone()),
        err: Some(Error::msg(&text)),
        ..Default::default()
    }
}

fn indirect_type(t: &TypeInfo) -> &TypeInfo {
    if t.kind == TypeKind::Pointer {
        if let Some(e) = &t.elem {
            return e;
        }
    }
    t
}

fn is_raw_value(t: &TypeInfo) -> bool {
    t.name == "jsontext.Value"
}

/// `makeStructFields`.
fn make_struct_fields(root: &StructDesc) -> Resolved {
    struct QueueEntry {
        desc: StructDesc,
        index: Vec<usize>,
        visit_children: bool,
    }
    let mut serr: Option<SemanticError> = None;
    let mut err_unsupported_format: Option<SemanticError> = None;
    let mut queue: Vec<QueueEntry> = vec![QueueEntry {
        desc: root.clone(),
        index: Vec::new(),
        visit_children: true,
    }];
    let mut queue_index = 0;
    let mut seen: HashMap<Option<TypeId>, bool> = HashMap::new();
    seen.insert(root.type_info.id, true);
    let mut all_fields: Vec<StructField> = Vec::new();
    let mut embedded_fallbacks: Vec<StructField> = Vec::new();

    while queue_index < queue.len() {
        let (t, index0, visit_children, fields) = {
            let qe = &queue[queue_index];
            (
                qe.desc.type_info.clone(),
                qe.index.clone(),
                qe.visit_children,
                qe.desc.fields.clone(),
            )
        };
        queue_index += 1;

        let mut embedded_fallback_index: Option<usize> = None;
        let mut names_index: HashMap<String, usize> = HashMap::new();
        let mut has_any_json_tag = false;
        let mut has_any_json_field = false;
        for (i, sf) in fields.iter().enumerate() {
            has_any_json_tag = has_any_json_tag || sf.has_tag;
            let (options, ignored, err) = parse_field_options(sf);
            if let Some(e) = err {
                serr = serr.or_else(|| Some(semantic(&t, e)));
            }
            if ignored {
                continue;
            }
            has_any_json_field = true;
            let mut index = index0.clone();
            index.push(i);
            let mut f = StructField {
                id: 0,
                index,
                opts: options,
            };
            if sf.anonymous && !f.opts.has_name {
                if indirect_type(&sf.type_info).kind != TypeKind::Struct {
                    serr = serr.or_else(|| {
                        Some(semantic(
                            &t,
                            format!(
                                "embedded Go struct field {} of non-struct type must be explicitly given a JSON name",
                                sf.name
                            ),
                        ))
                    });
                } else {
                    f.opts.embed = true;
                }
            }

            let mut as_regular_field = !f.opts.embed;
            if f.opts.embed {
                // handleEmbed
                let want = FieldOptions {
                    name: f.opts.name.clone(),
                    quoted_name: f.opts.quoted_name.clone(),
                    embed: true,
                    ..Default::default()
                };
                let mut proceed = true;
                if f.opts != want {
                    serr = serr.or_else(|| {
                        Some(semantic(
                            &t,
                            format!(
                                "Go struct field {} cannot have any options other than `embed` specified",
                                sf.name
                            ),
                        ))
                    });
                    if f.opts.has_name {
                        as_regular_field = true;
                        proceed = false;
                    } else {
                        f.opts = FieldOptions {
                            name: f.opts.name.clone(),
                            quoted_name: f.opts.quoted_name.clone(),
                            embed: f.opts.embed,
                            ..Default::default()
                        };
                    }
                }
                if proceed {
                    let tf = indirect_type(&sf.type_info);
                    let child = if tf.kind == TypeKind::Struct {
                        (sf.struct_desc)()
                    } else {
                        None
                    };
                    if tf.kind == TypeKind::Struct && child.is_none() && !is_raw_value(tf) {
                        serr = serr.or_else(|| {
                            Some(semantic(
                                &t,
                                format!(
                                    "embedded Go struct field {} of type {} must not implement marshal or unmarshal methods",
                                    sf.name, tf.name
                                ),
                            ))
                        });
                    }
                    if let (TypeKind::Struct, Some(child)) = (tf.kind, child) {
                        if visit_children {
                            let first = !seen.get(&tf.id).copied().unwrap_or(false);
                            queue.push(QueueEntry {
                                desc: child,
                                index: f.index.clone(),
                                visit_children: first,
                            });
                        }
                        seen.insert(tf.id, true);
                    } else {
                        let mut ok = true;
                        if is_raw_value(tf) {
                            // specially handled as an embedded fallback
                        } else if tf.kind == TypeKind::Map
                            && tf.key.as_ref().is_some_and(|k| k.kind == TypeKind::String)
                        {
                            // a map with a string key is an embedded fallback
                        } else {
                            serr = serr.or_else(|| {
                                Some(semantic(
                                    &t,
                                    format!(
                                        "embedded Go struct field {} of type {} must be a Go struct, Go map of string key, or jsontext.Value",
                                        sf.name, tf.name
                                    ),
                                ))
                            });
                            as_regular_field = true;
                            ok = false;
                        }
                        if ok {
                            if let Some(j) = embedded_fallback_index {
                                serr = serr.or_else(|| {
                                    Some(semantic(
                                        &t,
                                        format!(
                                            "embedded Go struct fields {} and {} cannot both be a Go map or jsontext.Value",
                                            fields[j].name, sf.name
                                        ),
                                    ))
                                });
                            }
                            embedded_fallback_index = Some(i);
                            embedded_fallbacks.push(f.clone());
                        }
                    }
                }
            }
            if as_regular_field {
                // handleField
                if let Some(&j) = names_index.get(&f.opts.name) {
                    serr = serr.or_else(|| {
                        Some(semantic(
                            &t,
                            format!(
                                "Go struct fields {} and {} conflict over JSON object name {}",
                                fields[j].name,
                                sf.name,
                                strconv::quote(&f.opts.name)
                            ),
                        ))
                    });
                }
                names_index.insert(f.opts.name.clone(), i);
                f.id = all_fields.len();
                if !f.opts.format.is_empty() && err_unsupported_format.is_none() {
                    err_unsupported_format = Some(semantic(
                        &t,
                        format!(
                            "Go struct field {} has unsupported `format` tag option",
                            sf.name
                        ),
                    ));
                }
                all_fields.push(f);
            }
        }
        let is_empty_struct = fields.is_empty();
        if !is_empty_struct && !has_any_json_tag && !has_any_json_field {
            serr = serr.or_else(|| {
                Some(SemanticError {
                    type_info: Some(t.clone()),
                    err: Some(err_no_exported_fields()),
                    ..Default::default()
                })
            });
        }
    }

    // Resolve name conflicts: the dominant field of each name wins.
    all_fields.sort_by(|x, y| {
        x.opts
            .name
            .cmp(&y.opts.name)
            .then(x.index.len().cmp(&y.index.len()))
            .then((!x.opts.has_name).cmp(&!y.opts.has_name))
    });
    let mut flattened: Vec<StructField> = Vec::new();
    let mut rest: &[StructField] = &all_fields;
    while !rest.is_empty() {
        let mut n = 1;
        while n < rest.len() && rest[n - 1].opts.name == rest[n].opts.name {
            n += 1;
        }
        if n == 1
            || rest[0].index.len() != rest[1].index.len()
            || rest[0].opts.has_name != rest[1].opts.has_name
        {
            flattened.push(rest[0].clone());
        }
        rest = &rest[n..];
    }
    flattened.sort_by_key(|f| f.id);
    for (i, f) in flattened.iter_mut().enumerate() {
        f.id = i;
    }
    flattened.sort_by(|x, y| x.index.cmp(&y.index));

    let mut by_actual_name = HashMap::new();
    let mut by_folded_name: HashMap<Vec<u8>, Vec<usize>> = HashMap::new();
    for (i, f) in flattened.iter().enumerate() {
        by_actual_name.insert(f.opts.name.clone(), i);
        by_folded_name
            .entry(fold_name(f.opts.name.as_bytes()))
            .or_default()
            .push(i);
    }
    for v in by_folded_name.values_mut() {
        if v.len() > 1 {
            v.sort_by_key(|&i| flattened[i].id);
        }
    }
    let n = embedded_fallbacks.len();
    let embedded_fallback = if n == 1
        || (n > 1 && embedded_fallbacks[0].index.len() != embedded_fallbacks[1].index.len())
    {
        Some(embedded_fallbacks[0].clone())
    } else {
        None
    };
    Resolved {
        fields: StructFields {
            flattened,
            by_actual_name,
            by_folded_name,
            embedded_fallback,
            err_unsupported_format,
        },
        err_init: serr,
    }
}

static CACHE: LazyLock<Mutex<HashMap<TypeId, Arc<Resolved>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn resolved<T: Any>(desc: impl FnOnce() -> StructDesc) -> Arc<Resolved> {
    let id = TypeId::of::<T>();
    if let Some(r) = CACHE.lock().expect("fields cache").get(&id) {
        return r.clone();
    }
    let r = Arc::new(make_struct_fields(&desc()));
    CACHE.lock().expect("fields cache").insert(id, r.clone());
    r
}

/// `lookupByFoldedName` followed by the first-match rule of unmarshaling:
/// the fields whose folded name equals that of `name`.
fn lookup_by_folded_name<'a>(fs: &'a StructFields, name: &[u8]) -> &'a [usize] {
    fs.by_folded_name
        .get(&fold_name(name))
        .map_or(&[][..], |v| v.as_slice())
}

// --------------------------------------------------------------- marshal

/// The marshal function of a struct (Go's `makeStructArshaler`).
pub fn marshal_struct<T: StructMarshal>(v: &T, enc: &mut Encoder<'_>) -> Result<(), Error> {
    let t = T::type_info();
    if enc.s.opts.flags.has(flags::TAG_FLAGS) {
        if enc.s.opts.flags.get(flags::STRING_TAG) {
            return Err(marshal_error_before(
                enc,
                Some(t),
                Some(err_invalid_string_tag()),
            ));
        }
        if enc.s.opts.flags.has(flags::FORMAT_TAG) {
            return Err(invalid_format_error_enc(enc, t));
        }
    }
    let r = resolved::<T>(|| T::struct_desc().expect("struct description"));
    if let Some(e) = &r.err_init {
        return Err(marshal_error_before(
            enc,
            e.type_info.clone(),
            e.err.clone(),
        ));
    } else if let Some(e) = &r.fields.err_unsupported_format {
        if !enc.s.opts.flags.get(flags::FORMAT_TAG_SUPPORTED) {
            return Err(marshal_error_before(
                enc,
                e.type_info.clone(),
                e.err.clone(),
            ));
        }
    }
    let fields = &r.fields;

    enc.write_token(&jsontext::begin_object())?;
    let mut seen_idxs: HashSet<usize> = HashSet::new();
    let mut prev_idx: Option<usize> = None;
    enc.s.state.tokens.last.disable_namespace();
    for f in &fields.flattened {
        let flags_original = enc.s.opts.flags;
        let outcome = v.with_field(&f.index, |fv| -> Result<bool, Error> {
            if (f.opts.omitzero || enc.s.opts.flags.get(flags::OMIT_ZERO_STRUCT_FIELDS))
                && fv.is_zero()
            {
                return Ok(false);
            }
            let non_default = fv.non_default(enc);
            if f.opts.omitempty && !non_default && fv.is_empty() == Some(true) {
                return Ok(false);
            }
            enc.write_token(&jsontext::string(&f.opts.name))?;
            if f.opts.string {
                enc.s.opts.flags.set(flags::STRING_TAG, true);
            }
            if !f.opts.format.is_empty() {
                enc.s.opts.flags.set(flags::FORMAT_TAG, true);
                enc.s.opts.format = f.opts.format.clone();
            }
            let err = fv.marshal(enc);
            enc.s.opts.flags = flags_original;
            enc.s.opts.format.clear();
            err?;
            Ok(true)
        });
        let Some(outcome) = outcome else { continue };
        if !outcome? {
            continue;
        }
        if f.opts.omitempty {
            let prev_name = prev_idx.map(|i| fields.flattened[i].opts.name.as_bytes());
            if enc.s.unwrite_empty_object_member(prev_name) {
                continue;
            }
        }
        if !enc.s.opts.flags.get(flags::ALLOW_DUPLICATE_NAMES) && fields.embedded_fallback.is_some()
        {
            seen_idxs.insert(f.id);
        }
        prev_idx = Some(f.id);
    }
    if let Some(fb) = &fields.embedded_fallback {
        let check_dups = !enc.s.opts.flags.get(flags::ALLOW_DUPLICATE_NAMES);
        let mut insert = |enc: &mut Encoder<'_>, name: &[u8]| -> bool {
            let folded = lookup_by_folded_name(fields, name);
            if !folded.is_empty() {
                let flags = enc.s.opts.flags;
                if let Some(&i) = fields.by_actual_name.get(&*String::from_utf8_lossy(name)) {
                    return seen_idxs.insert(fields.flattened[i].id);
                }
                for &i in folded {
                    if fields.flattened[i].match_folded_name(&flags) {
                        return seen_idxs.insert(fields.flattened[i].id);
                    }
                }
            }
            enc.s.state.last_namespace().insert_unquoted(name)
        };
        let insert_ref: Option<InsertName<'_>> = if check_dups { Some(&mut insert) } else { None };
        let mut insert_ref = insert_ref;
        let r = v.with_field(&fb.index, |fv| match fv.fallback() {
            Some(fallback) => fallback.marshal_all(enc, insert_ref.take()),
            None => Ok(()),
        });
        if let Some(r) = r {
            r?;
        }
    }
    enc.write_token(&jsontext::end_object())
}

// ------------------------------------------------------------- unmarshal

/// The unmarshal function of a struct (Go's `makeStructArshaler`).
pub fn unmarshal_struct<T: StructUnmarshal>(v: &mut T, dec: &mut Decoder<'_>) -> Result<(), Error> {
    let t = <T as UnmarshalFrom>::type_info();
    if dec.s.opts.flags.has(flags::TAG_FLAGS) {
        if dec.s.opts.flags.get(flags::STRING_TAG) {
            return Err(unmarshal_error_before(
                dec,
                Some(t),
                Some(err_invalid_string_tag()),
            ));
        }
        if dec.s.opts.flags.has(flags::FORMAT_TAG) {
            return Err(invalid_format_error_dec(dec, t));
        }
    }
    let tok = dec.read_token()?;
    match tok.kind() {
        KIND_NULL => {
            v.set_zero();
            Ok(())
        }
        KIND_BEGIN_OBJECT => unmarshal_struct_members(v, dec, &t),
        _ => Err(unmarshal_error_after(dec, Some(t), None)),
    }
}

fn unmarshal_struct_members<T: StructUnmarshal>(
    v: &mut T,
    dec: &mut Decoder<'_>,
    t: &TypeInfo,
) -> Result<(), Error> {
    let r = resolved::<T>(|| <T as UnmarshalFrom>::struct_desc().expect("struct description"));
    if let Some(e) = &r.err_init {
        return Err(unmarshal_error_after(
            dec,
            e.type_info.clone(),
            e.err.clone(),
        ));
    } else if let Some(e) = &r.fields.err_unsupported_format {
        if !dec.s.opts.flags.get(flags::FORMAT_TAG_SUPPORTED) {
            return Err(unmarshal_error_after(
                dec,
                e.type_info.clone(),
                e.err.clone(),
            ));
        }
    }
    let fields = &r.fields;
    let mut seen_idxs: HashSet<usize> = HashSet::new();
    dec.s.state.tokens.last.disable_namespace();
    let allow_dup = dec.s.opts.flags.get(flags::ALLOW_DUPLICATE_NAMES);
    while dec.peek_kind() != jsontext::KIND_END_OBJECT {
        let mut vf = ValueFlags::default();
        let val = dec.s.read_value(&mut vf)?;
        let name = wire::unquote_may_copy(&val, vf.is_verbatim());
        let mut field = fields
            .by_actual_name
            .get(&*String::from_utf8_lossy(&name))
            .filter(|_| std::str::from_utf8(&name).is_ok())
            .map(|&i| &fields.flattened[i]);
        if field.is_none() {
            let mut num_match = 0;
            for &i in lookup_by_folded_name(fields, &name) {
                if fields.flattened[i].match_folded_name(&dec.s.opts.flags) {
                    if field.is_none() {
                        field = Some(&fields.flattened[i]);
                    }
                    num_match += 1;
                }
            }
            if num_match > 1 {
                return Err(unmarshal_error_after(
                    dec,
                    Some(t.clone()),
                    Some(Error::AmbiguousName),
                ));
            }
            if field.is_none() {
                if dec.s.opts.flags.get(flags::REJECT_UNKNOWN_MEMBERS)
                    && fields.embedded_fallback.is_none()
                {
                    return Err(unmarshal_error_after(
                        dec,
                        Some(t.clone()),
                        Some(Error::UnknownName),
                    ));
                }
                if !allow_dup && !dec.s.state.last_namespace().insert_unquoted(&name) {
                    return Err(duplicate_name_error(dec, val.len()));
                }
                match &fields.embedded_fallback {
                    None => dec.skip_value()?,
                    Some(fb) => {
                        let r = v.with_field_mut(&fb.index, true, |fv| match fv.fallback_mut() {
                            Some(fallback) => fallback.unmarshal_next(dec, &val, &name),
                            None => dec.skip_value(),
                        });
                        if let Some(r) = r {
                            r?;
                        }
                    }
                }
                continue;
            }
        }
        let f = field.expect("a field matched");
        if !allow_dup && !seen_idxs.insert(f.id) {
            return Err(duplicate_name_error(dec, val.len()));
        }
        let flags_original = dec.s.opts.flags;
        if f.opts.string {
            dec.s.opts.flags.set(flags::STRING_TAG, true);
        }
        if !f.opts.format.is_empty() {
            dec.s.opts.flags.set(flags::FORMAT_TAG, true);
            dec.s.opts.format = f.opts.format.clone();
        }
        let outcome = v.with_field_mut(&f.index, true, |fv| fv.unmarshal(dec));
        dec.s.opts.flags = flags_original;
        dec.s.opts.format.clear();
        match outcome {
            Some(r) => r?,
            None => {
                return Err(unmarshal_error_before(
                    dec,
                    Some(t.clone()),
                    Some(err_nil_field()),
                ))
            }
        }
    }
    dec.read_token()?;
    Ok(())
}

fn duplicate_name_error(dec: &mut Decoder<'_>, val_len: usize) -> Error {
    let mut ptr = Vec::new();
    dec.s.append_stack_pointer(&mut ptr, -1);
    duplicate_name_error_at(
        Pointer::from(String::from_utf8_lossy(&ptr).into_owned()),
        None,
        dec.input_offset() - val_len as i64,
    )
}

// ------------------------------------------------------ embedded fallbacks

impl FallbackMarshal for Value {
    fn marshal_all(
        &self,
        enc: &mut Encoder<'_>,
        mut insert: Option<InsertName<'_>>,
    ) -> Result<(), Error> {
        let b = &self.0;
        if b.is_empty() {
            return Ok(());
        }
        let t = jsontext_value_type();
        let mut dec = Decoder::buffered(
            b,
            &[
                jsontext::allow_duplicate_names(true),
                jsontext::allow_invalid_utf8(true),
            ],
        );
        let tok = match dec.read_token() {
            Ok(tok) => tok,
            Err(e) => {
                let e = if matches!(e, Error::Eof) {
                    Error::UnexpectedEof
                } else {
                    e
                };
                return Err(marshal_error_before(enc, Some(t), Some(e)));
            }
        };
        if tok.kind() != KIND_BEGIN_OBJECT {
            return Err(marshal_error_before(
                enc,
                Some(t),
                Some(err_raw_embed_not_object()),
            ));
        }
        while dec.peek_kind() != jsontext::KIND_END_OBJECT {
            let mut vf = ValueFlags::default();
            let val = match dec.s.read_value(&mut vf) {
                Ok(v) => v,
                Err(e) => return Err(marshal_error_before(enc, Some(t), Some(e))),
            };
            if let Some(insert) = insert.as_mut() {
                let name = wire::unquote_may_copy(&val, vf.is_verbatim());
                if !insert(enc, &name) {
                    let off = enc.output_offset();
                    return Err(duplicate_name_error_at(
                        enc.stack_pointer().parent(),
                        Some(&val),
                        off,
                    ));
                }
            }
            enc.write_value(&Value(val))?;
            let val = match dec.s.read_value(&mut vf) {
                Ok(v) => v,
                Err(e) => return Err(marshal_error_before(enc, Some(t), Some(e))),
            };
            enc.write_value(&Value(val))?;
        }
        if let Err(e) = dec.read_token() {
            return Err(marshal_error_before(enc, Some(t), Some(e)));
        }
        if let Err(e) = dec.s.check_eof() {
            return Err(marshal_error_before(enc, Some(t), Some(e)));
        }
        Ok(())
    }
}

impl FallbackUnmarshal for Value {
    fn unmarshal_next(
        &mut self,
        dec: &mut Decoder<'_>,
        quoted_name: &[u8],
        _unquoted_name: &[u8],
    ) -> Result<(), Error> {
        let b = &mut self.0;
        if b.is_empty() {
            b.push(b'{');
        } else {
            let end = wire::trim_suffix_whitespace(b).len();
            b.truncate(end);
            if b.last() == Some(&b'}') {
                b.pop();
                let end = wire::trim_suffix_whitespace(b).len();
                b.truncate(end);
                if b.last() != Some(&b',') && b.last() != Some(&b'{') {
                    b.push(b',');
                }
            } else {
                return Err(unmarshal_error_after(
                    dec,
                    Some(jsontext_value_type()),
                    Some(err_raw_embed_not_object()),
                ));
            }
        }
        b.extend_from_slice(quoted_name);
        b.push(b':');
        let val = dec.read_value()?;
        b.extend_from_slice(&val.0);
        b.push(b'}');
        Ok(())
    }
}

/// The Go type `jsontext.Value`.
pub(crate) fn jsontext_value_type() -> TypeInfo {
    TypeInfo::of::<Value>("jsontext.Value", TypeKind::Slice)
        .with_elem(TypeInfo::of::<u8>("uint8", TypeKind::Uint8))
}

/// Writes the members of an embedded map fallback.
pub(crate) fn marshal_map_fallback<'a, K, V>(
    enc: &mut Encoder<'_>,
    entries: Vec<(&'a K, &'a V)>,
    mut insert: Option<InsertName<'_>>,
) -> Result<(), Error>
where
    K: MarshalTo,
    V: MarshalTo,
{
    let n = entries.len();
    if n == 0 {
        return Ok(());
    }
    let mut named: Vec<(String, &V)> = Vec::with_capacity(n);
    for (k, v) in entries {
        let name = k.as_str_key().unwrap_or("").to_string();
        named.push((name, v));
    }
    if enc.s.opts.flags.get(flags::DETERMINISTIC) && n > 1 {
        named.sort_by(|a, b| a.0.cmp(&b.0));
    }
    for (name, v) in named {
        let mut b = Vec::new();
        if let Some(e) = wire::append_quote(&mut b, name.as_bytes(), &enc.s.opts.flags) {
            return Err(marshal_error_before(enc, Some(K::type_info()), Some(e)));
        }
        if let Some(insert) = insert.as_mut() {
            let is_verbatim = !b.contains(&b'\\');
            let unq = wire::unquote_may_copy(&b, is_verbatim);
            if !insert(enc, &unq) {
                let off = enc.output_offset();
                return Err(duplicate_name_error_at(
                    enc.stack_pointer().parent(),
                    Some(&b),
                    off,
                ));
            }
        }
        enc.write_value(&Value(b))?;
        marshal_value(enc, v)?;
    }
    Ok(())
}
