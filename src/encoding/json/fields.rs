//! Struct field metadata for the derives: Go's tag parsing and its rules for
//! choosing between fields that have the same JSON name (`typeFields` in Go's
//! `encode.go`), plus case-insensitive name folding for decoding.
use std::collections::HashMap;

/// A parsed Go-style `json:"name,opt,opt"` struct tag, using the rules of
/// Go 1.27's `encoding/json` (which implements v1 on top of v2).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Tag {
    /// The JSON name; empty when the tag gives none or a malformed one.
    pub name: String,
    pub omit_empty: bool,
    pub omit_zero: bool,
    /// The `string` option.
    pub string: bool,
    /// The `case:strict` option: only an exact name matches when decoding.
    pub case_strict: bool,
}

fn is_letter_or_digit(c: char) -> bool {
    crate::unicode::is_letter(c as i32) || crate::unicode::is_digit(c as i32)
}

/// Go's `consumeTagOption`: returns the option text, how much of `input` it
/// used, and whether it was well formed.
fn consume_tag_option(input: &str, allow_quoted: bool) -> (String, usize, bool) {
    let comma = input.find(',').unwrap_or(input.len());
    let bad = || (input[..comma].to_string(), comma, false);
    match input.chars().next() {
        Some(c) if c == '_' || crate::unicode::is_letter(c as i32) => {
            let n = input
                .find(|c: char| !is_letter_or_digit(c))
                .unwrap_or(input.len());
            (input[..n].to_string(), n, true)
        }
        Some('\'') if allow_quoted => {
            // A single-quoted string with Go string escapes.
            let mut out = String::new();
            let mut chars = input[1..].char_indices();
            while let Some((i, c)) = chars.next() {
                match c {
                    '\'' => return (out, i + 2, true),
                    '\\' => match chars.next() {
                        Some((_, e @ ('\'' | '"' | '\\'))) => out.push(e),
                        Some((_, 'n')) => out.push('\n'),
                        Some((_, 't')) => out.push('\t'),
                        _ => return bad(),
                    },
                    c => out.push(c),
                }
            }
            bad()
        }
        _ => bad(),
    }
}

impl Tag {
    /// Parses the value of a `json` struct tag. The caller handles the `-`
    /// tag, which skips the field. Malformed tags are tolerated as Go's v1
    /// compatibility mode does.
    pub fn parse(tag: &str) -> Tag {
        let mut out = Tag::default();
        let mut rest = tag;
        if !rest.is_empty() && !rest.starts_with(',') {
            // Almost any unescaped name is accepted; commas, backslashes and
            // quotes are reserved.
            let n = rest.find([',', '\\', '\'', '"', '`']).unwrap_or(rest.len());
            let mut name = rest[..n].to_string();
            let mut used = n;
            let mut well_formed = true;
            if !rest[n..].starts_with(',') && n != rest.len() {
                let (opt, u, ok) = consume_tag_option(rest, false);
                name = opt;
                used = u;
                well_formed = ok;
            }
            if well_formed {
                out.name = name;
            }
            rest = &rest[used..];
        }
        while !rest.is_empty() {
            if let Some(after) = rest.strip_prefix(',') {
                rest = after;
                if rest.is_empty() {
                    break;
                }
            }
            let (opt, used, _) = consume_tag_option(rest, false);
            rest = &rest[used..];
            match opt.as_str() {
                "case" => {
                    if let Some(after) = rest.strip_prefix(':') {
                        let (value, used, ok) = consume_tag_option(after, false);
                        rest = &after[used..];
                        if ok && value == "strict" {
                            out.case_strict = true;
                        }
                    }
                }
                "omitzero" => out.omit_zero = true,
                "omitempty" => out.omit_empty = true,
                "string" => out.string = true,
                "format" => {
                    if let Some(after) = rest.strip_prefix(':') {
                        let (_, used, ok) = consume_tag_option(after, true);
                        rest = &after[if ok { used } else { 0 }..];
                    }
                }
                _ => {}
            }
        }
        out
    }
}

/// Go's `foldName`: case-insensitive comparison key for a JSON object key.
pub fn fold_name(name: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len());
    let mut i = 0;
    while i < name.len() {
        let c = name[i];
        if c < 0x80 {
            out.push(c.to_ascii_uppercase());
            i += 1;
            continue;
        }
        let (mut r, n) = crate::unicode::rune::decode_rune(&name[i..]);
        loop {
            let r2 = crate::unicode::simple_fold(r);
            if r2 <= r {
                r = r2;
                break;
            }
            r = r2;
        }
        crate::unicode::rune::append_rune(&mut out, r);
        i += n;
    }
    out
}

/// One struct field (or field of an embedded struct) before name conflicts
/// are resolved.
#[derive(Clone, Debug)]
pub struct Field {
    /// The JSON name.
    pub name: String,
    /// Whether the name came from a tag.
    pub tagged: bool,
    /// Position of the field at each embedding level, outermost first.
    pub index: Vec<usize>,
    /// Decoding slot of this field (see [`DeserializeFields`](super::DeserializeFields)).
    pub slot: usize,
    pub omit_empty: bool,
    pub omit_zero: bool,
    /// The `string` tag option was present.
    pub string: bool,
    /// The `case:strict` tag option was present.
    pub case_strict: bool,
    /// Rust names of the embedded structs leading to the field, then the
    /// field itself, for error paths.
    pub path: Vec<&'static str>,
}

/// Collects the fields of a struct and the structs embedded in it. The
/// derive macros call [`field`](Self::field) and
/// [`embedded`](Self::embedded) in declaration order.
#[derive(Default)]
pub struct FieldList {
    fields: Vec<Field>,
    index: Vec<usize>,
    path: Vec<&'static str>,
    visiting: Vec<&'static str>,
    next_slot: usize,
}

impl FieldList {
    pub fn new() -> Self {
        Self::default()
    }
    /// Number of decoding slots allocated so far.
    pub fn slots(&self) -> usize {
        self.next_slot
    }
    /// Registers an ordinary field at position `i` with its `json` tag.
    pub fn field(&mut self, i: usize, rust_name: &'static str, tag: &str) {
        let parsed = Tag::parse(tag);
        let mut index = self.index.clone();
        index.push(i);
        let mut path = self.path.clone();
        path.push(rust_name);
        let tagged = !parsed.name.is_empty();
        self.fields.push(Field {
            name: if tagged {
                parsed.name
            } else {
                rust_name.to_string()
            },
            tagged,
            index,
            slot: self.next_slot,
            omit_empty: parsed.omit_empty,
            omit_zero: parsed.omit_zero,
            string: parsed.string,
            case_strict: parsed.case_strict,
            path,
        });
        self.next_slot += 1;
    }
    /// Starts the promoted fields of an embedded struct at position `i`:
    /// the caller must then register them (through the embedded type's
    /// `json_fields`) and call [`leave`](Self::leave). Returns `false` for a
    /// type cycle, which Go does not revisit either; nothing is registered.
    #[must_use]
    pub fn embedded(&mut self, i: usize, rust_name: &'static str, type_name: &'static str) -> bool {
        if self.visiting.contains(&type_name) {
            return false;
        }
        self.visiting.push(type_name);
        self.index.push(i);
        self.path.push(rust_name);
        true
    }
    /// Ends the promoted fields of the struct opened by [`embedded`](Self::embedded).
    pub fn leave(&mut self) {
        self.visiting.pop();
        self.index.pop();
        self.path.pop();
    }
}

/// Fields after resolving name conflicts, in declaration order.
pub struct Resolved {
    pub fields: Vec<Field>,
    exact: HashMap<String, usize>,
    /// Fields sharing a folded name, in breadth-first order.
    folded: HashMap<Vec<u8>, Vec<usize>>,
}

impl Resolved {
    /// Go's lookup for an object key: exact name first, then folded.
    ///
    /// With `delimiters_matter` false, `-` and `_` are ignored when folding
    /// (Go's v2 matching, selected by `match_case_sensitive_delimiter(false)`).
    pub fn lookup(&self, key: &str, delimiters_matter: bool) -> Option<&Field> {
        if let Some(i) = self.exact.get(key) {
            return Some(&self.fields[*i]);
        }
        if delimiters_matter {
            return self
                .folded
                .get(&fold_name(key.as_bytes()))?
                .iter()
                .map(|i| &self.fields[*i])
                .find(|f| !f.case_strict);
        }
        let loose = |name: &str| -> Vec<u8> {
            fold_name(name.as_bytes())
                .into_iter()
                .filter(|c| *c != b'-' && *c != b'_')
                .collect()
        };
        let want = loose(key);
        let mut candidates: Vec<&Field> = self
            .fields
            .iter()
            .filter(|f| !f.case_strict && loose(&f.name) == want)
            .collect();
        candidates.sort_by(|a, b| {
            a.index
                .len()
                .cmp(&b.index.len())
                .then(a.index.cmp(&b.index))
        });
        candidates.into_iter().next()
    }
}

/// Go's `typeFields`: among fields with the same name the shallowest wins, a
/// tagged one beats an untagged one at equal depth, and otherwise all of them
/// are dropped.
pub fn resolve(list: FieldList) -> Resolved {
    let mut fields = list.fields;
    fields.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then(a.index.len().cmp(&b.index.len()))
            .then(b.tagged.cmp(&a.tagged))
            .then(a.index.cmp(&b.index))
    });
    let mut out: Vec<Field> = Vec::with_capacity(fields.len());
    let mut i = 0;
    while i < fields.len() {
        let mut advance = 1;
        while i + advance < fields.len() && fields[i + advance].name == fields[i].name {
            advance += 1;
        }
        let group = &fields[i..i + advance];
        let ambiguous = advance > 1
            && group[0].index.len() == group[1].index.len()
            && group[0].tagged == group[1].tagged;
        if !ambiguous {
            out.push(group[0].clone());
        }
        i += advance;
    }
    out.sort_by(|a, b| a.index.cmp(&b.index));
    let mut exact = HashMap::new();
    let mut folded: HashMap<Vec<u8>, Vec<usize>> = HashMap::new();
    for (i, f) in out.iter().enumerate() {
        exact.insert(f.name.clone(), i);
        folded
            .entry(fold_name(f.name.as_bytes()))
            .or_default()
            .push(i);
    }
    // Among names that fold together, shallower fields win, then earlier ones.
    for group in folded.values_mut() {
        group.sort_by(|a, b| {
            let (x, y) = (&out[*a].index, &out[*b].index);
            x.len().cmp(&y.len()).then(x.cmp(y))
        });
    }
    Resolved {
        fields: out,
        exact,
        folded,
    }
}
