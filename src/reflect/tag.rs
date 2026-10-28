//! `StructTag`: the tag string of a struct field, parsed exactly as Go's
//! `reflect.StructTag.Lookup` does.

use std::fmt;

use crate::strconv;

/// The tag string in a struct field (Go `reflect.StructTag`).
///
/// By convention, tag strings are a concatenation of optionally
/// space-separated `key:"value"` pairs. Each key is a non-empty string of
/// non-control characters other than space, quote and colon; each value is a
/// Go string literal in double quotes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StructTag(pub String);

impl StructTag {
    /// Wraps a tag string.
    pub fn new(tag: impl Into<String>) -> StructTag {
        StructTag(tag.into())
    }

    /// The raw tag text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Go `StructTag.Get`: the value associated with `key`, or the empty
    /// string. Use [`StructTag::lookup`] to tell an empty value from none.
    pub fn get(&self, key: &str) -> String {
        self.lookup(key).unwrap_or_default()
    }

    /// Go `StructTag.Lookup`: the value associated with `key` and whether it
    /// was explicitly set. A tag without the conventional format yields `None`
    /// from the first malformed pair on.
    pub fn lookup(&self, key: &str) -> Option<String> {
        let mut tag = self.0.as_bytes();
        while !tag.is_empty() {
            // Skip leading space.
            let mut i = 0;
            while i < tag.len() && tag[i] == b' ' {
                i += 1;
            }
            tag = &tag[i..];
            if tag.is_empty() {
                break;
            }

            // Scan to colon. A space, a quote or a control character is a
            // syntax error.
            i = 0;
            while i < tag.len()
                && tag[i] > b' '
                && tag[i] != b':'
                && tag[i] != b'"'
                && tag[i] != 0x7f
            {
                i += 1;
            }
            if i == 0 || i + 1 >= tag.len() || tag[i] != b':' || tag[i + 1] != b'"' {
                break;
            }
            let name = &tag[..i];
            tag = &tag[i + 1..];

            // Scan quoted string to find value.
            i = 1;
            while i < tag.len() && tag[i] != b'"' {
                if tag[i] == b'\\' {
                    i += 1;
                }
                i += 1;
            }
            if i >= tag.len() {
                break;
            }
            let qvalue = &tag[..i + 1];
            tag = &tag[i + 1..];

            if key.as_bytes() == name {
                return match strconv::unquote(qvalue) {
                    Ok(v) => Some(String::from_utf8_lossy(&v).into_owned()),
                    Err(_) => None,
                };
            }
        }
        None
    }
}

impl fmt::Display for StructTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for StructTag {
    fn from(s: &str) -> StructTag {
        StructTag(s.to_string())
    }
}

impl From<String> for StructTag {
    fn from(s: String) -> StructTag {
        StructTag(s)
    }
}
