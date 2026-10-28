//! Lexical utilities for slash-separated paths, matching Go's `path` package.
//! Backslashes are ordinary characters; this module does not use platform paths.

#[cfg(unix)]
pub mod filepath;

/// Clean returns the shortest slash-separated path equivalent to `path`.
pub fn clean(path: &str) -> String {
    if path.is_empty() {
        return ".".into();
    }
    let rooted = path.starts_with('/');
    let bytes = path.as_bytes();
    let mut components: Vec<&str> = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && bytes[i] == b'/' {
            i += 1;
        }
        if i == bytes.len() {
            break;
        }
        let start = i;
        while i < bytes.len() && bytes[i] != b'/' {
            i += 1;
        }
        let part = &path[start..i];
        match part {
            "." => {}
            ".." => {
                if components.last().is_some_and(|last| *last != "..") {
                    components.pop();
                } else if !rooted {
                    components.push("..");
                }
            }
            _ => components.push(part),
        }
    }
    let mut out = String::new();
    if rooted {
        out.push('/');
    }
    out.push_str(&components.join("/"));
    if out.is_empty() {
        ".".into()
    } else {
        out
    }
}

/// Split after the final slash. The pieces concatenate to the original input.
pub fn split(path: &str) -> (&str, &str) {
    match path.rfind('/') {
        Some(i) => (&path[..=i], &path[i + 1..]),
        None => ("", path),
    }
}

/// Join nonempty elements with slashes and clean the result. An empty argument
/// list, or a list containing only empty strings, yields an empty string.
pub fn join<P: AsRef<str>>(elements: &[P]) -> String {
    let mut joined = String::new();
    for element in elements {
        let element = element.as_ref();
        if !element.is_empty() {
            if !joined.is_empty() {
                joined.push('/');
            }
            joined.push_str(element);
        }
    }
    if joined.is_empty() {
        String::new()
    } else {
        clean(&joined)
    }
}

/// Base returns the final path component after trimming trailing slashes.
pub fn base(path: &str) -> &str {
    if path.is_empty() {
        return ".";
    }
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return "/";
    }
    match trimmed.rfind('/') {
        Some(i) => &trimmed[i + 1..],
        None => trimmed,
    }
}

/// Dir returns the cleaned directory portion of `path`.
pub fn dir(path: &str) -> String {
    clean(split(path).0)
}

/// Ext returns the suffix beginning at the final dot in the final component.
pub fn ext(path: &str) -> &str {
    let name = path.rsplit('/').next().unwrap_or("");
    match name.rfind('.') {
        Some(i) => &name[i..],
        None => "",
    }
}

/// IsAbs reports whether `path` begins with a slash.
pub fn is_abs(path: &str) -> bool {
    path.starts_with('/')
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadPattern;
impl std::fmt::Display for BadPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("syntax error in pattern")
    }
}
impl std::error::Error for BadPattern {}

/// Reports whether `name` matches the shell pattern (`path.Match`).
///
/// `*` and `?` never match `/`. A malformed pattern is an error even when the
/// match fails before reaching it.
pub fn matches(pattern: &str, name: &str) -> Result<bool, BadPattern> {
    match_pattern(pattern, name, true)
}

/// The matcher shared with `filepath::matches` (Unix). Go 1.27 differs
/// between the two packages: `path.Match` checks the unmatched rest of the
/// pattern before returning false (`check_rest`), while `filepath.Match`
/// reports a malformed pattern only when matching reaches it.
pub(crate) fn match_pattern(
    pattern: &str,
    name: &str,
    check_rest: bool,
) -> Result<bool, BadPattern> {
    let mut pattern = pattern.as_bytes();
    let mut name = name.as_bytes();
    'pattern: while !pattern.is_empty() {
        let (star, chunk, rest) = scan_chunk(pattern);
        pattern = rest;
        if star && chunk.is_empty() {
            // Trailing * matches the rest of the string unless it has a /.
            return Ok(!name.contains(&b'/'));
        }
        // Look for a match at the current position.
        let (t, ok, err) = match_chunk(chunk, name);
        // If we're the last chunk, make sure we've exhausted the name;
        // otherwise we'll give a false result even if we could still match
        // using the star.
        if ok && (t.is_empty() || !pattern.is_empty()) {
            name = t;
            continue;
        }
        if err {
            return Err(BadPattern);
        }
        if star {
            // Look for a match skipping i+1 bytes.
            let mut i = 0;
            while i < name.len() && name[i] != b'/' {
                let (t, ok, err) = match_chunk(chunk, &name[i + 1..]);
                if ok {
                    // If we're the last chunk, make sure we exhausted the name.
                    if pattern.is_empty() && !t.is_empty() {
                        i += 1;
                        continue;
                    }
                    name = t;
                    continue 'pattern;
                }
                if err {
                    return Err(BadPattern);
                }
                i += 1;
            }
        }
        // Before returning false with no error, check that the remainder of
        // the pattern is syntactically valid.
        while check_rest && !pattern.is_empty() {
            let (_, chunk, rest) = scan_chunk(pattern);
            pattern = rest;
            if match_chunk(chunk, b"").2 {
                return Err(BadPattern);
            }
        }
        return Ok(false);
    }
    Ok(name.is_empty())
}

/// Splits the leading stars and the chunk up to the next unbracketed star.
fn scan_chunk(mut pattern: &[u8]) -> (bool, &[u8], &[u8]) {
    let mut star = false;
    while !pattern.is_empty() && pattern[0] == b'*' {
        pattern = &pattern[1..];
        star = true;
    }
    let mut inrange = false;
    let mut i = 0;
    while i < pattern.len() {
        match pattern[i] {
            b'\\' => {
                if i + 1 < pattern.len() {
                    i += 1;
                }
            }
            b'[' => inrange = true,
            b']' => inrange = false,
            b'*' if !inrange => return (star, &pattern[..i], &pattern[i..]),
            _ => {}
        }
        i += 1;
    }
    (star, pattern, &[])
}

/// Decodes the first rune of `s`; invalid UTF-8 is `(U+FFFD, 1)`.
fn decode_rune(s: &[u8]) -> (char, usize) {
    for n in 1..=s.len().min(4) {
        if let Ok(t) = std::str::from_utf8(&s[..n]) {
            if let Some(c) = t.chars().next() {
                return (c, n);
            }
        }
    }
    ('\u{FFFD}', 1)
}

/// Matches `chunk` against the start of `s`: the rest of `s`, whether it
/// matched, and whether the chunk is malformed.
fn match_chunk<'a>(mut chunk: &[u8], mut s: &'a [u8]) -> (&'a [u8], bool, bool) {
    // Failed matches must still parse the whole chunk to report syntax errors.
    let mut failed = false;
    while !chunk.is_empty() {
        failed = failed || s.is_empty();
        match chunk[0] {
            b'[' => {
                let mut r = '\0';
                if !failed {
                    let (c, n) = decode_rune(s);
                    r = c;
                    s = &s[n..];
                }
                chunk = &chunk[1..];
                let mut negated = false;
                if !chunk.is_empty() && chunk[0] == b'^' {
                    negated = true;
                    chunk = &chunk[1..];
                }
                let mut matched = false;
                let mut nrange = 0;
                loop {
                    if !chunk.is_empty() && chunk[0] == b']' && nrange > 0 {
                        chunk = &chunk[1..];
                        break;
                    }
                    let Some((lo, rest)) = get_esc(chunk) else {
                        return (&[], false, true);
                    };
                    chunk = rest;
                    let mut hi = lo;
                    if chunk[0] == b'-' {
                        let Some((h, rest)) = get_esc(&chunk[1..]) else {
                            return (&[], false, true);
                        };
                        hi = h;
                        chunk = rest;
                    }
                    matched = matched || (lo <= r && r <= hi);
                    nrange += 1;
                }
                failed = failed || matched == negated;
            }
            b'?' => {
                if !failed {
                    failed = s[0] == b'/';
                    let (_, n) = decode_rune(s);
                    s = &s[n..];
                }
                chunk = &chunk[1..];
            }
            c => {
                if c == b'\\' {
                    chunk = &chunk[1..];
                    if chunk.is_empty() {
                        return (&[], false, true);
                    }
                }
                if !failed {
                    failed = chunk[0] != s[0];
                    s = &s[1..];
                }
                chunk = &chunk[1..];
            }
        }
    }
    if failed {
        return (&[], false, false);
    }
    (s, true, false)
}

/// Reads one possibly escaped character of a class; `None` if malformed.
fn get_esc(mut chunk: &[u8]) -> Option<(char, &[u8])> {
    if chunk.is_empty() || chunk[0] == b'-' || chunk[0] == b']' {
        return None;
    }
    if chunk[0] == b'\\' {
        chunk = &chunk[1..];
        if chunk.is_empty() {
            return None;
        }
    }
    let (r, n) = decode_rune(chunk);
    if r == '\u{FFFD}' && n == 1 {
        return None;
    }
    let rest = &chunk[n..];
    if rest.is_empty() {
        return None;
    }
    Some((r, rest))
}
