//! First-party JSON derives using the compiler's token-tree API.
//!
//! Named, tuple, and unit structs and externally tagged enums are supported.
//! Named structs follow Go's `encoding/json` rules, configured with
//! `#[json(...)]` field attributes (a Go struct tag string, or `rename`,
//! `omitempty`, `omitzero`, `string`, `skip` and `embedded` keywords).
//! Type, lifetime, and const parameters, defaults and where predicates are
//! preserved, with field-type JSON bounds added to each generated impl. Borrowed
//! field deserialization, representation-changing attributes and explicit enum
//! discriminants are rejected with compiler diagnostics. Nested
//! generic field types, raw identifiers, visibility, arrays, and tuples parse
//! as token trees. The runtime crate must be imported as `rust_stdlib`.
//!
//! `MarshalTo` and `UnmarshalFrom` derive the traits of
//! `rust_stdlib::encoding::json::v2` for named structs from the same
//! `#[json(...)]` attributes, which also take `inline` (an embedded struct),
//! `unknown` (a map or `jsontext::Value` for unmatched members), `case =
//! "ignore"` or `"strict"`, and `format = "..."`.
//!
//! `Marshal` and `Unmarshal` derive the typed traits of
//! `rust_stdlib::encoding::xml` from Go-style `#[xml("...")]` field tags; see
//! the `xml` module.
//! `embed!` is Go's `//go:embed`: it expands file, directory and wildcard
//! patterns into a `rust_stdlib::embed::FS`.
#![forbid(unsafe_code)]
extern crate proc_macro;
mod embed;
mod reflect;
mod v2;
mod xml;
use proc_macro::{Delimiter, TokenStream, TokenTree};
#[derive(Clone)]
struct NamedField {
    name: String,
    tag: String,
    skip: bool,
    embedded: bool,
    ty: String,
}
#[derive(Clone)]
enum Fields {
    Unit,
    Named(Vec<String>),
    Tuple(usize),
    /// Fields of a named struct, with their `#[json(...)]` options.
    Struct(Vec<NamedField>),
}
struct Header {
    name: String,
    prefix: String,
    impl_generics: String,
    type_generics: String,
    predicates: String,
    field_types: Vec<String>,
    embedded_types: Vec<String>,
    skipped_types: Vec<String>,
    borrowed: bool,
    type_parameters: Vec<String>,
}
enum Item {
    Struct(Header, Fields),
    Enum(Header, Vec<(String, Fields)>),
}
fn fail(message: &str) -> TokenStream {
    format!("compile_error!({message:?});")
        .parse()
        .expect("static diagnostic tokens")
}
fn ident(t: &TokenTree) -> Option<String> {
    match t {
        TokenTree::Ident(i) => Some(i.to_string()),
        _ => None,
    }
}
fn punct(t: &TokenTree, c: char) -> bool {
    matches!(t,TokenTree::Punct(p) if p.as_char()==c)
}
fn split(stream: TokenStream) -> Result<Vec<Vec<TokenTree>>, String> {
    let mut parts = Vec::new();
    let mut current = Vec::new();
    let mut angle = 0usize;
    for t in stream {
        if punct(&t, '<') {
            angle += 1;
        }
        if punct(&t, '>')
            && angle > 0
            && !current.last().is_some_and(|previous| punct(previous, '-'))
        {
            angle -= 1;
        }
        if punct(&t, ',') && angle == 0 {
            if current.is_empty() {
                return Err("empty field or enum variant".into());
            }
            parts.push(std::mem::take(&mut current));
        } else {
            current.push(t);
        }
    }
    if angle != 0 {
        return Err("unbalanced generic field type".into());
    }
    if !current.is_empty() {
        parts.push(current);
    }
    Ok(parts)
}
/// Attributes that do not change how a type is represented: documentation,
/// derives and lint levels.
fn harmless_attribute(text: &str) -> bool {
    [
        "doc ",
        "doc=",
        "derive ",
        "derive(",
        "xml(",
        "xml (",
        "reflect(",
        "reflect (",
        "allow",
        "warn",
        "deny",
        "forbid",
        "expect",
    ]
    .iter()
    .any(|prefix| text.starts_with(prefix))
}
fn skip_attrs(tokens: &[TokenTree], mut i: usize) -> Result<usize, String> {
    while i < tokens.len() && punct(&tokens[i], '#') {
        let Some(TokenTree::Group(g)) = tokens.get(i + 1) else {
            return Err("malformed attribute".into());
        };
        if g.delimiter() != Delimiter::Bracket {
            return Err("malformed attribute".into());
        }
        let text = g.stream().to_string();
        if !harmless_attribute(&text) {
            return Err(format!("unsupported derive attribute: {text}"));
        }
        i += 2;
    }
    Ok(i)
}
/// Replaces invisible groups, which `macro_rules!` fragments such as `meta`
/// arrive in, with their contents.
fn flatten_invisible(tokens: Vec<TokenTree>) -> Vec<TokenTree> {
    let mut out = Vec::new();
    for token in tokens {
        match token {
            TokenTree::Group(g) if g.delimiter() == Delimiter::None => {
                out.extend(flatten_invisible(g.stream().into_iter().collect()))
            }
            other => out.push(other),
        }
    }
    out
}
/// Unquotes a string literal token.
fn string_literal(token: &TokenTree) -> Result<String, String> {
    let TokenTree::Literal(literal) = token else {
        return Err("expected a string literal".into());
    };
    let text = literal.to_string();
    let inner = text
        .strip_prefix('"')
        .and_then(|t| t.strip_suffix('"'))
        .ok_or("expected a string literal")?;
    let mut out = String::new();
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('0') => out.push('\0'),
            Some(c @ ('\\' | '"' | '\'')) => out.push(c),
            _ => return Err("unsupported escape in json attribute string".into()),
        }
    }
    Ok(out)
}
/// Parses the attributes of a named struct field: `doc` is ignored and
/// `json(...)` configures the Go struct tag. Returns the next token index.
fn field_attrs(tokens: &[TokenTree], mut i: usize) -> Result<(usize, String, bool, bool), String> {
    let mut base = String::new();
    let mut rename: Option<String> = None;
    let mut options: Vec<String> = Vec::new();
    let mut format: Option<String> = None;
    let (mut skip, mut embedded, mut unexported) = (false, false, false);
    while i < tokens.len() && punct(&tokens[i], '#') {
        let Some(TokenTree::Group(g)) = tokens.get(i + 1) else {
            return Err("malformed attribute".into());
        };
        if g.delimiter() != Delimiter::Bracket {
            return Err("malformed attribute".into());
        }
        let inner = flatten_invisible(g.stream().into_iter().collect());
        if inner.first().and_then(ident).as_deref() == Some("json") {
            let Some(TokenTree::Group(args)) = inner.get(1).filter(|_| inner.len() == 2) else {
                return Err("malformed json attribute: expected #[json(...)]".into());
            };
            if args.delimiter() != Delimiter::Parenthesis {
                return Err("malformed json attribute: expected #[json(...)]".into());
            }
            for entry in split(args.stream())?.into_iter().map(flatten_invisible) {
                match entry.as_slice() {
                    [literal @ TokenTree::Literal(_)] => base = string_literal(literal)?,
                    [word] if ident(word).is_some() => match ident(word).as_deref() {
                        Some("omitempty") => options.push("omitempty".into()),
                        Some("omitzero") => options.push("omitzero".into()),
                        Some("string") => options.push("string".into()),
                        Some("skip") => skip = true,
                        // A field Go would not export: ignored without a tag.
                        Some("unexported") => unexported = true,
                        Some("embedded" | "flatten" | "inline") => embedded = true,
                        // A map or `jsontext::Value` that collects the
                        // members no field matches (Go v2's `embed` option).
                        Some("unknown" | "embed") => options.push("embed".into()),
                        Some("case_ignore") => options.push("case:ignore".into()),
                        Some("case_strict") => options.push("case:strict".into()),
                        _ => return Err("unsupported json attribute keyword".into()),
                    },
                    [key, eq, literal]
                        if ident(key).as_deref() == Some("rename") && punct(eq, '=') =>
                    {
                        rename = Some(string_literal(literal)?)
                    }
                    [key, eq, literal]
                        if ident(key).as_deref() == Some("case") && punct(eq, '=') =>
                    {
                        options.push(format!("case:{}", string_literal(literal)?));
                    }
                    [key, eq, literal]
                        if ident(key).as_deref() == Some("format") && punct(eq, '=') =>
                    {
                        format = Some(string_literal(literal)?);
                    }
                    _ => return Err("unsupported json attribute syntax".into()),
                }
            }
        } else {
            let text = g.stream().to_string();
            if !harmless_attribute(&text) {
                return Err(format!("unsupported derive attribute: {text}"));
            }
        }
        i += 2;
    }
    let (mut name, opts) = match base.split_once(',') {
        Some((n, o)) => (n.to_string(), o.to_string()),
        None => (base.clone(), String::new()),
    };
    skip |= base == "-";
    let renamed = rename.is_some();
    if let Some(r) = rename {
        name = r;
    }
    // A tag given alone is passed on exactly as written (it keeps a trailing
    // comma, for instance); one combined with keywords is rebuilt.
    let verbatim = options.is_empty() && format.is_none() && !renamed;
    let mut all: Vec<String> = opts
        .split(',')
        .filter(|o| !o.is_empty())
        .map(str::to_string)
        .collect();
    all.extend(options);
    if let Some(f) = format {
        let plain = f
            .chars()
            .next()
            .is_some_and(|c| c == '_' || c.is_alphabetic())
            && f.chars().all(|c| c == '_' || c.is_alphanumeric());
        all.push(if plain {
            format!("format:{f}")
        } else {
            format!("format:'{}'", f.replace('\\', "\\\\").replace('\'', "\\'"))
        });
    }
    skip |= unexported;
    let tag = if unexported {
        "\u{1}".to_string()
    } else if skip {
        "-".to_string()
    } else if verbatim {
        base
    } else if all.is_empty() {
        name
    } else {
        format!("{name},{}", all.join(","))
    };
    Ok((i, tag, skip, embedded))
}
/// Parses the fields of a named struct, filling the header's field types.
fn struct_fields(group: &proc_macro::Group, header: &mut Header) -> Result<Fields, String> {
    let mut out = Vec::new();
    for part in split(group.stream())? {
        let (i, tag, skip, embedded) = field_attrs(&part, 0)?;
        let i = skip_visibility(&part, i);
        let name = part.get(i).and_then(ident).ok_or("expected named field")?;
        if !part.get(i + 1).is_some_and(|t| punct(t, ':')) || i + 2 >= part.len() {
            return Err("expected field name followed by a type".into());
        }
        let ty = text(&part[i + 2..]);
        header.borrowed |= contains_reference(&part[i + 2..]);
        if skip {
            header.skipped_types.push(ty.clone());
        } else if embedded {
            header.embedded_types.push(ty.clone());
        } else {
            header.field_types.push(ty.clone());
        }
        out.push(NamedField {
            name,
            tag,
            skip,
            embedded,
            ty,
        });
    }
    Ok(Fields::Struct(out))
}
fn skip_visibility(tokens: &[TokenTree], mut i: usize) -> usize {
    if tokens.get(i).and_then(ident).as_deref() == Some("pub") {
        i += 1;
        if matches!(tokens.get(i),Some(TokenTree::Group(g))if g.delimiter()==Delimiter::Parenthesis)
        {
            i += 1;
        }
    }
    i
}
fn text(tokens: &[TokenTree]) -> String {
    tokens.iter().cloned().collect::<TokenStream>().to_string()
}
fn contains_reference(tokens: &[TokenTree]) -> bool {
    tokens.iter().any(|token| match token {
        TokenTree::Punct(p) => p.as_char() == '&',
        TokenTree::Group(g) if g.delimiter() != Delimiter::Brace => {
            contains_reference(&g.stream().into_iter().collect::<Vec<_>>())
        }
        _ => false,
    })
}
fn fields(group: &proc_macro::Group) -> Result<(Fields, Vec<String>, bool), String> {
    let parts = split(group.stream())?;
    let mut types = Vec::new();
    let mut borrowed = false;
    match group.delimiter() {
        Delimiter::Brace => {
            let mut names = Vec::new();
            for part in parts {
                let i = skip_visibility(&part, skip_attrs(&part, 0)?);
                let name = part.get(i).and_then(ident).ok_or("expected named field")?;
                if !part.get(i + 1).is_some_and(|t| punct(t, ':')) || i + 2 >= part.len() {
                    return Err("expected field name followed by a type".into());
                }
                names.push(name);
                types.push(text(&part[i + 2..]));
                borrowed |= contains_reference(&part[i + 2..]);
            }
            Ok((Fields::Named(names), types, borrowed))
        }
        Delimiter::Parenthesis => {
            for part in &parts {
                let i = skip_visibility(part, skip_attrs(part, 0)?);
                if i >= part.len() {
                    return Err("expected tuple field type".into());
                }
                types.push(text(&part[i..]));
                borrowed |= contains_reference(&part[i..]);
            }
            Ok((Fields::Tuple(parts.len()), types, borrowed))
        }
        _ => Err("unsupported item body".into()),
    }
}
/// Consume the compiler's generic token trees without parsing field types into
/// a second Rust grammar. Defaults cannot appear in impl parameter lists.
fn generics(tokens: &[TokenTree]) -> Result<(String, String, usize, Vec<String>), String> {
    if !tokens.first().is_some_and(|t| punct(t, '<')) {
        return Ok((String::new(), String::new(), 0, Vec::new()));
    }
    let mut depth = 1usize;
    let mut end = 1;
    while end < tokens.len() {
        if punct(&tokens[end], '<') {
            depth += 1;
        }
        if punct(&tokens[end], '>')
            && !tokens
                .get(end.wrapping_sub(1))
                .is_some_and(|t| punct(t, '-'))
        {
            depth -= 1;
            if depth == 0 {
                break;
            }
        }
        end += 1;
    }
    if depth != 0 {
        return Err("unterminated item generics".into());
    }
    let parameters = split(tokens[1..end].iter().cloned().collect())?;
    let mut declarations = Vec::new();
    let mut arguments = Vec::new();
    let mut type_parameters = Vec::new();
    for parameter in parameters {
        let first = skip_attrs(&parameter, 0)?;
        let argument = if parameter.get(first).is_some_and(|t| punct(t, '\'')) {
            format!(
                "'{}",
                parameter
                    .get(first + 1)
                    .and_then(ident)
                    .ok_or("expected lifetime parameter")?
            )
        } else if parameter.get(first).and_then(ident).as_deref() == Some("const") {
            parameter
                .get(first + 1)
                .and_then(ident)
                .ok_or("expected const parameter")?
        } else {
            {
                let name = parameter
                    .get(first)
                    .and_then(ident)
                    .ok_or("expected type parameter")?;
                type_parameters.push(name.clone());
                name
            }
        };
        let mut nested = 0usize;
        let mut default_at = parameter.len();
        for (i, t) in parameter.iter().enumerate() {
            if punct(t, '<') {
                nested += 1;
            }
            if punct(t, '>')
                && nested > 0
                && !parameter
                    .get(i.wrapping_sub(1))
                    .is_some_and(|t| punct(t, '-'))
            {
                nested -= 1;
            }
            if punct(t, '=') && nested == 0 {
                default_at = i;
                break;
            }
        }
        declarations.push(text(&parameter[first..default_at]));
        arguments.push(argument);
    }
    Ok((
        format!("<{}>", declarations.join(",")),
        format!("<{}>", arguments.join(",")),
        end + 1,
        type_parameters,
    ))
}
fn predicates(tokens: &[TokenTree]) -> Result<String, String> {
    if tokens.is_empty() {
        return Ok(String::new());
    }
    if tokens.first().and_then(ident).as_deref() != Some("where") {
        return Err("expected where clause before item body".into());
    }
    let mut tail = &tokens[1..];
    while tail.last().is_some_and(|t| punct(t, ',')) {
        tail = &tail[..tail.len() - 1];
    }
    Ok(text(tail))
}
fn all_identifiers(tokens: &[TokenTree], names: &mut Vec<String>) {
    for token in tokens {
        match token {
            TokenTree::Ident(i) => names.push(i.to_string()),
            TokenTree::Group(g) => {
                all_identifiers(&g.stream().into_iter().collect::<Vec<_>>(), names)
            }
            _ => {}
        }
    }
}
fn parse(input: TokenStream) -> Result<Item, String> {
    let tokens: Vec<_> = input.into_iter().collect();
    let i = skip_visibility(&tokens, skip_attrs(&tokens, 0)?);
    let kind = tokens
        .get(i)
        .and_then(ident)
        .ok_or("expected struct or enum")?;
    if kind != "struct" && kind != "enum" {
        return Err("JSON derives support structs and enums only".into());
    }
    let name = tokens
        .get(i + 1)
        .and_then(ident)
        .ok_or("expected item name")?;
    let (impl_generics, type_generics, used, type_parameters) = generics(&tokens[i + 2..])?;
    let rest = &tokens[i + 2 + used..];
    let mut names = Vec::new();
    all_identifiers(&tokens, &mut names);
    let mut prefix = "__rust_stdlib_".to_string();
    while names
        .iter()
        .any(|n| n.strip_prefix("r#").unwrap_or(n).starts_with(&prefix))
    {
        prefix.push('_');
    }
    let mut header = Header {
        name,
        prefix,
        impl_generics,
        type_generics,
        predicates: String::new(),
        field_types: Vec::new(),
        embedded_types: Vec::new(),
        skipped_types: Vec::new(),
        borrowed: false,
        type_parameters,
    };
    if kind == "struct" {
        if let Some(TokenTree::Group(group)) = rest
            .first()
            .filter(|t| matches!(t,TokenTree::Group(g)if g.delimiter()==Delimiter::Parenthesis))
        {
            if !rest.last().is_some_and(|t| punct(t, ';')) {
                return Err("expected tuple struct terminator".into());
            }
            header.predicates = predicates(&rest[1..rest.len() - 1])?;
            let (fields, types, borrowed) = fields(group)?;
            header.field_types = types;
            header.borrowed = borrowed;
            return Ok(Item::Struct(header, fields));
        }
        if let Some(TokenTree::Group(group)) = rest
            .last()
            .filter(|t| matches!(t,TokenTree::Group(g)if g.delimiter()==Delimiter::Brace))
        {
            header.predicates = predicates(&rest[..rest.len() - 1])?;
            let fields = struct_fields(group, &mut header)?;
            return Ok(Item::Struct(header, fields));
        }
        if rest.last().is_some_and(|t| punct(t, ';')) {
            header.predicates = predicates(&rest[..rest.len() - 1])?;
            return Ok(Item::Struct(header, Fields::Unit));
        }
        return Err("expected struct fields or terminator".into());
    }
    let Some(TokenTree::Group(group)) = rest.last() else {
        return Err("expected enum body".into());
    };
    if group.delimiter() != Delimiter::Brace {
        return Err("expected enum braces".into());
    }
    header.predicates = predicates(&rest[..rest.len() - 1])?;
    let mut variants = Vec::new();
    for part in split(group.stream())? {
        let j = skip_attrs(&part, 0)?;
        let variant = part.get(j).and_then(ident).ok_or("expected variant name")?;
        let fields = if j + 1 == part.len() {
            Fields::Unit
        } else if j + 2 == part.len() {
            match &part[j + 1] {
                TokenTree::Group(g) => {
                    let (f, t, b) = fields(g)?;
                    header.field_types.extend(t);
                    header.borrowed |= b;
                    f
                }
                _ => return Err("explicit enum discriminants are unsupported".into()),
            }
        } else {
            return Err(
                "explicit enum discriminants and trailing variant syntax are unsupported".into(),
            );
        };
        variants.push((variant, fields));
    }
    Ok(Item::Enum(header, variants))
}

fn key(s: &str) -> String {
    format!("{:?}", s.strip_prefix("r#").unwrap_or(s))
}
fn serialize_fields(fields: &Fields, access: &str, prefix: &str) -> String {
    let j = "::rust_stdlib::encoding::json";
    let ok = "::core::result::Result::Ok";
    match fields {
        Fields::Unit | Fields::Struct(_) => format!("{ok}({j}::Value::Null)"),
        Fields::Named(names) => {
            let object = format!("{prefix}object");
            let inserts = names
                .iter()
                .enumerate()
                .map(|(i, n)| {
                    let expression = if access.is_empty() {
                        format!("{prefix}field_{i}")
                    } else {
                        format!("&{access}{n}")
                    };
                    format!(
                        "{object}.insert({}.into(),{j}::Serialize::to_json({expression})?);",
                        key(n)
                    )
                })
                .collect::<String>();
            format!(
                "{{let mut {object}={j}::Map::new();{inserts}{ok}({j}::Value::Object({object}))}}"
            )
        }
        Fields::Tuple(count) => {
            let values = (0..*count)
                .map(|i| {
                    let expression = if access.is_empty() {
                        format!("{prefix}field_{i}")
                    } else {
                        format!("&{access}{i}")
                    };
                    format!("{j}::Serialize::to_json({expression})?")
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{ok}({j}::Value::Array(::std::vec![{values}]))")
        }
    }
}
fn deserialize_fields(fields: &Fields, constructor: &str, prefix: &str) -> String {
    let j = "::rust_stdlib::encoding::json";
    let ok = "::core::result::Result::Ok";
    let err = "::core::result::Result::Err";
    let value = format!("{prefix}value");
    let object = format!("{prefix}object");
    let array = format!("{prefix}array");
    match fields {
        Fields::Unit | Fields::Struct(_)=>format!("if *{value}=={j}::Value::Null{{{ok}({constructor})}}else{{{err}({j}::Error::Type(\"expected null for unit\"))}}"),
        Fields::Named(names)=>{
            let values=names.iter().map(|n|format!("{n}: {j}::Deserialize::from_json({object}.get({}).ok_or({j}::Error::Type(\"missing field\"))?)?",key(n))).collect::<Vec<_>>().join(",");
            format!("{{let {j}::Value::Object({object})={value} else{{return {err}({j}::Error::Type(\"expected object\"));}};if {object}.len()!={}{{return {err}({j}::Error::Type(\"unexpected field count\"));}}{ok}({constructor}{{{values}}})}}",names.len())
        }
        Fields::Tuple(count)=>{
            let values=(0..*count).map(|i|format!("{j}::Deserialize::from_json(&{array}[{i}])?")).collect::<Vec<_>>().join(",");
            format!("{{let {j}::Value::Array({array})={value} else{{return {err}({j}::Error::Type(\"expected array\"));}};if {array}.len()!={count}{{return {err}({j}::Error::Type(\"unexpected tuple length\"));}}{ok}({constructor}({values}))}}")
        }
    }
}
/// Trait bounds that make the generic field types `types` usable by an impl
/// of `trait_name` for the item.
fn json_bounds(header: &Header, types: &[String], trait_path: &str) -> Result<Vec<String>, String> {
    let mut bounds = Vec::new();
    let mut field_types = types.to_vec();
    field_types.sort();
    field_types.dedup();
    for ty in field_types {
        let tokens = ty
            .parse::<TokenStream>()
            .map_err(|_| "invalid compiler field tokens")?
            .into_iter()
            .collect::<Vec<_>>();
        let has_lifetime = tokens.iter().any(|token| punct(token, '\''));
        let mut names = Vec::new();
        all_identifiers(&tokens, &mut names);
        let projection = tokens.windows(3).any(|w| {
            ident(&w[0]).is_some_and(|name| header.type_parameters.contains(&name))
                && punct(&w[1], ':')
                && punct(&w[2], ':')
        }) || (tokens.first().is_some_and(|t| punct(t, '<'))
            && names.iter().any(|name| name == "as"));
        if (has_lifetime && !projection)
            || names
                .iter()
                .any(|name| name == "Self" || name == &header.name)
        {
            // Recursive bounds cycle back to this impl. Distinct lifetime-field
            // bounds can also overlap after outlives normalization. Bind their
            // type parameters instead, allowing the compiler to select wrappers.
            for parameter in &header.type_parameters {
                if names.contains(parameter) {
                    bounds.push(format!("{parameter}: {trait_path}"));
                }
            }
        } else if names
            .iter()
            .any(|name| header.type_parameters.contains(name))
        {
            bounds.push(format!("{ty}: {trait_path}"));
        }
    }
    Ok(bounds)
}
fn strip_raw(name: &str) -> &str {
    name.strip_prefix("r#").unwrap_or(name)
}
/// Impls for a named struct, following Go's `encoding/json` field rules.
fn generate_struct(
    header: Header,
    fields: &[NamedField],
    serialize: bool,
) -> Result<String, String> {
    let j = "::rust_stdlib::encoding::json";
    let p = &header.prefix;
    let (fields_trait, trait_name) = if serialize {
        ("SerializeFields", "Serialize")
    } else {
        ("DeserializeFields", "Deserialize")
    };
    let mut schema = String::new();
    let mut emit_arms = String::new();
    let mut build = String::new();
    let mut merge = String::new();
    let mut zero = String::from("true");
    for (i, f) in fields.iter().enumerate() {
        let rust_name = strip_raw(&f.name);
        let (name, ty) = (&f.name, &f.ty);
        if f.skip {
            build.push_str(&format!("{name}: ::core::default::Default::default(),"));
        } else if f.embedded {
            schema.push_str(&format!("if {p}fields.embedded({i},{rust_name:?},::core::any::type_name::<{ty}>()){{<{ty} as {j}::{fields_trait}>::json_fields({p}fields);{p}fields.leave();}}"));
            emit_arms.push_str(&format!("{i}=><{ty} as {j}::{fields_trait}>::json_emit(&self.{name},{p}w,{p}f,&{p}index[1..]),"));
            build.push_str(&format!("{name}:{p}b.embedded::<{ty}>()?,"));
            merge.push_str(&format!("{p}b.embedded_into(&mut self.{name})?;"));
            zero.push_str(&format!("&&{j}::Serialize::is_zero_value(&self.{name})"));
        } else {
            schema.push_str(&format!("{p}fields.field({i},{rust_name:?},{:?});", f.tag));
            emit_arms.push_str(&format!("{i}=>{p}w.field({p}f,&self.{name}),"));
            build.push_str(&format!("{name}:{p}b.field::<{ty}>({rust_name:?})?,"));
            merge.push_str(&format!("{p}b.field_into(&mut self.{name})?;"));
            zero.push_str(&format!("&&{j}::Serialize::is_zero_value(&self.{name})"));
        }
    }
    let mut bounds = Vec::new();
    if !header.predicates.is_empty() {
        bounds.push(header.predicates.clone());
    }
    bounds.extend(json_bounds(
        &header,
        &header.field_types,
        &format!("{j}::{trait_name}"),
    )?);
    bounds.extend(json_bounds(
        &header,
        &header.embedded_types,
        &format!("{j}::{fields_trait}"),
    )?);
    if serialize {
        bounds.extend(json_bounds(
            &header,
            &header.embedded_types,
            &format!("{j}::Serialize"),
        )?);
    } else {
        bounds.extend(json_bounds(
            &header,
            &header.skipped_types,
            "::core::default::Default",
        )?);
    }
    let constraints = if bounds.is_empty() {
        String::new()
    } else {
        format!("where {}", bounds.join(","))
    };
    let (name, impl_generics, type_generics) =
        (&header.name, &header.impl_generics, &header.type_generics);
    let schema_fn = format!("fn json_fields({p}fields:&mut {j}::FieldList){{{schema}}}");
    let result = format!("::core::result::Result<(),{j}::Error>");
    Ok(if serialize {
        format!(
            "impl{impl_generics} {j}::Serialize for {name}{type_generics} {constraints}{{\
fn to_json(&self)->::core::result::Result<{j}::Value,{j}::Error>{{{j}::serialize_to_value(self)}}\
fn serialize(&self,{p}s:&mut {j}::Serializer)->{result}{{{j}::serialize_struct(self,{p}s)}}\
fn is_zero_value(&self)->bool{{{zero}}}}}\
impl{impl_generics} {j}::SerializeFields for {name}{type_generics} {constraints}{{{schema_fn}\
fn json_emit(&self,{p}w:&mut {j}::ObjectWriter<'_>,{p}f:&{j}::Field,{p}index:&[usize])->{result}{{match {p}index[0]{{{emit_arms}_=>::core::result::Result::Ok(())}}}}}}"
        )
    } else {
        format!(
            "impl{impl_generics} {j}::Deserialize for {name}{type_generics} {constraints}{{\
fn from_json({p}v:&{j}::Value)->::core::result::Result<Self,{j}::Error>{{{j}::deserialize_from_value({p}v)}}\
fn unmarshal_json({p}n:&{j}::Node<'_>,{p}c:&mut {j}::DecodeState)->::core::result::Result<Self,{j}::Error>{{{j}::deserialize_struct::<Self>({p}n,{p}c,{name:?})}}\
fn unmarshal_json_into(&mut self,{p}n:&{j}::Node<'_>,{p}c:&mut {j}::DecodeState)->{result}{{{j}::merge_struct::<Self>(self,{p}n,{p}c,{name:?})}}\
fn json_zero()->::core::result::Result<Self,{j}::Error>{{{j}::zero_struct::<Self>({name:?})}}\
fn json_type_name()->::std::string::String{{::std::string::String::from({name:?})}}\
fn json_root_name()->&'static str{{{name:?}}}}}\
impl{impl_generics} {j}::DeserializeFields for {name}{type_generics} {constraints}{{{schema_fn}\
fn json_build({p}b:&mut {j}::Builder<'_,'_>)->::core::result::Result<Self,{j}::Error>{{::core::result::Result::Ok(Self{{{build}}})}}\
fn json_merge(&mut self,{p}b:&mut {j}::Builder<'_,'_>)->{result}{{{merge}::core::result::Result::Ok(())}}}}"
        )
    })
}
fn generate(item: Item, serialize: bool) -> Result<String, String> {
    let j = "::rust_stdlib::encoding::json";
    let ok = "::core::result::Result::Ok";
    let err = "::core::result::Result::Err";
    let item = match item {
        Item::Struct(header, Fields::Struct(fields)) => {
            if !serialize && header.borrowed {
                return Err(
                    "borrowed field deserialization is unsupported; use owned field types".into(),
                );
            }
            return generate_struct(header, &fields, serialize);
        }
        other => other,
    };
    let (header, body) = match item {
        Item::Struct(header, fields) => {
            let body = if serialize {
                serialize_fields(&fields, "self.", &header.prefix)
            } else {
                deserialize_fields(&fields, "Self", &header.prefix)
            };
            (header, body)
        }
        Item::Enum(header, variants) => {
            let prefix = &header.prefix;
            let value = format!("{prefix}value");
            let object = format!("{prefix}object");
            let tag = format!("{prefix}tag");
            let payload = format!("{prefix}payload");
            let body = if variants.is_empty() {
                if serialize {
                    "match *self {}".into()
                } else {
                    format!("{err}({j}::Error::Type(\"empty enum has no values\"))")
                }
            } else if serialize {
                let arms=variants.into_iter().map(|(variant,fields)|{
                    let pattern=match &fields {
                        Fields::Unit | Fields::Struct(_)=>format!("Self::{variant}"),
                        Fields::Named(names)=>format!("Self::{variant}{{{}}}",names.iter().enumerate().map(|(i,n)|format!("{n}: {prefix}field_{i}")).collect::<Vec<_>>().join(",")),
                        Fields::Tuple(count)=>format!("Self::{variant}({})",(0..*count).map(|i|format!("{prefix}field_{i}")).collect::<Vec<_>>().join(",")),
                    };
                    let value=serialize_fields(&fields,"",prefix);
                    format!("{pattern}=>{{let {payload}=(||->::core::result::Result<{j}::Value,{j}::Error>{{{value}}})()?;{ok}({j}::Value::object([({},{payload})]))}}",key(&variant))
                }).collect::<Vec<_>>().join(",");
                format!("match self{{{arms}}}")
            } else {
                let arms = variants
                    .into_iter()
                    .map(|(variant, fields)| {
                        format!(
                            "{}=>{}",
                            key(&variant),
                            deserialize_fields(&fields, &format!("Self::{variant}"), prefix)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                format!("let {j}::Value::Object({object})={value} else{{return {err}({j}::Error::Type(\"expected enum object\"));}};if {object}.len()!=1{{return {err}({j}::Error::Type(\"expected one variant\"));}}let ({tag},{value})={object}.iter().next().ok_or({j}::Error::Type(\"missing variant\"))?;match {tag}.as_str(){{{arms},_=>{err}({j}::Error::Type(\"unknown enum variant\"))}}")
            };
            (header, body)
        }
    };
    if !serialize && header.borrowed {
        return Err("borrowed field deserialization is unsupported; use owned field types".into());
    }
    let trait_name = if serialize {
        "Serialize"
    } else {
        "Deserialize"
    };
    let mut bounds = Vec::new();
    if !header.predicates.is_empty() {
        bounds.push(header.predicates.clone());
    }
    bounds.extend(json_bounds(
        &header,
        &header.field_types,
        &format!("{j}::{trait_name}"),
    )?);
    let constraints = if bounds.is_empty() {
        String::new()
    } else {
        format!("where {}", bounds.join(","))
    };
    let name = header.name;
    let declaration = format!(
        "impl {} {j}::{trait_name} for {name}{} {constraints}",
        header.impl_generics, header.type_generics
    );
    Ok(if serialize {
        format!("{declaration}{{fn to_json(&self)->::core::result::Result<{j}::Value,{j}::Error>{{{body}}}}}")
    } else {
        let value = format!("{}value", header.prefix);
        format!("{declaration}{{fn from_json({value}:&{j}::Value)->::core::result::Result<Self,{j}::Error>{{{body}}}}}")
    })
}

fn derive(input: TokenStream, serialize: bool) -> TokenStream {
    match parse(input).and_then(|item| generate(item, serialize)) {
        Ok(source) => source
            .parse()
            .unwrap_or_else(|_| fail("derive could not generate Rust syntax")),
        Err(e) => fail(&e),
    }
}

#[proc_macro_derive(Serialize, attributes(json))]
pub fn serialize(input: TokenStream) -> TokenStream {
    derive(input, true)
}
#[proc_macro_derive(Deserialize, attributes(json))]
pub fn deserialize(input: TokenStream) -> TokenStream {
    derive(input, false)
}

/// Derives `rust_stdlib::encoding::json::v2::MarshalTo` for a struct with
/// named fields, reading the same `#[json(...)]` field attributes as
/// `Serialize` (see the `v2` module).
#[proc_macro_derive(MarshalTo, attributes(json))]
pub fn marshal_to(input: TokenStream) -> TokenStream {
    v2::derive(input, true)
}

/// Derives `rust_stdlib::encoding::json::v2::UnmarshalFrom` for a struct with
/// named fields, reading the same `#[json(...)]` field attributes as
/// `Deserialize` (see the `v2` module).
#[proc_macro_derive(UnmarshalFrom, attributes(json))]
pub fn unmarshal_from(input: TokenStream) -> TokenStream {
    v2::derive(input, false)
}

/// Derives `rust_stdlib::encoding::xml::Marshal` for a struct with named
/// fields, reading Go-style field tags from `#[xml("...")]` attributes.
#[proc_macro_derive(Marshal, attributes(xml))]
pub fn xml_marshal(input: TokenStream) -> TokenStream {
    xml::derive(input, true)
}

/// Derives `rust_stdlib::encoding::xml::Unmarshal` for a struct with named
/// fields, reading Go-style field tags from `#[xml("...")]` attributes. Field
/// types and the struct itself (when used in `Vec` or `Option`) must be `Default`.
#[proc_macro_derive(Unmarshal, attributes(xml))]
pub fn xml_unmarshal(input: TokenStream) -> TokenStream {
    xml::derive(input, false)
}

/// Derives `rust_stdlib::reflect::{ReflectType, Reflect}` for a struct or a
/// unit-only enum: the static type information behind `reflect::Type` and
/// `reflect::Value`. Fields are exported when declared `pub`; Go struct tags,
/// embedding and names are set with `#[reflect(...)]` (see the `reflect`
/// module of this crate).
#[proc_macro_derive(Reflect, attributes(reflect))]
pub fn reflect(input: TokenStream) -> TokenStream {
    reflect::derive(input)
}

/// Registers the methods of one `impl` block with `rust_stdlib::reflect`, so
/// that `Value::method`, `Type::method` and `Type::implements` see them.
#[proc_macro_attribute]
pub fn reflect_methods(attr: TokenStream, item: TokenStream) -> TokenStream {
    reflect::methods_attribute(attr, item)
}

/// Makes `reflect::type_for::<dyn Trait>()` the Go interface type with the
/// trait's `&self`/`&mut self` methods.
#[proc_macro_attribute]
pub fn reflect_trait(attr: TokenStream, item: TokenStream) -> TokenStream {
    reflect::trait_attribute(attr, item)
}

/// Embeds files, directories and wildcard patterns (relative to the crate's
/// manifest directory) into a `rust_stdlib::embed::FS`, like `//go:embed`.
#[proc_macro]
pub fn embed(input: TokenStream) -> TokenStream {
    embed::embed(input)
}
