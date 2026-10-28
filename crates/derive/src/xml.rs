//! `Marshal` and `Unmarshal` derives for `rust_stdlib::encoding::xml`.
//!
//! Go's `encoding/xml` reads struct tags by reflection. These derives read the
//! same tag text from `#[xml("...")]` attributes and emit a static
//! `StructSpec`; the runtime interprets the tags exactly as Go does.
//!
//! * `#[xml("name,attr,omitempty")]` on a field is Go's `xml:"..."` tag, with
//!   all of Go's options (`attr`, `chardata`, `cdata`, `innerxml`, `comment`,
//!   `any`, `omitempty`, `a>b>c` paths, `"namespace name"` prefixes, `"-"`).
//! * `#[xml(embed)]` marks an anonymous (embedded) struct field whose fields are
//!   lifted into the outer struct; it may be combined with a tag string.
//! * A field named `xml_name` is Go's `XMLName`.
//! * The default element name of a field is its Rust identifier verbatim.
//! * Structs with named fields only; generic parameters are not supported.
use super::{fail, ident, punct, skip_visibility, split, text};
use proc_macro::{Delimiter, TokenStream, TokenTree};

struct Field {
    /// The field as written (`r#type` keeps its prefix for access).
    access: String,
    /// Go's field name.
    go_name: String,
    tag: String,
    embed: bool,
    ty: String,
}

struct Struct {
    name: String,
    fields: Vec<Field>,
}

/// The value of a (non-byte) string literal token.
pub(super) fn string_literal(token: &TokenTree) -> Result<String, String> {
    let TokenTree::Literal(l) = token else {
        return Err("expected a string literal".into());
    };
    let source = l.to_string();
    if let Some(rest) = source.strip_prefix('r') {
        let hashes = rest.bytes().take_while(|b| *b == b'#').count();
        let body = &rest[hashes..];
        let inner = body
            .strip_prefix('"')
            .and_then(|b| b.strip_suffix('"'))
            .ok_or("malformed raw string literal")?;
        let end = inner
            .len()
            .checked_sub(hashes)
            .ok_or("malformed raw string literal")?;
        return Ok(inner[..end].to_string());
    }
    let inner = source
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .ok_or("the xml attribute takes a string literal")?;
    let mut out = String::new();
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next().ok_or("malformed escape")? {
            'n' => out.push('\n'),
            't' => out.push('\t'),
            'r' => out.push('\r'),
            '0' => out.push('\0'),
            '\\' => out.push('\\'),
            '"' => out.push('"'),
            '\'' => out.push('\''),
            'u' => {
                let rest: String = chars.by_ref().take_while(|c| *c != '}').collect();
                let hex = rest.trim_start_matches('{').replace('_', "");
                let code = u32::from_str_radix(&hex, 16).map_err(|_| "malformed \\u escape")?;
                out.push(char::from_u32(code).ok_or("invalid \\u escape")?);
            }
            'x' => {
                let hex: String = chars.by_ref().take(2).collect();
                let code = u8::from_str_radix(&hex, 16).map_err(|_| "malformed \\x escape")?;
                out.push(char::from(code));
            }
            '\n' => {
                // Line continuation: skip the newline and leading whitespace.
                let rest = chars.as_str().trim_start();
                chars = rest.chars();
            }
            other => return Err(format!("unsupported escape \\{other}")),
        }
    }
    Ok(out)
}

/// Flattens the invisible groups that `macro_rules!` fragments (`meta`, `ty`)
/// arrive in.
fn flatten(stream: TokenStream) -> Vec<TokenTree> {
    let mut out = Vec::new();
    for t in stream {
        match t {
            TokenTree::Group(g) if g.delimiter() == Delimiter::None => {
                out.extend(flatten(g.stream()))
            }
            other => out.push(other),
        }
    }
    out
}

fn parse_field_attrs(part: &[TokenTree]) -> Result<(usize, Option<String>, bool), String> {
    let mut i = 0;
    let mut tag = None;
    let mut embed = false;
    while i < part.len() && punct(&part[i], '#') {
        let Some(TokenTree::Group(g)) = part.get(i + 1) else {
            return Err("malformed attribute".into());
        };
        if g.delimiter() != Delimiter::Bracket {
            return Err("malformed attribute".into());
        }
        let tokens = flatten(g.stream());
        match tokens.first().and_then(ident).as_deref() {
            Some(
                "doc" | "allow" | "warn" | "deny" | "cfg" | "must_use" | "deprecated" | "json"
                | "reflect",
            ) => {}
            Some("xml") => {
                let Some(TokenTree::Group(args)) = tokens.get(1) else {
                    return Err("expected #[xml(\"tag\")] or #[xml(embed)]".into());
                };
                if args.delimiter() != Delimiter::Parenthesis || tokens.len() != 2 {
                    return Err("expected #[xml(\"tag\")] or #[xml(embed)]".into());
                }
                for item in split(flatten(args.stream()).into_iter().collect())? {
                    match item.as_slice() {
                        [t] if ident(t).as_deref() == Some("embed") => embed = true,
                        [t @ TokenTree::Literal(_)] => {
                            if tag.is_some() {
                                return Err("duplicate xml tag string".into());
                            }
                            tag = Some(string_literal(t)?);
                        }
                        _ => return Err("expected #[xml(\"tag\")] or #[xml(embed)]".into()),
                    }
                }
            }
            _ => return Err(format!("unsupported derive attribute: {}", g.stream())),
        }
        i += 2;
    }
    Ok((i, tag, embed))
}

fn parse(input: TokenStream) -> Result<Struct, String> {
    let tokens: Vec<TokenTree> = input.into_iter().collect();
    for pair in tokens.windows(2) {
        if let (true, TokenTree::Group(g)) = (punct(&pair[0], '#'), &pair[1]) {
            if g.stream()
                .into_iter()
                .next()
                .and_then(|t| ident(&t))
                .as_deref()
                == Some("xml")
            {
                return Err("#[xml(...)] attributes belong on fields".into());
            }
        }
    }
    // Other container attributes (doc, derive, allow, ...) do not affect the
    // XML description and are left to the compiler.
    let mut i = 0;
    while i < tokens.len() && punct(&tokens[i], '#') {
        i += 2;
    }
    i = skip_visibility(&tokens, i);
    match tokens.get(i).and_then(ident).as_deref() {
        Some("struct") => {}
        _ => return Err("XML derives support structs with named fields only".into()),
    }
    let name = tokens
        .get(i + 1)
        .and_then(ident)
        .ok_or("expected item name")?;
    match tokens.get(i + 2) {
        Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Brace && tokens.len() == i + 3 => {
            let mut fields = Vec::new();
            for part in split(g.stream())? {
                let (mut j, tag, embed) = parse_field_attrs(&part)?;
                j = skip_visibility(&part, j);
                let access = part.get(j).and_then(ident).ok_or("expected named field")?;
                if !part.get(j + 1).is_some_and(|t| punct(t, ':')) || j + 2 >= part.len() {
                    return Err("expected field name followed by a type".into());
                }
                let bare = access.strip_prefix("r#").unwrap_or(&access).to_string();
                let go_name = if bare == "xml_name" {
                    "XMLName".to_string()
                } else {
                    bare
                };
                fields.push(Field {
                    access,
                    go_name,
                    tag: tag.unwrap_or_default(),
                    embed,
                    ty: text(&part[j + 2..]),
                });
            }
            Ok(Struct { name, fields })
        }
        Some(t) if punct(t, '<') => Err("XML derives do not support generic structs".into()),
        Some(t) if punct(t, ';') && tokens.len() == i + 3 => Ok(Struct {
            name,
            fields: Vec::new(),
        }),
        _ => Err("XML derives support structs with named fields only".into()),
    }
}

fn generate(s: &Struct, marshal: bool) -> String {
    let x = "::rust_stdlib::encoding::xml";
    let name = &s.name;
    let trait_name = if marshal { "Marshal" } else { "Unmarshal" };
    let fields = s
        .fields
        .iter()
        .map(|f| {
            format!(
                "{x}::FieldSpec{{name:{:?},tag:{:?},anonymous:{},type_string:stringify!({}),type_spec:<{} as {x}::{trait_name}>::xml_struct_spec}}",
                f.go_name, f.tag, f.embed, f.ty, f.ty
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let spec = format!(
        "static SPEC: {x}::StructSpec = {x}::StructSpec{{name:{name:?},type_string:{name:?},fields:&[{fields}]}};"
    );
    let body = if marshal {
        let arms = s
            .fields
            .iter()
            .enumerate()
            .map(|(i, f)| format!("{i}=>::core::option::Option::Some(&self.{}),", f.access))
            .collect::<String>();
        format!(
            "impl {x}::Marshal for {name}{{\
             fn xml_view(&self)->{x}::View<'_>{{{x}::View::Struct(&SPEC)}}\
             fn xml_type_name(&self)->&'static str{{{name:?}}}\
             fn xml_type_string(&self)->::std::string::String{{::std::string::String::from({name:?})}}\
             fn xml_elem_type_string()->::std::string::String{{::std::string::String::from({name:?})}}\
             fn xml_field(&self,i:usize)->::core::option::Option<&dyn {x}::Marshal>{{match i{{{arms}_=>::core::option::Option::None}}}}\
             fn xml_struct_spec()->::core::option::Option<&'static {x}::StructSpec>{{::core::option::Option::Some(&SPEC)}}\
             }}"
        )
    } else {
        let arms = s
            .fields
            .iter()
            .enumerate()
            .map(|(i, f)| format!("{i}=>::core::option::Option::Some(&mut self.{}),", f.access))
            .collect::<String>();
        format!(
            "impl {x}::Unmarshal for {name}{{\
             fn xml_kind(&self)->{x}::Kind{{{x}::Kind::Struct(&SPEC)}}\
             fn xml_type_string(&self)->::std::string::String{{::std::string::String::from({name:?})}}\
             fn xml_elem_type_string()->::std::string::String{{::std::string::String::from({name:?})}}\
             fn xml_field_mut(&mut self,i:usize)->::core::option::Option<&mut dyn {x}::Unmarshal>{{match i{{{arms}_=>::core::option::Option::None}}}}\
             fn xml_struct_spec()->::core::option::Option<&'static {x}::StructSpec>{{::core::option::Option::Some(&SPEC)}}\
             }}"
        )
    };
    format!("const _:()={{{spec}{body}}};")
}

pub(super) fn derive(input: TokenStream, marshal: bool) -> TokenStream {
    match parse(input).map(|s| generate(&s, marshal)) {
        Ok(source) => source
            .parse()
            .unwrap_or_else(|_| fail("derive could not generate Rust syntax")),
        Err(e) => fail(&e),
    }
}
