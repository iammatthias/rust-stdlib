//! `#[derive(Reflect)]`, `#[reflect_methods]` and `#[reflect_trait]` for
//! `rust_stdlib::reflect`.
//!
//! Go's reflection reads types out of the running program. Rust cannot, so
//! these macros write the static facts down: field names, Go struct tags,
//! embedding, exportedness, method signatures and trait method sets.
//!
//! * `#[derive(Reflect)]` on a struct (named, tuple or unit) or a unit-only
//!   enum. A field is *exported* (Go's capitalised name) when it is declared
//!   plain `pub`. Field attributes `#[reflect("go tag")]`,
//!   `#[reflect(name = "Go")]`, `#[reflect(embed)]`, `#[reflect(export)]` and
//!   `#[reflect(skip)]`; container attributes `#[reflect(pkg = "main")]` and
//!   `#[reflect(name = "T")]`.
//! * `#[reflect_methods]` on one `impl` block registers its methods that take
//!   `&self` or `&mut self` and no generics, so `Value::method`/`call` and
//!   `Type::implements` see them. A method is exported when it is `pub`
//!   (always, in a trait impl). Mark a method `#[reflect(skip)]` to leave it out.
//! * `#[reflect_trait]` on a trait definition makes `type_for::<dyn Trait>()`
//!   the Go interface type with the trait's `&self`/`&mut self` methods.
use super::xml::string_literal;
use super::{
    fail, flatten_invisible, generics, ident, predicates, punct, skip_visibility, split, text,
};
use proc_macro::{Delimiter, TokenStream, TokenTree};

const R: &str = "::rust_stdlib::reflect";

struct Field {
    /// How the field is accessed: a name, or the tuple index.
    access: String,
    go_name: String,
    tag: String,
    embedded: bool,
    exported: bool,
    skip: bool,
    ty: String,
}

enum Shape {
    Named,
    Tuple,
    Unit,
}

enum Body {
    Struct(Shape, Vec<Field>),
    Enum(Vec<String>),
}

struct Item {
    name: String,
    go_name: Option<String>,
    pkg: Option<String>,
    impl_generics: String,
    type_generics: String,
    predicates: String,
    type_params: Vec<String>,
    body: Body,
}

/// Parses a `#[reflect(...)]` attribute argument list.
struct Opts {
    tag: Option<String>,
    name: Option<String>,
    pkg: Option<String>,
    embed: bool,
    export: bool,
    skip: bool,
}

fn parse_opts(args: &proc_macro::Group) -> Result<Opts, String> {
    let mut o = Opts {
        tag: None,
        name: None,
        pkg: None,
        embed: false,
        export: false,
        skip: false,
    };
    for entry in split(args.stream())?.into_iter().map(flatten_invisible) {
        match entry.as_slice() {
            [lit @ TokenTree::Literal(_)] => {
                if o.tag.is_some() {
                    return Err("duplicate reflect tag string".into());
                }
                o.tag = Some(string_literal(lit)?);
            }
            [w] => match ident(w).as_deref() {
                Some("embed") => o.embed = true,
                Some("export") => o.export = true,
                Some("skip") => o.skip = true,
                _ => return Err("unsupported reflect attribute keyword".into()),
            },
            [k, eq, lit] if punct(eq, '=') => match ident(k).as_deref() {
                Some("name") => o.name = Some(string_literal(lit)?),
                Some("pkg") => o.pkg = Some(string_literal(lit)?),
                _ => return Err("unsupported reflect attribute key".into()),
            },
            _ => return Err("unsupported reflect attribute syntax".into()),
        }
    }
    Ok(o)
}

/// Reads the attributes in front of an item or field. Returns the index after
/// them and the merged `#[reflect(...)]` options; other attributes are ignored.
fn attrs(tokens: &[TokenTree], mut i: usize) -> Result<(usize, Opts), String> {
    let mut merged = Opts {
        tag: None,
        name: None,
        pkg: None,
        embed: false,
        export: false,
        skip: false,
    };
    while i < tokens.len() && punct(&tokens[i], '#') {
        let Some(TokenTree::Group(g)) = tokens.get(i + 1) else {
            return Err("malformed attribute".into());
        };
        if g.delimiter() != Delimiter::Bracket {
            return Err("malformed attribute".into());
        }
        let inner = flatten_invisible(g.stream().into_iter().collect());
        if inner.first().and_then(ident).as_deref() == Some("reflect") {
            let Some(TokenTree::Group(args)) = inner.get(1).filter(|_| inner.len() == 2) else {
                return Err("malformed reflect attribute: expected #[reflect(...)]".into());
            };
            if args.delimiter() != Delimiter::Parenthesis {
                return Err("malformed reflect attribute: expected #[reflect(...)]".into());
            }
            let o = parse_opts(args)?;
            merged.tag = o.tag.or(merged.tag);
            merged.name = o.name.or(merged.name);
            merged.pkg = o.pkg.or(merged.pkg);
            merged.embed |= o.embed;
            merged.export |= o.export;
            merged.skip |= o.skip;
        }
        i += 2;
    }
    Ok((i, merged))
}

/// The Go name an embedded field gets: the last path segment of its type,
/// looking through `Option`/`Box`/`Rc`/`Arc` pointers.
fn embedded_name(ty: &[TokenTree]) -> Option<String> {
    let mut i = 0;
    loop {
        let name = ty.get(i).and_then(ident)?;
        // Skip a path prefix such as `a::b::`.
        let mut j = i;
        let mut last = name;
        while ty.get(j + 1).is_some_and(|t| punct(t, ':'))
            && ty.get(j + 2).is_some_and(|t| punct(t, ':'))
        {
            j += 3;
            last = ty.get(j).and_then(ident)?;
        }
        if matches!(last.as_str(), "Option" | "Box" | "Rc" | "Arc")
            && ty.get(j + 1).is_some_and(|t| punct(t, '<'))
        {
            i = j + 2;
            continue;
        }
        return Some(last.strip_prefix("r#").unwrap_or(&last).to_string());
    }
}

fn parse_fields(group: &proc_macro::Group, named: bool) -> Result<Vec<Field>, String> {
    let mut out = Vec::new();
    for (idx, part) in split(group.stream())?.into_iter().enumerate() {
        let (mut i, o) = attrs(&part, 0)?;
        let exported = part.get(i).and_then(ident).as_deref() == Some("pub")
            && !matches!(part.get(i + 1), Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Parenthesis);
        i = skip_visibility(&part, i);
        let (access, bare, ty_tokens) = if named {
            let name = part.get(i).and_then(ident).ok_or("expected named field")?;
            if !part.get(i + 1).is_some_and(|t| punct(t, ':')) || i + 2 >= part.len() {
                return Err("expected field name followed by a type".into());
            }
            let bare = name.strip_prefix("r#").unwrap_or(&name).to_string();
            (name, bare, &part[i + 2..])
        } else {
            if i >= part.len() {
                return Err("expected tuple field type".into());
            }
            (idx.to_string(), format!("F{idx}"), &part[i..])
        };
        let go_name = if let Some(n) = o.name.clone() {
            n
        } else if o.embed {
            embedded_name(ty_tokens).unwrap_or(bare)
        } else {
            bare
        };
        out.push(Field {
            access,
            go_name,
            tag: o.tag.unwrap_or_default(),
            embedded: o.embed,
            exported: exported || o.export || !named,
            skip: o.skip,
            ty: text(ty_tokens),
        });
    }
    Ok(out)
}

fn parse(input: TokenStream) -> Result<Item, String> {
    let tokens: Vec<TokenTree> = input.into_iter().collect();
    let (i, o) = attrs(&tokens, 0)?;
    let i = skip_visibility(&tokens, i);
    let kind = tokens
        .get(i)
        .and_then(ident)
        .ok_or("expected struct or enum")?;
    if kind != "struct" && kind != "enum" {
        return Err("the Reflect derive supports structs and unit-only enums".into());
    }
    let name = tokens
        .get(i + 1)
        .and_then(ident)
        .ok_or("expected item name")?;
    let (impl_generics, type_generics, used, type_params) = generics(&tokens[i + 2..])?;
    if tokens[i + 2..i + 2 + used].iter().any(|t| punct(t, '\'')) {
        return Err(
            "the Reflect derive does not support lifetime parameters (types are 'static)".into(),
        );
    }
    let rest = &tokens[i + 2 + used..];
    let go_name = o.name.clone();
    let mk = |predicates_: String, body: Body| Item {
        name: name.clone(),
        go_name: go_name.clone(),
        pkg: o.pkg.clone(),
        impl_generics: impl_generics.clone(),
        type_generics: type_generics.clone(),
        predicates: predicates_,
        type_params: type_params.clone(),
        body,
    };
    if kind == "struct" {
        if let Some(TokenTree::Group(g)) = rest
            .first()
            .filter(|t| matches!(t, TokenTree::Group(g) if g.delimiter() == Delimiter::Parenthesis))
        {
            if !rest.last().is_some_and(|t| punct(t, ';')) {
                return Err("expected tuple struct terminator".into());
            }
            let p = predicates(&rest[1..rest.len() - 1])?;
            return Ok(mk(p, Body::Struct(Shape::Tuple, parse_fields(g, false)?)));
        }
        if let Some(TokenTree::Group(g)) = rest
            .last()
            .filter(|t| matches!(t, TokenTree::Group(g) if g.delimiter() == Delimiter::Brace))
        {
            let p = predicates(&rest[..rest.len() - 1])?;
            return Ok(mk(p, Body::Struct(Shape::Named, parse_fields(g, true)?)));
        }
        if rest.last().is_some_and(|t| punct(t, ';')) {
            let p = predicates(&rest[..rest.len() - 1])?;
            return Ok(mk(p, Body::Struct(Shape::Unit, Vec::new())));
        }
        return Err("expected struct fields or terminator".into());
    }
    let Some(TokenTree::Group(g)) = rest.last() else {
        return Err("expected enum body".into());
    };
    if g.delimiter() != Delimiter::Brace {
        return Err("expected enum braces".into());
    }
    let p = predicates(&rest[..rest.len() - 1])?;
    let mut variants = Vec::new();
    for part in split(g.stream())? {
        let (j, _) = attrs(&part, 0)?;
        let v = part.get(j).and_then(ident).ok_or("expected variant name")?;
        if j + 1 != part.len() {
            return Err(
                "the Reflect derive supports unit-only enums without explicit discriminants".into(),
            );
        }
        variants.push(v);
    }
    Ok(mk(p, Body::Enum(variants)))
}

fn bounds(item: &Item, bound: &str) -> String {
    let mut preds: Vec<String> = item
        .type_params
        .iter()
        .map(|p| format!("{p}: {bound}"))
        .collect();
    if !item.predicates.is_empty() {
        preds.push(item.predicates.clone());
    }
    if preds.is_empty() {
        String::new()
    } else {
        format!("where {}", preds.join(","))
    }
}

fn generate(item: &Item) -> String {
    let name = &item.name;
    let bare = name.strip_prefix("r#").unwrap_or(name);
    let go = item.go_name.clone().unwrap_or_else(|| bare.to_string());
    let pkg = match &item.pkg {
        Some(p) => format!("{p:?}"),
        None => "::core::module_path!()".to_string(),
    };
    let ig = &item.impl_generics;
    let tg = &item.type_generics;
    let ty = format!("{name}{tg}");
    let ty_name = if item.type_params.is_empty() {
        format!("::std::string::String::from({go:?})")
    } else {
        let args = item
            .type_params
            .iter()
            .map(|p| format!("<{p} as {R}::ReflectType>::reflect_type().to_string()"))
            .collect::<Vec<_>>()
            .join(",");
        format!("::std::format!(\"{go}[{{}}]\", [{args}].join(\",\"))")
    };
    let body_expr = match &item.body {
        Body::Struct(_, fields) => {
            let fs = fields
                .iter()
                .filter(|f| !f.skip)
                .map(|f| {
                    let fp = if f.exported {
                        "\"\"".to_string()
                    } else {
                        pkg.clone()
                    };
                    format!(
                        "{R}::__private::field({:?},<{} as {R}::ReflectType>::reflect_type(),{:?},{},{fp})",
                        f.go_name, f.ty, f.tag, f.embedded
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{R}::__private::struct_body(::std::vec![{fs}],{pkg})")
        }
        Body::Enum(_) => format!("{R}::__private::basic_body({R}::Kind::Int)"),
    };
    let methods = format!(
        "::core::option::Option::Some(|| {{use {R}::__private::{{ViaHas as _,ViaNone as _}};\
         (&{R}::__private::Probe::<{ty}>::new()).reflect_methods_probe()}})"
    );
    let type_impl = format!(
        "impl{ig} {R}::ReflectType for {ty} {} {{\
         fn reflect_type()->{R}::Type{{\
         {R}::__private::named_type::<Self>({pkg},|| {ty_name},|| {body_expr},{methods})}}}}",
        bounds(item, &format!("{R}::ReflectType")),
    );
    let (to_value, from_value) = match &item.body {
        Body::Struct(shape, fields) => {
            let parts = fields
                .iter()
                .filter(|f| !f.skip)
                .map(|f| format!("{R}::Reflect::to_value(&self.{})", f.access))
                .collect::<Vec<_>>()
                .join(",");
            let to = format!(
                "{R}::Value::from_parts(&<Self as {R}::ReflectType>::reflect_type(),&[{parts}])"
            );
            let mut idx = 0usize;
            let inits = fields
                .iter()
                .map(|f| {
                    let v = if f.skip {
                        "::core::default::Default::default()".to_string()
                    } else {
                        let s = format!("<{} as {R}::Reflect>::from_value(&v.field({idx}))?", f.ty);
                        idx += 1;
                        s
                    };
                    match shape {
                        Shape::Named => format!("{}: {v}", f.access),
                        _ => v,
                    }
                })
                .collect::<Vec<_>>()
                .join(",");
            let build = match shape {
                Shape::Named => format!("Self{{{inits}}}"),
                Shape::Tuple => format!("Self({inits})"),
                Shape::Unit => "Self".to_string(),
            };
            let count = fields.iter().filter(|f| !f.skip).count();
            let from = format!(
                "if v.kind()!={R}::Kind::Struct||v.num_field()!={count}usize{{return ::core::result::Result::Err({R}::__private::mismatch(v,\"struct\"));}}\
                 ::core::result::Result::Ok({build})"
            );
            (to, from)
        }
        Body::Enum(variants) => {
            let arms = variants
                .iter()
                .enumerate()
                .map(|(i, v)| format!("Self::{v}=>{i}i64,"))
                .collect::<String>();
            let to = format!(
                "{R}::Value::from_int(&<Self as {R}::ReflectType>::reflect_type(),match self{{{arms}}})"
            );
            let back = variants
                .iter()
                .enumerate()
                .map(|(i, v)| format!("{i}=>::core::result::Result::Ok(Self::{v}),"))
                .collect::<String>();
            let from = format!(
                "if v.kind()!={R}::Kind::Int{{return ::core::result::Result::Err({R}::__private::mismatch(v,\"enum\"));}}\
                 match v.int(){{{back}n=>::core::result::Result::Err({R}::__private::bad_variant({name:?},n))}}"
            );
            (to, from)
        }
    };
    let value_impl = format!(
        "impl{ig} {R}::Reflect for {ty} {} {{\
         fn to_value(&self)->{R}::Value{{{to_value}}}\
         fn from_value(v:&{R}::Value)->::core::result::Result<Self,{R}::Error>{{\
         let v=&v.dynamic();{from_value}}}}}",
        bounds(item, &format!("{R}::Reflect")),
    );
    format!(
        "#[allow(unused_mut,unused_variables,clippy::all)]const _:()={{{type_impl}{value_impl}}};"
    )
}

pub(super) fn derive(input: TokenStream) -> TokenStream {
    match parse(input).map(|s| generate(&s)) {
        Ok(source) => source
            .parse()
            .unwrap_or_else(|_| fail("derive could not generate Rust syntax")),
        Err(e) => fail(&e),
    }
}

// ---------------------------------------------------------------------------
// #[reflect_methods] and #[reflect_trait].

struct Sig {
    name: String,
    exported: bool,
    mutable: bool,
    /// (parameter name, argument type, pass-by prefix such as `&`)
    params: Vec<(String, String, &'static str)>,
    /// (return type, wrapper kind)
    ret: Ret,
}

enum Ret {
    Unit,
    One(String),
    Multi(Vec<String>),
}

/// Maps a parameter type to the owned type that crosses the reflection
/// boundary and the prefix used to pass it on.
fn param_type(ty: &[TokenTree]) -> Option<(String, &'static str)> {
    if ty.first().is_some_and(|t| punct(t, '&')) {
        let mut i = 1;
        if ty.get(i).is_some_and(|t| punct(t, '\'')) {
            i += 2;
        }
        let mutable = ty.get(i).and_then(ident).as_deref() == Some("mut");
        if mutable {
            i += 1;
        }
        let rest = &ty[i..];
        if has_unsupported(rest) {
            return None;
        }
        let prefix = if mutable { "&mut " } else { "&" };
        if rest.len() == 1 && ident(&rest[0]).as_deref() == Some("str") {
            return Some(("::std::string::String".into(), prefix));
        }
        if let [TokenTree::Group(g)] = rest {
            if g.delimiter() == Delimiter::Bracket {
                return Some((format!("::std::vec::Vec<{}>", g.stream()), prefix));
            }
        }
        if mutable {
            // `&mut T` is Go's `*T`: the caller passes a pointer and the
            // method's changes are written back through it.
            return Some((format!("{R}::__private::PtrArg<{}>", text(rest)), prefix));
        }
        return Some((text(rest), prefix));
    }
    if has_unsupported(ty) {
        return None;
    }
    Some((text(ty), ""))
}

fn has_unsupported(tokens: &[TokenTree]) -> bool {
    tokens.iter().any(|t| match t {
        TokenTree::Punct(p) => p.as_char() == '&',
        TokenTree::Ident(i) => matches!(i.to_string().as_str(), "impl" | "dyn"),
        TokenTree::Group(g) => has_unsupported(&g.stream().into_iter().collect::<Vec<_>>()),
        _ => false,
    })
}

fn is_arrow(tokens: &[TokenTree], i: usize) -> bool {
    punct(&tokens[i], '-') && tokens.get(i + 1).is_some_and(|t| punct(t, '>'))
}

/// Parses the signature of a function whose `fn` keyword is at `fn_at`.
fn parse_sig(tokens: &[TokenTree], fn_at: usize, exported: bool) -> Option<(Sig, usize)> {
    let name = tokens.get(fn_at + 1).and_then(ident)?;
    let mut i = fn_at + 2;
    // Generic functions cannot be reflected; skip to the body.
    let generic = tokens.get(i).is_some_and(|t| punct(t, '<'));
    if generic {
        let mut depth = 0;
        while i < tokens.len() {
            if punct(&tokens[i], '<') {
                depth += 1;
            } else if punct(&tokens[i], '>') && !(i > 0 && punct(&tokens[i - 1], '-')) {
                depth -= 1;
                if depth == 0 {
                    i += 1;
                    break;
                }
            }
            i += 1;
        }
    }
    let TokenTree::Group(args) = tokens.get(i)? else {
        return None;
    };
    if args.delimiter() != Delimiter::Parenthesis {
        return None;
    }
    i += 1;
    let mut ret_tokens: Vec<TokenTree> = Vec::new();
    if i + 1 < tokens.len() && is_arrow(tokens, i) {
        i += 2;
        while i < tokens.len() {
            let t = &tokens[i];
            if matches!(t, TokenTree::Group(g) if g.delimiter() == Delimiter::Brace)
                || punct(t, ';')
                || ident(t).as_deref() == Some("where")
            {
                break;
            }
            ret_tokens.push(t.clone());
            i += 1;
        }
    }
    // Skip a where clause and find the end of the item.
    while i < tokens.len() {
        match &tokens[i] {
            TokenTree::Group(g) if g.delimiter() == Delimiter::Brace => {
                i += 1;
                break;
            }
            t if punct(t, ';') => {
                i += 1;
                break;
            }
            _ => i += 1,
        }
    }
    if generic {
        return None;
    }
    let parts = split(args.stream()).ok()?;
    let recv = parts.first()?;
    let has_self = recv.iter().any(|t| ident(t).as_deref() == Some("self"));
    let by_ref = recv.first().is_some_and(|t| punct(t, '&'));
    if !has_self || !by_ref {
        return None;
    }
    let mutable = recv.iter().any(|t| ident(t).as_deref() == Some("mut"));
    let mut params = Vec::new();
    for (k, p) in parts.iter().skip(1).enumerate() {
        // pattern : type
        let colon = p.iter().position(|t| {
            matches!(t, TokenTree::Punct(c) if c.as_char() == ':' && c.spacing() == proc_macro::Spacing::Alone)
        })?;
        let (ty, prefix) = param_type(&p[colon + 1..])?;
        params.push((format!("__a{k}"), ty, prefix));
    }
    if has_unsupported(&ret_tokens) {
        return None;
    }
    let ret = if ret_tokens.is_empty() {
        Ret::Unit
    } else if let [TokenTree::Group(g)] = ret_tokens.as_slice() {
        if g.delimiter() == Delimiter::Parenthesis {
            let items = split(g.stream()).ok()?;
            match items.len() {
                0 => Ret::Unit,
                1 => Ret::One(text(&items[0])),
                _ => Ret::Multi(items.iter().map(|x| text(x)).collect()),
            }
        } else {
            Ret::One(text(&ret_tokens))
        }
    } else {
        Ret::One(text(&ret_tokens))
    };
    Some((
        Sig {
            name,
            exported,
            mutable,
            params,
            ret,
        },
        i,
    ))
}

fn ret_types(ret: &Ret) -> (String, String) {
    match ret {
        Ret::Unit => ("()".into(), "()".into()),
        Ret::One(t) => (format!("{R}::One<{t}>"), t.clone()),
        Ret::Multi(ts) => (
            format!("{R}::Multi<({},)>", ts.join(",")),
            format!("({})", ts.join(",")),
        ),
    }
}

fn arg_tuple(sig: &Sig) -> String {
    format!(
        "({})",
        sig.params
            .iter()
            .map(|(_, t, _)| format!("{t},"))
            .collect::<String>()
    )
}

/// The `(name, signature type)` entry describing a method.
fn signature_expr(sig: &Sig) -> String {
    let ins = sig
        .params
        .iter()
        .map(|(_, t, _)| format!("<{t} as {R}::ReflectType>::reflect_type()"))
        .collect::<Vec<_>>()
        .join(",");
    let outs = match &sig.ret {
        Ret::Unit => String::new(),
        Ret::One(t) => format!("<{t} as {R}::ReflectType>::reflect_type()"),
        Ret::Multi(ts) => ts
            .iter()
            .map(|t| format!("<{t} as {R}::ReflectType>::reflect_type()"))
            .collect::<Vec<_>>()
            .join(","),
    };
    format!("{R}::func_of(&[{ins}],&[{outs}],false)")
}

fn method_expr(sig: &Sig) -> String {
    let names = sig
        .params
        .iter()
        .map(|(n, _, _)| n.clone())
        .collect::<String>();
    let _ = names;
    let pat = format!(
        "({})",
        sig.params
            .iter()
            .map(|(n, _, _)| format!("mut {n},"))
            .collect::<String>()
    );
    let call_args = sig
        .params
        .iter()
        .map(|(n, t, p)| {
            if t.contains("::PtrArg<") {
                format!("&mut __l{n}")
            } else {
                format!("{p}{n}")
            }
        })
        .collect::<Vec<_>>()
        .join(",");
    let loads = sig
        .params
        .iter()
        .filter(|(_, t, _)| t.contains("::PtrArg<"))
        .map(|(n, _, _)| format!("let mut __l{n}={n}.load();"))
        .collect::<String>();
    let stores = sig
        .params
        .iter()
        .filter(|(_, t, _)| t.contains("::PtrArg<"))
        .map(|(n, _, _)| format!("{n}.store(&__l{n});"))
        .collect::<String>();
    let call = format!("__s.{}({call_args})", sig.name);
    let wrapped = match &sig.ret {
        Ret::Unit => format!("{{{loads}{call};{stores}}}"),
        Ret::One(_) => format!("{{{loads}let __r={call};{stores}{R}::One(__r)}}"),
        Ret::Multi(_) => format!("{{{loads}let __r={call};{stores}{R}::Multi(__r)}}"),
    };
    let (rt, _) = ret_types(&sig.ret);
    let recv = if sig.mutable { "Mutable" } else { "Shared" };
    format!(
        "{R}::__private::method::<Self,{},{rt}>({:?},{},::core::module_path!(),{R}::__private::Recv::{recv},\
         |__s:&mut Self,{pat}:{}|{wrapped})",
        arg_tuple(sig),
        sig.name,
        sig.exported,
        arg_tuple(sig),
    )
}

fn strip_skip_attrs(tokens: &[TokenTree]) -> (Vec<TokenTree>, Vec<bool>) {
    // Returns the tokens without `#[reflect(skip)]` and, for each `fn`
    // keyword position in the original, whether it was skipped. The flags
    // are consumed by `collect_methods` through `skip_before`.
    let mut out = Vec::new();
    let mut skipped = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        if punct(&tokens[i], '#') {
            if let Some(TokenTree::Group(g)) = tokens.get(i + 1) {
                let inner: Vec<TokenTree> = flatten_invisible(g.stream().into_iter().collect());
                if inner.first().and_then(ident).as_deref() == Some("reflect") {
                    // Remember the skip request for the next `fn`.
                    skipped.push(true);
                    i += 2;
                    continue;
                }
            }
        }
        out.push(tokens[i].clone());
        i += 1;
    }
    (out, skipped)
}

/// Splits an impl body into items and collects reflectable method signatures.
fn collect_methods(body: &[TokenTree], in_trait_impl: bool) -> Vec<Sig> {
    let mut sigs = Vec::new();
    let mut i = 0;
    while i < body.len() {
        // One item: attributes, visibility, qualifiers, then `fn`.
        let item_start = i;
        let mut skip = false;
        while i < body.len() && punct(&body[i], '#') {
            if let Some(TokenTree::Group(g)) = body.get(i + 1) {
                let inner = flatten_invisible(g.stream().into_iter().collect());
                if inner.first().and_then(ident).as_deref() == Some("reflect") {
                    skip = true;
                }
            }
            i += 2;
        }
        let exported = in_trait_impl
            || (body.get(i).and_then(ident).as_deref() == Some("pub")
                && !matches!(body.get(i + 1), Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Parenthesis));
        i = skip_visibility(body, i);
        let mut plain = true;
        while let Some(w) = body.get(i).and_then(ident) {
            match w.as_str() {
                "const" | "async" | "unsafe" | "default" => {
                    if w != "const" {
                        plain = false;
                    }
                    i += 1;
                }
                _ => break,
            }
        }
        if body.get(i).and_then(ident).as_deref() == Some("fn") {
            match parse_sig(body, i, exported) {
                Some((sig, next)) => {
                    if plain && !skip {
                        sigs.push(sig);
                    }
                    i = next;
                }
                None => {
                    // Skip to the end of this item.
                    while i < body.len() {
                        let end = matches!(&body[i], TokenTree::Group(g) if g.delimiter() == Delimiter::Brace)
                            || punct(&body[i], ';');
                        i += 1;
                        if end {
                            break;
                        }
                    }
                }
            }
        } else {
            while i < body.len() {
                let end = punct(&body[i], ';')
                    || (matches!(&body[i], TokenTree::Group(g) if g.delimiter() == Delimiter::Brace)
                        && !body[item_start..i].iter().any(|t| punct(t, '=')));
                i += 1;
                if end {
                    break;
                }
            }
        }
    }
    sigs
}

pub(super) fn methods_attribute(attr: TokenStream, item: TokenStream) -> TokenStream {
    if !attr.is_empty() {
        return fail("#[reflect_methods] takes no arguments");
    }
    let tokens: Vec<TokenTree> = item.clone().into_iter().collect();
    let Some(impl_at) = tokens
        .iter()
        .position(|t| ident(t).as_deref() == Some("impl"))
    else {
        return fail("#[reflect_methods] applies to an impl block");
    };
    let Some(TokenTree::Group(body)) = tokens
        .last()
        .filter(|t| matches!(t, TokenTree::Group(g) if g.delimiter() == Delimiter::Brace))
    else {
        return fail("#[reflect_methods] applies to an impl block");
    };
    let header = &tokens[impl_at + 1..tokens.len() - 1];
    let (impl_generics, _tg, used, _) = match generics(header) {
        Ok(g) => g,
        Err(e) => return fail(&e),
    };
    let header = &header[used..];
    // `impl Trait for Type` or `impl Type`.
    let for_at = header
        .iter()
        .position(|t| ident(t).as_deref() == Some("for"));
    let in_trait_impl = for_at.is_some();
    let ty_start = for_at.map_or(0, |p| p + 1);
    let where_at = header
        .iter()
        .position(|t| ident(t).as_deref() == Some("where"))
        .unwrap_or(header.len());
    let self_ty = text(&header[ty_start..where_at]);
    let where_clause = text(&header[where_at..]);
    let body_tokens: Vec<TokenTree> = body.stream().into_iter().collect();
    let sigs = collect_methods(&body_tokens, in_trait_impl);
    let exprs = sigs.iter().map(method_expr).collect::<Vec<_>>().join(",");
    let generated = format!(
        "#[allow(unused_mut,unused_variables,clippy::all)]const _:()={{impl{impl_generics} {R}::__private::ReflectMethods for {self_ty} {where_clause} {{\
         fn reflect_methods()->::std::vec::Vec<{R}::MethodDef>{{::std::vec![{exprs}]}}}}}};"
    );
    // The impl block is emitted unchanged except for `#[reflect(skip)]`.
    let (clean_body, _) = strip_skip_attrs(&body_tokens);
    let mut out_tokens: Vec<TokenTree> = tokens[..tokens.len() - 1].to_vec();
    let mut inner = TokenStream::new();
    inner.extend(clean_body);
    out_tokens.push(TokenTree::Group(proc_macro::Group::new(
        Delimiter::Brace,
        inner,
    )));
    let mut out = TokenStream::new();
    out.extend(out_tokens);
    match generated.parse::<TokenStream>() {
        Ok(g) => {
            out.extend(g);
            out
        }
        Err(_) => fail("#[reflect_methods] could not generate Rust syntax"),
    }
}

pub(super) fn trait_attribute(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attr_tokens: Vec<TokenTree> = attr.into_iter().collect();
    let pkg = match attr_tokens.as_slice() {
        [] => "::core::module_path!()".to_string(),
        [k, eq, lit] if ident(k).as_deref() == Some("pkg") && punct(eq, '=') => {
            match string_literal(lit) {
                Ok(p) => format!("{p:?}"),
                Err(e) => return fail(&e),
            }
        }
        _ => return fail("#[reflect_trait] takes only pkg = \"path\""),
    };
    let tokens: Vec<TokenTree> = item.clone().into_iter().collect();
    let Some(tr_at) = tokens
        .iter()
        .position(|t| ident(t).as_deref() == Some("trait"))
    else {
        return fail("#[reflect_trait] applies to a trait definition");
    };
    let Some(name) = tokens.get(tr_at + 1).and_then(ident) else {
        return fail("expected trait name");
    };
    let Some(TokenTree::Group(body)) = tokens
        .last()
        .filter(|t| matches!(t, TokenTree::Group(g) if g.delimiter() == Delimiter::Brace))
    else {
        return fail("#[reflect_trait] applies to a trait definition");
    };
    if tokens.get(tr_at + 2).is_some_and(|t| punct(t, '<')) {
        return fail("#[reflect_trait] does not support generic traits");
    }
    let body_tokens: Vec<TokenTree> = body.stream().into_iter().collect();
    // Trait methods have no bodies; reuse the impl scanner with every method
    // treated as exported.
    let sigs = collect_methods(&body_tokens, true);
    let entries = sigs
        .iter()
        .map(|s| format!("({:?},{})", s.name, signature_expr(s)))
        .collect::<Vec<_>>()
        .join(",");
    let bare = name.strip_prefix("r#").unwrap_or(&name);
    let generated = format!(
        "#[allow(clippy::all)]const _:()={{impl {R}::ReflectType for dyn {name} {{\
         fn reflect_type()->{R}::Type{{\
         {R}::__private::named_type::<dyn {name}>({pkg},|| ::std::string::String::from({bare:?}),\
         || {R}::__private::interface_body(&[{entries}]),::core::option::Option::None)}}}}}};"
    );
    let mut out = item;
    match generated.parse::<TokenStream>() {
        Ok(g) => {
            out.extend(g);
            out
        }
        Err(_) => fail("#[reflect_trait] could not generate Rust syntax"),
    }
}
