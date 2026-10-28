//! `MarshalTo` and `UnmarshalFrom` derives for
//! `rust_stdlib::encoding::json::v2`.
//!
//! They describe a struct with named fields to the runtime (its fields, Go
//! names and `json` tags) and give access to the fields by index path. Go
//! reads the same information from the type by reflection. The `#[json(...)]`
//! attributes are those of the `Serialize` and `Deserialize` derives:
//!
//! * a Go struct tag string, or `rename = "..."`, `omitempty`, `omitzero`,
//!   `string`, `skip` and `unexported` (the type of a skipped field must be
//!   `Default` and, for `MarshalTo`, `PartialEq`: it counts towards a struct
//!   being zero);
//! * `inline` (also `embedded`, `flatten`): an embedded struct whose fields
//!   are promoted into the parent, as for Go's embedded fields;
//! * `unknown` (also `embed`): a map with string keys or `jsontext::Value`
//!   that collects the members no field matches;
//! * `case = "ignore"` or `case = "strict"`;
//! * `format = "..."` (experimental in Go, see the `v2` module).
use super::{fail, json_bounds, parse, strip_raw, Fields, Header, Item, NamedField};
use proc_macro::TokenStream;

const J: &str = "::rust_stdlib::encoding::json";

pub(super) fn derive(input: TokenStream, marshal: bool) -> TokenStream {
    match parse(input).and_then(|item| generate(item, marshal)) {
        Ok(source) => source
            .parse()
            .unwrap_or_else(|_| fail("derive could not generate Rust syntax")),
        Err(e) => fail(&e),
    }
}

fn generate(item: Item, marshal: bool) -> Result<String, String> {
    let Item::Struct(header, Fields::Struct(fields)) = item else {
        return Err("the v2 JSON derives support structs with named fields only".into());
    };
    if !marshal && header.borrowed {
        return Err("borrowed field deserialization is unsupported; use owned field types".into());
    }
    generate_struct(&header, &fields, marshal)
}

fn generate_struct(
    header: &Header,
    fields: &[NamedField],
    marshal: bool,
) -> Result<String, String> {
    let p = &header.prefix;
    let (trait_name, access_trait) = if marshal {
        ("MarshalTo", "EmbedAccess")
    } else {
        ("UnmarshalFrom", "EmbedAccessMut")
    };
    let active: Vec<&NamedField> = fields.iter().collect();

    let mut bounds = Vec::new();
    if !header.predicates.is_empty() {
        bounds.push(header.predicates.clone());
    }
    bounds.extend(json_bounds(
        header,
        &header.field_types,
        &format!("{J}::v2::{trait_name}"),
    )?);
    bounds.extend(json_bounds(
        header,
        &header.embedded_types,
        &format!("{J}::v2::{trait_name}"),
    )?);
    bounds.extend(json_bounds(
        header,
        &header.embedded_types,
        &format!("{J}::v2::{access_trait}"),
    )?);
    bounds.extend(json_bounds(
        header,
        &header.skipped_types,
        "::core::default::Default",
    )?);
    if marshal {
        bounds.extend(json_bounds(
            header,
            &header.skipped_types,
            "::core::cmp::PartialEq",
        )?);
    }
    let constraints = if bounds.is_empty() {
        String::new()
    } else {
        format!("where {}", bounds.join(","))
    };
    let (name, impl_generics, type_generics) =
        (&header.name, &header.impl_generics, &header.type_generics);
    let target = format!("{name}{type_generics}");

    let type_info = format!("{J}::v2::TypeInfo::of::<Self>({name:?},{J}::v2::TypeKind::Struct)");
    let descs = active
        .iter()
        .map(|f| {
            let exported = f.tag != "\u{1}";
            let tag = if exported { f.tag.as_str() } else { "" };
            if f.skip {
                return format!(
                    "{J}::v2::FieldDesc::ignored({:?},{:?},{})",
                    strip_raw(&f.name),
                    tag,
                    exported
                );
            }
            let ty = &f.ty;
            format!(
                "{J}::v2::FieldDesc{{name:{:?},tag:{:?},has_tag:{},anonymous:{},exported:true,type_info:<{ty} as {J}::v2::{trait_name}>::type_info(),struct_desc:<{ty} as {J}::v2::{trait_name}>::struct_desc}}",
                strip_raw(&f.name),
                tag,
                !tag.is_empty(),
                f.embedded,
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let struct_desc = format!(
        "fn struct_desc()->::core::option::Option<{J}::v2::StructDesc>{{::core::option::Option::Some({J}::v2::StructDesc{{type_info: {type_info},fields: ::std::vec![{descs}]}})}}"
    );
    let type_info_fn = format!("fn type_info()->{J}::v2::TypeInfo{{{type_info}}}");

    let mut out = String::new();
    if marshal {
        // A struct is zero when all its fields are, including those JSON
        // ignores (as Go's `reflect.Value.IsZero` sees them).
        let zero = active
            .iter()
            .map(|f| {
                if f.skip {
                    // Naming the field type keeps the comparison unambiguous
                    // for types with several `PartialEq` impls, such as `String`.
                    format!(
                        "&&self.{}==<{} as ::core::default::Default>::default()",
                        f.name, f.ty
                    )
                } else {
                    format!("&&{J}::v2::MarshalTo::is_zero_value(&self.{})", f.name)
                }
            })
            .collect::<String>();
        let arms = active
            .iter()
            .enumerate()
            .filter(|(_, f)| !f.skip)
            .map(|(i, f)| {
                let n = &f.name;
                if f.embedded {
                    format!("{i}=>if {p}path.len()==1{{::core::option::Option::Some({p}f(&self.{n}))}}else{{{J}::v2::EmbedAccess::with_embedded(&self.{n},&{p}path[1..],{p}f)}},")
                } else {
                    format!("{i}=>::core::option::Option::Some({p}f(&self.{n})),")
                }
            })
            .collect::<String>();
        out.push_str(&format!(
            "impl{impl_generics} {J}::v2::MarshalTo for {target} {constraints}{{{type_info_fn}\
fn marshal_default(&self,{p}enc:&mut {J}::jsontext::Encoder<'_>)->::core::result::Result<(),{J}::jsontext::Error>{{{J}::v2::marshal_struct(self,{p}enc)}}\
fn is_zero_value(&self)->bool{{true{zero}}}{struct_desc}}}\
impl{impl_generics} {J}::v2::StructMarshal for {target} {constraints}{{\
fn with_field<{p}R>(&self,{p}path:&[usize],{p}f:impl ::core::ops::FnOnce(&dyn {J}::v2::FieldValue)->{p}R)->::core::option::Option<{p}R>{{match {p}path[0]{{{arms}_=>::core::option::Option::None}}}}}}\
impl{impl_generics} {J}::v2::EmbedAccess for {target} {constraints}{{\
fn with_embedded<{p}R>(&self,{p}path:&[usize],{p}f:impl ::core::ops::FnOnce(&dyn {J}::v2::FieldValue)->{p}R)->::core::option::Option<{p}R>{{{J}::v2::StructMarshal::with_field(self,{p}path,{p}f)}}}}"
        ));
    } else {
        let zero_build = fields
            .iter()
            .map(|f| {
                if f.skip {
                    format!("{}: ::core::default::Default::default(),", f.name)
                } else {
                    format!("{}: {J}::v2::UnmarshalFrom::zero(),", f.name)
                }
            })
            .collect::<String>();
        let set_zero = fields
            .iter()
            .map(|f| {
                if f.skip {
                    format!("self.{}=::core::default::Default::default();", f.name)
                } else {
                    format!("{J}::v2::UnmarshalFrom::set_zero(&mut self.{});", f.name)
                }
            })
            .collect::<String>();
        let arms = active
            .iter()
            .enumerate()
            .filter(|(_, f)| !f.skip)
            .map(|(i, f)| {
                let n = &f.name;
                if f.embedded {
                    format!("{i}=>if {p}path.len()==1{{::core::option::Option::Some({p}f(&mut self.{n}))}}else{{{J}::v2::EmbedAccessMut::with_embedded_mut(&mut self.{n},&{p}path[1..],{p}may_alloc,{p}f)}},")
                } else {
                    format!("{i}=>::core::option::Option::Some({p}f(&mut self.{n})),")
                }
            })
            .collect::<String>();
        out.push_str(&format!(
            "impl{impl_generics} {J}::v2::UnmarshalFrom for {target} {constraints}{{{type_info_fn}\
fn zero()->Self{{Self{{{zero_build}}}}}\
fn set_zero(&mut self){{{set_zero}}}\
fn unmarshal_default(&mut self,{p}dec:&mut {J}::jsontext::Decoder<'_>)->::core::result::Result<(),{J}::jsontext::Error>{{{J}::v2::unmarshal_struct(self,{p}dec)}}\
{struct_desc}}}\
impl{impl_generics} {J}::v2::StructUnmarshal for {target} {constraints}{{\
fn with_field_mut<{p}R>(&mut self,{p}path:&[usize],{p}may_alloc:bool,{p}f:impl ::core::ops::FnOnce(&mut dyn {J}::v2::FieldValueMut)->{p}R)->::core::option::Option<{p}R>{{match {p}path[0]{{{arms}_=>::core::option::Option::None}}}}}}\
impl{impl_generics} {J}::v2::EmbedAccessMut for {target} {constraints}{{\
fn with_embedded_mut<{p}R>(&mut self,{p}path:&[usize],{p}may_alloc:bool,{p}f:impl ::core::ops::FnOnce(&mut dyn {J}::v2::FieldValueMut)->{p}R)->::core::option::Option<{p}R>{{{J}::v2::StructUnmarshal::with_field_mut(self,{p}path,{p}may_alloc,{p}f)}}}}"
        ));
    }
    Ok(out)
}
