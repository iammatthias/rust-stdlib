//! Struct descriptions and Go's `typeinfo.go` tag processing.
//!
//! A struct type provides a static [`StructSpec`] (the `#[derive]` macros emit
//! one from `#[xml("...")]` attributes); this module interprets the Go tag text
//! at run time exactly as `getTypeInfo`/`structFieldInfo`/`addFieldInfo` do, so
//! tag errors and conflict resolution match Go.
use super::{
    conv::quote,
    error::{Error, TagPathError},
};
use std::{cell::RefCell, collections::HashMap, rc::Rc};

/// The static description of a struct's fields (the Rust stand-in for
/// `reflect.Type` of a struct).
#[derive(Debug)]
pub struct StructSpec {
    /// Go's `typ.Name()`: the default element name for the struct.
    pub name: &'static str,
    /// Go's `typ.String()`, used in error messages.
    pub type_string: &'static str,
    /// The fields in declaration order.
    pub fields: &'static [FieldSpec],
}

/// One struct field as `reflect.StructField` describes it.
#[derive(Debug)]
pub struct FieldSpec {
    /// Go's field name; `"XMLName"` marks the element-name field.
    pub name: &'static str,
    /// The text of Go's `xml:"..."` struct tag (empty when absent).
    pub tag: &'static str,
    /// Go's `Anonymous`: an embedded struct whose fields are lifted.
    pub anonymous: bool,
    /// The field type as `reflect.Type.String()` prints it.
    pub type_string: &'static str,
    /// The struct description of the field's type, looking through pointers
    /// (Go's `lookupXMLName` and embedding recurse into it).
    pub type_spec: fn() -> Option<&'static StructSpec>,
}

pub(super) const F_ELEMENT: u32 = 1 << 0;
pub(super) const F_ATTR: u32 = 1 << 1;
pub(super) const F_CDATA: u32 = 1 << 2;
pub(super) const F_CHARDATA: u32 = 1 << 3;
pub(super) const F_INNERXML: u32 = 1 << 4;
pub(super) const F_COMMENT: u32 = 1 << 5;
pub(super) const F_ANY: u32 = 1 << 6;
pub(super) const F_OMITEMPTY: u32 = 1 << 7;
pub(super) const F_MODE: u32 =
    F_ELEMENT | F_ATTR | F_CDATA | F_CHARDATA | F_INNERXML | F_COMMENT | F_ANY;

const XML_NAME: &str = "XMLName";

#[derive(Clone, Debug)]
pub(super) struct FieldInfo {
    pub idx: Vec<usize>,
    pub name: String,
    pub xmlns: String,
    pub flags: u32,
    pub parents: Vec<String>,
}

#[derive(Debug, Default)]
pub(super) struct TypeInfo {
    pub xmlname: Option<FieldInfo>,
    pub fields: Vec<FieldInfo>,
}

thread_local! {
    // Keyed by the address of the 'static spec; see `get_type_info`.
    static TINFO: RefCell<HashMap<usize, Rc<TypeInfo>>> = RefCell::new(HashMap::new());
}

/// Returns the details necessary for marshaling and unmarshaling `typ`
/// (Go `getTypeInfo`). Successful results are cached per thread, keyed by the
/// spec's address: equal addresses imply the same static spec.
pub(super) fn get_type_info(typ: &'static StructSpec) -> Result<Rc<TypeInfo>, Error> {
    let key = typ as *const StructSpec as usize;
    if let Some(ti) = TINFO.with(|m| m.borrow().get(&key).cloned()) {
        return Ok(ti);
    }
    let ti = Rc::new(build_type_info(typ)?);
    TINFO.with(|m| m.borrow_mut().insert(key, ti.clone()));
    Ok(ti)
}

fn build_type_info(typ: &'static StructSpec) -> Result<TypeInfo, Error> {
    let mut tinfo = TypeInfo::default();
    for (i, f) in typ.fields.iter().enumerate() {
        if f.tag == "-" {
            continue;
        }
        // For embedded structs, embed its fields.
        if f.anonymous {
            if let Some(inner_spec) = (f.type_spec)() {
                let inner = get_type_info(inner_spec)?;
                if tinfo.xmlname.is_none() {
                    tinfo.xmlname = inner.xmlname.clone();
                }
                for finfo in &inner.fields {
                    let mut finfo = finfo.clone();
                    finfo.idx.insert(0, i);
                    add_field_info(typ, &mut tinfo, finfo)?;
                }
                continue;
            }
        }
        let finfo = struct_field_info(typ, f, vec![i])?;
        if f.name == XML_NAME {
            tinfo.xmlname = Some(finfo);
            continue;
        }
        // Add the field if it doesn't conflict with other fields.
        add_field_info(typ, &mut tinfo, finfo)?;
    }
    Ok(tinfo)
}

/// Builds the [`FieldInfo`] for `f` (Go `structFieldInfo`).
fn struct_field_info(typ: &StructSpec, f: &FieldSpec, idx: Vec<usize>) -> Result<FieldInfo, Error> {
    let mut finfo = FieldInfo {
        idx,
        name: String::new(),
        xmlns: String::new(),
        flags: 0,
        parents: Vec::new(),
    };

    // Split the tag from the xml namespace if necessary.
    let mut tag = f.tag;
    if let Some((ns, t)) = tag.split_once(' ') {
        finfo.xmlns = ns.to_string();
        tag = t;
    }

    // Parse flags.
    let tokens: Vec<&str> = tag.split(',').collect();
    if tokens.len() == 1 {
        finfo.flags = F_ELEMENT;
    } else {
        tag = tokens[0];
        for flag in &tokens[1..] {
            match *flag {
                "attr" => finfo.flags |= F_ATTR,
                "cdata" => finfo.flags |= F_CDATA,
                "chardata" => finfo.flags |= F_CHARDATA,
                "innerxml" => finfo.flags |= F_INNERXML,
                "comment" => finfo.flags |= F_COMMENT,
                "any" => finfo.flags |= F_ANY,
                "omitempty" => finfo.flags |= F_OMITEMPTY,
                _ => {}
            }
        }

        // Validate the flags used.
        let mut valid = true;
        let mode = finfo.flags & F_MODE;
        if mode == 0 {
            finfo.flags |= F_ELEMENT;
        } else if matches!(
            mode,
            F_ATTR | F_CDATA | F_CHARDATA | F_INNERXML | F_COMMENT | F_ANY
        ) || mode == (F_ANY | F_ATTR)
        {
            if f.name == XML_NAME || (!tag.is_empty() && mode != F_ATTR) {
                valid = false;
            }
        } else {
            // This will also catch multiple modes in a single field.
            valid = false;
        }
        if finfo.flags & F_MODE == F_ANY {
            finfo.flags |= F_ELEMENT;
        }
        if finfo.flags & F_OMITEMPTY != 0 && finfo.flags & (F_ELEMENT | F_ATTR) == 0 {
            valid = false;
        }
        if !valid {
            return Err(Error::msg(format!(
                "xml: invalid tag in field {} of type {}: {}",
                f.name,
                typ.type_string,
                quote(f.tag.as_bytes())
            )));
        }
    }

    // Use of xmlns without a name is not allowed.
    if !finfo.xmlns.is_empty() && tag.is_empty() {
        return Err(Error::msg(format!(
            "xml: namespace without name in field {} of type {}: {}",
            f.name,
            typ.type_string,
            quote(f.tag.as_bytes())
        )));
    }

    if f.name == XML_NAME {
        // The XMLName field records the XML element name. Don't process it as
        // usual because its name should default to empty rather than to the
        // field name.
        finfo.name = tag.to_string();
        return Ok(finfo);
    }

    if tag.is_empty() {
        // If the name part of the tag is completely empty, get the default from
        // XMLName of the underlying struct if feasible, or the field name.
        if let Some(xmlname) = lookup_xml_name(f) {
            finfo.xmlns = xmlname.xmlns;
            finfo.name = xmlname.name;
        } else {
            finfo.name = f.name.to_string();
        }
        return Ok(finfo);
    }

    // Prepare field name and parents.
    let mut parents: Vec<String> = tag.split('>').map(str::to_string).collect();
    if parents[0].is_empty() {
        parents[0] = f.name.to_string();
    }
    if parents.last().is_some_and(String::is_empty) {
        return Err(Error::msg(format!(
            "xml: trailing '>' in field {} of type {}",
            f.name, typ.type_string
        )));
    }
    finfo.name = parents[parents.len() - 1].clone();
    if parents.len() > 1 {
        if finfo.flags & F_ELEMENT == 0 {
            return Err(Error::msg(format!(
                "xml: {} chain not valid with {} flag",
                tag,
                tokens[1..].join(",")
            )));
        }
        parents.pop();
        finfo.parents = parents;
    }

    // If the field type has an XMLName field, the names must match so that the
    // behavior of both marshaling and unmarshaling is unambiguous.
    if finfo.flags & F_ELEMENT != 0 {
        if let Some(xmlname) = lookup_xml_name(f) {
            if xmlname.name != finfo.name {
                return Err(Error::msg(format!(
                    "xml: name {} in tag of {}.{} conflicts with name {} in {}.XMLName",
                    quote(finfo.name.as_bytes()),
                    typ.type_string,
                    f.name,
                    quote(xmlname.name.as_bytes()),
                    f.type_string
                )));
            }
        }
    }
    Ok(finfo)
}

/// Returns the [`FieldInfo`] of the `XMLName` field of `f`'s type if it exists
/// and has a valid tag (Go `lookupXMLName`).
fn lookup_xml_name(f: &FieldSpec) -> Option<FieldInfo> {
    let spec = (f.type_spec)()?;
    for (i, g) in spec.fields.iter().enumerate() {
        if g.name != XML_NAME {
            continue;
        }
        if let Ok(finfo) = struct_field_info(spec, g, vec![i]) {
            if !finfo.name.is_empty() {
                return Some(finfo);
            }
        }
        // Also consider errors as a non-existent field tag and let
        // `get_type_info` itself report the error.
        break;
    }
    None
}

fn field_by_index(typ: &'static StructSpec, idx: &[usize]) -> &'static FieldSpec {
    let mut t = typ;
    for (k, i) in idx.iter().enumerate() {
        let f = &t.fields[*i];
        if k + 1 == idx.len() {
            return f;
        }
        t = (f.type_spec)().expect("embedded field has a struct spec");
    }
    unreachable!("empty field index")
}

/// Adds `newf` to `tinfo.fields` if there are no conflicts, or if conflicts
/// arise from previous fields obtained from deeper embedded structures than
/// `newf` (Go `addFieldInfo`).
fn add_field_info(
    typ: &'static StructSpec,
    tinfo: &mut TypeInfo,
    newf: FieldInfo,
) -> Result<(), Error> {
    let mut conflicts: Vec<usize> = Vec::new();
    // First, figure all conflicts. Most working code will have none.
    'outer: for (i, oldf) in tinfo.fields.iter().enumerate() {
        if oldf.flags & F_MODE != newf.flags & F_MODE {
            continue;
        }
        if !oldf.xmlns.is_empty() && !newf.xmlns.is_empty() && oldf.xmlns != newf.xmlns {
            continue;
        }
        let minl = newf.parents.len().min(oldf.parents.len());
        for p in 0..minl {
            if oldf.parents[p] != newf.parents[p] {
                continue 'outer;
            }
        }
        if oldf.parents.len() > newf.parents.len() {
            if oldf.parents[newf.parents.len()] == newf.name {
                conflicts.push(i);
            }
        } else if oldf.parents.len() < newf.parents.len() {
            if newf.parents[oldf.parents.len()] == oldf.name {
                conflicts.push(i);
            }
        } else if newf.name == oldf.name && newf.xmlns == oldf.xmlns {
            conflicts.push(i);
        }
    }
    // Without conflicts, add the new field and return.
    if conflicts.is_empty() {
        tinfo.fields.push(newf);
        return Ok(());
    }

    // If any conflict is shallower, ignore the new field. This matches the Go
    // field resolution on embedding.
    if conflicts
        .iter()
        .any(|&i| tinfo.fields[i].idx.len() < newf.idx.len())
    {
        return Ok(());
    }

    // Otherwise, if any of them is at the same depth level, it's an error.
    for &i in &conflicts {
        let oldf = &tinfo.fields[i];
        if oldf.idx.len() == newf.idx.len() {
            let f1 = field_by_index(typ, &oldf.idx);
            let f2 = field_by_index(typ, &newf.idx);
            return Err(Error::TagPath(TagPathError {
                struct_type: typ.type_string.to_string(),
                field1: f1.name.to_string(),
                tag1: f1.tag.to_string(),
                field2: f2.name.to_string(),
                tag2: f2.tag.to_string(),
            }));
        }
    }

    // Otherwise, the new field is shallower, and thus takes precedence, so drop
    // the conflicting fields from tinfo and append the new one.
    for &i in conflicts.iter().rev() {
        tinfo.fields.remove(i);
    }
    tinfo.fields.push(newf);
    Ok(())
}
