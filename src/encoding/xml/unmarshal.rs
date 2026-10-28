//! Decoding XML into typed values: Go's `read.go`.
use super::{
    conv::{parse_bool, parse_float, parse_int, parse_uint},
    marshal::TextUnmarshaler,
    typeinfo::{
        get_type_info, TypeInfo, F_ANY, F_ATTR, F_CDATA, F_CHARDATA, F_COMMENT, F_ELEMENT,
        F_INNERXML, F_MODE,
    },
    Attr, Decoder, Error, Name, StartElement, StructSpec, Token, UnmarshalError,
};
use std::rc::Rc;

/// An object that can unmarshal an XML element description of itself (Go
/// `Unmarshaler`). `unmarshal_xml` decodes a single XML element beginning with
/// `start` and must consume exactly that element. It may not use
/// [`Decoder::raw_token`]. A type opts in by returning itself from
/// [`Unmarshal::xml_unmarshaler`].
pub trait Unmarshaler {
    /// Go's `UnmarshalXML`.
    fn unmarshal_xml(&mut self, d: &mut Decoder<'_>, start: StartElement) -> Result<(), Error>;
}

/// An object that can unmarshal an XML attribute description of itself (Go
/// `UnmarshalerAttr`); used only for struct fields with the `attr` option.
/// Opt in with [`Unmarshal::xml_attr_unmarshaler`].
pub trait UnmarshalerAttr {
    /// Go's `UnmarshalXMLAttr`.
    fn unmarshal_xml_attr(&mut self, attr: Attr) -> Result<(), Error>;
}

/// The `reflect.Kind` distinctions Go's `unmarshal` branches on.
#[derive(Clone, Copy, Debug)]
pub enum Kind {
    /// A pointer: [`Unmarshal::xml_indirect`] allocates and returns the pointee.
    Ptr,
    /// An interface value with no usable content: the element is skipped.
    Interface,
    /// A slice of non-bytes: each element is appended.
    Slice,
    /// A byte slice: receives the character data.
    Bytes,
    /// A bool, number or string: receives the character data.
    Scalar,
    /// A struct with the given description.
    Struct(&'static StructSpec),
    /// The [`Name`] type: receives the element name.
    Name,
    /// Anything else: an `unknown type` error.
    Unknown,
}

/// A place XML can be decoded into (the Rust counterpart of what Go's
/// `Unmarshal` does through reflection). Implemented for the primitives,
/// `String`, `Vec<T>`, `Option<T>`, `Box<T>`, [`Name`] and [`Attr`], and by
/// `#[derive(Unmarshal)]` for structs. Element types of `Vec` and `Option` must
/// also be `Default`.
pub trait Unmarshal {
    /// The kind of this value.
    fn xml_kind(&self) -> Kind;

    /// Go's `typ.String()`, used in error messages.
    fn xml_type_string(&self) -> String {
        std::any::type_name_of_val(self).to_string()
    }

    /// For [`Kind::Ptr`]: allocates the pointee if nil and returns it.
    fn xml_indirect(&mut self) -> Option<&mut dyn Unmarshal> {
        None
    }

    /// For [`Kind::Slice`]: appends a zero element and returns it.
    fn xml_push_elem(&mut self) -> Option<&mut dyn Unmarshal> {
        None
    }

    /// For [`Kind::Slice`]: removes the last element (undoing `xml_push_elem`).
    fn xml_pop_elem(&mut self) {}

    /// Field `i` of a struct value.
    fn xml_field_mut(&mut self, _i: usize) -> Option<&mut dyn Unmarshal> {
        None
    }

    /// For [`Kind::Name`]: stores the element name; reports whether it did.
    fn xml_set_name(&mut self, _name: &Name) -> bool {
        false
    }

    /// For [`Attr`] values: stores the attribute; reports whether it did.
    fn xml_set_attr(&mut self, _attr: &Attr) -> bool {
        false
    }

    /// Go's `copyValue` for a non-pointer scalar or byte slice: sets the value
    /// from the accumulated character data.
    fn xml_set_text(&mut self, _src: &[u8]) -> Result<(), Error> {
        Err(Error::msg(format!(
            "cannot unmarshal into {}",
            self.xml_type_string()
        )))
    }

    /// Stores comment or inner-XML text into a string or byte-slice value;
    /// reports whether the value has such a type.
    fn xml_set_raw(&mut self, _data: &[u8]) -> bool {
        false
    }

    /// This value as an [`Unmarshaler`], if its type implements one.
    fn xml_unmarshaler(&mut self) -> Option<&mut dyn Unmarshaler> {
        None
    }

    /// This value as an [`UnmarshalerAttr`], if its type implements one.
    fn xml_attr_unmarshaler(&mut self) -> Option<&mut dyn UnmarshalerAttr> {
        None
    }

    /// This value as a [`TextUnmarshaler`], if its type implements one.
    fn xml_text_unmarshaler(&mut self) -> Option<&mut dyn TextUnmarshaler> {
        None
    }

    /// The struct description when the type is a struct, looking through
    /// pointers.
    fn xml_struct_spec() -> Option<&'static StructSpec>
    where
        Self: Sized,
    {
        None
    }

    /// Builds `Self` from a byte when the type is `u8`.
    fn xml_from_byte(_b: u8) -> Option<Self>
    where
        Self: Sized,
    {
        None
    }

    /// Go's type string of `Self` as an element of a slice.
    fn xml_elem_type_string() -> String
    where
        Self: Sized,
    {
        std::any::type_name::<Self>().to_string()
    }
}

/// Parses the XML-encoded `data` into a new `T` (Go `Unmarshal` into a zero
/// value). Well-formed data that does not fit into `T` is discarded.
pub fn unmarshal<T: Unmarshal + Default>(data: &[u8]) -> Result<T, Error> {
    Decoder::new(data).decode()
}

/// Parses the XML-encoded `data` and stores the result in `v`, keeping what
/// the data does not set (Go `Unmarshal(data, &v)` on an existing value).
pub fn unmarshal_into<T: Unmarshal>(data: &[u8], v: &mut T) -> Result<(), Error> {
    Decoder::new(data).decode_into(v)
}

impl<'a> Decoder<'a> {
    /// Reads the decoder stream to find the start element and unmarshals it
    /// into a new `T` (Go `Decode`).
    pub fn decode<T: Unmarshal + Default>(&mut self) -> Result<T, Error> {
        self.decode_element(None)
    }

    /// Like [`decode`](Self::decode) but decodes into an existing value (Go
    /// `Decode(&v)`).
    pub fn decode_into<T: Unmarshal>(&mut self, v: &mut T) -> Result<(), Error> {
        self.decode_element_into(v, None)
    }

    /// Like [`decode`](Self::decode) but takes the already-read start element
    /// (Go `DecodeElement`).
    pub fn decode_element<T: Unmarshal + Default>(
        &mut self,
        start: Option<&StartElement>,
    ) -> Result<T, Error> {
        let mut v = T::default();
        self.decode_element_into(&mut v, start)?;
        Ok(v)
    }

    /// Like [`decode_element`](Self::decode_element) but decodes into an
    /// existing value.
    pub fn decode_element_into<T: Unmarshal>(
        &mut self,
        v: &mut T,
        start: Option<&StartElement>,
    ) -> Result<(), Error> {
        // Remember where the outermost decode started, to bound recursion by
        // stack use (see `Decoder::max_unmarshal_stack`).
        let marker = 0u8;
        let outermost = self.stack_base.is_none();
        if outermost {
            self.stack_base = Some(std::ptr::from_ref(&marker) as usize);
        }
        let result = self.unmarshal_value(v, start.cloned());
        if outermost {
            self.stack_base = None;
        }
        result
    }

    /// Unmarshals a single XML element into `val` (Go `unmarshal`).
    ///
    /// The work is split into small `#[inline(never)]` steps so the frames that
    /// stay live across recursive calls are small: recursion depth is bounded
    /// by stack use (`Decoder::max_unmarshal_stack`).
    pub(super) fn unmarshal_value(
        &mut self,
        val: &mut dyn Unmarshal,
        start: Option<StartElement>,
    ) -> Result<(), Error> {
        self.check_depth()?;
        let start = match start {
            Some(s) => s,
            None => self.find_start()?,
        };
        let val = deref_ptr(val)?;
        if let Some(done) = self.unmarshal_hooks(val, &start) {
            return done;
        }
        match val.xml_kind() {
            Kind::Unknown | Kind::Ptr => Err(unknown_type(val)),
            // For now, simply ignore the field.
            Kind::Interface => self.skip(),
            Kind::Slice => self.unmarshal_slice(val, start),
            Kind::Bytes | Kind::Scalar => self.read_element(val, &Plan::scalar()),
            Kind::Name => {
                val.xml_set_name(&start.name);
                self.read_element(val, &Plan::default())
            }
            Kind::Struct(spec) => {
                let plan = self.plan_struct(val, spec, &start)?;
                self.read_element(val, &plan)
            }
        }
    }

    fn check_depth(&self) -> Result<(), Error> {
        let marker = 0u8;
        let used = self.stack_base.map_or(0, |base| {
            base.abs_diff(std::ptr::from_ref(&marker) as usize)
        });
        if self.stk_depth > self.max_unmarshal_depth || used > self.max_unmarshal_stack {
            return Err(Error::msg("exceeded max depth"));
        }
        Ok(())
    }

    /// Finds the start element when the caller did not supply one.
    #[inline(never)]
    fn find_start(&mut self) -> Result<StartElement, Error> {
        loop {
            if let Token::StartElement(t) = self.token()? {
                return Ok(t);
            }
        }
    }

    /// The `Unmarshaler` and `TextUnmarshaler` hooks, which take precedence over
    /// the value's kind. `None` means neither applies.
    #[inline(never)]
    fn unmarshal_hooks(
        &mut self,
        val: &mut dyn Unmarshal,
        start: &StartElement,
    ) -> Option<Result<(), Error>> {
        // Only the error message of a misbehaving Unmarshaler needs the name.
        let type_string = if val.xml_unmarshaler().is_some() {
            val.xml_type_string()
        } else {
            String::new()
        };
        if let Some(u) = val.xml_unmarshaler() {
            return Some(self.unmarshal_interface(u, &type_string, start));
        }
        val.xml_text_unmarshaler()
            .map(|t| self.unmarshal_text_interface(t))
    }

    /// Slice of element values: grows the slice and recurs to read the element
    /// into it, shrinking again on failure.
    #[inline(never)]
    fn unmarshal_slice(
        &mut self,
        val: &mut dyn Unmarshal,
        start: StartElement,
    ) -> Result<(), Error> {
        let Some(elem) = val.xml_push_elem() else {
            return Err(unknown_type(val));
        };
        if let Err(e) = self.unmarshal_value(elem, Some(start)) {
            val.xml_pop_elem();
            return Err(e);
        }
        Ok(())
    }

    /// Validates and assigns the element name, assigns attributes and decides
    /// where character data, comments, inner XML and `any` children are saved.
    #[inline(never)]
    fn plan_struct(
        &mut self,
        val: &mut dyn Unmarshal,
        spec: &'static StructSpec,
        start: &StartElement,
    ) -> Result<Plan, Error> {
        let tinfo = get_type_info(spec)?;
        let mut plan = Plan::default();

        // Validate and assign element name.
        if let Some(finfo) = &tinfo.xmlname {
            if !finfo.name.is_empty() && finfo.name != start.name.local {
                return Err(Error::Unmarshal(UnmarshalError(format!(
                    "expected element type <{}> but have <{}>",
                    finfo.name, start.name.local
                ))));
            }
            if !finfo.xmlns.is_empty() && finfo.xmlns != start.name.space {
                let mut e = format!(
                    "expected element <{}> in name space {} but have ",
                    finfo.name, finfo.xmlns
                );
                if start.name.space.is_empty() {
                    e.push_str("no name space");
                } else {
                    e.push_str(&start.name.space);
                }
                return Err(Error::Unmarshal(UnmarshalError(e)));
            }
            if let Some(fv) = resolve(val, &finfo.idx) {
                fv.xml_set_name(&start.name);
            }
        }

        // Assign attributes.
        for a in &start.attr {
            let mut handled = false;
            let mut any: Option<usize> = None;
            for (i, finfo) in tinfo.fields.iter().enumerate() {
                match finfo.flags & F_MODE {
                    F_ATTR => {
                        let strv = resolve(val, &finfo.idx);
                        if a.name.local == finfo.name
                            && (finfo.xmlns.is_empty() || finfo.xmlns == a.name.space)
                        {
                            if let Some(strv) = strv {
                                self.unmarshal_attr(strv, a)?;
                            }
                            handled = true;
                        }
                    }
                    m if m == (F_ANY | F_ATTR) && any.is_none() => any = Some(i),
                    _ => {}
                }
            }
            if !handled {
                if let Some(i) = any {
                    if let Some(strv) = resolve(val, &tinfo.fields[i].idx) {
                        self.unmarshal_attr(strv, a)?;
                    }
                }
            }
        }

        // Determine whether we need to save character data or comments.
        for finfo in &tinfo.fields {
            let usable = |val: &mut dyn Unmarshal| resolve(val, &finfo.idx).is_some();
            match finfo.flags & F_MODE {
                F_CDATA | F_CHARDATA if plan.save_data.is_none() && usable(val) => {
                    plan.save_data = Some(finfo.idx.clone());
                }
                F_COMMENT if plan.save_comment.is_none() && usable(val) => {
                    plan.save_comment = Some(finfo.idx.clone());
                }
                m if (m == F_ANY || m == (F_ANY | F_ELEMENT))
                    && plan.save_any.is_none()
                    && usable(val) =>
                {
                    plan.save_any = Some(finfo.idx.clone());
                }
                F_INNERXML if plan.save_xml.is_none() && usable(val) => {
                    plan.save_xml = Some(finfo.idx.clone());
                    if self.saved.is_none() {
                        plan.save_xml_index = 0;
                        self.saved = Some(Vec::new());
                    } else {
                        plan.save_xml_index = self.saved_offset();
                    }
                }
                _ => {}
            }
        }
        plan.tinfo = Some(tinfo);
        Ok(plan)
    }

    /// Finds the end element, processing sub-elements along the way, then stores
    /// what was saved.
    fn read_element(&mut self, val: &mut dyn Unmarshal, plan: &Plan) -> Result<(), Error> {
        let mut data: Vec<u8> = Vec::new();
        let mut comment: Vec<u8> = Vec::new();
        let mut xml: Vec<u8> = Vec::new();
        loop {
            let saved_offset = if plan.save_xml.is_some() {
                self.saved_offset()
            } else {
                0
            };
            match self.token()? {
                Token::StartElement(t) => self.element_child(val, plan, t)?,
                Token::EndElement(_) => {
                    if plan.save_xml.is_some() {
                        xml = self.take_saved(plan.save_xml_index, saved_offset);
                    }
                    break;
                }
                Token::CharData(t) if plan.save_data.is_some() => {
                    data.extend_from_slice(&t.0);
                }
                Token::Comment(t) if plan.save_comment.is_some() => {
                    comment.extend_from_slice(&t.0);
                }
                _ => {}
            }
        }
        finish_element(val, plan, &data, &comment, &xml)
    }

    /// The saved inner-XML bytes between `from` and `to`.
    #[inline(never)]
    fn take_saved(&mut self, from: usize, to: usize) -> Vec<u8> {
        let saved = self.saved.as_deref().unwrap_or(&[]);
        let end = to.min(saved.len());
        let out = saved[from.min(end)..end].to_vec();
        if from == 0 {
            self.saved = None;
        }
        out
    }

    /// A sub-element of a struct: a field, the `any` field, or skipped.
    #[inline(never)]
    fn element_child(
        &mut self,
        val: &mut dyn Unmarshal,
        plan: &Plan,
        t: StartElement,
    ) -> Result<(), Error> {
        let mut consumed = false;
        if let Some(tinfo) = &plan.tinfo {
            consumed = self.unmarshal_path(tinfo, val, &[], &t)?;
            if !consumed {
                if let Some(path) = &plan.save_any {
                    consumed = true;
                    if let Some(any) = resolve(val, path) {
                        return self.unmarshal_value(any, Some(t));
                    }
                }
            }
        }
        if !consumed {
            self.skip()?;
        }
        Ok(())
    }

    fn unmarshal_interface(
        &mut self,
        val: &mut dyn Unmarshaler,
        type_string: &str,
        start: &StartElement,
    ) -> Result<(), Error> {
        // Record that decoder must stop at end tag corresponding to start.
        self.push_eof()?;

        let saved_in_unmarshal_xml = self.in_unmarshal_xml;
        self.in_unmarshal_xml = true;
        let result = val.unmarshal_xml(self, start.clone());
        self.in_unmarshal_xml = saved_in_unmarshal_xml;

        if let Err(e) = result {
            self.pop_eof();
            return Err(e);
        }

        if !self.pop_eof() {
            return Err(Error::msg(format!(
                "xml: (*{type_string}).UnmarshalXML did not consume entire <{}> element",
                start.name.local
            )));
        }
        Ok(())
    }

    /// Unmarshals the character data of a single element (not its children) into
    /// a `TextUnmarshaler`.
    fn unmarshal_text_interface(&mut self, val: &mut dyn TextUnmarshaler) -> Result<(), Error> {
        let mut buf = Vec::new();
        let mut depth = 1;
        while depth > 0 {
            match self.token()? {
                Token::CharData(t) => {
                    if depth == 1 {
                        buf.extend_from_slice(&t.0);
                    }
                }
                Token::StartElement(_) => depth += 1,
                Token::EndElement(_) => depth -= 1,
                _ => {}
            }
        }
        val.unmarshal_text(&buf)
    }

    /// Unmarshals a single XML attribute into `val`.
    fn unmarshal_attr(&mut self, val: &mut dyn Unmarshal, attr: &Attr) -> Result<(), Error> {
        let mut val = val;
        if matches!(val.xml_kind(), Kind::Ptr) {
            val = val
                .xml_indirect()
                .ok_or_else(|| Error::msg("cannot allocate pointer"))?;
        }
        if let Some(u) = val.xml_attr_unmarshaler() {
            return u.unmarshal_xml_attr(attr.clone());
        }

        // Not an UnmarshalerAttr; try TextUnmarshaler.
        if let Some(t) = val.xml_text_unmarshaler() {
            return t.unmarshal_text(attr.value.as_bytes());
        }

        if matches!(val.xml_kind(), Kind::Slice) {
            // Slice of element values. Grow slice, recur to read the attribute
            // into it, and shrink again on failure.
            let elem = val
                .xml_push_elem()
                .ok_or_else(|| Error::msg("cannot grow slice"))?;
            if let Err(e) = self.unmarshal_attr(elem, attr) {
                val.xml_pop_elem();
                return Err(e);
            }
            return Ok(());
        }

        if val.xml_set_attr(attr) {
            return Ok(());
        }

        copy_value(val, attr.value.as_bytes())
    }

    /// Walks down an XML structure looking for wanted paths, and unmarshals them.
    /// The result tells whether XML elements have been consumed from the decoder
    /// until `start`'s matching end element, or if it is still untouched because
    /// `start` is uninteresting for `sv`'s fields.
    fn unmarshal_path(
        &mut self,
        tinfo: &TypeInfo,
        sv: &mut dyn Unmarshal,
        parents: &[String],
        start: &StartElement,
    ) -> Result<bool, Error> {
        match find_path_step(tinfo, parents, start) {
            // We have no business with this element.
            PathStep::None => Ok(false),
            PathStep::Field(idx) => {
                // It's a perfect match, unmarshal the field.
                if let Some(fv) = resolve(sv, &idx) {
                    self.unmarshal_value(fv, Some(start.clone()))?;
                }
                Ok(true)
            }
            PathStep::Prefix(parents) => {
                self.walk_prefix(tinfo, sv, &parents)?;
                Ok(true)
            }
        }
    }

    /// The element is not a perfect match for any field, but one or more fields
    /// have the path to this element as a parent prefix. Recurse and attempt to
    /// match these.
    #[inline(never)]
    fn walk_prefix(
        &mut self,
        tinfo: &TypeInfo,
        sv: &mut dyn Unmarshal,
        parents: &[String],
    ) -> Result<(), Error> {
        loop {
            match self.token()? {
                Token::StartElement(t) => {
                    if !self.unmarshal_path(tinfo, sv, parents, &t)? {
                        self.skip()?;
                    }
                }
                Token::EndElement(_) => return Ok(()),
                _ => {}
            }
        }
    }
}

/// What to do with a start element found inside a struct.
enum PathStep {
    None,
    Field(Vec<usize>),
    Prefix(Vec<String>),
}

#[inline(never)]
fn find_path_step(tinfo: &TypeInfo, parents: &[String], start: &StartElement) -> PathStep {
    'fields: for finfo in &tinfo.fields {
        if finfo.flags & F_ELEMENT == 0
            || finfo.parents.len() < parents.len()
            || (!finfo.xmlns.is_empty() && finfo.xmlns != start.name.space)
        {
            continue;
        }
        if parents.iter().zip(&finfo.parents).any(|(a, b)| a != b) {
            continue 'fields;
        }
        if finfo.parents.len() == parents.len() && finfo.name == start.name.local {
            return PathStep::Field(finfo.idx.clone());
        }
        if finfo.parents.len() > parents.len() && finfo.parents[parents.len()] == start.name.local {
            // It's a prefix for the field. It is not ok for one field path to be
            // itself the prefix for another.
            return PathStep::Prefix(finfo.parents[..parents.len() + 1].to_vec());
        }
    }
    PathStep::None
}

/// Where `read_element` saves what it reads.
#[derive(Default)]
struct Plan {
    tinfo: Option<Rc<TypeInfo>>,
    save_data: Option<Vec<usize>>,
    save_comment: Option<Vec<usize>>,
    save_xml: Option<Vec<usize>>,
    save_xml_index: usize,
    save_any: Option<Vec<usize>>,
}

impl Plan {
    /// A scalar or byte slice saves its own character data.
    fn scalar() -> Plan {
        Plan {
            save_data: Some(Vec::new()),
            ..Plan::default()
        }
    }
}

/// Stores the saved character data, comments and inner XML.
#[inline(never)]
fn finish_element(
    val: &mut dyn Unmarshal,
    plan: &Plan,
    data: &[u8],
    comment: &[u8],
    xml: &[u8],
) -> Result<(), Error> {
    let mut save_data = plan.save_data.as_deref();
    if let Some(path) = save_data {
        if let Some(sd) = resolve(val, path) {
            if let Some(t) = sd.xml_text_unmarshaler() {
                t.unmarshal_text(data)?;
                save_data = None;
            }
        }
    }

    if let Some(path) = save_data {
        if let Some(sd) = resolve(val, path) {
            copy_value(sd, data)?;
        }
    }

    if let Some(path) = &plan.save_comment {
        if let Some(sc) = resolve(val, path) {
            sc.xml_set_raw(comment);
        }
    }

    if let Some(path) = &plan.save_xml {
        if let Some(sx) = resolve(val, path) {
            sx.xml_set_raw(xml);
        }
    }
    Ok(())
}

/// The error for a kind Go's `unmarshal` cannot handle.
fn unknown_type(val: &dyn Unmarshal) -> Error {
    Error::msg(format!("unknown type {}", val.xml_type_string()))
}

/// Allocates and dereferences a pointer value (one level, as Go does).
fn deref_ptr(val: &mut dyn Unmarshal) -> Result<&mut dyn Unmarshal, Error> {
    if matches!(val.xml_kind(), Kind::Ptr) {
        return val
            .xml_indirect()
            .ok_or_else(|| Error::msg("cannot allocate pointer"));
    }
    Ok(val)
}

/// The field of `v` addressed by `idx`, allocating nil embedded pointers (Go
/// `fieldInfo.value` with `initNilPointers`).
fn resolve<'v>(v: &'v mut dyn Unmarshal, idx: &[usize]) -> Option<&'v mut dyn Unmarshal> {
    let mut v = v;
    for (i, x) in idx.iter().enumerate() {
        if i > 0 {
            while matches!(v.xml_kind(), Kind::Ptr) {
                v = v.xml_indirect()?;
            }
        }
        v = v.xml_field_mut(*x)?;
    }
    Some(v)
}

/// Sets `dst` from `src` (Go `copyValue`), allocating a pointer destination.
fn copy_value(dst: &mut dyn Unmarshal, src: &[u8]) -> Result<(), Error> {
    if matches!(dst.xml_kind(), Kind::Ptr) {
        let Some(inner) = dst.xml_indirect() else {
            return Err(Error::msg("cannot unmarshal into pointer"));
        };
        return match inner.xml_kind() {
            Kind::Scalar | Kind::Bytes => inner.xml_set_text(src),
            _ => Err(Error::msg(format!(
                "cannot unmarshal into *{}",
                inner.xml_type_string()
            ))),
        };
    }
    match dst.xml_kind() {
        Kind::Scalar | Kind::Bytes => dst.xml_set_text(src),
        _ => Err(Error::msg(format!(
            "cannot unmarshal into {}",
            dst.xml_type_string()
        ))),
    }
}

fn text_of(src: &[u8]) -> String {
    String::from_utf8_lossy(src).into_owned()
}

macro_rules! signed_impl {
    ($($t:ty => $bits:expr, $name:expr;)*) => {$(
        impl Unmarshal for $t {
            fn xml_kind(&self) -> Kind { Kind::Scalar }
            fn xml_type_string(&self) -> String { $name.to_string() }
            fn xml_elem_type_string() -> String { $name.to_string() }
            fn xml_set_text(&mut self, src: &[u8]) -> Result<(), Error> {
                if src.is_empty() { *self = 0; return Ok(()); }
                let s = text_of(src);
                *self = parse_int(s.trim(), $bits).map_err(Error::msg)? as $t;
                Ok(())
            }
        }
    )*};
}
signed_impl! {
    i8 => 8, "int8";
    i16 => 16, "int16";
    i32 => 32, "int32";
    i64 => 64, "int64";
    isize => 64, "int";
}

macro_rules! unsigned_impl {
    ($($t:ty => $bits:expr, $name:expr;)*) => {$(
        impl Unmarshal for $t {
            fn xml_kind(&self) -> Kind { Kind::Scalar }
            fn xml_type_string(&self) -> String { $name.to_string() }
            fn xml_elem_type_string() -> String { $name.to_string() }
            fn xml_set_text(&mut self, src: &[u8]) -> Result<(), Error> {
                if src.is_empty() { *self = 0; return Ok(()); }
                let s = text_of(src);
                *self = parse_uint(s.trim(), $bits, "ParseUint").map_err(Error::msg)? as $t;
                Ok(())
            }
        }
    )*};
}
unsigned_impl! {
    u16 => 16, "uint16";
    u32 => 32, "uint32";
    u64 => 64, "uint64";
    usize => 64, "uint";
}

impl Unmarshal for u8 {
    fn xml_kind(&self) -> Kind {
        Kind::Scalar
    }
    fn xml_type_string(&self) -> String {
        "uint8".into()
    }
    fn xml_elem_type_string() -> String {
        "uint8".into()
    }
    fn xml_set_text(&mut self, src: &[u8]) -> Result<(), Error> {
        if src.is_empty() {
            *self = 0;
            return Ok(());
        }
        let s = text_of(src);
        *self = parse_uint(s.trim(), 8, "ParseUint").map_err(Error::msg)? as u8;
        Ok(())
    }
    fn xml_from_byte(b: u8) -> Option<Self> {
        Some(b)
    }
}

impl Unmarshal for bool {
    fn xml_kind(&self) -> Kind {
        Kind::Scalar
    }
    fn xml_type_string(&self) -> String {
        "bool".into()
    }
    fn xml_elem_type_string() -> String {
        "bool".into()
    }
    fn xml_set_text(&mut self, src: &[u8]) -> Result<(), Error> {
        if src.is_empty() {
            *self = false;
            return Ok(());
        }
        *self = parse_bool(text_of(src).trim()).map_err(Error::msg)?;
        Ok(())
    }
}

macro_rules! float_impl {
    ($($t:ty => $bits:expr, $name:expr;)*) => {$(
        impl Unmarshal for $t {
            fn xml_kind(&self) -> Kind { Kind::Scalar }
            fn xml_type_string(&self) -> String { $name.to_string() }
            fn xml_elem_type_string() -> String { $name.to_string() }
            fn xml_set_text(&mut self, src: &[u8]) -> Result<(), Error> {
                if src.is_empty() { *self = 0.0; return Ok(()); }
                let s = text_of(src);
                *self = parse_float(s.trim(), $bits).map_err(Error::msg)? as $t;
                Ok(())
            }
        }
    )*};
}
float_impl! {
    f32 => 32, "float32";
    f64 => 64, "float64";
}

impl Unmarshal for String {
    fn xml_kind(&self) -> Kind {
        Kind::Scalar
    }
    fn xml_type_string(&self) -> String {
        "string".into()
    }
    fn xml_elem_type_string() -> String {
        "string".into()
    }
    fn xml_set_text(&mut self, src: &[u8]) -> Result<(), Error> {
        *self = text_of(src);
        Ok(())
    }
    fn xml_set_raw(&mut self, data: &[u8]) -> bool {
        *self = text_of(data);
        true
    }
}

/// An ignored interface value: the element is skipped.
impl Unmarshal for () {
    fn xml_kind(&self) -> Kind {
        Kind::Interface
    }
}

impl<T: Unmarshal + Default> Unmarshal for Vec<T> {
    fn xml_kind(&self) -> Kind {
        if T::xml_from_byte(0).is_some() {
            Kind::Bytes
        } else {
            Kind::Slice
        }
    }
    fn xml_type_string(&self) -> String {
        format!("[]{}", T::xml_elem_type_string())
    }
    fn xml_elem_type_string() -> String {
        format!("[]{}", T::xml_elem_type_string())
    }
    fn xml_push_elem(&mut self) -> Option<&mut dyn Unmarshal> {
        self.push(T::default());
        self.last_mut().map(|t| t as &mut dyn Unmarshal)
    }
    fn xml_pop_elem(&mut self) {
        self.pop();
    }
    fn xml_set_text(&mut self, src: &[u8]) -> Result<(), Error> {
        // Bytes: non-nil even when empty (a Vec is always non-nil).
        *self = src.iter().filter_map(|b| T::xml_from_byte(*b)).collect();
        Ok(())
    }
    fn xml_set_raw(&mut self, data: &[u8]) -> bool {
        if T::xml_from_byte(0).is_some() {
            *self = data.iter().filter_map(|b| T::xml_from_byte(*b)).collect();
            true
        } else {
            false
        }
    }
}

impl<T: Unmarshal + Default, const N: usize> Unmarshal for [T; N] {
    fn xml_kind(&self) -> Kind {
        Kind::Unknown
    }
    fn xml_type_string(&self) -> String {
        format!("[{N}]{}", T::xml_elem_type_string())
    }
}

/// `None` is a nil pointer; decoding allocates it.
impl<T: Unmarshal + Default> Unmarshal for Option<T> {
    fn xml_kind(&self) -> Kind {
        Kind::Ptr
    }
    fn xml_type_string(&self) -> String {
        format!("*{}", T::xml_elem_type_string())
    }
    fn xml_elem_type_string() -> String {
        format!("*{}", T::xml_elem_type_string())
    }
    fn xml_indirect(&mut self) -> Option<&mut dyn Unmarshal> {
        if self.is_none() {
            *self = Some(T::default());
        }
        self.as_mut().map(|t| t as &mut dyn Unmarshal)
    }
    fn xml_struct_spec() -> Option<&'static StructSpec> {
        T::xml_struct_spec()
    }
}

impl<T: Unmarshal> Unmarshal for Box<T> {
    fn xml_kind(&self) -> Kind {
        (**self).xml_kind()
    }
    fn xml_type_string(&self) -> String {
        (**self).xml_type_string()
    }
    fn xml_elem_type_string() -> String {
        T::xml_elem_type_string()
    }
    fn xml_indirect(&mut self) -> Option<&mut dyn Unmarshal> {
        (**self).xml_indirect()
    }
    fn xml_push_elem(&mut self) -> Option<&mut dyn Unmarshal> {
        (**self).xml_push_elem()
    }
    fn xml_pop_elem(&mut self) {
        (**self).xml_pop_elem()
    }
    fn xml_field_mut(&mut self, i: usize) -> Option<&mut dyn Unmarshal> {
        (**self).xml_field_mut(i)
    }
    fn xml_set_name(&mut self, name: &Name) -> bool {
        (**self).xml_set_name(name)
    }
    fn xml_set_attr(&mut self, attr: &Attr) -> bool {
        (**self).xml_set_attr(attr)
    }
    fn xml_set_text(&mut self, src: &[u8]) -> Result<(), Error> {
        (**self).xml_set_text(src)
    }
    fn xml_set_raw(&mut self, data: &[u8]) -> bool {
        (**self).xml_set_raw(data)
    }
    fn xml_unmarshaler(&mut self) -> Option<&mut dyn Unmarshaler> {
        (**self).xml_unmarshaler()
    }
    fn xml_attr_unmarshaler(&mut self) -> Option<&mut dyn UnmarshalerAttr> {
        (**self).xml_attr_unmarshaler()
    }
    fn xml_text_unmarshaler(&mut self) -> Option<&mut dyn TextUnmarshaler> {
        (**self).xml_text_unmarshaler()
    }
    fn xml_struct_spec() -> Option<&'static StructSpec> {
        T::xml_struct_spec()
    }
    fn xml_from_byte(b: u8) -> Option<Self> {
        T::xml_from_byte(b).map(Box::new)
    }
}

impl Unmarshal for Name {
    fn xml_kind(&self) -> Kind {
        Kind::Name
    }
    fn xml_type_string(&self) -> String {
        "xml.Name".into()
    }
    fn xml_elem_type_string() -> String {
        "xml.Name".into()
    }
    fn xml_set_name(&mut self, name: &Name) -> bool {
        *self = name.clone();
        true
    }
}

impl Unmarshal for Attr {
    fn xml_kind(&self) -> Kind {
        Kind::Struct(&super::marshal::ATTR_SPEC)
    }
    fn xml_type_string(&self) -> String {
        "xml.Attr".into()
    }
    fn xml_elem_type_string() -> String {
        "xml.Attr".into()
    }
    fn xml_field_mut(&mut self, i: usize) -> Option<&mut dyn Unmarshal> {
        match i {
            0 => Some(&mut self.name),
            1 => Some(&mut self.value),
            _ => None,
        }
    }
    fn xml_set_attr(&mut self, attr: &Attr) -> bool {
        *self = attr.clone();
        true
    }
}

/// Go cannot unmarshal into maps: the element is rejected as an unknown type.
impl<K: Unmarshal, V: Unmarshal, S> Unmarshal for std::collections::HashMap<K, V, S> {
    fn xml_kind(&self) -> Kind {
        Kind::Unknown
    }
    fn xml_type_string(&self) -> String {
        format!(
            "map[{}]{}",
            K::xml_elem_type_string(),
            V::xml_elem_type_string()
        )
    }
}

impl<K: Unmarshal, V: Unmarshal> Unmarshal for std::collections::BTreeMap<K, V> {
    fn xml_kind(&self) -> Kind {
        Kind::Unknown
    }
    fn xml_type_string(&self) -> String {
        format!(
            "map[{}]{}",
            K::xml_elem_type_string(),
            V::xml_elem_type_string()
        )
    }
}
