//! The encoder: Go's `printer`, `EncodeToken` and the `marshalValue` engine.
use super::{
    conv::format_float_g,
    is_in_character_range, is_name,
    marshal::{Marshal, Marshaler, View},
    typeinfo::{
        get_type_info, FieldInfo, TypeInfo, F_ANY, F_ATTR, F_CDATA, F_CHARDATA, F_COMMENT,
        F_ELEMENT, F_INNERXML, F_MODE, F_OMITEMPTY,
    },
    Attr, Error, Name, StartElement, Token, UnsupportedTypeError,
};
use crate::{text::BytesExt, unicode::rune::decode_rune};
use std::{
    collections::HashMap,
    io::{self, Write},
    rc::Rc,
};

const XML_URL: &str = "http://www.w3.org/XML/1998/namespace";
const XMLNS_PREFIX: &str = "xmlns";
const XML_PREFIX: &str = "xml";
const BUF_SIZE: usize = 4096;

/// Go's `bufio.Writer` (4096 bytes) with sticky errors, so that `Buffered`,
/// partial flushes and write-error latching behave as in Go.
struct BufWriter<'a> {
    wr: Box<dyn Write + 'a>,
    buf: Vec<u8>,
    err: Option<Error>,
}

impl BufWriter<'_> {
    fn available(&self) -> usize {
        BUF_SIZE - self.buf.len()
    }

    fn flush(&mut self) -> Result<(), Error> {
        if let Some(e) = &self.err {
            return Err(e.clone());
        }
        if self.buf.is_empty() {
            return Ok(());
        }
        if let Err(e) = self.wr.write_all(&self.buf) {
            let e = Error::from(e);
            self.err = Some(e.clone());
            return Err(e);
        }
        self.buf.clear();
        Ok(())
    }

    fn write(&mut self, mut p: &[u8]) -> Result<(), Error> {
        while p.len() > self.available() && self.err.is_none() {
            if self.buf.is_empty() {
                // Large write, empty buffer: write directly from p.
                if let Err(e) = self.wr.write_all(p) {
                    self.err = Some(Error::from(e));
                }
                p = &[];
            } else {
                let n = self.available();
                self.buf.extend_from_slice(&p[..n]);
                p = &p[n..];
                let _ = self.flush();
            }
        }
        if let Some(e) = &self.err {
            return Err(e.clone());
        }
        self.buf.extend_from_slice(p);
        Ok(())
    }

    fn write_byte(&mut self, c: u8) -> Result<(), Error> {
        if let Some(e) = &self.err {
            return Err(e.clone());
        }
        if self.available() == 0 {
            self.flush()?;
        }
        self.buf.push(c);
        Ok(())
    }
}

/// An XML writer (Go `xml.Encoder`).
pub struct Encoder<'a> {
    w: BufWriter<'a>,
    seq: usize,
    indent: String,
    prefix: String,
    depth: i32,
    indented_in: bool,
    put_newline: bool,
    attr_ns: HashMap<String, String>,
    attr_prefix: HashMap<String, String>,
    prefixes: Vec<String>,
    tags: Vec<Name>,
    closed: bool,
    err: Option<Error>,
}

impl<'a> Encoder<'a> {
    /// Returns a new encoder that writes to `w` (Go `NewEncoder`).
    pub fn new(w: impl Write + 'a) -> Self {
        Encoder {
            w: BufWriter {
                wr: Box::new(w),
                buf: Vec::with_capacity(BUF_SIZE),
                err: None,
            },
            seq: 0,
            indent: String::new(),
            prefix: String::new(),
            depth: 0,
            indented_in: false,
            put_newline: false,
            attr_ns: HashMap::new(),
            attr_prefix: HashMap::new(),
            prefixes: Vec::new(),
            tags: Vec::new(),
            closed: false,
            err: None,
        }
    }

    /// Sets the encoder to generate XML in which each element begins on a new
    /// indented line that starts with `prefix` and is followed by copies of
    /// `indent` according to the nesting depth (Go `Indent`).
    pub fn indent(&mut self, prefix: &str, indent: &str) {
        self.prefix = prefix.to_string();
        self.indent = indent.to_string();
    }

    /// Writes the XML encoding of `v` to the stream, then flushes (Go `Encode`).
    pub fn encode<T: Marshal>(&mut self, v: &T) -> Result<(), Error> {
        self.marshal_value(v, None, None)?;
        self.w.flush()
    }

    /// Like [`encode`](Self::encode) but uses `start` as the outermost tag (Go
    /// `EncodeElement`).
    pub fn encode_element<T: Marshal>(&mut self, v: &T, start: StartElement) -> Result<(), Error> {
        self.marshal_value(v, None, Some(&start))?;
        self.w.flush()
    }

    /// Writes the given XML token to the stream (Go `EncodeToken`). It returns an
    /// error if start and end elements are not properly matched. It does not
    /// flush; call [`flush`](Self::flush) when finished.
    pub fn encode_token(&mut self, t: Token) -> Result<(), Error> {
        match t {
            Token::StartElement(mut t) => self.write_start(&mut t)?,
            Token::EndElement(t) => self.write_end(&t.name)?,
            Token::CharData(t) => self.escape_text_bytes(&t.0, false),
            Token::Comment(t) => {
                if find(&t.0, b"-->") {
                    return Err(Error::msg(
                        "xml: EncodeToken of Comment containing --> marker",
                    ));
                }
                self.write_str("<!--");
                self.write(&t.0);
                self.write_str("-->");
                return self.cached_write_error();
            }
            Token::ProcInst(t) => {
                // The first token encoded which is also a ProcInst with target
                // xml is the xml declaration, the only place that target is allowed.
                if t.target == "xml" && !self.w.buf.is_empty() {
                    return Err(Error::msg(
                        "xml: EncodeToken of ProcInst xml target only valid for xml declaration, first token encoded",
                    ));
                }
                if !is_name(t.target.as_bytes()) {
                    return Err(Error::msg(
                        "xml: EncodeToken of ProcInst with invalid Target",
                    ));
                }
                if find(&t.inst, b"?>") {
                    return Err(Error::msg(
                        "xml: EncodeToken of ProcInst containing ?> marker",
                    ));
                }
                self.write_str("<?");
                self.write_str(&t.target);
                if !t.inst.is_empty() {
                    self.write_byte(b' ');
                    self.write(&t.inst);
                }
                self.write_str("?>");
            }
            Token::Directive(t) => {
                if !is_valid_directive(&t.0) {
                    return Err(Error::msg(
                        "xml: EncodeToken of Directive containing wrong < or > markers",
                    ));
                }
                self.write_str("<!");
                self.write(&t.0);
                self.write_str(">");
            }
        }
        self.cached_write_error()
    }

    /// Flushes any buffered XML to the underlying writer (Go `Flush`).
    pub fn flush(&mut self) -> Result<(), Error> {
        self.w.flush()
    }

    /// Closes the encoder: flushes, and fails if elements are left unclosed (Go
    /// `Close`).
    pub fn close(&mut self) -> Result<(), Error> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        self.w.flush()?;
        if let Some(top) = self.tags.last() {
            return Err(Error::msg(format!("unclosed tag <{}>", top.local)));
        }
        Ok(())
    }

    // ---- printer primitives -------------------------------------------------

    fn write(&mut self, b: &[u8]) {
        if self.closed && self.err.is_none() {
            self.err = Some(Error::msg("use of closed Encoder"));
        }
        if self.err.is_none() {
            if let Err(e) = self.w.write(b) {
                self.err = Some(e);
            }
        }
    }

    fn write_str(&mut self, s: &str) {
        self.write(s.as_bytes());
    }

    fn write_byte(&mut self, c: u8) {
        if self.closed && self.err.is_none() {
            self.err = Some(Error::msg("use of closed Encoder"));
        }
        if self.err.is_none() {
            if let Err(e) = self.w.write_byte(c) {
                self.err = Some(e);
            }
        }
    }

    /// Returns the cached write error.
    fn cached_write_error(&mut self) -> Result<(), Error> {
        self.write(&[]);
        match &self.err {
            Some(e) => Err(e.clone()),
            None => Ok(()),
        }
    }

    fn escape_text_bytes(&mut self, s: &[u8], escape_newline: bool) {
        let _ = escape_pieces(s, escape_newline, &mut |piece| {
            self.write(piece);
            match &self.err {
                Some(_) => Err(io::Error::other("printer error")),
                None => Ok(()),
            }
        });
    }

    fn escape_string(&mut self, s: &str) {
        self.escape_text_bytes(s.as_bytes(), true);
    }

    fn write_indent(&mut self, depth_delta: i32) {
        if self.prefix.is_empty() && self.indent.is_empty() {
            return;
        }
        if depth_delta < 0 {
            self.depth -= 1;
            if self.indented_in {
                self.indented_in = false;
                return;
            }
            self.indented_in = false;
        }
        if self.put_newline {
            self.write_byte(b'\n');
        } else {
            self.put_newline = true;
        }
        if !self.prefix.is_empty() {
            let p = self.prefix.clone();
            self.write_str(&p);
        }
        if !self.indent.is_empty() {
            let ind = self.indent.clone();
            for _ in 0..self.depth {
                self.write_str(&ind);
            }
        }
        if depth_delta > 0 {
            self.depth += 1;
            self.indented_in = true;
        }
    }

    // ---- name space prefixes ------------------------------------------------

    /// Finds the name space prefix attribute to use for `url`, defining a new
    /// prefix if necessary.
    fn create_attr_prefix(&mut self, url: &str) -> String {
        if let Some(prefix) = self.attr_prefix.get(url) {
            if !prefix.is_empty() {
                return prefix.clone();
            }
        }

        // The "http://www.w3.org/XML/1998/namespace" name space is predefined as
        // "xml" and must be referred to that way.
        if url == XML_URL {
            return XML_PREFIX.to_string();
        }

        // Pick a name. We try to use the final element of the path but fall
        // back to _.
        let mut prefix = url.trim_end_matches('/').to_string();
        if let Some(i) = prefix.rfind('/') {
            prefix = prefix[i + 1..].to_string();
        }
        if prefix.is_empty() || !is_name(prefix.as_bytes()) || prefix.contains(':') {
            prefix = "_".to_string();
        }
        // xmlanything is reserved and any variant of it regardless of case.
        if prefix.len() >= 3
            && prefix.is_char_boundary(3)
            && prefix.as_bytes()[..3].equal_fold(b"xml")
        {
            prefix = format!("_{prefix}");
        }
        if self.attr_ns.get(&prefix).is_some_and(|v| !v.is_empty()) {
            // Name is taken. Find a better one.
            loop {
                self.seq += 1;
                let id = format!("{prefix}_{}", self.seq);
                if self.attr_ns.get(&id).is_none_or(String::is_empty) {
                    prefix = id;
                    break;
                }
            }
        }

        self.attr_prefix.insert(url.to_string(), prefix.clone());
        self.attr_ns.insert(prefix.clone(), url.to_string());

        self.write_str("xmlns:");
        self.write_str(&prefix);
        self.write_str("=\"");
        self.escape_text_bytes(url.as_bytes(), true);
        self.write_str("\" ");

        self.prefixes.push(prefix.clone());
        prefix
    }

    fn delete_attr_prefix(&mut self, prefix: &str) {
        if let Some(url) = self.attr_ns.get(prefix).cloned() {
            self.attr_prefix.remove(&url);
        } else {
            self.attr_prefix.remove("");
        }
        self.attr_ns.remove(prefix);
    }

    fn mark_prefix(&mut self) {
        self.prefixes.push(String::new());
    }

    fn pop_prefix(&mut self) {
        while let Some(prefix) = self.prefixes.pop() {
            if prefix.is_empty() {
                break;
            }
            self.delete_attr_prefix(&prefix);
        }
    }

    // ---- tags ---------------------------------------------------------------

    fn write_start(&mut self, start: &mut StartElement) -> Result<(), Error> {
        if start.name.local.is_empty() {
            return Err(Error::msg("xml: start tag with no name"));
        }

        self.tags.push(start.name.clone());
        self.mark_prefix();

        self.write_indent(1);
        self.write_byte(b'<');
        self.write_str(&start.name.local);

        if !start.name.space.is_empty() {
            self.write_str(" xmlns=\"");
            self.escape_string(&start.name.space);
            self.write_byte(b'"');
        }

        // Attributes
        for attr in &start.attr {
            let name = &attr.name;
            if name.local.is_empty() {
                continue;
            }
            self.write_byte(b' ');
            if !name.space.is_empty() {
                let p = self.create_attr_prefix(&name.space);
                self.write_str(&p);
                self.write_byte(b':');
            }
            self.write_str(&name.local);
            self.write_str("=\"");
            self.escape_string(&attr.value);
            self.write_byte(b'"');
        }
        self.write_byte(b'>');
        Ok(())
    }

    fn write_end(&mut self, name: &Name) -> Result<(), Error> {
        if name.local.is_empty() {
            return Err(Error::msg("xml: end tag with no name"));
        }
        let top = match self.tags.last() {
            Some(t) if !t.local.is_empty() => t.clone(),
            _ => {
                return Err(Error::msg(format!(
                    "xml: end tag </{}> without start tag",
                    name.local
                )))
            }
        };
        if &top != name {
            if top.local != name.local {
                return Err(Error::msg(format!(
                    "xml: end tag </{}> does not match start tag <{}>",
                    name.local, top.local
                )));
            }
            return Err(Error::msg(format!(
                "xml: end tag </{}> in namespace {} does not match start tag <{}> in namespace {}",
                name.local, name.space, top.local, top.space
            )));
        }
        self.tags.pop();

        self.write_indent(-1);
        self.write_byte(b'<');
        self.write_byte(b'/');
        self.write_str(&name.local);
        self.write_byte(b'>');
        self.pop_prefix();
        Ok(())
    }

    // ---- marshaling ---------------------------------------------------------

    /// Writes one or more XML elements representing `val`. If `val` was obtained
    /// from a struct field, `finfo` has its details.
    fn marshal_value(
        &mut self,
        val: &dyn Marshal,
        finfo: Option<&FieldInfo>,
        start_template: Option<&StartElement>,
    ) -> Result<(), Error> {
        if let Some(st) = start_template {
            if st.name.local.is_empty() {
                return Err(Error::msg(
                    "xml: EncodeElement of StartElement with missing name",
                ));
            }
        }
        if let Some(fi) = finfo {
            if fi.flags & F_OMITEMPTY != 0 && is_empty_value(val) {
                return Ok(());
            }
        }

        // Drill into interfaces and pointers.
        let mut val = val;
        let view = loop {
            match val.xml_view() {
                View::Nil => return Ok(()),
                View::Ptr(p) => val = p,
                other => break other,
            }
        };

        // Check for marshaler, then text marshaler.
        if let Some(m) = val.xml_marshaler() {
            return self.marshal_interface(m, val, default_start(val, finfo, start_template));
        }
        if let Some(m) = val.xml_text_marshaler() {
            let start = default_start(val, finfo, start_template);
            return self.marshal_text_interface(m, start);
        }

        // Slices and arrays iterate over the elements. They do not have an
        // enclosing tag.
        if let View::Seq(items) = &view {
            for item in items {
                self.marshal_value(*item, finfo, start_template)?;
            }
            return Ok(());
        }

        let tinfo: Rc<TypeInfo> = match &view {
            View::Struct(spec) => get_type_info(spec)?,
            _ => Rc::new(TypeInfo::default()),
        };

        // Create start element. Precedence for the XML element name is:
        // 0. start_template
        // 1. XMLName field in underlying struct;
        // 2. field name/tag in the struct field; and
        // 3. type name
        let mut start = StartElement::default();

        if let Some(st) = start_template {
            start.name = st.name.clone();
            start.attr.extend(st.attr.iter().cloned());
        } else if let Some(xmlname) = &tinfo.xmlname {
            if !xmlname.name.is_empty() {
                start.name.space = xmlname.xmlns.clone();
                start.name.local = xmlname.name.clone();
            } else if let Some(v) = field_value(val, &xmlname.idx).and_then(|f| f.xml_as_name()) {
                if !v.local.is_empty() {
                    start.name = v.clone();
                }
            }
        }
        if start.name.local.is_empty() {
            if let Some(fi) = finfo {
                start.name.space = fi.xmlns.clone();
                start.name.local = fi.name.clone();
            }
        }
        if start.name.local.is_empty() {
            let mut name = val.xml_type_name();
            if let Some(i) = name.find('[') {
                // Truncate generic instantiation name. See Go issue 48318.
                name = &name[..i];
            }
            if name.is_empty() {
                return Err(Error::UnsupportedType(UnsupportedTypeError {
                    type_name: val.xml_type_string(),
                }));
            }
            start.name.local = name.to_string();
        }

        // Attributes
        for finfo in &tinfo.fields {
            if finfo.flags & F_ATTR == 0 {
                continue;
            }
            let Some(fv) = field_value(val, &finfo.idx) else {
                // Behind a nil embedded pointer: Go would panic on the invalid
                // value without omitempty; skipping is the useful behaviour.
                continue;
            };

            if finfo.flags & F_OMITEMPTY != 0 && is_empty_value(fv) {
                continue;
            }

            let name = Name {
                space: finfo.xmlns.clone(),
                local: finfo.name.clone(),
            };
            self.marshal_attr(&mut start, name, fv)?;
        }

        // If an empty name was found, namespace is overridden with an empty space
        if let Some(xmlname) = &tinfo.xmlname {
            if start.name.space.is_empty()
                && xmlname.xmlns.is_empty()
                && xmlname.name.is_empty()
                && self.tags.last().is_some_and(|t| !t.space.is_empty())
            {
                start.attr.push(Attr {
                    name: Name {
                        space: String::new(),
                        local: XMLNS_PREFIX.to_string(),
                    },
                    value: String::new(),
                });
            }
        }
        self.write_start(&mut start)?;

        if matches!(view, View::Struct(_)) {
            self.marshal_struct(&tinfo, val)?;
        } else {
            let (s, b) = marshal_simple(val, &view)?;
            match b {
                Some(b) => self.escape_text_bytes(&b, true),
                None => self.escape_string(&s),
            }
        }

        self.write_end(&start.name)?;

        self.cached_write_error()
    }

    /// Marshals an attribute with the given name and value, adding to
    /// `start.attr`.
    fn marshal_attr(
        &mut self,
        start: &mut StartElement,
        name: Name,
        val: &dyn Marshal,
    ) -> Result<(), Error> {
        if let Some(m) = val.xml_attr_marshaler() {
            let attr = m.marshal_xml_attr(name)?;
            if !attr.name.local.is_empty() {
                start.attr.push(attr);
            }
            return Ok(());
        }
        if let Some(m) = val.xml_text_marshaler() {
            let text = m.marshal_text()?;
            start.attr.push(Attr {
                name,
                value: lossy(&text),
            });
            return Ok(());
        }

        // Dereference or skip nil pointer, interface values.
        let mut val = val;
        let mut view = val.xml_view();
        match view {
            View::Nil => return Ok(()),
            View::Ptr(p) => {
                val = p;
                view = val.xml_view();
            }
            _ => {}
        }

        // Walk slices.
        if let View::Seq(items) = &view {
            for item in items {
                self.marshal_attr(start, name.clone(), *item)?;
            }
            return Ok(());
        }

        if let Some(attr) = val.xml_as_attr() {
            start.attr.push(attr.clone());
            return Ok(());
        }

        let (s, b) = marshal_simple(val, &view)?;
        let value = match b {
            Some(b) => lossy(&b),
            None => s,
        };
        start.attr.push(Attr { name, value });
        Ok(())
    }

    /// Marshals a `Marshaler` value.
    fn marshal_interface(
        &mut self,
        m: &dyn Marshaler,
        val: &dyn Marshal,
        start: StartElement,
    ) -> Result<(), Error> {
        // Push a marker onto the tag stack so that marshal_xml cannot close the
        // XML tags that it did not open.
        self.tags.push(Name::default());
        let n = self.tags.len();

        m.marshal_xml(self, start)?;

        // Make sure marshal_xml closed all its tags. tags[n-1] is the mark.
        if self.tags.len() > n {
            let ts = val.xml_type_string();
            let receiver = if val.xml_type_name().is_empty() {
                format!("({ts})")
            } else {
                ts
            };
            return Err(Error::msg(format!(
                "xml: {receiver}.MarshalXML wrote invalid XML: <{}> not closed",
                self.tags[self.tags.len() - 1].local
            )));
        }
        self.tags.truncate(n - 1);
        Ok(())
    }

    /// Marshals a `TextMarshaler` value.
    fn marshal_text_interface(
        &mut self,
        m: &dyn super::marshal::TextMarshaler,
        mut start: StartElement,
    ) -> Result<(), Error> {
        self.write_start(&mut start)?;
        let text = m.marshal_text()?;
        self.escape_text_bytes(&text, true);
        self.write_end(&start.name)
    }

    fn marshal_struct(&mut self, tinfo: &TypeInfo, val: &dyn Marshal) -> Result<(), Error> {
        let mut s = ParentStack { stack: Vec::new() };
        for finfo in &tinfo.fields {
            if finfo.flags & F_ATTR != 0 {
                continue;
            }
            let Some(vf) = field_value(val, &finfo.idx) else {
                // The field is behind an anonymous struct field that's nil. Skip it.
                continue;
            };

            match finfo.flags & F_MODE {
                F_CDATA | F_CHARDATA => {
                    let cdata = finfo.flags & F_MODE == F_CDATA;
                    s.trim(self, &finfo.parents)?;
                    if let Some(m) = vf.xml_text_marshaler() {
                        let data = m.marshal_text()?;
                        self.emit(&data, cdata)?;
                        continue;
                    }
                    let vf = indirect(vf);
                    match vf.xml_view() {
                        View::Int(v) => self.emit(v.to_string().as_bytes(), cdata)?,
                        View::Uint(v) => self.emit(v.to_string().as_bytes(), cdata)?,
                        View::Float(v, bits) => {
                            self.emit(format_float_g(v, bits).as_bytes(), cdata)?
                        }
                        View::Bool(v) => self.emit(v.to_string().as_bytes(), cdata)?,
                        View::Str(v) => self.emit(v.as_bytes(), cdata)?,
                        View::Bytes(v) => self.emit(&v, cdata)?,
                        _ => {}
                    }
                    continue;
                }

                F_COMMENT => {
                    s.trim(self, &finfo.parents)?;
                    let vf = indirect(vf);
                    let bytes: Vec<u8> = match vf.xml_view() {
                        View::Str(v) => v.as_bytes().to_vec(),
                        View::Bytes(v) => v.into_owned(),
                        _ => {
                            let ts = match find_spec_string(val) {
                                Some(t) => t,
                                None => val.xml_type_string(),
                            };
                            return Err(Error::msg(format!(
                                "xml: bad type for comment field of {ts}"
                            )));
                        }
                    };
                    if bytes.is_empty() {
                        continue;
                    }
                    self.write_indent(0);
                    self.write_str("<!--");
                    let dash_dash = find(&bytes, b"--");
                    let dash_last = bytes[bytes.len() - 1] == b'-';
                    if !dash_dash {
                        self.write(&bytes);
                    }
                    if dash_dash {
                        return Err(Error::msg("xml: comments must not contain \"--\""));
                    }
                    if dash_last {
                        // "--->" is invalid grammar. Make it "- -->"
                        self.write_byte(b' ');
                    }
                    self.write_str("-->");
                    continue;
                }

                F_INNERXML => {
                    let vf = indirect(vf);
                    match vf.xml_view() {
                        View::Bytes(raw) => {
                            self.write(&raw);
                            continue;
                        }
                        View::Str(raw) => {
                            self.write_str(raw);
                            continue;
                        }
                        _ => {}
                    }
                    // Falls through to marshal_value below, as in Go.
                    self.marshal_value(vf, Some(finfo), None)?;
                    continue;
                }

                m if m == F_ELEMENT || m == (F_ELEMENT | F_ANY) => {
                    s.trim(self, &finfo.parents)?;
                    if finfo.parents.len() > s.stack.len() {
                        let nil_ptr = matches!(vf.xml_view(), View::Nil);
                        if !nil_ptr {
                            s.push(self, &finfo.parents[s.stack.len()..])?;
                        }
                    }
                }
                _ => {}
            }
            self.marshal_value(vf, Some(finfo), None)?;
        }
        let _ = s.trim(self, &[]);
        self.cached_write_error()
    }

    fn emit(&mut self, data: &[u8], cdata: bool) -> Result<(), Error> {
        if cdata {
            self.emit_cdata(data)
        } else {
            self.escape_text_bytes(data, true);
            Ok(())
        }
    }

    /// Writes the CDATA-wrapped plain text, escaping nested `]]>`.
    fn emit_cdata(&mut self, mut s: &[u8]) -> Result<(), Error> {
        if s.is_empty() {
            return Ok(());
        }
        self.write(b"<![CDATA[");
        while let Some(i) = s.windows(3).position(|w| w == b"]]>") {
            self.write(&s[..i]);
            self.write(b"]]]]><![CDATA[>");
            s = &s[i + 3..];
        }
        self.write(s);
        self.write(b"]]>");
        match &self.err {
            Some(e) => Err(e.clone()),
            None => Ok(()),
        }
    }
}

/// Type string of a struct value, for error messages.
fn find_spec_string(val: &dyn Marshal) -> Option<String> {
    match val.xml_view() {
        View::Struct(spec) => Some(spec.type_string.to_string()),
        _ => None,
    }
}

/// Drills into pointers, returning the pointed-at value or the nil value.
fn indirect(mut v: &dyn Marshal) -> &dyn Marshal {
    while let View::Ptr(p) = v.xml_view() {
        v = p;
    }
    v
}

/// The field of `v` addressed by `idx` (Go `fieldInfo.value` with
/// `dontInitNilPointers`): `None` when a nil embedded pointer is on the path.
pub(super) fn field_value<'a>(mut v: &'a dyn Marshal, idx: &[usize]) -> Option<&'a dyn Marshal> {
    for (i, x) in idx.iter().enumerate() {
        if i > 0 {
            loop {
                match v.xml_view() {
                    View::Ptr(p) => v = p,
                    View::Nil => return None,
                    _ => break,
                }
            }
        }
        v = v.xml_field(*x)?;
    }
    Some(v)
}

/// Go's `isEmptyValue`.
fn is_empty_value(v: &dyn Marshal) -> bool {
    match v.xml_view() {
        View::Nil => true,
        View::Ptr(_) | View::Struct(_) | View::Unsupported => false,
        View::Bool(b) => !b,
        View::Int(i) => i == 0,
        View::Uint(u) => u == 0,
        View::Float(f, _) => f == 0.0,
        View::Str(s) => s.is_empty(),
        View::Bytes(b) => b.is_empty(),
        View::Seq(s) => s.is_empty(),
        View::Map { len } => len == 0,
    }
}

/// Go's `defaultStart`: the start element for a Marshaler/TextMarshaler.
fn default_start(
    val: &dyn Marshal,
    finfo: Option<&FieldInfo>,
    start_template: Option<&StartElement>,
) -> StartElement {
    let mut start = StartElement::default();
    if let Some(st) = start_template {
        start.name = st.name.clone();
        start.attr.extend(st.attr.iter().cloned());
    } else if let Some(fi) = finfo.filter(|fi| !fi.name.is_empty()) {
        start.name.local = fi.name.clone();
        start.name.space = fi.xmlns.clone();
    } else {
        start.name.local = val.xml_type_name().to_string();
    }
    start
}

/// Go's `marshalSimple`: the text of a scalar (a string, or raw bytes).
fn marshal_simple(val: &dyn Marshal, view: &View<'_>) -> Result<(String, Option<Vec<u8>>), Error> {
    Ok(match view {
        View::Int(v) => (v.to_string(), None),
        View::Uint(v) => (v.to_string(), None),
        View::Float(v, bits) => (format_float_g(*v, *bits), None),
        View::Str(s) => ((*s).to_string(), None),
        View::Bool(b) => (b.to_string(), None),
        View::Bytes(b) => (String::new(), Some(b.to_vec())),
        _ => {
            return Err(Error::UnsupportedType(UnsupportedTypeError {
                type_name: val.xml_type_string(),
            }))
        }
    })
}

fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn find(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Reports whether `dir` is a valid directive text: angle brackets matched,
/// ignoring comments and strings (Go `isValidDirective`).
fn is_valid_directive(dir: &[u8]) -> bool {
    let mut depth = 0i32;
    let mut inquote = 0u8;
    let mut incomment = false;
    for (i, &c) in dir.iter().enumerate() {
        if incomment {
            if c == b'>' && i + 1 >= 3 && &dir[i + 1 - 3..=i] == b"-->" {
                incomment = false;
            }
            // Just ignore anything in comment
        } else if inquote != 0 {
            if c == inquote {
                inquote = 0;
            }
            // Just ignore anything within quotes
        } else if c == b'\'' || c == b'"' {
            inquote = c;
        } else if c == b'<' {
            if i + 4 < dir.len() && &dir[i..i + 4] == b"<!--" {
                incomment = true;
            } else {
                depth += 1;
            }
        } else if c == b'>' {
            if depth == 0 {
                return false;
            }
            depth -= 1;
        }
    }
    depth == 0 && inquote == 0 && !incomment
}

struct ParentStack {
    stack: Vec<String>,
}

impl ParentStack {
    /// Updates the XML context to match the longest common prefix of the stack
    /// and `parents`, writing a closing tag for every parent popped.
    fn trim(&mut self, p: &mut Encoder<'_>, parents: &[String]) -> Result<(), Error> {
        let mut split = 0;
        while split < parents.len() && split < self.stack.len() {
            if parents[split] != self.stack[split] {
                break;
            }
            split += 1;
        }
        for i in (split..self.stack.len()).rev() {
            p.write_end(&Name {
                space: String::new(),
                local: self.stack[i].clone(),
            })?;
        }
        self.stack.truncate(split);
        Ok(())
    }

    /// Adds parent elements to the stack and writes open tags.
    fn push(&mut self, p: &mut Encoder<'_>, parents: &[String]) -> Result<(), Error> {
        for parent in parents {
            p.write_start(&mut StartElement {
                name: Name {
                    space: String::new(),
                    local: parent.clone(),
                },
                attr: Vec::new(),
            })?;
        }
        self.stack.extend(parents.iter().cloned());
        Ok(())
    }
}

/// Emits the escaped form of `s` in the same pieces Go's `escapeText` writes
/// (text before each escape, the escape, and the tail), stopping at the first
/// error. The piece boundaries matter to a buffered writer's flush points.
fn escape_pieces(
    s: &[u8],
    escape_newline: bool,
    emit: &mut dyn FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<()> {
    let mut last = 0;
    let mut i = 0;
    while i < s.len() {
        let (r, width) = decode_rune(&s[i..]);
        i += width;
        let esc: &[u8] = match r {
            0x22 => b"&#34;",
            0x27 => b"&#39;",
            0x26 => b"&amp;",
            0x3C => b"&lt;",
            0x3E => b"&gt;",
            0x09 => b"&#x9;",
            0x0A => {
                if !escape_newline {
                    continue;
                }
                b"&#xA;"
            }
            0x0D => b"&#xD;",
            _ => {
                if !is_in_character_range(r) || (r == 0xFFFD && width == 1) {
                    "\u{FFFD}".as_bytes()
                } else {
                    continue;
                }
            }
        };
        emit(&s[last..i - width])?;
        emit(esc)?;
        last = i;
    }
    emit(&s[last..])
}

/// Writes to `w` the properly escaped XML equivalent of the plain text data `s`
/// (Go `EscapeText`).
pub fn escape_text<W: Write>(mut w: W, s: &[u8]) -> io::Result<()> {
    escape_pieces(s, true, &mut |piece| w.write_all(piece))
}

/// Like [`escape_text`] but omits the error return value (Go `Escape`).
pub fn escape<W: Write>(w: W, s: &[u8]) {
    let _ = escape_text(w, s);
}

/// Returns the XML encoding of `v` (Go `Marshal`).
pub fn marshal<T: Marshal>(v: &T) -> Result<Vec<u8>, Error> {
    let mut b = Vec::new();
    {
        let mut enc = Encoder::new(&mut b);
        enc.encode(v)?;
        enc.close()?;
    }
    Ok(b)
}

/// Works like [`marshal`], but each XML element begins on a new indented line
/// that starts with `prefix` and is followed by copies of `indent` according to
/// the nesting depth (Go `MarshalIndent`).
pub fn marshal_indent<T: Marshal>(v: &T, prefix: &str, indent: &str) -> Result<Vec<u8>, Error> {
    let mut b = Vec::new();
    {
        let mut enc = Encoder::new(&mut b);
        enc.indent(prefix, indent);
        enc.encode(v)?;
        enc.close()?;
    }
    Ok(b)
}
