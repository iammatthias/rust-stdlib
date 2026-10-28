//! Data-driven templates for generating HTML output safe against code
//! injection (Go `html/template`).
//!
//! It provides the same interface as [`crate::text::template`] and should be
//! used instead of it whenever the output is HTML. The documentation for
//! `text/template` describes the template language and the way templates are
//! executed; this module documents the security features it adds.
//!
//! The templates are parsed and executed as in `text/template`. On the first
//! execution, each template is analyzed to find the context (HTML text, an
//! attribute value, a URL, JavaScript, CSS and so on) of every action, and
//! the escaping functions that context requires are added to the action's
//! pipeline. Typed strings ([`Html`], [`Css`], [`Js`], [`JsStr`], [`Url`],
//! [`Srcset`] and [`HtmlAttr`]) mark content that is known to be safe in a
//! given context and need not be escaped.
//!
//! This engine stays separate from [`crate::html`]'s text escaping functions.
//!
//! # Deviations from Go
//!
//! - Everything `text/template` documents (panics on invalid `Funcs`,
//!   UTF-8 strings, flattened variadic arguments) applies here too.
//! - Errors from this module are [`TemplateError`]: an escaping [`Error`], an
//!   error of the underlying text template, or a plain message.
//! - The output of a custom `MarshalJSON` method that is not valid JSON is
//!   compacted but not validated before it is embedded.
//! - Escaper edits are applied to a copy of the parse tree, so a tree obtained
//!   with [`Template::tree`] before the first execution does not show them;
//!   call it again afterwards.

mod attr;
mod content;
mod context;
mod css;
mod error;
mod escape;
mod escapers;
mod js;
mod jsonenc;
mod jsonscan;
mod transition;
mod url;
mod util;

pub use content::{
    css_type, html_attr_type, html_type, js_str_type, js_type, srcset_type, url_type, Css, Html,
    HtmlAttr, Js, JsStr, Srcset, Url,
};
pub use error::{Error, ErrorCode};

use crate::io::fs::FS;
use crate::text::template as text;
use crate::text::template::helper;
use crate::text::template::parse::{on_big_stack, Node, Tree};
use crate::text::template::value::{ToValue, Value};
use context::{Context, State};
use escape::{Cx, Escaper};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

pub use text::FuncMap;

/// Writes to `w` the escaped HTML equivalent of the plain text data `b` (Go
/// `template.HTMLEscape`).
pub fn html_escape<W: Write + ?Sized>(w: &mut W, b: &[u8]) -> io::Result<()> {
    text::html_escape(w, b)
}

/// Returns the escaped HTML equivalent of the plain text data `s` (Go
/// `template.HTMLEscapeString`).
pub fn html_escape_string(s: &str) -> String {
    text::html_escape_string(s)
}

/// Returns the escaped HTML equivalent of the textual representation of its
/// arguments (Go `template.HTMLEscaper`).
pub fn html_escaper(args: &[Value]) -> String {
    text::html_escaper(args)
}

/// Writes to `w` the escaped JavaScript equivalent of the plain text data `b`
/// (Go `template.JSEscape`).
pub fn js_escape<W: Write + ?Sized>(w: &mut W, b: &[u8]) -> io::Result<()> {
    text::js_escape(w, b)
}

/// Returns the escaped JavaScript equivalent of the plain text data `s` (Go
/// `template.JSEscapeString`).
pub fn js_escape_string(s: &str) -> String {
    text::js_escape_string(s)
}

/// Returns the escaped JavaScript equivalent of the textual representation of
/// its arguments (Go `template.JSEscaper`).
pub fn js_escaper(args: &[Value]) -> String {
    text::js_escaper(args)
}

/// Returns the escaped value of the textual representation of its arguments
/// in a form suitable for embedding in a URL query (Go
/// `template.URLQueryEscaper`).
pub fn url_query_escaper(args: &[Value]) -> String {
    text::url_query_escaper(args)
}

/// Reports whether the value is "true", in the sense of an `if` action, and
/// whether it has a truth value at all (Go `template.IsTrue`).
pub fn is_true(val: &Value) -> (bool, bool) {
    text::is_true(val)
}

/// An error returned by the template methods: an escaping error, an error
/// from the underlying `text/template`, or a plain message.
#[derive(Debug)]
pub enum TemplateError {
    /// The template could not be escaped (Go `*template.Error`).
    Escape(Error),
    /// A `text/template` error: parsing, executing or writing.
    Text(text::Error),
    /// Any other error, such as a missing template.
    Msg(String),
}

impl fmt::Display for TemplateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TemplateError::Escape(e) => e.fmt(f),
            TemplateError::Text(e) => e.fmt(f),
            TemplateError::Msg(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for TemplateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TemplateError::Escape(e) => Some(e),
            TemplateError::Text(e) => Some(e),
            TemplateError::Msg(_) => None,
        }
    }
}

impl From<Error> for TemplateError {
    fn from(e: Error) -> TemplateError {
        TemplateError::Escape(e)
    }
}

impl From<text::Error> for TemplateError {
    fn from(e: text::Error) -> TemplateError {
        TemplateError::Text(e)
    }
}

type Res<T> = Result<T, TemplateError>;

/// The result of escaping a template.
#[derive(Clone, Debug)]
enum EscapeState {
    /// Not yet escaped.
    NotEscaped,
    /// Escaped correctly.
    Ok,
    /// Escaping failed.
    Err(Error),
}

#[derive(Clone)]
struct Inner {
    escape_err: EscapeState,
    text: text::Template,
    tree: Option<Arc<Tree>>,
    ns: Arc<NameSpace>,
}

struct NameSpace {
    m: Mutex<NsInner>,
}

struct NsInner {
    set: BTreeMap<String, Template>,
    escaped: bool,
    esc: Escaper,
}

/// The representation of a parsed HTML template (Go `template.Template`). A
/// `Template` is a handle, like a Go `*Template`: cloning it with [`Clone`]
/// gives another handle to the same template.
#[derive(Clone)]
pub struct Template(Arc<Mutex<Inner>>);

impl PartialEq for Template {
    /// Two handles are equal when they are the same template, as Go's
    /// `*Template` comparison.
    fn eq(&self, other: &Template) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for Template {}

impl fmt::Debug for Template {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Template({:?})", self.name())
    }
}

/// Allocates a new HTML template with the given name (Go `template.New`).
pub fn new(name: &str) -> Template {
    Template::new(name)
}

/// A wrapper that panics if the template could not be created (Go
/// `template.Must`).
pub fn must(r: Res<Template>) -> Template {
    match r {
        Ok(t) => t,
        Err(e) => panic!("{e}"),
    }
}

impl Template {
    fn inner(&self) -> Inner {
        self.0.lock().expect("template lock").clone()
    }

    fn ns(&self) -> Arc<NameSpace> {
        self.0.lock().expect("template lock").ns.clone()
    }

    fn text(&self) -> text::Template {
        self.0.lock().expect("template lock").text.clone()
    }

    /// Allocates a new HTML template with the given name (Go
    /// `template.New`).
    pub fn new(name: &str) -> Template {
        let ns = Arc::new(NameSpace {
            m: Mutex::new(NsInner {
                set: BTreeMap::new(),
                escaped: false,
                esc: Escaper::default(),
            }),
        });
        let tmpl = Template(Arc::new(Mutex::new(Inner {
            escape_err: EscapeState::NotEscaped,
            text: text::Template::new(name),
            tree: None,
            ns: ns.clone(),
        })));
        ns.m.lock()
            .expect("ns lock")
            .set
            .insert(name.to_owned(), tmpl.clone());
        tmpl
    }

    /// Returns the name of the template (Go `Template.Name`).
    pub fn name(&self) -> String {
        self.text().name().to_owned()
    }

    /// The parse tree of the template (Go `Template.Tree`).
    pub fn tree(&self) -> Option<Arc<Tree>> {
        self.0.lock().expect("template lock").tree.clone()
    }

    /// Returns a slice of the templates associated with t, including t itself
    /// (Go `Template.Templates`).
    pub fn templates(&self) -> Vec<Template> {
        let ns = self.ns();
        let g = ns.m.lock().expect("ns lock");
        g.set.values().cloned().collect()
    }

    /// Sets options for the template (Go `Template.Option`); see
    /// [`text::Template::option`].
    pub fn option(&self, opts: &[&str]) -> Template {
        self.text().option(opts);
        self.clone()
    }

    fn check_can_parse(&self) -> Res<()> {
        let ns = self.ns();
        let g = ns.m.lock().expect("ns lock");
        if g.escaped {
            return Err(TemplateError::Msg(
                "html/template: cannot Parse after Execute".to_owned(),
            ));
        }
        Ok(())
    }

    /// Escapes the template if it has not been, reporting failure.
    fn escape(&self) -> Res<()> {
        let ns = self.ns();
        let mut g = ns.m.lock().expect("ns lock");
        g.escaped = true;
        let me = self.inner();
        match me.escape_err {
            EscapeState::NotEscaped => {
                if me.tree.is_none() {
                    return Err(TemplateError::Msg(format!(
                        "template: {} is an incomplete or empty template",
                        crate::strconv::quote(me.text.name())
                    )));
                }
                let root = me
                    .text
                    .tree()
                    .and_then(|t| t.root.as_ref().map(|r| Node::List(r.clone())));
                let name = me.text.name().to_owned();
                // Escaping recurses over the whole template; give it room.
                let inner: &mut NsInner = &mut g;
                on_big_stack(move || escape_template(inner, &me.text, root, &name))
            }
            EscapeState::Err(e) => Err(TemplateError::Escape(e)),
            EscapeState::Ok => Ok(()),
        }
    }

    /// Applies the template to the data object and writes the output to `wr`
    /// (Go `Template.Execute`). The template is escaped on first use.
    pub fn execute<W: Write + ?Sized, D: ToValue + ?Sized>(&self, wr: &mut W, data: &D) -> Res<()> {
        self.escape()?;
        self.text().execute(wr, data).map_err(TemplateError::Text)
    }

    /// Like [`Template::execute`] for data that is already a [`Value`].
    pub fn execute_value(&self, wr: &mut dyn Write, value: Value) -> Res<()> {
        self.escape()?;
        self.text()
            .execute_value(wr, value)
            .map_err(TemplateError::Text)
    }

    /// Applies the template associated with t that has the given name to the
    /// data object and writes the output to `wr` (Go
    /// `Template.ExecuteTemplate`).
    pub fn execute_template<W: Write + ?Sized, D: ToValue + ?Sized>(
        &self,
        wr: &mut W,
        name: &str,
        data: &D,
    ) -> Res<()> {
        let tmpl = self.lookup_and_escape_template(name)?;
        tmpl.text().execute(wr, data).map_err(TemplateError::Text)
    }

    /// Like [`Template::execute_template`] for data that is already a
    /// [`Value`].
    pub fn execute_template_value(&self, wr: &mut dyn Write, name: &str, value: Value) -> Res<()> {
        let tmpl = self.lookup_and_escape_template(name)?;
        tmpl.text()
            .execute_value(wr, value)
            .map_err(TemplateError::Text)
    }

    /// Returns the template with the given name, after escaping it.
    fn lookup_and_escape_template(&self, name: &str) -> Res<Template> {
        let ns = self.ns();
        let mut g = ns.m.lock().expect("ns lock");
        g.escaped = true;
        let Some(tmpl) = g.set.get(name).cloned() else {
            return Err(TemplateError::Msg(format!(
                "html/template: {} is undefined",
                crate::strconv::quote(name)
            )));
        };
        let tm = tmpl.inner();
        if let EscapeState::Err(e) = &tm.escape_err {
            return Err(TemplateError::Escape(e.clone()));
        }
        let has_root = tm.text.tree().is_some_and(|t| t.root.is_some());
        if !has_root {
            return Err(TemplateError::Msg(format!(
                "html/template: {} is an incomplete template",
                crate::strconv::quote(name)
            )));
        }
        if self.text().lookup(name).is_none() {
            // Two cases: The template exists but is empty, or has never been
            // mentioned at all. Distinguish the cases in the error messages.
            panic!("html/template internal error: template escaping out of sync");
        }
        if matches!(tm.escape_err, EscapeState::NotEscaped) {
            let root = tm
                .text
                .tree()
                .and_then(|t| t.root.as_ref().map(|r| Node::List(r.clone())));
            let inner: &mut NsInner = &mut g;
            on_big_stack(move || escape_template(inner, &tm.text, root, name))?;
        }
        Ok(tmpl)
    }

    /// Returns a string listing the defined templates, prefixed by the string
    /// "; defined templates are: " (Go `Template.DefinedTemplates`).
    pub fn defined_templates(&self) -> String {
        self.text().defined_templates()
    }

    /// Parses text as a template body for t (Go `Template.Parse`).
    pub fn parse(&self, text_src: &str) -> Res<Template> {
        self.check_can_parse()?;
        let ret = self.text().parse(text_src).map_err(TemplateError::Text)?;

        // In general, all the named templates might have changed underfoot.
        // Regardless, some new ones may have been defined.
        // The template.Template set has been updated; update ours.
        let ns = self.ns();
        let mut g = ns.m.lock().expect("ns lock");
        for v in ret.templates() {
            let name = v.name().to_owned();
            let tmpl = match g.set.get(&name).cloned() {
                Some(t) => t,
                None => self.new_locked(&mut g, &name),
            };
            let mut inner = tmpl.0.lock().expect("template lock");
            inner.tree = v.tree();
            inner.text = v;
        }
        Ok(self.clone())
    }

    /// Adds a parse tree for the template with the given name (Go
    /// `Template.AddParseTree`).
    pub fn add_parse_tree(&self, name: &str, tree: Tree) -> Res<Template> {
        self.check_can_parse()?;
        let ns = self.ns();
        let mut g = ns.m.lock().expect("ns lock");
        let text = self
            .text()
            .add_parse_tree(name, tree)
            .map_err(TemplateError::Text)?;
        let ret = Template(Arc::new(Mutex::new(Inner {
            escape_err: EscapeState::NotEscaped,
            tree: text.tree(),
            text,
            ns: ns.clone(),
        })));
        g.set.insert(name.to_owned(), ret.clone());
        Ok(ret)
    }

    /// Creates a copy of t, which must not have been executed (Go
    /// `Template.Clone`).
    pub fn clone_template(&self) -> Res<Template> {
        let ns = self.ns();
        let g = ns.m.lock().expect("ns lock");
        let me = self.inner();
        if !matches!(me.escape_err, EscapeState::NotEscaped) {
            return Err(TemplateError::Msg(format!(
                "html/template: cannot Clone {} after it has executed",
                crate::strconv::quote(me.text.name())
            )));
        }
        let text_clone = me.text.clone_template().map_err(TemplateError::Text)?;
        let new_ns = Arc::new(NameSpace {
            m: Mutex::new(NsInner {
                set: BTreeMap::new(),
                escaped: false,
                esc: Escaper::default(),
            }),
        });
        let ret = Template(Arc::new(Mutex::new(Inner {
            escape_err: EscapeState::NotEscaped,
            tree: text_clone.tree(),
            text: text_clone.clone(),
            ns: new_ns.clone(),
        })));
        let ret_name = text_clone.name().to_owned();
        let mut ng = new_ns.m.lock().expect("ns lock");
        ng.set.insert(ret_name.clone(), ret);
        for x in text_clone.templates() {
            let name = x.name().to_owned();
            let src = g.set.get(&name);
            let bad = match src {
                None => true,
                Some(s) => !matches!(s.inner().escape_err, EscapeState::NotEscaped),
            };
            if bad {
                return Err(TemplateError::Msg(format!(
                    "html/template: cannot Clone {} after it has executed",
                    crate::strconv::quote(me.text.name())
                )));
            }
            x.set_tree(x.tree().map(|t| t.copy()));
            let tree = x.tree();
            ng.set.insert(
                name,
                Template(Arc::new(Mutex::new(Inner {
                    escape_err: EscapeState::NotEscaped,
                    text: x,
                    tree,
                    ns: new_ns.clone(),
                }))),
            );
        }
        Ok(ng.set.get(&ret_name).cloned().expect("cloned template"))
    }

    /// Allocates a new HTML template associated with the given one and with
    /// the same delimiters (Go `Template.New`).
    pub fn associated(&self, name: &str) -> Template {
        let ns = self.ns();
        let mut g = ns.m.lock().expect("ns lock");
        self.new_locked(&mut g, name)
    }

    fn new_locked(&self, g: &mut NsInner, name: &str) -> Template {
        let ns = self.ns();
        let tmpl = Template(Arc::new(Mutex::new(Inner {
            escape_err: EscapeState::NotEscaped,
            text: self.text().associated(name),
            tree: None,
            ns,
        })));
        // If a template by this name exists, the dependency graph for
        // escaping the templates is in doubt: replace the existing template
        // with an empty one in a namespace of its own.
        if let Some(existing) = g.set.get(name).cloned() {
            let empty = Template::new(&existing.name());
            let inner = empty.inner();
            *existing.0.lock().expect("template lock") = inner;
        }
        g.set.insert(name.to_owned(), tmpl.clone());
        tmpl
    }

    /// Adds the elements of the argument map to the template's function map
    /// (Go `Template.Funcs`).
    pub fn funcs(&self, func_map: &FuncMap) -> Template {
        self.text().funcs(func_map);
        self.clone()
    }

    /// Sets the action delimiters (Go `Template.Delims`).
    pub fn delims(&self, left: &str, right: &str) -> Template {
        self.text().delims(left, right);
        self.clone()
    }

    /// Returns the template with the given name that is associated with t, or
    /// `None` (Go `Template.Lookup`).
    pub fn lookup(&self, name: &str) -> Option<Template> {
        let ns = self.ns();
        let g = ns.m.lock().expect("ns lock");
        g.set.get(name).cloned()
    }

    /// Parses the named files and associates the resulting templates with t
    /// (Go `Template.ParseFiles`).
    pub fn parse_files(&self, filenames: &[&str]) -> Res<Template> {
        parse_files_into(Some(self.clone()), &helper::OsFiles, filenames)
    }

    /// Parses the template definitions in the files identified by the
    /// pattern (Go `Template.ParseGlob`).
    pub fn parse_glob(&self, pattern: &str) -> Res<Template> {
        parse_glob_into(Some(self.clone()), pattern)
    }

    /// Parses the named files from the file system (Go `Template.ParseFS`).
    pub fn parse_fs(&self, fsys: &dyn FS, patterns: &[&str]) -> Res<Template> {
        parse_fs_into(Some(self.clone()), fsys, patterns)
    }
}

/// Escapes the named template in the namespace (Go `escapeTemplate`).
fn escape_template(
    g: &mut NsInner,
    text: &text::Template,
    root: Option<Node>,
    name: &str,
) -> Res<()> {
    let set_names: BTreeSet<String> = g.set.keys().cloned().collect();
    let anchor = g
        .set
        .values()
        .next()
        .map(Template::text)
        .unwrap_or_else(|| text.clone());
    let cx = Cx {
        anchor: &anchor,
        set_names: &set_names,
    };
    let node = root.unwrap_or_else(|| Node::List(Default::default()));
    let c: Context = g.esc.escape_top(&cx, node, name);
    let mut err: Option<Error> = None;
    if let Some(e) = &c.err {
        let mut e = e.lock().expect("error lock");
        e.name = name.to_owned();
        err = Some(e.clone());
    } else if c.state != State::Text {
        err = Some(Error {
            error_code: ErrorCode::EndContext,
            node: None,
            name: name.to_owned(),
            line: 0,
            description: format!("ends in a non-text context: {c}"),
        });
    }
    if let Some(err) = err {
        // Prevent execution of unsafe templates.
        if let Some(t) = g.set.get(name) {
            let mut inner = t.0.lock().expect("template lock");
            inner.escape_err = EscapeState::Err(err.clone());
            inner.text.set_tree(None);
            inner.tree = None;
        }
        return Err(TemplateError::Escape(err));
    }
    let touched = g.esc.commit(&cx);
    for n in &touched {
        if let Some(t) = g.set.get(n) {
            let mut inner = t.0.lock().expect("template lock");
            inner.tree = inner.text.tree();
        }
    }
    if let Some(t) = g.set.get(name) {
        let mut inner = t.0.lock().expect("template lock");
        inner.escape_err = EscapeState::Ok;
        inner.tree = inner.text.tree();
    }
    Ok(())
}

/// Creates a new template and parses the template definitions from the named
/// files (Go `template.ParseFiles`).
pub fn parse_files(filenames: &[&str]) -> Res<Template> {
    parse_files_into(None, &helper::OsFiles, filenames)
}

fn parse_files_into(
    t: Option<Template>,
    src: &dyn helper::FileSource,
    filenames: &[&str],
) -> Res<Template> {
    if let Some(t) = &t {
        t.check_can_parse()?;
    }
    if filenames.is_empty() {
        // Not really a problem, but be consistent.
        return Err(TemplateError::Msg(
            "html/template: no files named in call to ParseFiles".to_owned(),
        ));
    }
    let mut t = t;
    for filename in filenames {
        let (name, b) = src
            .read(filename)
            .map_err(|e| TemplateError::Msg(e.to_string()))?;
        let s = String::from_utf8_lossy(&b).into_owned();
        // First template becomes return value if not already defined, and we
        // use that one for subsequent New calls to associated all the
        // templates together. Also, if this file has the same name as t, this
        // file becomes the contents of t, so t, with name t.Name(), works.
        let tmpl = match &t {
            None => {
                let nt = Template::new(&name);
                t = Some(nt.clone());
                nt
            }
            Some(existing) => {
                if name == existing.name() {
                    existing.clone()
                } else {
                    existing.associated(&name)
                }
            }
        };
        tmpl.parse(&s)?;
    }
    Ok(t.expect("at least one file"))
}

/// Creates a new template and parses the template definitions from the files
/// identified by the pattern (Go `template.ParseGlob`).
pub fn parse_glob(pattern: &str) -> Res<Template> {
    parse_glob_into(None, pattern)
}

fn parse_glob_into(t: Option<Template>, pattern: &str) -> Res<Template> {
    if let Some(t) = &t {
        t.check_can_parse()?;
    }
    let filenames = helper::os_glob(pattern).map_err(|e| TemplateError::Msg(e.to_string()))?;
    if filenames.is_empty() {
        return Err(TemplateError::Msg(format!(
            "html/template: pattern matches no files: {}",
            helper::sharp_q(pattern)
        )));
    }
    let names: Vec<&str> = filenames.iter().map(String::as_str).collect();
    parse_files_into(t, &helper::OsFiles, &names)
}

/// Creates a new template and parses the template definitions from the files
/// in the file system identified by the patterns (Go `template.ParseFS`).
pub fn parse_fs(fsys: &dyn FS, patterns: &[&str]) -> Res<Template> {
    parse_fs_into(None, fsys, patterns)
}

fn parse_fs_into(t: Option<Template>, fsys: &dyn FS, patterns: &[&str]) -> Res<Template> {
    let mut filenames: Vec<String> = Vec::new();
    for pattern in patterns {
        let list = helper::fs_glob(fsys, pattern).map_err(|e| TemplateError::Msg(e.to_string()))?;
        if list.is_empty() {
            return Err(TemplateError::Msg(format!(
                "template: pattern matches no files: {}",
                helper::sharp_q(pattern)
            )));
        }
        filenames.extend(list);
    }
    let names: Vec<&str> = filenames.iter().map(String::as_str).collect();
    parse_files_into(t, &helper::fs_files(fsys), &names)
}
