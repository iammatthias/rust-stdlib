//! Data-driven templates for generating textual output (Go `text/template`).
//!
//! Templates are executed by applying them to a data structure. Annotations
//! in the template refer to elements of the data structure (typically a field
//! of a struct or a key in a map) to control execution and derive values to
//! be displayed. The syntax, the predefined functions and the execution
//! rules are Go's; see Go's `text/template` documentation for the language.
//!
//! # Rust shape
//!
//! Go executes templates over `reflect` values. Here the data is a [`Value`]
//! (see [`value`]): typed, immutable and built from Rust data with
//! [`ToValue`] or directly with the [`Value`] constructors. Structs are
//! described by a [`Type`](value::Type) whose fields are values; methods are
//! registered callables on named types; functions are callables
//! ([`Value::func_of`], or [`func1`] and friends for typed Rust closures). Maps keep their
//! entries in Go's `fmtsort` order, so `range` and printing are deterministic.
//!
//! ```
//! use rust_stdlib::text::template::{Template, Value};
//!
//! let t = Template::new("hello").parse("Hello, {{.name}}! {{len .items}} item(s)").unwrap();
//! let data = rust_stdlib::text::template::map_of_any([
//!     ("name", Value::string("world")),
//!     ("items", Value::slice(&rust_stdlib::text::template::value::Type::any(), vec![Value::int(1)])),
//! ]);
//! let mut out = Vec::new();
//! t.execute(&mut out, &data).unwrap();
//! assert_eq!(String::from_utf8(out).unwrap(), "Hello, world! 1 item(s)");
//! ```
//!
//! # Deviations from Go
//!
//! - `Funcs` and `Option` panic on invalid names, signatures and options, as
//!   Go's do, because they are programmer errors.
//! - Strings are UTF-8 (`String`); Go strings may hold arbitrary bytes.
//! - Callables receive the arguments of a variadic parameter flattened, not
//!   packed into a slice.
//! - Execution and parsing recurse on the native stack. Deep nesting continues
//!   on a large-stack worker thread and the template call depth limit stays
//!   Go's (100000); only a recursion that would outgrow that worker stack
//!   stops with an "exceeded the available stack space" error.

mod exec;
mod func;
mod funcs;
pub(crate) mod helper;
mod option;
pub mod parse;
pub mod value;
pub mod verbs;

pub use exec::ExecError;
pub use func::{func0, func1, func2, func3, func4, variadic, Fallible, FromValue, IntoResult};
pub use funcs::{
    html_escape, html_escape_string, html_escaper, is_true, js_escape, js_escape_string,
    js_escaper, url_query_escaper, FuncMap,
};
pub use helper::{must, parse_files, parse_fs, parse_glob};
pub use value::{ToValue, Value};

pub(crate) use exec::Located;
pub(crate) use option::MissingKey;

use crate::io::fs::FS;
use parse::{Mode, Tree};
use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Write};
use std::sync::{Arc, RwLock};

/// An error from this package: a parse error, an execution error, an I/O
/// error from a writer or the file system, or a plain message.
#[derive(Debug)]
pub enum Error {
    /// A template failed to parse.
    Parse(parse::Error),
    /// A template failed to execute (Go `ExecError`).
    Exec(ExecError),
    /// Writing the output or reading a file failed.
    Io(io::Error),
    /// Any other error, such as a missing template.
    Msg(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Parse(e) => e.fmt(f),
            Error::Exec(e) => e.fmt(f),
            Error::Io(e) => e.fmt(f),
            Error::Msg(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Parse(e) => Some(e),
            Error::Exec(e) => Some(e),
            Error::Io(e) => Some(e),
            Error::Msg(_) => None,
        }
    }
}

impl From<parse::Error> for Error {
    fn from(e: parse::Error) -> Error {
        Error::Parse(e)
    }
}

/// A `map[string]interface{}` built from key/value pairs.
pub fn map_of_any<'a>(entries: impl IntoIterator<Item = (&'a str, Value)>) -> Value {
    let ty = value::Type::map_of(value::Type::string(), value::Type::any());
    Value::map(
        &ty,
        entries
            .into_iter()
            .map(|(k, v)| (Value::string(k), Value::any(v)))
            .collect(),
    )
}

pub(crate) struct TemplateData {
    name: String,
    tree: RwLock<Option<Arc<Tree>>>,
    delims: RwLock<(String, String)>,
}

pub(crate) struct Common {
    tmpl: RwLock<BTreeMap<String, Arc<TemplateData>>>,
    option: RwLock<MissingKey>,
    funcs: RwLock<FuncMap>,
}

impl Common {
    fn new() -> Common {
        Common {
            tmpl: RwLock::new(BTreeMap::new()),
            option: RwLock::new(MissingKey::Invalid),
            funcs: RwLock::new(FuncMap::new()),
        }
    }
}

/// The representation of a parsed template (Go `template.Template`). A
/// `Template` is a handle: cloning it with [`Clone`] gives another handle to
/// the same template, as copying a Go `*Template` does. [`Template::clone_template`]
/// is Go's deep `Clone`.
#[derive(Clone)]
pub struct Template {
    data: Arc<TemplateData>,
    common: Arc<Common>,
}

impl PartialEq for Template {
    /// Two handles are equal when they are the same template, as Go's
    /// `*Template` comparison.
    fn eq(&self, other: &Template) -> bool {
        Arc::ptr_eq(&self.data, &other.data)
    }
}

impl Eq for Template {}

impl fmt::Debug for Template {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Template({:?})", self.data.name)
    }
}

/// Allocates a new, undefined template with the given name (Go
/// `template.New`).
pub fn new(name: &str) -> Template {
    Template::new(name)
}

impl Template {
    /// Allocates a new, undefined template with the given name (Go
    /// `template.New`).
    pub fn new(name: &str) -> Template {
        Template {
            data: Arc::new(TemplateData {
                name: name.to_owned(),
                tree: RwLock::new(None),
                delims: RwLock::new((String::new(), String::new())),
            }),
            common: Arc::new(Common::new()),
        }
    }

    /// The name of the template (Go `Template.Name`).
    pub fn name(&self) -> &str {
        &self.data.name
    }

    /// The parse tree of the template, if it has been parsed (Go
    /// `Template.Tree`).
    pub fn tree(&self) -> Option<Arc<Tree>> {
        self.data.tree.read().expect("tree lock").clone()
    }

    /// Replaces the parse tree of the template.
    pub fn set_tree(&self, tree: Option<Tree>) {
        *self.data.tree.write().expect("tree lock") = tree.map(Arc::new);
    }

    /// Allocates a new, undefined template associated with the given one and
    /// with the same delimiters. The association, which is transitive, allows
    /// one template to invoke another with a `{{template}}` action (Go
    /// `Template.New`).
    pub fn associated(&self, name: &str) -> Template {
        let delims = self.data.delims.read().expect("delims lock").clone();
        Template {
            data: Arc::new(TemplateData {
                name: name.to_owned(),
                tree: RwLock::new(None),
                delims: RwLock::new(delims),
            }),
            common: self.common.clone(),
        }
    }

    fn copy(&self, common: Arc<Common>) -> Template {
        Template {
            data: Arc::new(TemplateData {
                name: self.data.name.clone(),
                tree: RwLock::new(self.tree()),
                delims: RwLock::new(self.data.delims.read().expect("delims lock").clone()),
            }),
            common,
        }
    }

    /// Creates a duplicate of a template, so that further calls to `parse`
    /// on the copy do not affect the original (Go `Template.Clone`).
    pub fn clone_template(&self) -> Result<Template, Error> {
        let nc = Arc::new(Common::new());
        let nt = self.copy(nc.clone());
        *nc.option.write().expect("option lock") = *self.common.option.read().expect("option lock");
        {
            let tmpl = self.common.tmpl.read().expect("tmpl lock");
            let mut ntmpl = nc.tmpl.write().expect("tmpl lock");
            for (k, v) in tmpl.iter() {
                if *k == self.data.name {
                    ntmpl.insert(self.data.name.clone(), nt.data.clone());
                    continue;
                }
                let other = Template {
                    data: v.clone(),
                    common: self.common.clone(),
                };
                ntmpl.insert(k.clone(), other.copy(nc.clone()).data);
            }
        }
        {
            let f = self.common.funcs.read().expect("funcs lock");
            let mut nf = nc.funcs.write().expect("funcs lock");
            for (k, v) in f.iter() {
                nf.insert(k.clone(), v.clone());
            }
        }
        Ok(nt)
    }

    /// Adds a parse tree for the template with the given name, associating it
    /// with this template. If the template does not already exist, it will
    /// create a new one. If the template does exist, it will be replaced
    /// (Go `Template.AddParseTree`).
    pub fn add_parse_tree(&self, name: &str, tree: Tree) -> Result<Template, Error> {
        let nt = if name != self.data.name {
            self.associated(name)
        } else {
            self.clone()
        };
        // Even if nt == t, we need to install it in the common.tmpl map.
        if self.associate(&nt, &tree) || nt.tree().is_none() {
            nt.set_tree(Some(tree));
        }
        Ok(nt)
    }

    /// Installs the new template into the group of templates associated with
    /// t. It reports whether the tree should replace the template's.
    fn associate(&self, new: &Template, tree: &Tree) -> bool {
        let mut tmpl = self.common.tmpl.write().expect("tmpl lock");
        if let Some(old) = tmpl.get(&new.data.name) {
            let old_has_tree = old.tree.read().expect("tree lock").is_some();
            let empty = tree
                .root
                .as_ref()
                .is_none_or(|r| parse::is_empty_tree(Some(&parse::Node::List(r.clone()))));
            if empty && old_has_tree {
                // If a template by that name exists, don't replace it with an
                // empty template.
                return false;
            }
        }
        tmpl.insert(new.data.name.clone(), new.data.clone());
        true
    }

    /// Returns a slice of defined templates associated with t (Go
    /// `Template.Templates`).
    pub fn templates(&self) -> Vec<Template> {
        self.common
            .tmpl
            .read()
            .expect("tmpl lock")
            .values()
            .map(|d| Template {
                data: d.clone(),
                common: self.common.clone(),
            })
            .collect()
    }

    /// Sets the action delimiters to the specified strings, to be used in
    /// subsequent calls to `parse`. An empty delimiter stands for the
    /// corresponding default: `{{` or `}}` (Go `Template.Delims`).
    pub fn delims(&self, left: &str, right: &str) -> Template {
        *self.data.delims.write().expect("delims lock") = (left.to_owned(), right.to_owned());
        self.clone()
    }

    /// Adds the elements of the argument map to the template's function map.
    /// It must be called before the template is parsed. It panics if a value
    /// in the map is not a function with appropriate return type or if the
    /// name cannot be used syntactically as a function in a template. It is
    /// legal to overwrite elements of the map (Go `Template.Funcs`).
    pub fn funcs(&self, func_map: &FuncMap) -> Template {
        let mut f = self.common.funcs.write().expect("funcs lock");
        funcs::add_value_funcs(&mut f, func_map);
        drop(f);
        self.clone()
    }

    /// Returns the template with the given name that is associated with t (Go
    /// `Template.Lookup`).
    pub fn lookup(&self, name: &str) -> Option<Template> {
        self.common
            .tmpl
            .read()
            .expect("tmpl lock")
            .get(name)
            .map(|d| Template {
                data: d.clone(),
                common: self.common.clone(),
            })
    }

    pub(crate) fn func(&self, name: &str) -> Option<Value> {
        self.common
            .funcs
            .read()
            .expect("funcs lock")
            .get(name)
            .cloned()
    }

    pub(crate) fn missing_key(&self) -> MissingKey {
        *self.common.option.read().expect("option lock")
    }

    pub(crate) fn set_missing_key(&self, m: MissingKey) {
        *self.common.option.write().expect("option lock") = m;
    }

    /// Parses text as a template body for t. Named template definitions in
    /// text (`{{define ...}}` or `{{block ...}}` statements) define
    /// additional templates associated with t and are removed from the
    /// definition of t itself (Go `Template.Parse`).
    pub fn parse(&self, text: &str) -> Result<Template, Error> {
        let (left, right) = self.data.delims.read().expect("delims lock").clone();
        let trees = {
            let f = self.common.funcs.read().expect("funcs lock");
            parse::parse(
                &self.data.name,
                text,
                &left,
                &right,
                &[&*f, funcs::builtins()],
            )?
        };
        // Add the newly parsed trees, including the one for t, into our
        // common structure.
        for (name, tree) in trees {
            self.add_parse_tree(&name, tree)?;
        }
        Ok(self.clone())
    }

    /// Reports the location and the string form of the node, as an
    /// execution error does.
    pub(crate) fn error_context(&self, n: &dyn Located) -> (String, String) {
        match self.tree() {
            Some(t) => t.error_context_at(n.pos(), n.tree_info(), n.describe()),
            None => {
                Tree::new(&self.data.name).error_context_at(n.pos(), n.tree_info(), n.describe())
            }
        }
    }

    /// Applies the template to the data and writes the output to `wr`. If an
    /// error occurs executing the template or writing its output, execution
    /// stops, but partial results may already have been written to the output
    /// writer (Go `Template.Execute`).
    pub fn execute<W: Write + ?Sized, D: ToValue + ?Sized>(
        &self,
        wr: &mut W,
        data: &D,
    ) -> Result<(), Error> {
        let mut w = WriteAdapter(wr);
        self.execute_value(&mut w, data.to_value())
    }

    /// Like [`Template::execute`] for data that is already a [`Value`].
    pub fn execute_value(&self, wr: &mut dyn Write, value: Value) -> Result<(), Error> {
        let mut state = exec::State::new(self.clone(), wr, value.clone());
        let Some(tree) = self.tree() else {
            return state.incomplete(self.name()).map_err(Self::unwind);
        };
        let Some(root) = tree.root.as_ref() else {
            return state.incomplete(self.name()).map_err(Self::unwind);
        };
        state.walk_list(&value, root).map_err(Self::unwind)
    }

    fn unwind(u: exec::Unwind) -> Error {
        match u {
            exec::Unwind::Exec(e) => Error::Exec(e),
            exec::Unwind::Write(e) => Error::Io(e),
            exec::Unwind::Break | exec::Unwind::Continue => {
                Error::Msg("break or continue outside range".to_owned())
            }
        }
    }

    /// Applies the template associated with t that has the given name to the
    /// data and writes the output to `wr` (Go `Template.ExecuteTemplate`).
    pub fn execute_template<W: Write + ?Sized, D: ToValue + ?Sized>(
        &self,
        wr: &mut W,
        name: &str,
        data: &D,
    ) -> Result<(), Error> {
        let Some(tmpl) = self.lookup(name) else {
            return Err(Error::Msg(format!(
                "template: no template {} associated with template {}",
                crate::strconv::quote(name),
                crate::strconv::quote(self.name()),
            )));
        };
        tmpl.execute(wr, data)
    }

    /// Returns a string listing the defined templates, prefixed by the string
    /// "; defined templates are: ". If there are none, it returns the empty
    /// string. Used to generate an error message (Go
    /// `Template.DefinedTemplates`).
    pub fn defined_templates(&self) -> String {
        let mut b = String::new();
        let tmpl = self.common.tmpl.read().expect("tmpl lock");
        for (name, t) in tmpl.iter() {
            let ok = t
                .tree
                .read()
                .expect("tree lock")
                .as_ref()
                .is_some_and(|tr| tr.root.is_some());
            if !ok {
                continue;
            }
            if b.is_empty() {
                b.push_str("; defined templates are: ");
            } else {
                b.push_str(", ");
            }
            b.push_str(&crate::strconv::quote(name));
        }
        b
    }

    /// Sets options for the template. Options are described by strings,
    /// either a simple string or "key=value". There can be at most one equals
    /// sign in an option string. If the option string is unrecognized or
    /// otherwise invalid, `option` panics (Go `Template.Option`).
    pub fn option(&self, opts: &[&str]) -> Template {
        for s in opts {
            option::set_option(self, s);
        }
        self.clone()
    }

    /// Parses the named files and associates the resulting templates with t
    /// (Go `Template.ParseFiles`).
    pub fn parse_files(&self, filenames: &[&str]) -> Result<Template, Error> {
        helper::parse_files_into(Some(self.clone()), &helper::OsFiles, filenames)
    }

    /// Parses the template definitions in the files identified by the pattern
    /// and associates the resulting templates with t (Go
    /// `Template.ParseGlob`).
    pub fn parse_glob(&self, pattern: &str) -> Result<Template, Error> {
        helper::parse_glob_into(Some(self.clone()), pattern)
    }

    /// Parses the named files in the file system and associates the resulting
    /// templates with t (Go `Template.ParseFS`).
    pub fn parse_fs(&self, fsys: &dyn FS, patterns: &[&str]) -> Result<Template, Error> {
        helper::parse_fs_into(Some(self.clone()), fsys, patterns)
    }

    /// Mode used when this template was last parsed (always the default).
    #[doc(hidden)]
    pub fn parse_mode(&self) -> Mode {
        Mode(0)
    }
}

struct WriteAdapter<'a, W: Write + ?Sized>(&'a mut W);

impl<W: Write + ?Sized> Write for WriteAdapter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl ToValue for () {
    fn go_type() -> value::Type {
        value::Type::any()
    }
    fn to_value(&self) -> Value {
        Value::nil()
    }
}
