//! Contextual autoescaping of templates (Go `html/template` `escape.go`).
//!
//! Go's escaper edits the parse tree in place through node pointers. Nodes
//! here are owned values, so edits are recorded against a node's *path*
//! (the template name plus the indexes leading to the node from the root
//! list) and applied to a copy of the tree when the escaper commits.

use super::context::{
    is_comment, is_in_script_literal, Attr, Context, Delim, Element, JsCtx, State, UrlPart,
};
use super::error::{errorf, Error, ErrorCode};
use super::escapers::{delim_ends, FUNC_NAMES};
use super::js::is_js_type;
use super::transition::{quote_bytes, t_special_tag_end, transition};
use super::util::{index_any, index_any_runes};
use crate::strconv;
use crate::text::template::parse::{
    ActionNode, BranchNode, CommandNode, IdentifierNode, IfNode, ListNode, Node, NodeType,
    PipeNode, Pos, RangeNode, TemplateNode, TextNode, Tree, WithNode,
};
use crate::text::template::Template as TextTemplate;
use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

/// Decides whether a conditional escape's results are kept.
type Filter<'a> = &'a dyn Fn(&Escaper, &Context) -> bool;

/// The path of a node: the indexes from the root list of its tree.
pub(crate) type Path = Vec<u32>;
/// An edit target: a tree name and a node path.
pub(crate) type Key = (String, Path);

/// Tracks the contexts of the `break` and `continue` actions of a range loop.
#[derive(Default)]
pub(crate) struct RangeContext {
    outer: Option<Arc<Mutex<RangeContext>>>,
    breaks: Vec<Context>,
    continues: Vec<Context>,
}

type RangeCtx = Arc<Mutex<RangeContext>>;

/// What the escaper needs to know about the template namespace.
pub(crate) struct Cx<'a> {
    /// Any text template of the namespace; they share their functions and
    /// associations.
    pub anchor: &'a TextTemplate,
    /// The names of the html templates in the namespace.
    pub set_names: &'a BTreeSet<String>,
}

/// Edits recorded while escaping, applied by [`Escaper::commit`].
#[derive(Default)]
pub(crate) struct Escaper {
    /// Records the output context of each template, by (mangled) name.
    pub output: HashMap<String, Context>,
    /// Derived templates, which are copies of templates escaped in a context
    /// other than the default.
    pub derived: HashMap<String, TextTemplate>,
    /// Templates called.
    pub called: HashMap<String, bool>,
    pub action_node_edits: HashMap<Key, Vec<String>>,
    pub template_node_edits: HashMap<Key, String>,
    pub text_node_edits: HashMap<Key, Vec<u8>>,
    range_context: Option<RangeCtx>,
}

impl Cx<'_> {
    /// Returns the text template with the given name, if any.
    fn lookup(&self, name: &str) -> Option<TextTemplate> {
        self.anchor.lookup(name)
    }
}

/// The node of an `if`, `range` or `with` branch as a [`Node`] (for errors).
fn branch_as_node(b: &BranchNode) -> Node {
    match b.node_type {
        NodeType::If => Node::If(IfNode {
            branch_node: b.clone(),
        }),
        NodeType::Range => Node::Range(RangeNode {
            branch_node: b.clone(),
        }),
        _ => Node::With(WithNode {
            branch_node: b.clone(),
        }),
    }
}

fn child_path(p: &Path, i: u32) -> Path {
    let mut q = p.clone();
    q.push(i);
    q
}

impl Escaper {
    /// Escapes a node in context `c`; the returned context is the context
    /// after the node. `tn` and `path` locate the node for edits.
    fn escape(&mut self, cx: &Cx, c: Context, n: &Node, tn: &str, path: &Path) -> Context {
        match n {
            Node::Action(a) => self.escape_action(c, a, tn, path),
            Node::Break(b) => {
                let mut c = c;
                c.n = Some(Node::Break(b.clone()));
                if let Some(rc) = &self.range_context {
                    rc.lock().expect("range lock").breaks.push(c);
                }
                Context::new(State::Dead)
            }
            Node::Comment(_) => c,
            Node::Continue(b) => {
                let mut c = c;
                c.n = Some(Node::Continue(b.clone()));
                if let Some(rc) = &self.range_context {
                    rc.lock().expect("range lock").continues.push(c);
                }
                Context::new(State::Dead)
            }
            Node::If(b) => self.escape_branch(cx, c, &b.branch_node, "if", tn, path),
            Node::List(l) => self.escape_list(cx, c, Some(l), tn, path),
            Node::Range(b) => self.escape_branch(cx, c, &b.branch_node, "range", tn, path),
            Node::Template(t) => self.escape_template(cx, c, t, tn, path),
            Node::Text(t) => self.escape_text(c, t, tn, path),
            Node::With(b) => self.escape_branch(cx, c, &b.branch_node, "with", tn, path),
            other => panic!("escaping {other} is unimplemented"),
        }
    }

    /// Escapes an action node, recording the escapers to add to its
    /// pipeline.
    fn escape_action(&mut self, c: Context, n: &ActionNode, tn: &str, path: &Path) -> Context {
        if !n.pipe.decl.is_empty() {
            // A local variable assignment, not an interpolation.
            return c;
        }
        let mut c = nudge(c);
        // Check for disallowed use of predefined escapers in the pipeline.
        for (pos, id_node) in n.pipe.cmds.iter().enumerate() {
            let Some(Node::Identifier(node)) = id_node.args.first() else {
                // A predefined escaper "esc" will never be found as an
                // identifier in a command that takes arguments, so we have
                // nothing to check.
                continue;
            };
            let ident = &node.ident;
            if PREDEFINED_ESCAPERS.contains(&ident.as_str()) {
                // Predefined escapers are only allowed as the last command,
                // and "html" is not allowed in unquoted attribute values.
                if pos < n.pipe.cmds.len() - 1
                    || (c.state == State::Attr
                        && c.delim == Delim::SpaceOrTagEnd
                        && ident == "html")
                {
                    return Context::error(errorf(
                        ErrorCode::PredefinedEscaper,
                        Some(Node::Action(n.clone())),
                        n.line,
                        format!(
                            "predefined escaper {} disallowed in template",
                            strconv::quote(ident)
                        ),
                    ));
                }
            }
        }
        let mut s: Vec<&'static str> = Vec::with_capacity(3);
        match c.state {
            State::Error => return c,
            State::Url
            | State::CssDqStr
            | State::CssSqStr
            | State::CssDqUrl
            | State::CssSqUrl
            | State::CssUrl => match c.url_part {
                UrlPart::None => {
                    s.push("_html_template_urlfilter");
                    match c.state {
                        State::CssDqStr | State::CssSqStr => s.push("_html_template_cssescaper"),
                        _ => s.push("_html_template_urlnormalizer"),
                    }
                }
                UrlPart::PreQuery => match c.state {
                    State::CssDqStr | State::CssSqStr => s.push("_html_template_cssescaper"),
                    _ => s.push("_html_template_urlnormalizer"),
                },
                UrlPart::QueryOrFrag => s.push("_html_template_urlescaper"),
                UrlPart::Unknown => {
                    return Context::error(errorf(
                        ErrorCode::AmbigContext,
                        Some(Node::Action(n.clone())),
                        n.line,
                        format!("{n} appears in an ambiguous context within a URL"),
                    ));
                }
            },
            State::MetaContent => {}
            State::MetaContentUrl => {
                // The default (GODEBUG htmlmetacontenturlescape unset or not
                // "0") filters the URL.
                s.push("_html_template_urlfilter");
            }
            State::Js => {
                s.push("_html_template_jsvalescaper");
                // A slash after a value starts a div operator.
                c.js_ctx = JsCtx::DivOp;
            }
            State::JsDqStr | State::JsSqStr => s.push("_html_template_jsstrescaper"),
            State::JsTmplLit => s.push("_html_template_jstmpllitescaper"),
            State::JsRegexp => s.push("_html_template_jsregexpescaper"),
            State::Css => s.push("_html_template_cssvaluefilter"),
            State::Text => s.push("_html_template_htmlescaper"),
            State::Rcdata => s.push("_html_template_rcdataescaper"),
            State::Attr => {
                // Handled below in delim check.
            }
            State::AttrName | State::Tag => {
                c.state = State::AttrName;
                s.push("_html_template_htmlnamefilter");
            }
            State::Srcset => s.push("_html_template_srcsetescaper"),
            other => {
                if is_comment(other) {
                    s.push("_html_template_commentescaper");
                } else {
                    panic!("unexpected state {}", other.name());
                }
            }
        }
        match c.delim {
            Delim::None => {
                // No extra-escaping needed for raw text content.
            }
            Delim::SpaceOrTagEnd => s.push("_html_template_nospaceescaper"),
            _ => s.push("_html_template_attrescaper"),
        }
        let key = (tn.to_owned(), path.clone());
        if self.action_node_edits.contains_key(&key) {
            panic!("node {n} shared between templates");
        }
        self.action_node_edits
            .insert(key, s.iter().map(|x| (*x).to_owned()).collect());
        c
    }

    /// Escapes a branch (`if`, `range` or `with`).
    fn escape_branch(
        &mut self,
        cx: &Cx,
        c: Context,
        n: &BranchNode,
        node_name: &str,
        tn: &str,
        path: &Path,
    ) -> Context {
        let list_path = child_path(path, 0);
        let else_path = child_path(path, 1);
        if node_name == "range" {
            self.range_context = Some(Arc::new(Mutex::new(RangeContext {
                outer: self.range_context.take(),
                ..RangeContext::default()
            })));
        }
        let mut c0 = self.escape_list(cx, c.clone(), Some(&n.list), tn, &list_path);
        if node_name == "range" {
            if c0.state != State::Error {
                c0 = join_range(c0, self.range_context.as_ref().expect("range context"));
            }
            self.range_context = self.pop_range();
            if c0.state == State::Error {
                return c0;
            }

            // The "true" branch of a "range" node can execute multiple times.
            // We check that executing n.List once results in the same context
            // as executing n.List twice.
            self.range_context = Some(Arc::new(Mutex::new(RangeContext {
                outer: self.range_context.take(),
                ..RangeContext::default()
            })));
            let (c1, _) =
                self.escape_list_conditionally(cx, c0.clone(), &n.list, None, tn, &list_path);
            c0 = join(&c0, &c1, Some(branch_as_node(n)), node_name);
            if c0.state == State::Error {
                // Make clear that this is a problem on loop re-entry since
                // developers tend to overlook that branch when debugging
                // templates.
                self.range_context = self.pop_range();
                if let Some(err) = &c0.err {
                    let mut e = err.lock().expect("error lock");
                    e.line = n.line;
                    e.description = format!("on range loop re-entry: {}", e.description);
                }
                return c0;
            }
            c0 = join_range(c0, self.range_context.as_ref().expect("range context"));
            self.range_context = self.pop_range();
            if c0.state == State::Error {
                return c0;
            }
        }
        let c1 = self.escape_list(cx, c, n.else_list.as_ref(), tn, &else_path);
        join(&c0, &c1, Some(branch_as_node(n)), node_name)
    }

    fn pop_range(&mut self) -> Option<RangeCtx> {
        let rc = self.range_context.take()?;
        let outer = rc.lock().expect("range lock").outer.clone();
        outer
    }

    /// Escapes a list of nodes.
    fn escape_list(
        &mut self,
        cx: &Cx,
        c: Context,
        n: Option<&ListNode>,
        tn: &str,
        path: &Path,
    ) -> Context {
        let Some(n) = n else {
            return c;
        };
        let mut c = c;
        for (i, m) in n.nodes.iter().enumerate() {
            c = self.escape(cx, c, m, tn, &child_path(path, i as u32));
            if c.state == State::Dead {
                break;
            }
        }
        c
    }

    /// Escapes a list and, if the filter accepts the result, keeps its
    /// effects. It returns the output context and whether the filter
    /// accepted.
    fn escape_list_conditionally(
        &mut self,
        cx: &Cx,
        c: Context,
        n: &ListNode,
        filter: Option<Filter<'_>>,
        tn: &str,
        path: &Path,
    ) -> (Context, bool) {
        let mut e1 = Escaper {
            range_context: self.range_context.clone(),
            output: self.output.clone(),
            ..Escaper::default()
        };
        // Make type inferences available to f.
        let c = e1.escape_list(cx, c, Some(n), tn, path);
        let ok = filter.is_some_and(|f| f(&e1, &c));
        if ok {
            // Copy inferences and edits from e1 back into e.
            self.output.extend(e1.output);
            self.derived.extend(e1.derived);
            self.called.extend(e1.called);
            for (k, v) in e1.action_node_edits {
                self.edit_action(k, v);
            }
            for (k, v) in e1.template_node_edits {
                self.edit_template(k, v);
            }
            for (k, v) in e1.text_node_edits {
                self.edit_text(k, v);
            }
        }
        (c, ok)
    }

    /// Escapes a template node.
    fn escape_template(
        &mut self,
        cx: &Cx,
        c: Context,
        n: &TemplateNode,
        tn: &str,
        path: &Path,
    ) -> Context {
        let (c, name) = self.escape_tree(cx, c, Node::Template(n.clone()), &n.name, n.line);
        if name != n.name {
            self.edit_template((tn.to_owned(), path.clone()), name);
        }
        c
    }

    /// Escapes the named template in the given context. It returns the output
    /// context and the name under which the (possibly derived) template is
    /// known.
    pub(crate) fn escape_tree(
        &mut self,
        cx: &Cx,
        c: Context,
        node: Node,
        name: &str,
        line: usize,
    ) -> (Context, String) {
        // Mangle the template name with the input context to produce a
        // reliable identifier.
        let dname = c.mangle(name);
        self.called.insert(dname.clone(), true);
        if let Some(out) = self.output.get(&dname) {
            // Already escaped.
            return (out.clone(), dname);
        }
        let Some(mut t) = self.template(cx, name) else {
            // Two cases: The template exists but is empty, or has never been
            // mentioned at all. Distinguish the cases in the error messages.
            if cx.set_names.contains(name) {
                return (
                    Context::error(errorf(
                        ErrorCode::NoSuchTemplate,
                        Some(node),
                        line,
                        format!(
                            "{} is an incomplete or empty template",
                            strconv::quote(name)
                        ),
                    )),
                    dname,
                );
            }
            return (
                Context::error(errorf(
                    ErrorCode::NoSuchTemplate,
                    Some(node),
                    line,
                    format!("no such template {}", strconv::quote(name)),
                )),
                dname,
            );
        };
        if dname != name {
            // Use any template derived during an earlier call to escapeTemplate
            // with different top level templates, or clone if necessary.
            let dt = match self.template(cx, &dname) {
                Some(dt) => dt,
                None => {
                    let dt = TextTemplate::new(&dname);
                    let root = t
                        .tree()
                        .and_then(|tr| tr.root.as_ref().map(ListNode::copy_list));
                    let mut tree = Tree::new(&dname);
                    tree.root = root;
                    dt.set_tree(Some(tree));
                    self.derived.insert(dname.clone(), dt.clone());
                    dt
                }
            };
            t = dt;
        }
        let out = self.compute_out_ctx(cx, c, &t);
        (out, dname)
    }

    /// Computes the output context of a template given the input context,
    /// escaping it as needed.
    fn compute_out_ctx(&mut self, cx: &Cx, c: Context, t: &TextTemplate) -> Context {
        // Propagate context over the body.
        let (c1, ok) = self.escape_template_body(cx, c, t);
        let mut c1 = c1;
        let mut ok = ok;
        if !ok {
            // Look for a fixed point by assuming c1 as the output context.
            let (c2, ok2) = self.escape_template_body(cx, c1.clone(), t);
            if ok2 {
                c1 = c2;
                ok = true;
            }
            // Use c1 as the error context if neither assumption worked.
        }
        if !ok && c1.state != State::Error {
            let root = t
                .tree()
                .and_then(|tr| tr.root.as_ref().map(|r| Node::List(r.clone())));
            return Context::error(errorf(
                ErrorCode::OutputContext,
                root,
                0,
                format!("cannot compute output context for template {}", t.name()),
            ));
        }
        c1
    }

    /// Escapes the template body in the given context, returning the output
    /// context and whether the body's output context is the input context.
    fn escape_template_body(&mut self, cx: &Cx, c: Context, t: &TextTemplate) -> (Context, bool) {
        let name = t.name().to_owned();
        let c_in = c.clone();
        let filter = {
            let name = name.clone();
            move |e1: &Escaper, c1: &Context| -> bool {
                if c1.state == State::Error {
                    // Do not update the input escaper, e.
                    return false;
                }
                if !e1.called.get(&name).copied().unwrap_or(false) {
                    // If t is not recursively called, then c1 is an
                    // accurate output context.
                    return true;
                }
                // c1 is accurate if it matches our assumed output context.
                c_in.eq(c1)
            }
        };
        // We need to assume an output context so that recursive template calls
        // take the fast path out of escapeTree instead of infinitely
        // recurring. Naively assuming that the input context is the same as
        // the output works >90% of the time.
        self.output.insert(name.clone(), c.clone());
        let tree = t.tree().expect("template has a tree");
        let root = tree.root.as_ref().expect("template has a root");
        self.escape_list_conditionally(cx, c, root, Some(&filter), &name, &Vec::new())
    }

    /// Escapes a text node.
    fn escape_text(&mut self, c: Context, n: &TextNode, tn: &str, path: &Path) -> Context {
        let s = &n.text;
        let mut written = 0usize;
        let mut i = 0usize;
        let mut b: Vec<u8> = Vec::new();
        let mut c = c;
        while i != s.len() {
            let (c1, nread) = context_after_text(c.clone(), &s[i..]);
            let i1 = i + nread;
            if c.state == State::Text || c.state == State::Rcdata {
                let mut end = i1;
                if c1.state != c.state {
                    for j in (i..end).rev() {
                        if s[j] == b'<' {
                            end = j;
                            break;
                        }
                    }
                }
                for j in i..end {
                    if s[j] == b'<' && !starts_with_doctype(&s[j..]) {
                        b.extend_from_slice(&s[written..j]);
                        b.extend_from_slice(b"&lt;");
                        written = j + 1;
                    }
                }
            } else if is_comment(c.state) && c.delim == Delim::None {
                match c.state {
                    State::JsBlockCmt => {
                        // https://es5.github.io/#x7.4:
                        // "Comments behave like white space and are
                        // discarded except that, if a MultiLineComment
                        // contains a line terminator character, then the
                        // entire comment is considered to be a
                        // LineTerminator for purposes of parsing by the
                        // syntactic grammar."
                        if index_any_runes(&s[written..i1], "\n\r\u{2028}\u{2029}").is_some() {
                            b.push(b'\n');
                        } else {
                            b.push(b' ');
                        }
                    }
                    State::CssBlockCmt => b.push(b' '),
                    _ => {}
                }
                written = i1;
            }
            if c.state != c1.state && is_comment(c1.state) && c1.delim == Delim::None {
                // Preserve the portion between written and the comment start.
                let mut cs = i1 as isize - 2;
                if c1.state == State::HtmlCmt || c1.state == State::JsHtmlOpenCmt {
                    // "<!--" instead of "/*" or "//"
                    cs -= 2;
                } else if c1.state == State::JsHtmlCloseCmt {
                    // "-->" instead of "/*" or "//"
                    cs -= 1;
                }
                b.extend_from_slice(&s[written..cs as usize]);
                written = i1;
            }
            if is_in_script_literal(c.state) && contains_special_script_tag(&s[i..i1]) {
                b.extend_from_slice(&s[written..i]);
                b.extend_from_slice(&escape_special_script_tags(&s[i..i1]));
                written = i1;
            }
            if i == i1 && c.state == c1.state {
                panic!(
                    "infinite loop from {} to {} on {}..{}",
                    c,
                    c1,
                    quote_bytes(&s[..i], None),
                    quote_bytes(&s[i..], None)
                );
            }
            c = c1;
            i = i1;
        }

        if written != 0 && c.state != State::Error {
            if !is_comment(c.state) || c.delim != Delim::None {
                b.extend_from_slice(&n.text[written..]);
            }
            self.edit_text((tn.to_owned(), path.clone()), b);
        }
        c
    }

    fn edit_action(&mut self, k: Key, cmds: Vec<String>) {
        if self.action_node_edits.contains_key(&k) {
            panic!("node shared between templates");
        }
        self.action_node_edits.insert(k, cmds);
    }

    fn edit_template(&mut self, k: Key, callee: String) {
        if self.template_node_edits.contains_key(&k) {
            panic!("node shared between templates");
        }
        self.template_node_edits.insert(k, callee);
    }

    fn edit_text(&mut self, k: Key, text: Vec<u8>) {
        if self.text_node_edits.contains_key(&k) {
            panic!("node shared between templates");
        }
        self.text_node_edits.insert(k, text);
    }

    /// Returns the named text template: associated with the namespace, or
    /// derived by this escaper.
    fn template(&self, cx: &Cx, name: &str) -> Option<TextTemplate> {
        cx.lookup(name).or_else(|| self.derived.get(name).cloned())
    }

    /// Escapes the top-level template `name` in the default context, the
    /// entry point of Go's `escapeTemplate`. Returns the output context.
    pub(crate) fn escape_top(&mut self, cx: &Cx, node: Node, name: &str) -> Context {
        self.escape_tree(cx, Context::default(), node, name, 0).0
    }

    /// Applies the recorded edits to the template trees and clears them.
    pub(crate) fn commit(&mut self, cx: &Cx) -> Vec<String> {
        for name in self.output.keys().cloned().collect::<Vec<_>>() {
            if let Some(t) = self.template(cx, &name) {
                t.funcs(super::escapers::func_map());
            }
        }
        // Any template from the name space associated with this escaper can be
        // used to add derived templates to the underlying text/template name
        // space.
        let mut derived: Vec<(String, TextTemplate)> = self
            .derived
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        derived.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, t) in &derived {
            let tree = t.tree().map(|a| (*a).clone());
            if let Some(tree) = tree {
                if cx.anchor.add_parse_tree(name, tree).is_err() {
                    panic!("error adding derived template");
                }
            }
        }
        // Group the edits by tree.
        let mut touched: Vec<String> = Vec::new();
        let mut by_tree: HashMap<String, Vec<(Path, Edit)>> = HashMap::new();
        for ((name, path), s) in std::mem::take(&mut self.action_node_edits) {
            by_tree
                .entry(name)
                .or_default()
                .push((path, Edit::Action(s)));
        }
        for ((name, path), s) in std::mem::take(&mut self.template_node_edits) {
            by_tree
                .entry(name)
                .or_default()
                .push((path, Edit::Template(s)));
        }
        for ((name, path), s) in std::mem::take(&mut self.text_node_edits) {
            by_tree.entry(name).or_default().push((path, Edit::Text(s)));
        }
        let mut names: Vec<String> = by_tree.keys().cloned().collect();
        names.sort();
        for name in names {
            let edits = by_tree.remove(&name).expect("present");
            let Some(t) = cx
                .lookup(&name)
                .or_else(|| self.derived.get(&name).cloned())
            else {
                continue;
            };
            let Some(tree) = t.tree() else { continue };
            let mut tree: Tree = (*tree).clone();
            if let Some(root) = tree.root.as_mut() {
                for (path, edit) in edits {
                    apply_edit(root, &path, edit);
                }
            }
            t.set_tree(Some(tree));
            touched.push(name);
        }
        // Reset state that is specific to this commit so that the same changes
        // are not re-applied to the template on subsequent calls to commit.
        self.called = HashMap::new();
        touched
    }
}

enum Edit {
    Action(Vec<String>),
    Template(String),
    Text(Vec<u8>),
}

/// Finds the node at `path` below the list `root`.
fn node_at<'a>(root: &'a mut ListNode, path: &[u32]) -> &'a mut Node {
    let node = &mut root.nodes[path[0] as usize];
    if path.len() == 1 {
        return node;
    }
    let branch: &mut BranchNode = match node {
        Node::If(b) => &mut b.branch_node,
        Node::Range(b) => &mut b.branch_node,
        Node::With(b) => &mut b.branch_node,
        _ => unreachable!("only branch nodes have child lists"),
    };
    let list: &mut ListNode = if path[1] == 0 {
        &mut branch.list
    } else {
        branch.else_list.as_mut().expect("else list")
    };
    node_at(list, &path[2..])
}

fn apply_edit(root: &mut ListNode, path: &[u32], edit: Edit) {
    match edit {
        Edit::Action(s) => {
            if let Node::Action(a) = node_at(root, path) {
                ensure_pipeline_contains(&mut a.pipe, s);
            }
        }
        Edit::Template(name) => {
            if let Node::Template(t) = node_at(root, path) {
                t.name = name;
            }
        }
        Edit::Text(text) => {
            if let Node::Text(t) = node_at(root, path) {
                t.text = text;
            }
        }
    }
}

const PREDEFINED_ESCAPERS: &[&str] = &["html", "urlquery"];

/// Maps escapers to the predefined escaper they are equivalent to.
fn equiv_escaper(e: &str) -> Option<&'static str> {
    match e {
        "_html_template_attrescaper" => Some("html"),
        "_html_template_htmlescaper" => Some("html"),
        "_html_template_rcdataescaper" => Some("html"),
        "_html_template_urlescaper" => Some("urlquery"),
        "_html_template_urlnormalizer" => Some("urlquery"),
        _ => None,
    }
}

/// Reports whether the two escaper names are equivalent.
fn esc_fns_eq(a: &str, b: &str) -> bool {
    normalize_esc_fn(a) == normalize_esc_fn(b)
}

/// Returns the normalized form of an escaper name.
fn normalize_esc_fn(e: &str) -> &str {
    equiv_escaper(e).unwrap_or(e)
}

/// Whether `next` is redundant after `last`.
fn redundant_func(last: &str, next: &str) -> bool {
    matches!(
        (last, next),
        (
            "_html_template_commentescaper",
            "_html_template_attrescaper"
        ) | (
            "_html_template_commentescaper",
            "_html_template_htmlescaper"
        ) | ("_html_template_cssescaper", "_html_template_attrescaper")
            | (
                "_html_template_jsregexpescaper",
                "_html_template_attrescaper"
            )
            | ("_html_template_jsstrescaper", "_html_template_attrescaper")
            | (
                "_html_template_jstmpllitescaper",
                "_html_template_attrescaper"
            )
            | ("_html_template_urlescaper", "_html_template_urlnormalizer")
    )
}

/// Appends `cmd` unless it is redundant given the last command.
fn append_cmd(cmds: &mut Vec<CommandNode>, cmd: CommandNode) {
    if let Some(last) = cmds.last() {
        if let (Some(Node::Identifier(l)), Some(Node::Identifier(n))) =
            (last.args.first(), cmd.args.first())
        {
            if redundant_func(&l.ident, &n.ident) {
                return;
            }
        }
    }
    cmds.push(cmd);
}

/// A command that calls the named function with no arguments.
fn new_ident_cmd(identifier: &str, pos: Pos) -> CommandNode {
    CommandNode {
        pos: Pos(0),
        tr: None,
        args: vec![Node::Identifier(
            IdentifierNode::new(identifier).set_pos(pos),
        )],
    }
}

/// Ensures that the pipeline ends with the commands named in `s`.
pub(crate) fn ensure_pipeline_contains(p: &mut PipeNode, mut s: Vec<String>) {
    // Pipeline cannot be empty, but check anyway.
    if s.is_empty() {
        // Do not rewrite pipeline if we have no escapers to insert.
        return;
    }
    // Precondition: p.Cmds contains at most one predefined escaper and the
    // escaper will be present at p.Cmds[len(p.Cmds)-1]. This precondition is
    // always true because of the checks in escapeAction.
    let mut pipeline_len = p.cmds.len();
    if pipeline_len > 0 {
        let last_idx = pipeline_len - 1;
        let esc = match p.cmds[last_idx].args.first() {
            Some(Node::Identifier(id)) if PREDEFINED_ESCAPERS.contains(&id.ident.as_str()) => {
                Some(id.ident.clone())
            }
            _ => None,
        };
        if let Some(esc) = esc {
            // The pipeline ends with a predefined escaper.
            if p.cmds.len() == 1 && p.cmds[last_idx].args.len() > 1 {
                // Special case: pipeline is of the form {{ esc arg1 arg2 ... argN }},
                // where esc is the predefined escaper, and arg1...argN are its arguments.
                // Convert this into the equivalent form
                // {{ _eval_args_ arg1 arg2 ... argN | esc }}, so that esc can be easily
                // merged with the escapers in s.
                let pos = p.cmds[last_idx].args[0].position();
                p.cmds[last_idx].args[0] =
                    Node::Identifier(IdentifierNode::new("_eval_args_").set_pos(pos));
                let pos = p.pos;
                let cmd = new_ident_cmd(&esc, pos);
                append_cmd(&mut p.cmds, cmd);
                pipeline_len += 1;
            }
            // If any of the commands in s that we are about to insert is
            // equivalent to the predefined escaper, use the predefined escaper
            // instead.
            let mut dup = false;
            for escaper in s.iter_mut() {
                if esc_fns_eq(&esc, escaper) {
                    *escaper = esc.clone();
                    dup = true;
                }
            }
            if dup {
                // The predefined escaper will already be inserted along with
                // the escapers in s, so do not copy it to the rewritten
                // pipeline.
                pipeline_len -= 1;
            }
        }
    }
    // Rewrite the pipeline, creating the escapers in s at the end of the
    // pipeline.
    let mut new_cmds: Vec<CommandNode> = p.cmds[..pipeline_len].to_vec();
    let mut inserted_idents: Vec<String> = Vec::new();
    for cmd in &new_cmds {
        if let Some(Node::Identifier(id)) = cmd.args.first() {
            inserted_idents.push(normalize_esc_fn(&id.ident).to_owned());
        }
    }
    for name in &s {
        if !inserted_idents.iter().any(|i| i == normalize_esc_fn(name)) {
            // When two templates share an underlying parse tree via the use of
            // AddParseTree and one template is executed after the other, this check
            // ensures that escapers that were already inserted into the pipeline on
            // the first escaping pass do not get inserted again.
            let pos = p.pos;
            append_cmd(&mut new_cmds, new_ident_cmd(name, pos));
        }
    }
    p.cmds = new_cmds;
}

/// Adjusts a context to the state it will have once an action's output is
/// written: a tag state waits for an attribute name, and so on.
pub(crate) fn nudge(mut c: Context) -> Context {
    match c.state {
        State::Tag => {
            // In `<foo {{.}}`, the action should emit an attribute.
            c.state = State::AttrName;
        }
        State::BeforeValue => {
            // In `<foo bar={{.}}`, the action is an undelimited value.
            c.state = attr_start_state(c.attr);
            c.delim = Delim::SpaceOrTagEnd;
            c.attr = Attr::None;
        }
        State::AfterName => {
            // In `<foo bar {{.}}`, the action is an attribute name.
            c.state = State::AttrName;
            c.attr = Attr::None;
        }
        _ => {}
    }
    c
}

fn attr_start_state(a: Attr) -> State {
    match a {
        Attr::None => State::Attr,
        Attr::Script => State::Js,
        Attr::ScriptType => State::Attr,
        Attr::Style => State::Css,
        Attr::Url => State::Url,
        Attr::Srcset => State::Srcset,
        Attr::MetaContent => State::MetaContent,
    }
}

/// Joins two contexts, such as the contexts at the ends of an `if`'s
/// branches. An error context results when they cannot be reconciled.
pub(crate) fn join(a: &Context, b: &Context, node: Option<Node>, node_name: &str) -> Context {
    if a.state == State::Error {
        return a.clone();
    }
    if b.state == State::Error {
        return b.clone();
    }
    if a.state == State::Dead {
        return b.clone();
    }
    if b.state == State::Dead {
        return a.clone();
    }
    if a.eq(b) {
        return a.clone();
    }

    let mut c = a.clone();
    c.url_part = b.url_part;
    if c.eq(b) {
        // The contexts differ only by urlPart.
        c.url_part = UrlPart::Unknown;
        return c;
    }

    c = a.clone();
    c.js_ctx = b.js_ctx;
    if c.eq(b) {
        // The contexts differ only by jsCtx.
        c.js_ctx = JsCtx::Unknown;
        return c;
    }

    // Allow a nudged context to join with an unnudged one.
    // This means that
    //   <p title={{if .C}}{{.}}{{end}}
    // ends in an unquoted value state even though the else branch
    // ends in stateBeforeValue.
    let (c2, d) = (nudge(a.clone()), nudge(b.clone()));
    if !(c2.eq(a) && d.eq(b)) {
        let e = join(&c2, &d, node.clone(), node_name);
        if e.state != State::Error {
            return e;
        }
    }

    Context::error(errorf(
        ErrorCode::BranchEnd,
        node,
        0,
        format!("{{{{{node_name}}}}} branches end in different contexts: {a}, {b}"),
    ))
}

/// Joins the contexts of a range loop's `break` and `continue` actions into
/// the loop body's output context.
fn join_range(mut c0: Context, rc: &RangeCtx) -> Context {
    let (breaks, continues) = {
        let g = rc.lock().expect("range lock");
        (g.breaks.clone(), g.continues.clone())
    };
    // Merge contexts at break and continue statements into overall body
    // context. In theory we could treat breaks differently from continues, but
    // for now it is enough to treat them the same.
    for c in &breaks {
        // Treat the break as a join in the range.
        c0 = join(&c0, c, c.n.clone(), "range");
        if c0.state == State::Error {
            if let (Some(err), Some(Node::Break(b))) = (&c0.err, &c.n) {
                let mut e = err.lock().expect("error lock");
                e.line = b.line;
                e.description = format!("at range loop break: {}", e.description);
            }
            return c0;
        }
    }
    for c in &continues {
        c0 = join(&c0, c, c.n.clone(), "range");
        if c0.state == State::Error {
            if let (Some(err), Some(Node::Continue(b))) = (&c0.err, &c.n) {
                let mut e = err.lock().expect("error lock");
                e.line = b.line;
                e.description = format!("at range loop continue: {}", e.description);
            }
            return c0;
        }
    }
    c0
}

fn starts_with_doctype(s: &[u8]) -> bool {
    // bytes.HasPrefix(bytes.ToUpper(s[j:]), "<!DOCTYPE")
    let head = &s[..s.len().min(64)];
    crate::text::BytesExt::to_upper(head).starts_with(b"<!DOCTYPE")
}

/// Reports whether `s` has a `<script`, `</script` or `<!--` in any case.
fn contains_special_script_tag(s: &[u8]) -> bool {
    find_special_script_tag(s, 0).is_some()
}

/// Finds the next match of `(?i)<(script|/script|!--)`: (start, end).
fn find_special_script_tag(s: &[u8], from: usize) -> Option<(usize, usize)> {
    let mut i = from;
    while i < s.len() {
        if s[i] == b'<' {
            let rest = &s[i + 1..];
            for pat in [&b"script"[..], b"/script", b"!--"] {
                if rest.len() >= pat.len() && rest[..pat.len()].eq_ignore_ascii_case(pat) {
                    return Some((i, i + 1 + pat.len()));
                }
            }
        }
        i += 1;
    }
    None
}

/// Replaces the special tags with `\x3C` followed by the tag text.
fn escape_special_script_tags(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut last = 0;
    let mut from = 0;
    while let Some((start, end)) = find_special_script_tag(s, from) {
        out.extend_from_slice(&s[last..start]);
        out.extend_from_slice(b"\\x3C");
        out.extend_from_slice(&s[start + 1..end]);
        last = end;
        from = end;
    }
    out.extend_from_slice(&s[last..]);
    out
}

/// Returns the context that follows the longest prefix of `s` that changes
/// it, and the length of that prefix.
fn context_after_text(c: Context, s: &[u8]) -> (Context, usize) {
    if c.delim == Delim::None {
        let (c1, i) = t_special_tag_end(c.clone(), s);
        if i == 0 {
            // A special end tag (`</script>`) has been seen and all content
            // preceding it has been consumed.
            return (c1, 0);
        }
        // Consider all content up to any end tag.
        return transition(c.state, c, &s[..i]);
    }

    // We are at the beginning of an attribute value.

    let i = index_any(s, delim_ends(c.delim)).unwrap_or(s.len());
    if c.delim == Delim::SpaceOrTagEnd {
        // https://www.w3.org/TR/html5/syntax.html#attribute-value-(unquoted)-state
        // lists the runes below as error characters.
        // Error out because HTML spec is quite ambiguous about the behavior of these
        // characters in unquoted attribute values.
        if let Some(j) = index_any(&s[..i], b"\"'<=`") {
            return (
                Context::error(errorf(
                    ErrorCode::BadHtml,
                    None,
                    0,
                    format!(
                        "{} in unquoted attr: {}",
                        quote_bytes(&s[j..j + 1], None),
                        quote_bytes(&s[..i], None)
                    ),
                )),
                s.len(),
            );
        }
    }
    if i == s.len() {
        // Remain inside the attribute.
        // Decode the value so non-HTML rules can easily handle
        //     <button onclick="alert(&quot;Hi!&quot;)">
        // without having to entity decode token boundaries.
        let mut c = c;
        let mut u = crate::html::unescape(&String::from_utf8_lossy(s)).into_bytes();
        while !u.is_empty() {
            let (c1, i1) = transition(c.state, c.clone(), &u);
            c = c1;
            u.drain(..i1);
        }
        return (c, s.len());
    }

    let mut element = c.element;

    // If this is a non-JS "type" attribute inside script tag, do not treat the
    // contents as JS.
    if c.state == State::Attr
        && c.element == Element::Script
        && c.attr == Attr::ScriptType
        && !is_js_type(&String::from_utf8_lossy(&s[..i]))
    {
        element = Element::None;
    }

    let mut i = i;
    if c.delim != Delim::SpaceOrTagEnd {
        // Consume any quote.
        i += 1;
    }
    // On exiting an attribute, we discard all state information
    // except the state and element.
    (
        Context {
            state: State::Tag,
            element,
            ..Context::default()
        },
        i,
    )
}

#[allow(dead_code)]
fn unused() -> (&'static [&'static str], Option<Error>) {
    (FUNC_NAMES, None)
}
