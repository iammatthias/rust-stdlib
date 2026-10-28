//! Parse tree nodes, a port of Go's `text/template/parse/node.go`.

use super::lex::ItemType;
use crate::strconv;
use std::fmt;
use std::sync::Arc;

/// A byte position in the input text (Go `parse.Pos`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pos(pub usize);

impl Pos {
    /// Allows embedding a `Pos` in a node (Go `Pos.Position`).
    pub fn position(self) -> Pos {
        self
    }
}

/// The type of a parse tree node (Go `parse.NodeType`). The values match
/// Go's, including the gaps left by its unexported `else` and `end` types.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(i32)]
pub enum NodeType {
    /// Plain text.
    Text = 0,
    /// A non-control action such as a field evaluation.
    Action = 1,
    /// A boolean constant.
    Bool = 2,
    /// A sequence of field accesses.
    Chain = 3,
    /// An element of a pipeline.
    Command = 4,
    /// The cursor, dot.
    Dot = 5,
    /// A field or method name.
    Field = 8,
    /// An identifier; always a function name.
    Identifier = 9,
    /// An if action.
    If = 10,
    /// A list of nodes.
    List = 11,
    /// An untyped nil constant.
    Nil = 12,
    /// A numerical constant.
    Number = 13,
    /// A pipeline of commands.
    Pipe = 14,
    /// A range action.
    Range = 15,
    /// A string constant.
    String = 16,
    /// A template invocation action.
    Template = 17,
    /// A `$` variable.
    Variable = 18,
    /// A with action.
    With = 19,
    /// A comment.
    Comment = 20,
    /// A break action.
    Break = 21,
    /// A continue action.
    Continue = 22,
}

impl NodeType {
    /// Returns itself, so that a `NodeType` can be embedded (Go
    /// `NodeType.Type`).
    pub fn node_type(self) -> NodeType {
        self
    }
}

/// Information about the tree a node was parsed from, used for error
/// context and for the delimiters in a node's string form.
#[derive(Debug, PartialEq, Eq)]
pub struct TreeInfo {
    pub(crate) parse_name: String,
    pub(crate) text: String,
    pub(crate) left_delim: String,
    pub(crate) right_delim: String,
}

pub(crate) type Tr = Option<Arc<TreeInfo>>;

fn delims(tr: &Tr) -> (&str, &str) {
    match tr {
        Some(t) => (&t.left_delim, &t.right_delim),
        None => ("", ""),
    }
}

/// Nesting at which a recursive tree operation continues on a thread with a
/// large stack. Go's goroutine stacks grow on demand; native stacks do not,
/// and a template may nest control structures and parentheses arbitrarily.
const DEEP_NEST: usize = 48;
const DEEP_STACK_BYTES: usize = 1 << 30;

thread_local! {
    static DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static BIG: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Runs `f`, one level deeper in a recursive tree operation. Past
/// [`DEEP_NEST`] levels it runs on a freshly spawned thread with a large
/// stack, so the operation cannot overflow the caller's stack.
pub(crate) fn deep<T: Send>(f: impl FnOnce() -> T + Send) -> T {
    let depth = DEPTH.with(|c| {
        c.set(c.get() + 1);
        c.get()
    });
    let result = if depth == DEEP_NEST && !BIG.with(std::cell::Cell::get) {
        on_big_stack(|| {
            BIG.with(|b| b.set(true));
            f()
        })
    } else {
        f()
    };
    DEPTH.with(|c| c.set(c.get() - 1));
    result
}

/// Runs `f` on a freshly spawned thread with a large stack (virtual memory,
/// committed only as used) and returns its result. If no such thread can be
/// created, `f` runs on the caller's stack.
pub(crate) fn on_big_stack<T: Send>(f: impl FnOnce() -> T + Send) -> T {
    let mut slot = Some(f);
    let spawned = std::thread::scope(|scope| {
        let h = std::thread::Builder::new()
            .stack_size(DEEP_STACK_BYTES)
            .spawn_scoped(scope, || (slot.take().expect("runs once"))());
        match h {
            Ok(h) => match h.join() {
                Ok(r) => Some(r),
                Err(p) => std::panic::resume_unwind(p),
            },
            Err(_) => None,
        }
    });
    match spawned {
        Some(r) => r,
        // Could not get a bigger stack; carry on with this one.
        None => (slot.take().expect("closure not consumed"))(),
    }
}

/// An element in the parse tree (Go `parse.Node`).
#[derive(Debug)]
pub enum Node {
    Action(ActionNode),
    Bool(BoolNode),
    Break(BreakNode),
    Chain(Box<ChainNode>),
    Command(CommandNode),
    Comment(CommentNode),
    Continue(ContinueNode),
    Dot(DotNode),
    Field(FieldNode),
    Identifier(IdentifierNode),
    If(IfNode),
    List(ListNode),
    Nil(NilNode),
    Number(NumberNode),
    Pipe(PipeNode),
    Range(RangeNode),
    String(StringNode),
    Template(TemplateNode),
    Text(TextNode),
    Variable(VariableNode),
    With(WithNode),
}

impl Clone for Node {
    fn clone(&self) -> Node {
        deep(|| match self {
            Node::Action(n) => Node::Action(n.clone()),
            Node::Bool(n) => Node::Bool(n.clone()),
            Node::Break(n) => Node::Break(n.clone()),
            Node::Chain(n) => Node::Chain(n.clone()),
            Node::Command(n) => Node::Command(n.clone()),
            Node::Comment(n) => Node::Comment(n.clone()),
            Node::Continue(n) => Node::Continue(n.clone()),
            Node::Dot(n) => Node::Dot(n.clone()),
            Node::Field(n) => Node::Field(n.clone()),
            Node::Identifier(n) => Node::Identifier(n.clone()),
            Node::If(n) => Node::If(n.clone()),
            Node::List(n) => Node::List(n.clone()),
            Node::Nil(n) => Node::Nil(n.clone()),
            Node::Number(n) => Node::Number(n.clone()),
            Node::Pipe(n) => Node::Pipe(n.clone()),
            Node::Range(n) => Node::Range(n.clone()),
            Node::String(n) => Node::String(n.clone()),
            Node::Template(n) => Node::Template(n.clone()),
            Node::Text(n) => Node::Text(n.clone()),
            Node::Variable(n) => Node::Variable(n.clone()),
            Node::With(n) => Node::With(n.clone()),
        })
    }
}

impl PartialEq for Node {
    fn eq(&self, other: &Node) -> bool {
        deep(|| match (self, other) {
            (Node::Action(a), Node::Action(b)) => a == b,
            (Node::Bool(a), Node::Bool(b)) => a == b,
            (Node::Break(a), Node::Break(b)) => a == b,
            (Node::Chain(a), Node::Chain(b)) => a == b,
            (Node::Command(a), Node::Command(b)) => a == b,
            (Node::Comment(a), Node::Comment(b)) => a == b,
            (Node::Continue(a), Node::Continue(b)) => a == b,
            (Node::Dot(a), Node::Dot(b)) => a == b,
            (Node::Field(a), Node::Field(b)) => a == b,
            (Node::Identifier(a), Node::Identifier(b)) => a == b,
            (Node::If(a), Node::If(b)) => a == b,
            (Node::List(a), Node::List(b)) => a == b,
            (Node::Nil(a), Node::Nil(b)) => a == b,
            (Node::Number(a), Node::Number(b)) => a == b,
            (Node::Pipe(a), Node::Pipe(b)) => a == b,
            (Node::Range(a), Node::Range(b)) => a == b,
            (Node::String(a), Node::String(b)) => a == b,
            (Node::Template(a), Node::Template(b)) => a == b,
            (Node::Text(a), Node::Text(b)) => a == b,
            (Node::Variable(a), Node::Variable(b)) => a == b,
            (Node::With(a), Node::With(b)) => a == b,
            _ => false,
        })
    }
}

macro_rules! each_node {
    ($self:expr, $n:ident => $e:expr) => {
        match $self {
            Node::Action($n) => $e,
            Node::Bool($n) => $e,
            Node::Break($n) => $e,
            Node::Chain($n) => $e,
            Node::Command($n) => $e,
            Node::Comment($n) => $e,
            Node::Continue($n) => $e,
            Node::Dot($n) => $e,
            Node::Field($n) => $e,
            Node::Identifier($n) => $e,
            Node::If($n) => $e,
            Node::List($n) => $e,
            Node::Nil($n) => $e,
            Node::Number($n) => $e,
            Node::Pipe($n) => $e,
            Node::Range($n) => $e,
            Node::String($n) => $e,
            Node::Template($n) => $e,
            Node::Text($n) => $e,
            Node::Variable($n) => $e,
            Node::With($n) => $e,
        }
    };
}

impl Node {
    /// The type of the node (Go `Node.Type`).
    pub fn node_type(&self) -> NodeType {
        each_node!(self, n => n.node_type())
    }

    /// The byte position of the start of the node in the full original input
    /// string (Go `Node.Position`).
    pub fn position(&self) -> Pos {
        each_node!(self, n => n.pos)
    }

    /// A deep copy of the node (Go `Node.Copy`).
    pub fn copy(&self) -> Node {
        self.clone()
    }

    pub(crate) fn tree(&self) -> &Tr {
        each_node!(self, n => &n.tr)
    }

    pub(crate) fn write_to(&self, sb: &mut String) {
        deep(|| each_node!(self, n => n.write_to(sb)))
    }
}

impl Node {
    /// Moves every child node into `out`, leaving this node childless.
    fn take_children(&mut self, out: &mut Vec<Node>) {
        fn pipe(p: &mut PipeNode, out: &mut Vec<Node>) {
            for c in &mut p.cmds {
                out.append(&mut c.args);
            }
        }
        fn branch(b: &mut BranchNode, out: &mut Vec<Node>) {
            pipe(&mut b.pipe, out);
            out.append(&mut b.list.nodes);
            if let Some(e) = &mut b.else_list {
                out.append(&mut e.nodes);
            }
        }
        match self {
            Node::Action(a) => pipe(&mut a.pipe, out),
            Node::Command(c) => out.append(&mut c.args),
            Node::Pipe(p) => pipe(p, out),
            Node::Chain(c) => {
                let inner = std::mem::replace(&mut c.node, Node::Dot(DotNode::default()));
                out.push(inner);
            }
            Node::If(b) => branch(&mut b.branch_node, out),
            Node::Range(b) => branch(&mut b.branch_node, out),
            Node::With(b) => branch(&mut b.branch_node, out),
            Node::List(l) => out.append(&mut l.nodes),
            Node::Template(t) => {
                if let Some(p) = &mut t.pipe {
                    pipe(p, out);
                }
            }
            _ => {}
        }
    }
}

/// Dropping a deeply nested tree must not recurse once per level: children
/// are unlinked and released iteratively.
impl Drop for Node {
    fn drop(&mut self) {
        let mut work: Vec<Node> = Vec::new();
        self.take_children(&mut work);
        while let Some(mut n) = work.pop() {
            n.take_children(&mut work);
        }
    }
}

impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = String::new();
        self.write_to(&mut s);
        f.write_str(&s)
    }
}

macro_rules! node_from {
    ($t:ident, $v:ident) => {
        impl From<$t> for Node {
            fn from(n: $t) -> Node {
                Node::$v(n.into())
            }
        }
    };
}

macro_rules! node_common2 {
    ($t:ident, $ty:expr) => {
        impl $t {
            /// The node's type (the embedded Go `NodeType`).
            pub fn node_type(&self) -> NodeType {
                $ty
            }
            /// A deep copy of the node (Go `Copy`).
            pub fn copy(&self) -> $t {
                self.clone()
            }
            /// The byte position of the start of the node (Go `Position`).
            pub fn position(&self) -> Pos {
                self.pos
            }
        }
        impl fmt::Display for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let mut s = String::new();
                self.write_to(&mut s);
                f.write_str(&s)
            }
        }
    };
}
/// A list of nodes (Go `parse.ListNode`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ListNode {
    pub pos: Pos,
    pub(crate) tr: Tr,
    /// The element nodes in lexical order.
    pub nodes: Vec<Node>,
}
node_common2!(ListNode, NodeType::List);
node_from!(ListNode, List);

impl ListNode {
    pub(crate) fn new(tr: Tr, pos: Pos) -> ListNode {
        ListNode {
            pos,
            tr,
            nodes: Vec::new(),
        }
    }

    pub(crate) fn append(&mut self, n: Node) {
        self.nodes.push(n);
    }

    pub(crate) fn write_to(&self, sb: &mut String) {
        for n in &self.nodes {
            n.write_to(sb);
        }
    }

    /// A deep copy of the list (Go `CopyList`).
    pub fn copy_list(&self) -> ListNode {
        self.clone()
    }
}

/// Plain text (Go `parse.TextNode`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TextNode {
    pub pos: Pos,
    pub(crate) tr: Tr,
    /// The text; may span newlines.
    pub text: Vec<u8>,
}
node_common2!(TextNode, NodeType::Text);
node_from!(TextNode, Text);

impl TextNode {
    pub(crate) fn new(tr: Tr, pos: Pos, text: &str) -> TextNode {
        TextNode {
            pos,
            tr,
            text: text.as_bytes().to_vec(),
        }
    }
    pub(crate) fn write_to(&self, sb: &mut String) {
        sb.push_str(&String::from_utf8_lossy(&self.text));
    }
}

/// A comment (Go `parse.CommentNode`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CommentNode {
    pub pos: Pos,
    pub(crate) tr: Tr,
    /// Comment text.
    pub text: String,
}
node_common2!(CommentNode, NodeType::Comment);
node_from!(CommentNode, Comment);

impl CommentNode {
    pub(crate) fn write_to(&self, sb: &mut String) {
        let (l, r) = delims(&self.tr);
        sb.push_str(l);
        sb.push_str(&self.text);
        sb.push_str(r);
    }
}

/// A pipeline of commands (Go `parse.PipeNode`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PipeNode {
    pub pos: Pos,
    pub(crate) tr: Tr,
    /// The line number in the input (deprecated in Go, kept for
    /// compatibility).
    pub line: usize,
    /// The variables are being assigned, not declared.
    pub is_assign: bool,
    /// Variables in lexical order.
    pub decl: Vec<VariableNode>,
    /// The commands in lexical order.
    pub cmds: Vec<CommandNode>,
}
node_common2!(PipeNode, NodeType::Pipe);
node_from!(PipeNode, Pipe);

impl PipeNode {
    pub(crate) fn write_to(&self, sb: &mut String) {
        if !self.decl.is_empty() {
            for (i, v) in self.decl.iter().enumerate() {
                if i > 0 {
                    sb.push_str(", ");
                }
                v.write_to(sb);
            }
            sb.push_str(if self.is_assign { " = " } else { " := " });
        }
        for (i, c) in self.cmds.iter().enumerate() {
            if i > 0 {
                sb.push_str(" | ");
            }
            c.write_to(sb);
        }
    }

    /// A deep copy of the pipeline (Go `CopyPipe`).
    pub fn copy_pipe(&self) -> PipeNode {
        self.clone()
    }
}

/// An action: a pipeline in delimiters (Go `parse.ActionNode`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ActionNode {
    pub pos: Pos,
    pub(crate) tr: Tr,
    /// The line number in the input (deprecated in Go, kept for
    /// compatibility).
    pub line: usize,
    /// The pipeline in the action.
    pub pipe: PipeNode,
}
node_common2!(ActionNode, NodeType::Action);
node_from!(ActionNode, Action);

impl ActionNode {
    pub(crate) fn write_to(&self, sb: &mut String) {
        let (l, r) = delims(&self.tr);
        sb.push_str(l);
        self.pipe.write_to(sb);
        sb.push_str(r);
    }
}

/// A command: an element of a pipeline (Go `parse.CommandNode`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CommandNode {
    pub pos: Pos,
    pub(crate) tr: Tr,
    /// Arguments in lexical order: identifier, field, or constant.
    pub args: Vec<Node>,
}
node_common2!(CommandNode, NodeType::Command);
node_from!(CommandNode, Command);

impl CommandNode {
    pub(crate) fn write_to(&self, sb: &mut String) {
        for (i, arg) in self.args.iter().enumerate() {
            if i > 0 {
                sb.push(' ');
            }
            if let Node::Pipe(p) = arg {
                sb.push('(');
                p.write_to(sb);
                sb.push(')');
                continue;
            }
            arg.write_to(sb);
        }
    }
}

/// An identifier, always a function name (Go `parse.IdentifierNode`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct IdentifierNode {
    pub pos: Pos,
    pub(crate) tr: Tr,
    /// The identifier's name.
    pub ident: String,
}
node_common2!(IdentifierNode, NodeType::Identifier);
node_from!(IdentifierNode, Identifier);

impl IdentifierNode {
    /// Holds the special identifier (Go `parse.NewIdentifier`).
    pub fn new(ident: &str) -> IdentifierNode {
        IdentifierNode {
            pos: Pos(0),
            tr: None,
            ident: ident.to_owned(),
        }
    }
    /// Sets the position (Go `SetPos`).
    pub fn set_pos(mut self, pos: Pos) -> IdentifierNode {
        self.pos = pos;
        self
    }
    /// Sets the tree, which is retained only for error context in Go (Go
    /// `SetTree`). The tree's text is shared when the argument has been
    /// parsed.
    pub fn set_tree(mut self, t: Option<&Tree>) -> IdentifierNode {
        self.tr = t.and_then(|t| t.info.clone());
        self
    }
    pub(crate) fn write_to(&self, sb: &mut String) {
        sb.push_str(&self.ident);
    }
}

use super::Tree;

/// A `$` variable (Go `parse.VariableNode`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct VariableNode {
    pub pos: Pos,
    pub(crate) tr: Tr,
    /// Variable name and fields in lexical order.
    pub ident: Vec<String>,
}
node_common2!(VariableNode, NodeType::Variable);
node_from!(VariableNode, Variable);

impl VariableNode {
    pub(crate) fn new(tr: Tr, pos: Pos, ident: &str) -> VariableNode {
        VariableNode {
            pos,
            tr,
            ident: ident.split('.').map(str::to_owned).collect(),
        }
    }
    pub(crate) fn write_to(&self, sb: &mut String) {
        sb.push_str(&self.ident.join("."));
    }
}

/// The cursor, dot (Go `parse.DotNode`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DotNode {
    pub pos: Pos,
    pub(crate) tr: Tr,
}
node_common2!(DotNode, NodeType::Dot);
node_from!(DotNode, Dot);

impl DotNode {
    /// The type of the node, always [`NodeType::Dot`] (Go `DotNode.Type`).
    pub fn type_(&self) -> NodeType {
        NodeType::Dot
    }
    pub(crate) fn write_to(&self, sb: &mut String) {
        sb.push('.');
    }
}

/// The untyped nil constant (Go `parse.NilNode`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct NilNode {
    pub pos: Pos,
    pub(crate) tr: Tr,
}
node_common2!(NilNode, NodeType::Nil);
node_from!(NilNode, Nil);

impl NilNode {
    /// The type of the node, always [`NodeType::Nil`] (Go `NilNode.Type`).
    pub fn type_(&self) -> NodeType {
        NodeType::Nil
    }
    pub(crate) fn write_to(&self, sb: &mut String) {
        sb.push_str("nil");
    }
}

/// A field or method name (Go `parse.FieldNode`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FieldNode {
    pub pos: Pos,
    pub(crate) tr: Tr,
    /// The identifiers in lexical order.
    pub ident: Vec<String>,
}
node_common2!(FieldNode, NodeType::Field);
node_from!(FieldNode, Field);

impl FieldNode {
    pub(crate) fn new(tr: Tr, pos: Pos, ident: &str) -> FieldNode {
        FieldNode {
            pos,
            tr,
            ident: ident[1..].split('.').map(str::to_owned).collect(),
        }
    }
    pub(crate) fn write_to(&self, sb: &mut String) {
        for id in &self.ident {
            sb.push('.');
            sb.push_str(id);
        }
    }
}

/// A term followed by a chain of field accesses (Go `parse.ChainNode`).
#[derive(Clone, Debug, PartialEq)]
pub struct ChainNode {
    pub pos: Pos,
    pub(crate) tr: Tr,
    pub node: Node,
    /// The identifiers in lexical order.
    pub field: Vec<String>,
}
node_common2!(ChainNode, NodeType::Chain);

impl From<ChainNode> for Node {
    fn from(n: ChainNode) -> Node {
        Node::Chain(Box::new(n))
    }
}

impl ChainNode {
    pub(crate) fn new(tr: Tr, pos: Pos, node: Node) -> ChainNode {
        ChainNode {
            pos,
            tr,
            node,
            field: Vec::new(),
        }
    }

    /// Adds the named field (which should start with a period) to the end of
    /// the chain (Go `ChainNode.Add`). Panics like Go if the field is empty
    /// or lacks the period.
    pub fn add(&mut self, field: &str) {
        if field.is_empty() || !field.starts_with('.') {
            panic!("no dot in field");
        }
        let field = &field[1..];
        if field.is_empty() {
            panic!("empty field");
        }
        self.field.push(field.to_owned());
    }

    pub(crate) fn write_to(&self, sb: &mut String) {
        if let Node::Pipe(p) = &self.node {
            sb.push('(');
            p.write_to(sb);
            sb.push(')');
        } else {
            self.node.write_to(sb);
        }
        for f in &self.field {
            sb.push('.');
            sb.push_str(f);
        }
    }
}

/// A boolean constant (Go `parse.BoolNode`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BoolNode {
    pub pos: Pos,
    pub(crate) tr: Tr,
    /// The value of the boolean constant.
    pub true_: bool,
}
node_common2!(BoolNode, NodeType::Bool);
node_from!(BoolNode, Bool);

impl BoolNode {
    pub(crate) fn write_to(&self, sb: &mut String) {
        sb.push_str(if self.true_ { "true" } else { "false" });
    }
}

/// A numeric constant (Go `parse.NumberNode`). It may be an integer, a
/// float, or complex, and records every representation that is exact.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct NumberNode {
    pub pos: Pos,
    pub(crate) tr: Tr,
    /// The number has an integral value.
    pub is_int: bool,
    /// The number has an unsigned integral value.
    pub is_uint: bool,
    /// The number has a floating-point value.
    pub is_float: bool,
    /// The number is complex.
    pub is_complex: bool,
    /// The signed integer value.
    pub int64: i64,
    /// The unsigned integer value.
    pub uint64: u64,
    /// The floating-point value.
    pub float64: f64,
    /// The complex value.
    pub complex128: strconv::Complex,
    /// The original textual representation from the input.
    pub text: String,
}
node_common2!(NumberNode, NodeType::Number);
node_from!(NumberNode, Number);

/// A cursor over the characters of a number being scanned by `scan_complex`.
struct Scan<'a> {
    s: &'a [u8],
    pos: usize,
    buf: String,
}

impl Scan<'_> {
    fn accept(&mut self, valid: &str) -> bool {
        if let Some(&c) = self.s.get(self.pos) {
            if valid.as_bytes().contains(&c) {
                self.buf.push(c as char);
                self.pos += 1;
                return true;
            }
        }
        false
    }

    /// fmt's `floatToken`: the longest prefix that looks like a float.
    fn float_token(&mut self) -> String {
        self.buf.clear();
        // NaN?
        if self.accept("nN") && self.accept("aA") && self.accept("nN") {
            return self.buf.clone();
        }
        // leading sign?
        self.accept("+-");
        // Inf?
        if self.accept("iI") && self.accept("nN") && self.accept("fF") {
            return self.buf.clone();
        }
        let mut digits = "0123456789_";
        let mut exp = "eEpP";
        if self.accept("0") && self.accept("xX") {
            digits = "0123456789aAbBcCdDeEfF_";
            exp = "pP";
        }
        while self.accept(digits) {}
        if self.accept(".") {
            while self.accept(digits) {}
        }
        if self.accept(exp) {
            self.accept("+-");
            while self.accept("0123456789_") {}
        }
        self.buf.clone()
    }
}

fn ldexp(f: f64, mut m: i64) -> f64 {
    let mut f = f;
    while m > 1000 {
        f *= 2f64.powi(1000);
        m -= 1000;
    }
    while m < -1000 {
        f *= 2f64.powi(-1000);
        m += 1000;
    }
    f * 2f64.powi(m as i32)
}

/// fmt's `convertFloat`: a float token, with decimal mantissas allowed a
/// binary exponent.
fn convert_float(s: &str) -> Result<f64, String> {
    if let Some(p) = s.find('p') {
        if !s.contains(['x', 'X']) {
            let with_full_num = |mut e: strconv::NumError| {
                e.num = s.to_owned();
                e.to_string()
            };
            let f = strconv::parse_float(&s[..p], 64).map_err(with_full_num)?;
            let m = strconv::atoi(&s[p + 1..]).map_err(with_full_num)?;
            return Ok(ldexp(f, m as i64));
        }
    }
    strconv::parse_float(s, 64).map_err(|e| e.to_string())
}

/// What `fmt.Sscan(text, &complex128)` makes of a complex constant.
fn scan_complex(text: &str) -> Result<strconv::Complex, String> {
    const ERR_COMPLEX: &str = "syntax error scanning complex number";
    let mut sc = Scan {
        s: text.as_bytes(),
        pos: 0,
        buf: String::new(),
    };
    let parens = sc.accept("(");
    let real = sc.float_token();
    sc.buf.clear();
    // Must now have a sign.
    if !sc.accept("+-") {
        return Err(ERR_COMPLEX.to_owned());
    }
    let imag_sign = sc.buf.clone();
    let imag = sc.float_token();
    if !sc.accept("i") {
        return Err(ERR_COMPLEX.to_owned());
    }
    if parens && !sc.accept(")") {
        return Err(ERR_COMPLEX.to_owned());
    }
    let re = convert_float(&real)?;
    let im = convert_float(&format!("{imag_sign}{imag}"))?;
    Ok(strconv::Complex { re, im })
}

fn float_to_i64(f: f64) -> i64 {
    f as i64
}

fn float_to_u64(f: f64) -> u64 {
    f as u64
}

impl NumberNode {
    pub(crate) fn new(tr: Tr, pos: Pos, text: &str, typ: ItemType) -> Result<NumberNode, String> {
        let mut n = NumberNode {
            pos,
            tr,
            text: text.to_owned(),
            ..NumberNode::default()
        };
        match typ {
            ItemType::CharConstant => {
                let b = text.as_bytes();
                let (rune, _multibyte, tail) =
                    strconv::unquote_char(&b[1..], b[0]).map_err(|e| e.to_string())?;
                if tail != b"'" {
                    return Err(format!("malformed character constant: {text}"));
                }
                n.int64 = i64::from(rune);
                n.is_int = true;
                n.uint64 = u64::from(rune);
                n.is_uint = true;
                n.float64 = f64::from(rune); // odd but those are the rules.
                n.is_float = true;
                return Ok(n);
            }
            ItemType::Complex => {
                // Go lets fmt.Sscan parse the pair; scan_complex does the same.
                n.complex128 = scan_complex(text)?;
                n.is_complex = true;
                n.simplify_complex();
                return Ok(n);
            }
            _ => {}
        }
        // Imaginary constants can only be complex unless they are zero.
        if let Some(stripped) = text.strip_suffix('i') {
            if let Ok(f) = strconv::parse_float(stripped, 64) {
                n.is_complex = true;
                n.complex128 = strconv::Complex { re: 0.0, im: f };
                n.simplify_complex();
                return Ok(n);
            }
        }
        // Do integer test first so we get 0x123 etc.
        let u = strconv::parse_uint(text, 0, 64);
        if let Ok(u) = u {
            n.is_uint = true;
            n.uint64 = u;
        }
        if let Ok(i) = strconv::parse_int(text, 0, 64) {
            n.is_int = true;
            n.int64 = i;
            if i == 0 {
                n.is_uint = true; // in case of -0.
                n.uint64 = u.unwrap_or(0);
            }
        }
        // If an integer extraction succeeded, promote the float.
        if n.is_int {
            n.is_float = true;
            n.float64 = n.int64 as f64;
        } else if n.is_uint {
            n.is_float = true;
            n.float64 = n.uint64 as f64;
        } else if let Ok(f) = strconv::parse_float(text, 64) {
            // If we parsed it as a float but it looks like an integer,
            // it's a huge number too large to fit in an int. Reject it.
            if !text.contains(['.', 'e', 'E', 'p', 'P']) {
                return Err(format!("integer overflow: {}", strconv::quote(text)));
            }
            n.is_float = true;
            n.float64 = f;
            // If a floating-point extraction succeeded, extract the int if
            // needed.
            if !n.is_int && float_to_i64(f) as f64 == f {
                n.is_int = true;
                n.int64 = float_to_i64(f);
            }
            if !n.is_uint && float_to_u64(f) as f64 == f {
                n.is_uint = true;
                n.uint64 = float_to_u64(f);
            }
        }
        if !n.is_int && !n.is_uint && !n.is_float {
            return Err(format!("illegal number syntax: {}", strconv::quote(text)));
        }
        Ok(n)
    }

    /// Checks if a complex is actually a real and, if so, fills in the other
    /// fields.
    fn simplify_complex(&mut self) {
        self.is_float = self.complex128.im == 0.0;
        if self.is_float {
            self.float64 = self.complex128.re;
            self.is_int = float_to_i64(self.float64) as f64 == self.float64;
            if self.is_int {
                self.int64 = float_to_i64(self.float64);
            }
            self.is_uint = float_to_u64(self.float64) as f64 == self.float64;
            if self.is_uint {
                self.uint64 = float_to_u64(self.float64);
            }
        }
    }

    pub(crate) fn write_to(&self, sb: &mut String) {
        sb.push_str(&self.text);
    }
}

/// A string constant (Go `parse.StringNode`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct StringNode {
    pub pos: Pos,
    pub(crate) tr: Tr,
    /// The original text of the string, with quotes.
    pub quoted: String,
    /// The string, after quote processing.
    pub text: String,
}
node_common2!(StringNode, NodeType::String);
node_from!(StringNode, String);

impl StringNode {
    pub(crate) fn write_to(&self, sb: &mut String) {
        sb.push_str(&self.quoted);
    }
}

/// A `break` action (Go `parse.BreakNode`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BreakNode {
    pub(crate) tr: Tr,
    pub pos: Pos,
    pub line: usize,
}
node_common2!(BreakNode, NodeType::Break);
node_from!(BreakNode, Break);

impl BreakNode {
    pub(crate) fn write_to(&self, sb: &mut String) {
        let (l, r) = delims(&self.tr);
        sb.push_str(l);
        sb.push_str("break");
        sb.push_str(r);
    }
}

/// A `continue` action (Go `parse.ContinueNode`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ContinueNode {
    pub(crate) tr: Tr,
    pub pos: Pos,
    pub line: usize,
}
node_common2!(ContinueNode, NodeType::Continue);
node_from!(ContinueNode, Continue);

impl ContinueNode {
    pub(crate) fn write_to(&self, sb: &mut String) {
        let (l, r) = delims(&self.tr);
        sb.push_str(l);
        sb.push_str("continue");
        sb.push_str(r);
    }
}

/// The common part of if, range and with (Go `parse.BranchNode`).
#[derive(Clone, Debug, PartialEq)]
pub struct BranchNode {
    pub node_type: NodeType,
    pub pos: Pos,
    pub(crate) tr: Tr,
    /// The line number in the input (deprecated in Go, kept for
    /// compatibility).
    pub line: usize,
    /// The pipeline to be evaluated.
    pub pipe: PipeNode,
    /// What to execute if the value is non-empty.
    pub list: ListNode,
    /// What to execute if the value is empty (`None` if absent).
    pub else_list: Option<ListNode>,
}

impl BranchNode {
    /// The node's type (the embedded Go `NodeType`).
    pub fn node_type(&self) -> NodeType {
        self.node_type
    }
    /// A deep copy of the node (Go `Copy`).
    pub fn copy(&self) -> BranchNode {
        self.clone()
    }
    /// The byte position of the start of the node (Go `Position`).
    pub fn position(&self) -> Pos {
        self.pos
    }

    pub(crate) fn write_to(&self, sb: &mut String) {
        let name = match self.node_type {
            NodeType::If => "if",
            NodeType::Range => "range",
            NodeType::With => "with",
            _ => panic!("unknown branch type"),
        };
        let (l, r) = delims(&self.tr);
        sb.push_str(l);
        sb.push_str(name);
        sb.push(' ');
        self.pipe.write_to(sb);
        sb.push_str(r);
        self.list.write_to(sb);
        if let Some(e) = &self.else_list {
            sb.push_str(l);
            sb.push_str("else");
            sb.push_str(r);
            e.write_to(sb);
        }
        sb.push_str(l);
        sb.push_str("end");
        sb.push_str(r);
    }
}

impl fmt::Display for BranchNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = String::new();
        self.write_to(&mut s);
        f.write_str(&s)
    }
}

macro_rules! branch_node {
    ($(#[$doc:meta])* $t:ident, $v:ident, $ty:expr) => {
        $(#[$doc])*
        #[derive(Clone, Debug, PartialEq)]
        pub struct $t {
            pub branch_node: BranchNode,
        }
        impl std::ops::Deref for $t {
            type Target = BranchNode;
            fn deref(&self) -> &BranchNode {
                &self.branch_node
            }
        }
        impl std::ops::DerefMut for $t {
            fn deref_mut(&mut self) -> &mut BranchNode {
                &mut self.branch_node
            }
        }
        impl $t {
            pub(crate) fn new(
                tr: Tr,
                pos: Pos,
                line: usize,
                pipe: PipeNode,
                list: ListNode,
                else_list: Option<ListNode>,
            ) -> $t {
                $t {
                    branch_node: BranchNode {
                        node_type: $ty,
                        pos,
                        tr,
                        line,
                        pipe,
                        list,
                        else_list,
                    },
                }
            }
            /// A deep copy of the node (Go `Copy`).
            pub fn copy(&self) -> $t {
                self.clone()
            }
            pub(crate) fn write_to(&self, sb: &mut String) {
                self.branch_node.write_to(sb)
            }
        }
        impl fmt::Display for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.branch_node.fmt(f)
            }
        }
        impl From<$t> for Node {
            fn from(n: $t) -> Node {
                Node::$v(n)
            }
        }
    };
}

branch_node!(
    /// An if action (Go `parse.IfNode`).
    IfNode, If, NodeType::If
);
branch_node!(
    /// A range action (Go `parse.RangeNode`).
    RangeNode, Range, NodeType::Range
);
branch_node!(
    /// A with action (Go `parse.WithNode`).
    WithNode, With, NodeType::With
);

/// A template invocation action (Go `parse.TemplateNode`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TemplateNode {
    pub pos: Pos,
    pub(crate) tr: Tr,
    /// The line number in the input (deprecated in Go, kept for
    /// compatibility).
    pub line: usize,
    /// The name of the template (unquoted).
    pub name: String,
    /// The command to evaluate as dot for the template.
    pub pipe: Option<PipeNode>,
}
node_common2!(TemplateNode, NodeType::Template);
node_from!(TemplateNode, Template);

impl TemplateNode {
    pub(crate) fn write_to(&self, sb: &mut String) {
        let (l, r) = delims(&self.tr);
        sb.push_str(l);
        sb.push_str("template ");
        sb.push_str(&strconv::quote(&self.name));
        if let Some(p) = &self.pipe {
            sb.push(' ');
            p.write_to(sb);
        }
        sb.push_str(r);
    }
}
