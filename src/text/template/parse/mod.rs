//! Parse trees for templates (Go `text/template/parse`).
//!
//! The lexer, parser and node types port Go's package: the grammar, the
//! node string forms and the error texts are Go's. Nodes own their children
//! (`Vec`/`Option`) rather than sharing pointers, so a tree can be edited in
//! place; copying is `Clone`. Differences from Go that Rust's types force:
//! a `Tree` holds its results by value, `Tree::parse` fills in `self`
//! instead of returning the tree, function tables are consulted through the
//! [`FuncLookup`] trait, and quoted strings must be valid UTF-8.

mod lex;
mod node;

pub use node::{
    ActionNode, BoolNode, BranchNode, BreakNode, ChainNode, CommandNode, CommentNode, ContinueNode,
    DotNode, FieldNode, IdentifierNode, IfNode, ListNode, NilNode, Node, NodeType, NumberNode,
    PipeNode, Pos, RangeNode, StringNode, TemplateNode, TextNode, TreeInfo, VariableNode, WithNode,
};

use crate::strconv;
use lex::{Item, ItemType, Lexer};
pub(crate) use node::{on_big_stack, Tr};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::Arc;

/// A parse error. Its text is Go's, for example
/// `template: t:1: unexpected "}" in operand`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    message: String,
}

impl Error {
    /// Builds an error with the given text.
    pub fn new(message: impl Into<String>) -> Error {
        Error {
            message: message.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

type R<T> = Result<T, Error>;

/// Parse mode flags (Go `parse.Mode`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Mode(pub u32);

/// Parse comments and add them to the AST (Go `parse.ParseComments`).
pub const PARSE_COMMENTS: Mode = Mode(1);
/// Do not check that functions are defined (Go `parse.SkipFuncCheck`).
pub const SKIP_FUNC_CHECK: Mode = Mode(2);

impl Mode {
    /// Reports whether every bit of `flag` is set.
    pub fn contains(self, flag: Mode) -> bool {
        self.0 & flag.0 != 0
    }
}

impl std::ops::BitOr for Mode {
    type Output = Mode;
    fn bitor(self, rhs: Mode) -> Mode {
        Mode(self.0 | rhs.0)
    }
}

/// A set of function names the parser checks identifiers against. Go passes
/// `map[string]any`; any map keyed by name works here.
pub trait FuncLookup: Sync {
    /// Reports whether a function with this name is defined.
    fn has_function(&self, name: &str) -> bool;
}

impl<V: Sync> FuncLookup for HashMap<String, V> {
    fn has_function(&self, name: &str) -> bool {
        self.contains_key(name)
    }
}

impl<V: Sync> FuncLookup for BTreeMap<String, V> {
    fn has_function(&self, name: &str) -> bool {
        self.contains_key(name)
    }
}

const MAX_STACK_DEPTH: usize = 10000;

/// The representation of a single parsed template (Go `parse.Tree`).
#[derive(Clone, Debug, PartialEq)]
pub struct Tree {
    /// Name of the template represented by the tree.
    pub name: String,
    /// Name of the top-level template during parsing, for error messages.
    pub parse_name: String,
    /// Top-level root of the tree.
    pub root: Option<ListNode>,
    /// Parsing mode.
    pub mode: Mode,
    text: String,
    left_delim: String,
    right_delim: String,
    info: Tr,
    max_stack_depth: usize,
}

impl Default for Tree {
    fn default() -> Tree {
        Tree {
            name: String::new(),
            parse_name: String::new(),
            root: None,
            mode: Mode(0),
            text: String::new(),
            left_delim: String::new(),
            right_delim: String::new(),
            info: None,
            max_stack_depth: MAX_STACK_DEPTH,
        }
    }
}

/// Creates a new tree with the given name (Go `parse.New`).
pub fn new(name: &str) -> Tree {
    Tree::new(name)
}

/// Creates a tree for the template with the given name and text, together
/// with every template it defines, keyed by name (Go `parse.Parse`).
/// `funcs` are the function tables the parser checks identifiers against.
pub fn parse(
    name: &str,
    text: &str,
    left_delim: &str,
    right_delim: &str,
    funcs: &[&dyn FuncLookup],
) -> Result<BTreeMap<String, Tree>, Error> {
    let mut tree_set = BTreeMap::new();
    let mut t = Tree::new(name);
    t.text = text.to_owned();
    t.parse(text, left_delim, right_delim, &mut tree_set, funcs)?;
    Ok(tree_set)
}

/// Reports whether this tree (node) is empty of everything but space or
/// comments (Go `parse.IsEmptyTree`). `None` stands for a nil node.
pub fn is_empty_tree(n: Option<&Node>) -> bool {
    match n {
        None => true,
        Some(Node::Comment(_)) => true,
        Some(Node::List(l)) => is_empty_list(l),
        Some(Node::Text(t)) => String::from_utf8_lossy(&t.text).trim().is_empty(),
        // Action, If, Range, Template and With nodes are never empty. Go
        // panics on node types that cannot appear at the top of a tree.
        Some(_) => false,
    }
}

fn is_empty_list(l: &ListNode) -> bool {
    l.nodes.iter().all(|n| is_empty_tree(Some(n)))
}

impl Tree {
    /// Allocates a new parse tree with the given name (Go `parse.New`).
    pub fn new(name: &str) -> Tree {
        Tree {
            name: name.to_owned(),
            ..Tree::default()
        }
    }

    /// Returns a copy of the tree. Any parsing state is discarded (Go
    /// `Tree.Copy`).
    pub fn copy(&self) -> Tree {
        Tree {
            name: self.name.clone(),
            parse_name: self.parse_name.clone(),
            root: self.root.clone(),
            mode: Mode(0),
            text: self.text.clone(),
            left_delim: self.left_delim.clone(),
            right_delim: self.right_delim.clone(),
            info: self.info.clone(),
            max_stack_depth: self.max_stack_depth,
        }
    }

    /// Sets the maximum nesting depth of parenthesized expressions (Go's
    /// unexported `maxStackDepth`, 10000 by default, which its tests lower).
    pub fn set_max_expression_depth(&mut self, depth: usize) {
        self.max_stack_depth = depth;
    }

    /// The text parsed to create the template (or its parent).
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Returns a textual representation of the node's location in the input
    /// text, as `name:line:byte`, and the node's string form (Go
    /// `Tree.ErrorContext`).
    pub fn error_context(&self, n: &Node) -> (String, String) {
        self.error_context_at(n.position(), n.tree(), n.to_string())
    }

    pub(crate) fn error_context_at(&self, pos: Pos, tr: &Tr, context: String) -> (String, String) {
        let pos = pos.0;
        let (parse_name, text) = match tr {
            Some(i) => (i.parse_name.as_str(), i.text.as_str()),
            None => (self.parse_name.as_str(), self.text.as_str()),
        };
        let pos = pos.min(text.len());
        let text = &text.as_bytes()[..pos];
        let byte_num = match text.iter().rposition(|&b| b == b'\n') {
            None => pos, // On first line.
            Some(i) => pos - (i + 1),
        };
        let line_num = 1 + text.iter().filter(|&&b| b == b'\n').count();
        (format!("{parse_name}:{line_num}:{byte_num}"), context)
    }

    /// Parses the template definition string to construct a representation of
    /// the template for execution. Templates it defines are added to
    /// `tree_set`; this tree becomes the parsed template named `self.name`
    /// (Go `Tree.Parse`).
    pub fn parse(
        &mut self,
        text: &str,
        left_delim: &str,
        right_delim: &str,
        tree_set: &mut BTreeMap<String, Tree>,
        funcs: &[&dyn FuncLookup],
    ) -> Result<(), Error> {
        self.parse_name = self.name.clone();
        self.left_delim = if left_delim.is_empty() {
            lex::DEFAULT_LEFT_DELIM.to_owned()
        } else {
            left_delim.to_owned()
        };
        self.right_delim = if right_delim.is_empty() {
            lex::DEFAULT_RIGHT_DELIM.to_owned()
        } else {
            right_delim.to_owned()
        };
        self.text = text.to_owned();
        self.info = Some(Arc::new(TreeInfo {
            parse_name: self.parse_name.clone(),
            text: self.text.clone(),
            left_delim: self.left_delim.clone(),
            right_delim: self.right_delim.clone(),
        }));
        let mut lexer = Lexer::new(text, &self.left_delim, &self.right_delim);
        let t = std::mem::take(self);
        let mut p = Parser::new(t, &mut lexer, funcs, tree_set);
        p.start_parse();
        let r = p.parse().and_then(|()| p.add());
        *self = p.t;
        if r.is_err() {
            self.root = None;
        }
        r
    }
}

struct Parser<'a> {
    t: Tree,
    lex: &'a mut Lexer,
    funcs: &'a [&'a dyn FuncLookup],
    tree_set: &'a mut BTreeMap<String, Tree>,
    token: [Item; 3],
    peek_count: usize,
    vars: Vec<String>,
    action_line: usize,
    range_depth: usize,
    stack_depth: usize,
    /// Nesting of recursive parse calls on the native stack.
    nest: usize,
    /// Whether parsing already runs on the large worker stack.
    on_big: bool,
    /// Address near the base of the worker stack (0 on the caller's stack).
    stack_base: usize,
}

/// Nesting at which parsing moves to a thread with a large stack. Go grows
/// goroutine stacks on demand and so parses arbitrarily deep templates;
/// native stacks cannot grow, so deep nesting continues on a big one.
const BIG_STACK_NEST: usize = 16;
/// Stack size of the worker thread (virtual memory, committed on use).
const BIG_STACK_BYTES: usize = 1 << 30;

/// What `text_or_action`, `action` and the control parsers produce: a node,
/// or one of Go's unexported `end` and `else` markers.
enum Parsed {
    Node(Node),
    End,
    Else(Pos),
}

impl Parsed {
    fn describe(&self, t: &Tree) -> String {
        let (l, r) = (&t.left_delim, &t.right_delim);
        match self {
            Parsed::Node(n) => n.to_string(),
            Parsed::End => format!("{l}end{r}"),
            Parsed::Else(_) => format!("{l}else{r}"),
        }
    }
}

fn empty_item() -> Item {
    Item {
        typ: ItemType::Eof,
        pos: Pos(0),
        val: String::new(),
        line: 0,
    }
}

impl<'a> Parser<'a> {
    fn new(
        t: Tree,
        lex: &'a mut Lexer,
        funcs: &'a [&'a dyn FuncLookup],
        tree_set: &'a mut BTreeMap<String, Tree>,
    ) -> Parser<'a> {
        Parser {
            t,
            lex,
            funcs,
            tree_set,
            token: [empty_item(), empty_item(), empty_item()],
            peek_count: 0,
            vars: Vec::new(),
            action_line: 0,
            range_depth: 0,
            stack_depth: 0,
            nest: 0,
            on_big: false,
            stack_base: 0,
        }
    }

    /// Runs a recursive parse step, moving to a thread with a large stack
    /// when the nesting gets deep.
    fn nested<T: Send>(&mut self, f: impl FnOnce(&mut Parser<'a>) -> R<T> + Send) -> R<T> {
        if self.stack_base != 0 {
            let marker = 0u8;
            let here = std::ptr::from_ref(&marker) as usize;
            if self.stack_base.abs_diff(here) > BIG_STACK_BYTES / 10 * 9 {
                return self
                    .errorf("nesting too deep: exceeded the available stack space".to_owned());
            }
        }
        self.nest += 1;
        let r = if self.nest == BIG_STACK_NEST && !self.on_big {
            self.on_big_stack(f)
        } else {
            f(self)
        };
        self.nest -= 1;
        r
    }

    fn on_big_stack<T: Send>(&mut self, f: impl FnOnce(&mut Parser<'a>) -> R<T> + Send) -> R<T> {
        self.on_big = true;
        let mut slot = Some(f);
        let me = &mut *self;
        let res = std::thread::scope(|scope| {
            let spawned = std::thread::Builder::new()
                .stack_size(BIG_STACK_BYTES)
                .spawn_scoped(scope, || {
                    let marker = 0u8;
                    me.stack_base = std::ptr::from_ref(&marker) as usize;
                    let f = slot.take().expect("closure runs once");
                    let r = f(me);
                    me.stack_base = 0;
                    r
                });
            match spawned {
                Ok(h) => match h.join() {
                    Ok(r) => Some(r),
                    Err(p) => std::panic::resume_unwind(p),
                },
                Err(_) => None,
            }
        });
        self.on_big = false;
        match res {
            Some(r) => r,
            None => self.errorf("nesting too deep: no stack space available".to_owned()),
        }
    }

    fn tr(&self) -> Tr {
        self.t.info.clone()
    }

    /// Starts a parser for a nested template (a define or block) that shares
    /// the lexer, function tables and tree set.
    fn sub(&mut self, name: &str) -> Parser<'_> {
        let mut nt = Tree::new(name);
        nt.text = self.t.text.clone();
        nt.mode = self.t.mode;
        nt.left_delim = self.t.left_delim.clone();
        nt.right_delim = self.t.right_delim.clone();
        nt.parse_name = self.t.parse_name.clone();
        nt.info = self.t.info.clone();
        nt.max_stack_depth = self.t.max_stack_depth;
        let mut p = Parser::new(nt, &mut *self.lex, self.funcs, &mut *self.tree_set);
        p.start_parse();
        p
    }

    fn next(&mut self) -> Item {
        if self.peek_count > 0 {
            self.peek_count -= 1;
        } else {
            self.token[0] = self.lex.next_item();
        }
        self.token[self.peek_count].clone()
    }

    fn backup(&mut self) {
        self.peek_count += 1;
    }

    fn backup2(&mut self, t1: Item) {
        self.token[1] = t1;
        self.peek_count = 2;
    }

    fn backup3(&mut self, t2: Item, t1: Item) {
        // Reverse order: we're pushing back.
        self.token[1] = t1;
        self.token[2] = t2;
        self.peek_count = 3;
    }

    fn peek(&mut self) -> Item {
        if self.peek_count > 0 {
            return self.token[self.peek_count - 1].clone();
        }
        self.peek_count = 1;
        self.token[0] = self.lex.next_item();
        self.token[0].clone()
    }

    fn next_non_space(&mut self) -> Item {
        loop {
            let token = self.next();
            if token.typ != ItemType::Space {
                return token;
            }
        }
    }

    fn peek_non_space(&mut self) -> Item {
        let token = self.next_non_space();
        self.backup();
        token
    }

    fn errorf<T>(&mut self, msg: String) -> R<T> {
        self.t.root = None;
        Err(Error::new(format!(
            "template: {}:{}: {}",
            self.t.parse_name, self.token[0].line, msg
        )))
    }

    fn expect(&mut self, expected: ItemType, context: &str) -> R<Item> {
        let token = self.next_non_space();
        if token.typ != expected {
            return self.unexpected(token, context);
        }
        Ok(token)
    }

    fn expect_one_of(&mut self, e1: ItemType, e2: ItemType, context: &str) -> R<Item> {
        let token = self.next_non_space();
        if token.typ != e1 && token.typ != e2 {
            return self.unexpected(token, context);
        }
        Ok(token)
    }

    fn unexpected<T>(&mut self, token: Item, context: &str) -> R<T> {
        if token.typ == ItemType::Error {
            let mut extra = String::new();
            if self.action_line != 0 && self.action_line != token.line {
                extra = format!(
                    " in action started at {}:{}",
                    self.t.parse_name, self.action_line
                );
                if token.val.ends_with(" action") {
                    extra = extra[" in action".len()..].to_owned(); // avoid "action in action"
                }
            }
            return self.errorf(format!("{token}{extra}"));
        }
        self.errorf(format!("unexpected {token} in {context}"))
    }

    fn start_parse(&mut self) {
        self.t.root = None;
        self.vars = vec!["$".to_owned()];
        self.stack_depth = 0;
        self.lex.options = lex::LexOptions {
            emit_comment: self.t.mode.contains(PARSE_COMMENTS),
            break_ok: !self.has_function("break"),
            continue_ok: !self.has_function("continue"),
        };
    }

    /// Adds the tree to the tree set, enforcing single definitions.
    fn add(&mut self) -> R<()> {
        let existing_empty = match self.tree_set.get(&self.t.name) {
            None => true,
            Some(tree) => tree.root.as_ref().is_none_or(is_empty_list),
        };
        if existing_empty {
            self.tree_set.insert(self.t.name.clone(), self.t.clone());
            return Ok(());
        }
        if !self.t.root.as_ref().is_none_or(is_empty_list) {
            let name = strconv::quote(&self.t.name);
            return self.errorf(format!("template: multiple definition of template {name}"));
        }
        Ok(())
    }

    /// Parses a top-level template.
    fn parse(&mut self) -> R<()> {
        let pos = self.peek().pos;
        self.t.root = Some(ListNode::new(self.tr(), pos));
        while self.peek().typ != ItemType::Eof {
            if self.peek().typ == ItemType::LeftDelim {
                let delim = self.next();
                if self.next_non_space().typ == ItemType::Define {
                    let mut np = self.sub("definition");
                    np.parse_definition()?;
                    continue;
                }
                self.backup2(delim);
            }
            match self.text_or_action()? {
                p @ (Parsed::End | Parsed::Else(_)) => {
                    let d = p.describe(&self.t);
                    return self.errorf(format!("unexpected {d}"));
                }
                Parsed::Node(n) => self.root_mut().append(n),
            }
        }
        Ok(())
    }

    fn root_mut(&mut self) -> &mut ListNode {
        self.t.root.as_mut().expect("root is set while parsing")
    }

    /// Parses a `{{define}} ...  {{end}}` template definition.
    fn parse_definition(&mut self) -> R<()> {
        const CONTEXT: &str = "define clause";
        let name = self.expect_one_of(ItemType::String, ItemType::RawString, CONTEXT)?;
        match unquote_string(&name.val) {
            Ok(s) => self.t.name = s,
            Err(e) => return self.errorf(e),
        }
        self.expect(ItemType::RightDelim, CONTEXT)?;
        let (list, end) = self.item_list()?;
        self.t.root = Some(list);
        if !matches!(end, Parsed::End) {
            let d = end.describe(&self.t);
            return self.errorf(format!("unexpected {d} in {CONTEXT}"));
        }
        self.add()
    }

    /// Parses a list of nodes until `{{end}}` or `{{else}}`, which is
    /// returned along with the list.
    fn item_list(&mut self) -> R<(ListNode, Parsed)> {
        self.nested(|p| p.item_list_inner())
    }

    fn item_list_inner(&mut self) -> R<(ListNode, Parsed)> {
        let pos = self.peek_non_space().pos;
        let mut list = ListNode::new(self.tr(), pos);
        while self.peek_non_space().typ != ItemType::Eof {
            let n = self.text_or_action()?;
            match n {
                Parsed::End | Parsed::Else(_) => return Ok((list, n)),
                Parsed::Node(n) => list.append(n),
            }
        }
        self.errorf("unexpected EOF".to_owned())
    }

    fn text_or_action(&mut self) -> R<Parsed> {
        let token = self.next_non_space();
        match token.typ {
            ItemType::Text => Ok(Parsed::Node(
                TextNode::new(self.tr(), token.pos, &token.val).into(),
            )),
            ItemType::LeftDelim => {
                self.action_line = token.line;
                let r = self.action();
                self.action_line = 0;
                r
            }
            ItemType::Comment => Ok(Parsed::Node(
                CommentNode {
                    pos: token.pos,
                    tr: self.tr(),
                    text: token.val,
                }
                .into(),
            )),
            _ => self.unexpected(token, "input"),
        }
    }

    fn action(&mut self) -> R<Parsed> {
        let token = self.next_non_space();
        match token.typ {
            ItemType::Block => return self.block_control(),
            ItemType::Break => return self.break_control(token.pos, token.line),
            ItemType::Continue => return self.continue_control(token.pos, token.line),
            ItemType::Else => return self.else_control(),
            ItemType::End => return self.end_control(),
            ItemType::If => return self.if_control(),
            ItemType::Range => return self.range_control(),
            ItemType::Template => return self.template_control(),
            ItemType::With => return self.with_control(),
            _ => {}
        }
        self.backup();
        let token = self.peek();
        let pipe = self.pipeline("command", ItemType::RightDelim)?;
        Ok(Parsed::Node(
            ActionNode {
                pos: token.pos,
                tr: self.tr(),
                line: token.line,
                pipe,
            }
            .into(),
        ))
    }

    fn break_control(&mut self, pos: Pos, line: usize) -> R<Parsed> {
        let token = self.next_non_space();
        if token.typ != ItemType::RightDelim {
            return self.unexpected(token, "{{break}}");
        }
        if self.range_depth == 0 {
            return self.errorf("{{break}} outside {{range}}".to_owned());
        }
        Ok(Parsed::Node(
            BreakNode {
                tr: self.tr(),
                pos,
                line,
            }
            .into(),
        ))
    }

    fn continue_control(&mut self, pos: Pos, line: usize) -> R<Parsed> {
        let token = self.next_non_space();
        if token.typ != ItemType::RightDelim {
            return self.unexpected(token, "{{continue}}");
        }
        if self.range_depth == 0 {
            return self.errorf("{{continue}} outside {{range}}".to_owned());
        }
        Ok(Parsed::Node(
            ContinueNode {
                tr: self.tr(),
                pos,
                line,
            }
            .into(),
        ))
    }

    /// Parses a pipeline, optionally with variable declarations, up to the
    /// `end` item.
    fn pipeline(&mut self, context: &str, end: ItemType) -> R<PipeNode> {
        let token = self.peek_non_space();
        let mut pipe = PipeNode {
            pos: token.pos,
            tr: self.tr(),
            line: token.line,
            ..PipeNode::default()
        };
        // Are there declarations or assignments?
        loop {
            let v = self.peek_non_space();
            if v.typ != ItemType::Variable {
                break;
            }
            self.next();
            // Since space is a token, we need 3-token look-ahead here in the
            // worst case: in "$x foo" we need to read "foo" (as opposed to
            // ":=") to know that $x is an argument variable rather than a
            // declaration.
            let token_after_variable = self.peek();
            let next = self.peek_non_space();
            if next.typ == ItemType::Assign || next.typ == ItemType::Declare {
                pipe.is_assign = next.typ == ItemType::Assign;
                self.next_non_space();
                pipe.decl.push(VariableNode::new(self.tr(), v.pos, &v.val));
                self.vars.push(v.val);
                break;
            } else if next.typ == ItemType::Char && next.val == "," {
                self.next_non_space();
                pipe.decl.push(VariableNode::new(self.tr(), v.pos, &v.val));
                self.vars.push(v.val);
                if context == "range" && pipe.decl.len() < 2 {
                    match self.peek_non_space().typ {
                        ItemType::Variable | ItemType::RightDelim | ItemType::RightParen => {
                            // second initialized variable in a range pipeline
                            continue;
                        }
                        _ => return self.errorf("range can only initialize variables".to_owned()),
                    }
                }
                return self.errorf(format!("too many declarations in {context}"));
            } else if token_after_variable.typ == ItemType::Space {
                self.backup3(v, token_after_variable);
            } else {
                self.backup2(v);
            }
            break;
        }
        loop {
            let token = self.next_non_space();
            if token.typ == end {
                // At this point, the pipeline is complete.
                self.check_pipeline(&pipe, context)?;
                return Ok(pipe);
            }
            match token.typ {
                ItemType::Bool
                | ItemType::CharConstant
                | ItemType::Complex
                | ItemType::Dot
                | ItemType::Field
                | ItemType::Identifier
                | ItemType::Number
                | ItemType::Nil
                | ItemType::RawString
                | ItemType::String
                | ItemType::Variable
                | ItemType::LeftParen => {
                    self.backup();
                    let c = self.command()?;
                    pipe.cmds.push(c);
                }
                _ => return self.unexpected(token, context),
            }
        }
    }

    fn check_pipeline(&mut self, pipe: &PipeNode, context: &str) -> R<()> {
        // Reject empty pipelines.
        if pipe.cmds.is_empty() {
            return self.errorf(format!("missing value for {context}"));
        }
        // Only the first command of a pipeline can start with a non-executable
        // operand.
        for (i, c) in pipe.cmds.iter().enumerate().skip(1) {
            match c.args[0].node_type() {
                NodeType::Bool
                | NodeType::Dot
                | NodeType::Nil
                | NodeType::Number
                | NodeType::String => {
                    // With A|B|C, pipeline stage 2 is B.
                    return self.errorf(format!(
                        "non executable command in pipeline stage {}",
                        i + 1
                    ));
                }
                _ => {}
            }
        }
        Ok(())
    }

    #[allow(clippy::type_complexity)]
    fn parse_control(
        &mut self,
        context: &str,
    ) -> R<(Pos, usize, PipeNode, ListNode, Option<ListNode>)> {
        let saved_vars = self.vars.len();
        let r = self.parse_control_inner(context);
        self.vars.truncate(saved_vars);
        r
    }

    #[allow(clippy::type_complexity)]
    fn parse_control_inner(
        &mut self,
        context: &str,
    ) -> R<(Pos, usize, PipeNode, ListNode, Option<ListNode>)> {
        let pipe = self.pipeline(context, ItemType::RightDelim)?;
        if context == "range" {
            self.range_depth += 1;
        }
        let r = self.item_list();
        if context == "range" {
            self.range_depth -= 1;
        }
        let (list, next) = r?;
        let mut else_list = None;
        match next {
            Parsed::End => {}
            Parsed::Else(pos) => {
                // Special case for "else if" and "else with". If the "else"
                // is followed immediately by an "if" or "with", the else
                // action is shorthand for "else {{if ...}}", and the closing
                // "end" is shared.
                if context == "if" && self.peek().typ == ItemType::If {
                    self.next(); // Consume the "if" token.
                    let mut l = ListNode::new(self.tr(), pos);
                    l.append(self.if_control_node()?);
                    else_list = Some(l);
                } else if context == "with" && self.peek().typ == ItemType::With {
                    self.next();
                    let mut l = ListNode::new(self.tr(), pos);
                    l.append(self.with_control_node()?);
                    else_list = Some(l);
                } else {
                    let (l, next) = self.item_list()?;
                    if !matches!(next, Parsed::End) {
                        let d = next.describe(&self.t);
                        return self.errorf(format!("expected end; found {d}"));
                    }
                    else_list = Some(l);
                }
            }
            Parsed::Node(_) => {}
        }
        Ok((pipe.pos, pipe.line, pipe, list, else_list))
    }

    fn if_control_node(&mut self) -> R<Node> {
        let (pos, line, pipe, list, else_list) = self.parse_control("if")?;
        Ok(IfNode::new(self.tr(), pos, line, pipe, list, else_list).into())
    }

    fn with_control_node(&mut self) -> R<Node> {
        let (pos, line, pipe, list, else_list) = self.parse_control("with")?;
        Ok(WithNode::new(self.tr(), pos, line, pipe, list, else_list).into())
    }

    fn if_control(&mut self) -> R<Parsed> {
        self.if_control_node().map(Parsed::Node)
    }

    fn range_control(&mut self) -> R<Parsed> {
        let (pos, line, pipe, list, else_list) = self.parse_control("range")?;
        Ok(Parsed::Node(
            RangeNode::new(self.tr(), pos, line, pipe, list, else_list).into(),
        ))
    }

    fn with_control(&mut self) -> R<Parsed> {
        self.with_control_node().map(Parsed::Node)
    }

    fn end_control(&mut self) -> R<Parsed> {
        self.expect(ItemType::RightDelim, "end")?;
        Ok(Parsed::End)
    }

    fn else_control(&mut self) -> R<Parsed> {
        // Special case for "else if".
        let peek = self.peek_non_space();
        if peek.typ == ItemType::If || peek.typ == ItemType::With {
            // We see "{{else if ... " but in effect rewrite it to
            // "{{else}}{{if ... ".
            return Ok(Parsed::Else(peek.pos));
        }
        let token = self.expect(ItemType::RightDelim, "else")?;
        Ok(Parsed::Else(token.pos))
    }

    /// Parses `{{block name pipeline}}`, which defines a template and
    /// executes it in place.
    fn block_control(&mut self) -> R<Parsed> {
        const CONTEXT: &str = "block clause";
        let token = self.next_non_space();
        let name = self.parse_template_name(&token, CONTEXT)?;
        let pipe = self.pipeline(CONTEXT, ItemType::RightDelim)?;

        let (end_is_end, end_desc) = {
            let mut block = self.sub(&name);
            let (list, end) = block.item_list()?;
            block.t.root = Some(list);
            let r = (matches!(end, Parsed::End), end.describe(&block.t));
            if r.0 {
                block.add()?;
            }
            r
        };
        if !end_is_end {
            return self.errorf(format!("unexpected {end_desc} in {CONTEXT}"));
        }
        Ok(Parsed::Node(
            TemplateNode {
                pos: token.pos,
                tr: self.tr(),
                line: token.line,
                name,
                pipe: Some(pipe),
            }
            .into(),
        ))
    }

    /// Parses `{{template "name" pipeline}}`.
    fn template_control(&mut self) -> R<Parsed> {
        const CONTEXT: &str = "template clause";
        let token = self.next_non_space();
        let name = self.parse_template_name(&token, CONTEXT)?;
        let mut pipe = None;
        if self.next_non_space().typ != ItemType::RightDelim {
            self.backup();
            // Do not pop variables; they persist until "end".
            pipe = Some(self.pipeline(CONTEXT, ItemType::RightDelim)?);
        }
        Ok(Parsed::Node(
            TemplateNode {
                pos: token.pos,
                tr: self.tr(),
                line: token.line,
                name,
                pipe,
            }
            .into(),
        ))
    }

    fn parse_template_name(&mut self, token: &Item, context: &str) -> R<String> {
        match token.typ {
            ItemType::String | ItemType::RawString => match unquote_string(&token.val) {
                Ok(s) => Ok(s),
                Err(e) => self.errorf(e),
            },
            _ => self.unexpected(token.clone(), context),
        }
    }

    /// Parses a command: `operand (space operand)*`, ended by a pipe, right
    /// paren or right delimiter.
    fn command(&mut self) -> R<CommandNode> {
        let pos = self.peek_non_space().pos;
        let mut cmd = CommandNode {
            pos,
            tr: self.tr(),
            args: Vec::new(),
        };
        loop {
            self.peek_non_space(); // skip leading spaces.
            if let Some(operand) = self.operand()? {
                cmd.args.push(operand);
            }
            let token = self.next();
            match token.typ {
                ItemType::Space => continue,
                ItemType::RightDelim | ItemType::RightParen => self.backup(),
                ItemType::Pipe => {
                    // nothing here; break loop below
                }
                _ => return self.unexpected(token, "operand"),
            }
            break;
        }
        if cmd.args.is_empty() {
            return self.errorf("empty command".to_owned());
        }
        Ok(cmd)
    }

    /// Parses a term, possibly followed by a chain of field accesses.
    fn operand(&mut self) -> R<Option<Node>> {
        let Some(mut node) = self.term()? else {
            return Ok(None);
        };
        if self.peek().typ == ItemType::Field {
            let pos = self.peek().pos;
            let mut chain = ChainNode::new(self.tr(), pos, node.clone());
            while self.peek().typ == ItemType::Field {
                let v = self.next().val;
                chain.add(&v);
            }
            // Compatibility with original API: If the term is of type
            // NodeField or NodeVariable, just put more fields on the original.
            // Otherwise, keep the Chain node.
            match node.node_type() {
                NodeType::Field => {
                    node = FieldNode::new(self.tr(), chain.pos, &chain.to_string()).into();
                }
                NodeType::Variable => {
                    node = VariableNode::new(self.tr(), chain.pos, &chain.to_string()).into();
                }
                NodeType::Bool
                | NodeType::String
                | NodeType::Number
                | NodeType::Nil
                | NodeType::Dot => {
                    return self.errorf(format!(
                        "unexpected . after term {}",
                        strconv::quote(node.to_string())
                    ));
                }
                _ => node = chain.into(),
            }
        }
        Ok(Some(node))
    }

    /// Parses a literal, a field, a variable, a function name, a dot, a nil, a
    /// parenthesized pipeline or nothing.
    fn term(&mut self) -> R<Option<Node>> {
        let token = self.next_non_space();
        match token.typ {
            ItemType::Identifier => {
                let check_func = !self.t.mode.contains(SKIP_FUNC_CHECK);
                if check_func && !self.has_function(&token.val) {
                    return self.errorf(format!(
                        "function {} not defined",
                        strconv::quote(&token.val)
                    ));
                }
                let mut id = IdentifierNode::new(&token.val).set_pos(token.pos);
                id.tr = self.tr();
                Ok(Some(id.into()))
            }
            ItemType::Dot => Ok(Some(
                DotNode {
                    pos: token.pos,
                    tr: self.tr(),
                }
                .into(),
            )),
            ItemType::Nil => Ok(Some(
                NilNode {
                    pos: token.pos,
                    tr: self.tr(),
                }
                .into(),
            )),
            ItemType::Variable => self.use_var(token.pos, &token.val).map(Some),
            ItemType::Field => Ok(Some(
                FieldNode::new(self.tr(), token.pos, &token.val).into(),
            )),
            ItemType::Bool => Ok(Some(
                BoolNode {
                    pos: token.pos,
                    tr: self.tr(),
                    true_: token.val == "true",
                }
                .into(),
            )),
            ItemType::CharConstant | ItemType::Complex | ItemType::Number => {
                match NumberNode::new(self.tr(), token.pos, &token.val, token.typ) {
                    Ok(n) => Ok(Some(n.into())),
                    Err(e) => self.errorf(e),
                }
            }
            ItemType::LeftParen => {
                if self.stack_depth >= self.t.max_stack_depth {
                    return self.errorf("max expression depth exceeded".to_owned());
                }
                self.stack_depth += 1;
                let r = self.nested(|p| p.pipeline("parenthesized pipeline", ItemType::RightParen));
                self.stack_depth -= 1;
                r.map(|p| Some(p.into()))
            }
            ItemType::String | ItemType::RawString => match unquote_string(&token.val) {
                Ok(s) => Ok(Some(
                    StringNode {
                        pos: token.pos,
                        tr: self.tr(),
                        quoted: token.val,
                        text: s,
                    }
                    .into(),
                )),
                Err(e) => self.errorf(e),
            },
            _ => {
                self.backup();
                Ok(None)
            }
        }
    }

    fn has_function(&self, name: &str) -> bool {
        self.funcs.iter().any(|f| f.has_function(name))
    }

    /// Returns a node for a variable reference. Errors if the variable is not
    /// defined.
    fn use_var(&mut self, pos: Pos, name: &str) -> R<Node> {
        let v = VariableNode::new(self.tr(), pos, name);
        if self.vars.iter().any(|n| *n == v.ident[0]) {
            return Ok(v.into());
        }
        let q = strconv::quote(&v.ident[0]);
        self.errorf(format!("undefined variable {q}"))
    }
}

fn unquote_string(s: &str) -> Result<String, String> {
    match strconv::unquote(s) {
        Ok(b) => Ok(String::from_utf8_lossy(&b).into_owned()),
        Err(e) => Err(e.to_string()),
    }
}
