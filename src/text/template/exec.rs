//! Template execution (Go `text/template` `exec.go`).

use super::funcs::{self, can_be_nil, good_func, indirect, indirect_interface};
use super::parse::{
    self, BranchNode, ChainNode, CommandNode, FieldNode, IdentifierNode, ListNode, Node, NodeType,
    NumberNode, PipeNode, Pos, TemplateNode, VariableNode,
};
use super::value::{CallError, FuncError, Kind, Type, Value};
use super::verbs;
use super::{MissingKey, Template};
use crate::strconv;
use std::io::{self, Write};
use std::sync::{Arc, OnceLock};

/// The maximum template call depth (Go `maxExecDepth`).
pub(crate) const MAX_EXEC_DEPTH: usize = 100_000;

/// An error that occurred while executing a template (Go
/// `template.ExecError`).
#[derive(Clone, Debug)]
pub struct ExecError {
    /// Name of the template.
    pub name: String,
    /// The pre-formatted error.
    pub err: FuncError,
}

impl ExecError {
    /// The error text (Go `ExecError.Error`).
    pub fn error(&self) -> String {
        self.err.to_string()
    }
    /// The underlying error (Go `ExecError.Unwrap`).
    pub fn unwrap(&self) -> &FuncError {
        &self.err
    }
}

impl std::fmt::Display for ExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.err.fmt(f)
    }
}

impl std::error::Error for ExecError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.err)
    }
}

/// Non-local exits of the walk: Go uses panics for these.
pub(crate) enum Unwind {
    Exec(ExecError),
    Write(io::Error),
    Break,
    Continue,
}

type R<T> = Result<T, Unwind>;

/// A node, or part of one, that errors can point at.
pub(crate) trait Located: Sync {
    fn pos(&self) -> Pos;
    fn tree_info(&self) -> &parse::Tr;
    fn describe(&self) -> String;
}

macro_rules! located {
    ($($t:ty),+) => { $(
        impl Located for $t {
            fn pos(&self) -> Pos { self.pos }
            fn tree_info(&self) -> &parse::Tr { &self.tr }
            fn describe(&self) -> String { self.to_string() }
        }
    )+ };
}
located!(
    PipeNode,
    CommandNode,
    ListNode,
    FieldNode,
    ChainNode,
    VariableNode,
    IdentifierNode,
    NumberNode,
    TemplateNode,
    parse::RangeNode
);

impl Located for Node {
    fn pos(&self) -> Pos {
        self.position()
    }
    fn tree_info(&self) -> &parse::Tr {
        self.tree()
    }
    fn describe(&self) -> String {
        self.to_string()
    }
}

struct Variable {
    name: String,
    value: Value,
}

pub(crate) struct State<'t, 'w> {
    tmpl: Template,
    wr: &'w mut dyn Write,
    node: Option<&'t dyn Located>,
    vars: Vec<Variable>,
    depth: usize,
    /// Recursion depth of `walk` and `eval_pipeline` on the native stack.
    nest: usize,
    /// Whether this state runs on the large worker stack already.
    on_big: bool,
    /// Address near the base of the worker stack (0 on the caller's stack).
    stack_base: usize,
}

/// Nesting at which execution moves to a thread with a large stack. Go grows
/// goroutine stacks on demand; Rust cannot, and a template may recurse up to
/// [`MAX_EXEC_DEPTH`] levels.
const BIG_STACK_NEST: usize = 48;
/// Stack size of the worker thread (virtual memory, committed on use).
const BIG_STACK_BYTES: usize = 1 << 30;
/// Execution stops with an error once it has used this much of the worker's
/// stack, rather than overflowing it.
const STACK_LIMIT_BYTES: usize = BIG_STACK_BYTES / 10 * 9;

/// A message from the worker thread executing on the large stack.
enum Msg<T> {
    Write(Vec<u8>, std::sync::mpsc::SyncSender<io::Result<()>>),
    Done(R<T>, Vec<Variable>),
}

/// The writer of a worker state: forwards writes to the caller's thread.
struct ChanWriter<T> {
    tx: std::sync::mpsc::Sender<Msg<T>>,
}

impl<T> Write for ChanWriter<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let (rtx, rrx) = std::sync::mpsc::sync_channel(1);
        self.tx
            .send(Msg::Write(buf.to_vec(), rtx))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "template executor stopped"))?;
        match rrx.recv() {
            Ok(r) => r.map(|()| buf.len()),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "template executor stopped",
            )),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn missing_val_type() -> Type {
    static T: OnceLock<Type> = OnceLock::new();
    T.get_or_init(|| {
        Type::named(
            "template",
            "missingValType",
            Type::struct_of(Vec::new()),
            Vec::new(),
        )
    })
    .clone()
}

fn missing_val() -> Value {
    Value::struct_(&missing_val_type(), Vec::new())
}

fn is_missing(v: &Value) -> bool {
    v.is_valid() && v.type_() == Some(&missing_val_type())
}

/// The value as the pipeline would print it, or `None` if it can't be
/// printed (Go `printableValue`).
pub(crate) fn printable_value(v: &Value) -> Option<Value> {
    let mut v = v.clone();
    if v.kind() == Kind::Pointer {
        v = indirect(&v).0; // fmt handles nil.
    }
    if !v.is_valid() {
        return Some(Value::string("<no value>"));
    }
    let t = v.type_().expect("valid").clone();
    if !t.implements(&Type::error()) && !t.implements(&Type::stringer()) {
        let pt = Type::ptr_to(t);
        if v.can_addr() && (pt.implements(&Type::error()) || pt.implements(&Type::stringer())) {
            v = v.addr();
        } else if matches!(v.kind(), Kind::Chan | Kind::Func) {
            return None;
        }
    }
    Some(v.interface())
}

impl<'t, 'w> State<'t, 'w> {
    pub(crate) fn new(tmpl: Template, wr: &'w mut dyn Write, dot: Value) -> State<'t, 'w> {
        State {
            tmpl,
            wr,
            node: None,
            vars: vec![Variable {
                name: "$".to_owned(),
                value: dot,
            }],
            depth: 0,
            nest: 0,
            on_big: false,
            stack_base: 0,
        }
    }

    /// Runs `f` on a thread with a large stack, forwarding its writes to this
    /// state's writer, and returns its result. The variables the worker
    /// leaves behind replace this state's.
    fn run_on_big_stack<T, F>(&mut self, f: F) -> R<T>
    where
        T: Send,
        F: for<'x> FnOnce(&mut State<'t, 'x>) -> R<T> + Send,
    {
        let tmpl = self.tmpl.clone();
        let node = self.node;
        let vars = std::mem::take(&mut self.vars);
        let depth = self.depth;
        let nest = self.nest;
        let spawned = std::thread::scope(|scope| {
            let (tx, rx) = std::sync::mpsc::channel::<Msg<T>>();
            let worker_tx = tx.clone();
            let handle = std::thread::Builder::new()
                .stack_size(BIG_STACK_BYTES)
                .spawn_scoped(scope, move || {
                    let mut w = ChanWriter {
                        tx: worker_tx.clone(),
                    };
                    let marker = 0u8;
                    let mut st = State {
                        tmpl,
                        wr: &mut w,
                        node,
                        vars,
                        depth,
                        nest,
                        on_big: true,
                        stack_base: std::ptr::from_ref(&marker) as usize,
                    };
                    let r = f(&mut st);
                    let _ = worker_tx.send(Msg::Done(r, std::mem::take(&mut st.vars)));
                });
            let handle = match handle {
                Ok(h) => h,
                Err(_) => return None,
            };
            drop(tx);
            let mut result = None;
            while let Ok(msg) = rx.recv() {
                match msg {
                    Msg::Write(buf, reply) => {
                        let _ = reply.send(self.wr.write_all(&buf));
                    }
                    Msg::Done(r, vars) => {
                        result = Some((r, vars));
                        break;
                    }
                }
            }
            if let Err(p) = handle.join() {
                std::panic::resume_unwind(p);
            }
            result
        });
        match spawned {
            Some((r, vars)) => {
                self.vars = vars;
                r
            }
            None => {
                self.vars = Vec::new();
                self.errorf("could not allocate stack space for deeply nested execution".to_owned())
            }
        }
    }

    /// Stops execution with an error before it can overflow the worker's
    /// stack (Go grows stacks instead).
    fn check_stack(&self) -> R<()> {
        if self.stack_base != 0 {
            let marker = 0u8;
            let here = std::ptr::from_ref(&marker) as usize;
            if self.stack_base.abs_diff(here) > STACK_LIMIT_BYTES {
                return self.errorf("exceeded the available stack space".to_owned());
            }
        }
        Ok(())
    }

    fn push(&mut self, name: &str, value: Value) {
        self.vars.push(Variable {
            name: name.to_owned(),
            value,
        });
    }

    fn mark(&self) -> usize {
        self.vars.len()
    }

    fn pop(&mut self, mark: usize) {
        self.vars.truncate(mark);
    }

    fn set_var(&mut self, name: &str, value: Value) -> R<()> {
        for i in (0..self.vars.len()).rev() {
            if self.vars[i].name == name {
                self.vars[i].value = value;
                return Ok(());
            }
        }
        self.errorf(format!("undefined variable: {name}"))
    }

    fn set_top_var(&mut self, n: usize, value: Value) {
        let len = self.vars.len();
        self.vars[len - n].value = value;
    }

    fn var_value(&self, name: &str) -> R<Value> {
        for i in (0..self.vars.len()).rev() {
            if self.vars[i].name == name {
                return Ok(self.vars[i].value.clone());
            }
        }
        self.errorf(format!("undefined variable: {name}"))
    }

    fn at(&mut self, node: &'t dyn Located) {
        self.node = Some(node);
    }

    /// Formats an error with the location and context of the current node.
    fn errorf<T>(&self, msg: String) -> R<T> {
        self.errorf_wrap(msg, None)
    }

    fn errorf_wrap<T>(
        &self,
        msg: String,
        source: Option<Arc<dyn std::error::Error + Send + Sync>>,
    ) -> R<T> {
        let name = self.tmpl.name().to_owned();
        let text = match self.node {
            None => format!("template: {name}: {msg}"),
            Some(n) => {
                let (location, context) = self.tmpl.error_context(n);
                format!(
                    "template: {location}: executing {} at <{context}>: {msg}",
                    strconv::quote(&name)
                )
            }
        };
        let err = match source {
            Some(s) => FuncError::wrap(text, s),
            None => FuncError::new(text),
        };
        Err(Unwind::Exec(ExecError { name, err }))
    }

    /// The error for executing a template that has no parse tree.
    pub(crate) fn incomplete(&mut self, name: &str) -> R<()> {
        self.errorf(format!(
            "{} is an incomplete or empty template",
            strconv::quote(name)
        ))
    }

    // ---- walking ------------------------------------------------------

    pub(crate) fn walk_list(&mut self, dot: &Value, list: &'t ListNode) -> R<()> {
        self.at(list);
        for node in &list.nodes {
            self.walk(dot, node)?;
        }
        Ok(())
    }

    /// Executes the tree rooted at `node`, writing to the output; `dot` is
    /// the current value.
    pub(crate) fn walk(&mut self, dot: &Value, node: &'t Node) -> R<()> {
        self.check_stack()?;
        self.nest += 1;
        let r = if self.nest == BIG_STACK_NEST && !self.on_big {
            self.run_on_big_stack(|st| st.walk_inner(dot, node))
        } else {
            self.walk_inner(dot, node)
        };
        self.nest -= 1;
        r
    }

    fn walk_inner(&mut self, dot: &Value, node: &'t Node) -> R<()> {
        self.at(node);
        match node {
            Node::Action(n) => {
                // Do not pop variables so they persist until next end.
                // Also, if the action declares variables, don't print the
                // result.
                let val = self.eval_pipeline(dot, Some(&n.pipe))?;
                if n.pipe.decl.is_empty() {
                    self.print_value(node, &val)?;
                }
                Ok(())
            }
            Node::Break(_) => Err(Unwind::Break),
            Node::Comment(_) => Ok(()),
            Node::Continue(_) => Err(Unwind::Continue),
            Node::If(n) => self.walk_if_or_with(NodeType::If, dot, n),
            Node::List(l) => self.walk_list(dot, l),
            Node::Range(n) => self.walk_range(dot, n),
            Node::Template(n) => self.walk_template(dot, n),
            Node::Text(n) => self.wr.write_all(&n.text).map_err(Unwind::Write),
            Node::With(n) => self.walk_if_or_with(NodeType::With, dot, n),
            _ => self.errorf(format!("unknown node: {node}")),
        }
    }

    fn walk_if_or_with(&mut self, typ: NodeType, dot: &Value, b: &'t BranchNode) -> R<()> {
        let m = self.mark();
        let r = self.walk_if_or_with_inner(typ, dot, b);
        self.pop(m);
        r
    }

    fn walk_if_or_with_inner(&mut self, typ: NodeType, dot: &Value, b: &'t BranchNode) -> R<()> {
        let val = self.eval_pipeline(dot, Some(&b.pipe))?;
        let (truth, ok) = funcs::is_true_value(&indirect_interface(&val));
        if !ok {
            return self.errorf(format!("if/with can't use {}", fmt_v(&val)));
        }
        if truth {
            if typ == NodeType::With {
                self.walk_list(&val, &b.list)
            } else {
                self.walk_list(dot, &b.list)
            }
        } else if let Some(e) = &b.else_list {
            self.walk_list(dot, e)
        } else {
            Ok(())
        }
    }

    fn walk_range(&mut self, dot: &Value, r: &'t parse::RangeNode) -> R<()> {
        self.at(r);
        let m = self.mark();
        let res = self.walk_range_inner(dot, r);
        self.pop(m);
        match res {
            Err(Unwind::Break) => Ok(()),
            other => other,
        }
    }

    fn one_iteration(
        &mut self,
        r: &'t parse::RangeNode,
        mark: usize,
        index: Value,
        elem: Value,
    ) -> R<()> {
        if !r.pipe.decl.is_empty() {
            if r.pipe.is_assign {
                // With two variables, index comes first. With one, we use the
                // element.
                if r.pipe.decl.len() > 1 {
                    self.set_var(&r.pipe.decl[0].ident[0], index.clone())?;
                } else {
                    self.set_var(&r.pipe.decl[0].ident[0], elem.clone())?;
                }
            } else {
                // Set top var (lexically the second if there are two) to the
                // element.
                self.set_top_var(1, elem.clone());
            }
        }
        if r.pipe.decl.len() > 1 {
            if r.pipe.is_assign {
                self.set_var(&r.pipe.decl[1].ident[0], elem.clone())?;
            } else {
                // Set next var (lexically the first if there are two) to the
                // index.
                self.set_top_var(2, index);
            }
        }
        let res = self.walk_list(&elem, &r.list);
        self.pop(mark);
        match res {
            Err(Unwind::Continue) => Ok(()),
            other => other,
        }
    }

    fn walk_range_inner(&mut self, dot: &Value, r: &'t parse::RangeNode) -> R<()> {
        let v = self.eval_pipeline(dot, Some(&r.pipe))?;
        let (val, _) = indirect(&v);
        let mark = self.mark();
        let two_vars = r.pipe.decl.len() > 1;
        match val.kind() {
            k if k.int_like() => {
                if two_vars {
                    return self.errorf(format!(
                        "can't use {} to iterate over more than one variable",
                        fmt_v(&val)
                    ));
                }
                let mut run = false;
                let ty = val.type_().expect("valid").clone();
                if k.is_int() {
                    let n = val.as_int();
                    let mut i = 0i64;
                    while i < n {
                        run = true;
                        self.one_iteration(r, mark, Value::nil(), Value::int_of(&ty, i))?;
                        i += 1;
                    }
                } else {
                    let n = val.as_uint();
                    let mut i = 0u64;
                    while i < n {
                        run = true;
                        self.one_iteration(r, mark, Value::nil(), Value::uint_of(&ty, i))?;
                        i += 1;
                    }
                }
                if run {
                    return Ok(());
                }
            }
            Kind::Array | Kind::Slice => {
                if !val.is_empty() {
                    for i in 0..val.len() {
                        self.one_iteration(r, mark, Value::int(i as i64), val.index(i))?;
                    }
                    return Ok(());
                }
            }
            Kind::Map => {
                if !val.is_empty() {
                    for (k, v) in val.map_entries() {
                        self.one_iteration(r, mark, k, v)?;
                    }
                    return Ok(());
                }
            }
            Kind::Chan => {
                if !val.is_nil() {
                    if val.type_().expect("valid").chan_dir() == Some(super::value::ChanDir::Send) {
                        return self
                            .errorf(format!("range over send-only channel {}", fmt_v(&val)));
                    }
                    let mut i = 0i64;
                    while let Some(elem) = val.recv() {
                        self.one_iteration(r, mark, Value::int(i), elem)?;
                        i += 1;
                    }
                    if i > 0 {
                        return Ok(());
                    }
                }
            }
            Kind::Invalid => {} // An invalid value is likely a nil map, etc. and acts like an empty map.
            Kind::Func => {
                if let Some(seq) = val.as_seq() {
                    if two_vars {
                        return self.errorf(format!(
                            "can't use {} iterate over more than one variable",
                            fmt_v(&val)
                        ));
                    }
                    let mut run = false;
                    let mut result: R<()> = Ok(());
                    seq(&mut |v| {
                        run = true;
                        match self.one_iteration(r, mark, Value::nil(), v) {
                            Ok(()) => true,
                            Err(e) => {
                                result = Err(e);
                                false
                            }
                        }
                    });
                    result?;
                    if run {
                        return Ok(());
                    }
                } else if let Some(seq) = val.as_seq2() {
                    let mut run = false;
                    let mut result: R<()> = Ok(());
                    seq(&mut |i, v| {
                        run = true;
                        let res = if two_vars {
                            self.one_iteration(r, mark, i, v)
                        } else {
                            self.one_iteration(r, mark, Value::nil(), i)
                        };
                        match res {
                            Ok(()) => true,
                            Err(e) => {
                                result = Err(e);
                                false
                            }
                        }
                    });
                    result?;
                    if run {
                        return Ok(());
                    }
                } else {
                    return self.errorf(format!("range can't iterate over {}", fmt_v(&val)));
                }
            }
            _ => return self.errorf(format!("range can't iterate over {}", fmt_v(&val))),
        }
        if let Some(e) = &r.else_list {
            return self.walk_list(dot, e);
        }
        Ok(())
    }

    fn walk_template(&mut self, dot: &Value, t: &'t TemplateNode) -> R<()> {
        self.at(t);
        let Some(tmpl) = self.tmpl.lookup(&t.name) else {
            return self.errorf(format!("template {} not defined", strconv::quote(&t.name)));
        };
        if self.depth == MAX_EXEC_DEPTH {
            return self.errorf(format!(
                "exceeded maximum template depth ({MAX_EXEC_DEPTH})"
            ));
        }
        // Variables declared by the pipeline persist until the end of the
        // template call.
        let dot = self.eval_pipeline(dot, t.pipe.as_ref())?;
        let Some(tree) = tmpl.tree() else {
            return self.errorf(format!(
                "{} is an incomplete or empty template",
                strconv::quote(tmpl.name())
            ));
        };
        let Some(root) = tree.root.as_ref() else {
            return self.errorf(format!(
                "{} is an incomplete or empty template",
                strconv::quote(tmpl.name())
            ));
        };
        let mut new_state = State {
            tmpl,
            wr: &mut *self.wr,
            node: None,
            vars: vec![Variable {
                name: "$".to_owned(),
                value: dot.clone(),
            }],
            depth: self.depth + 1,
            nest: self.nest,
            on_big: self.on_big,
            stack_base: self.stack_base,
        };
        new_state.walk_list(&dot, root)
    }

    // ---- evaluation ---------------------------------------------------

    /// Evaluates a pipeline; declared variables are pushed or assigned.
    pub(crate) fn eval_pipeline(&mut self, dot: &Value, pipe: Option<&'t PipeNode>) -> R<Value> {
        self.check_stack()?;
        self.nest += 1;
        let r = if self.nest == BIG_STACK_NEST && !self.on_big {
            self.run_on_big_stack(|st| st.eval_pipeline_inner(dot, pipe))
        } else {
            self.eval_pipeline_inner(dot, pipe)
        };
        self.nest -= 1;
        r
    }

    fn eval_pipeline_inner(&mut self, dot: &Value, pipe: Option<&'t PipeNode>) -> R<Value> {
        let Some(pipe) = pipe else {
            return Ok(Value::nil());
        };
        self.at(pipe);
        let mut value = missing_val();
        for cmd in &pipe.cmds {
            value = self.eval_command(dot, cmd, &value)?;
            // If the object has type interface{}, dig down one level to the
            // thing inside.
            if value.kind() == Kind::Interface && value.type_().expect("valid").num_method() == 0 {
                value = value.elem(); // Lovely!
            }
        }
        for variable in &pipe.decl {
            if pipe.is_assign {
                self.set_var(&variable.ident[0], value.clone())?;
            } else {
                self.push(&variable.ident[0], value.clone());
            }
        }
        Ok(value)
    }

    fn not_a_function(&self, args: &[Node], final_: &Value) -> R<()> {
        if args.len() > 1 || !is_missing(final_) {
            return self.errorf(format!("can't give argument to non-function {}", args[0]));
        }
        Ok(())
    }

    fn eval_command(&mut self, dot: &Value, cmd: &'t CommandNode, final_: &Value) -> R<Value> {
        let first_word = &cmd.args[0];
        match first_word {
            Node::Field(n) => return self.eval_field_node(dot, n, &cmd.args, final_),
            Node::Chain(n) => return self.eval_chain_node(dot, n, &cmd.args, final_),
            Node::Identifier(n) => return self.eval_function(dot, n, cmd, Some(&cmd.args), final_),
            Node::Pipe(n) => {
                self.not_a_function(&cmd.args, final_)?;
                return self.eval_pipeline(dot, Some(n));
            }
            Node::Variable(n) => return self.eval_variable_node(dot, n, Some(&cmd.args), final_),
            _ => {}
        }
        self.at(first_word);
        self.not_a_function(&cmd.args, final_)?;
        match first_word {
            Node::Bool(n) => Ok(Value::bool_(n.true_)),
            Node::Dot(_) => Ok(dot.clone()),
            Node::Nil(_) => self.errorf("nil is not a command".to_owned()),
            Node::Number(n) => self.ideal_constant(n),
            Node::String(n) => Ok(Value::string(&n.text)),
            _ => self.errorf(format!(
                "can't evaluate command {}",
                strconv::quote(first_word.to_string())
            )),
        }
    }

    fn ideal_constant(&mut self, constant: &'t NumberNode) -> R<Value> {
        // These are ideal constants but we don't know the type and we have no
        // context. (If it was a method argument, we'd know what we need.) The
        // syntax guides us to some extent.
        self.at(constant);
        if constant.is_complex {
            return Ok(Value::complex128(
                constant.complex128.re,
                constant.complex128.im,
            )); // incontrovertible.
        }
        if constant.is_float
            && !is_hex_int(&constant.text)
            && !is_rune_int(&constant.text)
            && constant.text.contains(['.', 'e', 'E', 'p', 'P'])
        {
            return Ok(Value::float64(constant.float64));
        }
        if constant.is_int {
            let n = constant.int64 as isize;
            if n as i64 != constant.int64 {
                return self.errorf(format!("{} overflows int", constant.text));
            }
            return Ok(Value::int(constant.int64));
        }
        if constant.is_uint {
            return self.errorf(format!("{} overflows int", constant.text));
        }
        Ok(Value::nil())
    }

    fn eval_field_node(
        &mut self,
        dot: &Value,
        field: &'t FieldNode,
        args: &'t [Node],
        final_: &Value,
    ) -> R<Value> {
        self.at(field);
        self.eval_field_chain(dot, dot, field, &field.ident, Some(args), final_)
    }

    fn eval_chain_node(
        &mut self,
        dot: &Value,
        chain: &'t ChainNode,
        args: &'t [Node],
        final_: &Value,
    ) -> R<Value> {
        self.at(chain);
        if chain.field.is_empty() {
            return self.errorf("internal error: no fields in evalChainNode".to_owned());
        }
        if chain.node.node_type() == NodeType::Nil {
            return self.errorf(format!("indirection through explicit nil in {chain}"));
        }
        // (pipe).Field1.Field2 has pipe as .Node, fields as .Field. Eval the
        // pipeline, then the fields.
        let pipe = self.eval_arg(dot, None, &chain.node)?;
        self.eval_field_chain(dot, &pipe, chain, &chain.field, Some(args), final_)
    }

    fn eval_variable_node(
        &mut self,
        dot: &Value,
        variable: &'t VariableNode,
        args: Option<&'t [Node]>,
        final_: &Value,
    ) -> R<Value> {
        // $x.Field has $x as the first ident, Field as the second. Eval the
        // var, then the fields.
        self.at(variable);
        let value = self.var_value(&variable.ident[0])?;
        if variable.ident.len() == 1 {
            self.not_a_function_opt(args, final_)?;
            return Ok(value);
        }
        self.eval_field_chain(dot, &value, variable, &variable.ident[1..], args, final_)
    }

    fn not_a_function_opt(&self, args: Option<&[Node]>, final_: &Value) -> R<()> {
        // Go indexes args[0] only when it has to report; nil args can't have
        // more than one element.
        match args {
            Some(a) => self.not_a_function(a, final_),
            None => {
                if !is_missing(final_) {
                    return self.errorf("can't give argument to non-function ".to_owned());
                }
                Ok(())
            }
        }
    }

    /// Evaluates `.Field1.Field2...` where all but the last field are plain
    /// accesses and the last may be a method call with arguments.
    fn eval_field_chain(
        &mut self,
        dot: &Value,
        receiver: &Value,
        node: &'t dyn Located,
        ident: &[String],
        args: Option<&'t [Node]>,
        final_: &Value,
    ) -> R<Value> {
        let n = ident.len();
        let mut receiver = receiver.clone();
        for name in &ident[..n - 1] {
            receiver = self.eval_field(dot, name, node, None, &missing_val(), &receiver)?;
        }
        // Now if it's a method, it gets the arguments.
        self.eval_field(dot, &ident[n - 1], node, args, final_, &receiver)
    }

    fn eval_function(
        &mut self,
        dot: &Value,
        node: &'t IdentifierNode,
        cmd: &'t dyn Located,
        args: Option<&'t [Node]>,
        final_: &Value,
    ) -> R<Value> {
        self.at(node);
        let name = &node.ident;
        let Some((function, is_builtin)) = funcs::find_function(name, &self.tmpl) else {
            return self.errorf(format!(
                "{} is not a defined function",
                strconv::quote(name)
            ));
        };
        self.eval_call(dot, function, is_builtin, cmd, name, args, final_)
    }

    /// Evaluates a field of the receiver: a method, a struct field or a map
    /// entry.
    fn eval_field(
        &mut self,
        dot: &Value,
        field_name: &str,
        node: &'t dyn Located,
        args: Option<&'t [Node]>,
        final_: &Value,
        receiver: &Value,
    ) -> R<Value> {
        if !receiver.is_valid() {
            if self.tmpl.missing_key() == MissingKey::Error {
                // Treat invalid value as missing map key.
                return self.errorf(format!(
                    "nil data; no entry for key {}",
                    strconv::quote(field_name)
                ));
            }
            return Ok(Value::nil());
        }
        let typ = receiver.type_().expect("valid").clone();
        let (receiver, is_nil) = indirect(receiver);
        if receiver.kind() == Kind::Interface && is_nil {
            // Calling a method on a nil interface can't work. The
            // MethodByName method call below would panic.
            return self.errorf(format!(
                "nil pointer evaluating {}.{field_name}",
                typ.type_string()
            ));
        }

        // Unless it's an interface, need to get to a value of type *T to guarantee
        // we see all methods of both T and *T.
        let mut ptr = receiver.clone();
        if ptr.kind() != Kind::Interface && ptr.kind() != Kind::Pointer && ptr.can_addr() {
            ptr = ptr.addr();
        }
        let method = if is_exported_name(field_name) {
            ptr.method_by_name(field_name)
        } else {
            Value::nil()
        };
        if method.is_valid() {
            return self.eval_call(dot, method, false, node, field_name, args, final_);
        }
        let has_args = args.is_some_and(|a| a.len() > 1) || !is_missing(final_);
        // It's not a method; must be a field of a struct or an element of a
        // map.
        match receiver.kind() {
            Kind::Struct => {
                let rt = receiver.type_().expect("valid").clone();
                if let Some(path) = rt.field_by_name(field_name) {
                    let field = receiver.field_by_index_err(&path);
                    // The last field of the path decides exportedness.
                    let t_field = field_at_path(&rt, &path);
                    if !t_field.is_exported() {
                        return self.errorf(format!(
                            "{field_name} is an unexported field of struct type {}",
                            typ.type_string()
                        ));
                    }
                    let field = match field {
                        Ok(f) => f,
                        Err(e) => return self.errorf(e),
                    };
                    // If it's a function, we must call it.
                    if has_args {
                        return self.errorf(format!(
                            "{field_name} has arguments but cannot be invoked as function"
                        ));
                    }
                    return Ok(field);
                }
            }
            Kind::Map => {
                // If it's a map, attempt to use the field name as a key.
                let name_val = Value::string(field_name);
                let key_t = receiver.type_().expect("valid").key().expect("map");
                if Type::string().assignable_to(&key_t) {
                    if has_args {
                        return self
                            .errorf(format!("{field_name} is not a method but has arguments"));
                    }
                    let mut result = receiver.map_index(&name_val);
                    if !result.is_valid() {
                        match self.tmpl.missing_key() {
                            MissingKey::Invalid => {
                                // Just use the invalid value.
                            }
                            MissingKey::ZeroValue => {
                                result = Value::zero(
                                    &receiver.type_().expect("valid").elem().expect("map"),
                                );
                            }
                            MissingKey::Error => {
                                return self.errorf(format!(
                                    "map has no entry for key {}",
                                    strconv::quote(field_name)
                                ));
                            }
                        }
                    }
                    return Ok(result);
                }
            }
            Kind::Pointer => {
                let etyp = receiver.type_().expect("valid").elem().expect("ptr");
                let field_exists =
                    etyp.kind() != Kind::Struct || etyp.field_by_name(field_name).is_some();
                if field_exists && is_nil {
                    return self.errorf(format!(
                        "nil pointer evaluating {}.{field_name}",
                        typ.type_string()
                    ));
                }
            }
            _ => {}
        }
        self.errorf(format!(
            "can't evaluate field {field_name} in type {}",
            typ.type_string()
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn eval_call(
        &mut self,
        dot: &Value,
        fun: Value,
        is_builtin: bool,
        node: &'t dyn Located,
        name: &str,
        args: Option<&'t [Node]>,
        final_: &Value,
    ) -> R<Value> {
        // Zeroth arg is function name/node; not passed to function.
        let args: &'t [Node] = match args {
            Some(a) => &a[1..],
            None => &[],
        };
        let sig = fun.type_().expect("function").sig().expect("function type");
        let mut num_in = args.len();
        if !is_missing(final_) {
            num_in += 1;
        }
        let mut num_fixed = args.len();
        if sig.variadic {
            num_fixed = sig.ins.len() - 1; // last arg is the variadic one.
            if num_in < num_fixed {
                return self.errorf(format!(
                    "wrong number of args for {name}: want at least {} got {}",
                    sig.ins.len() - 1,
                    args.len()
                ));
            }
        } else if num_in != sig.ins.len() {
            return self.errorf(format!(
                "wrong number of args for {name}: want {} got {num_in}",
                sig.ins.len()
            ));
        }
        if let Err(e) = good_func(name, &sig) {
            return self.errorf(e);
        }

        // Special case for builtin and/or, which short-circuit.
        if is_builtin && (name == "and" || name == "or") {
            let arg_type = sig.ins[0].clone();
            let mut v = Value::nil();
            for arg in args {
                v = self.eval_arg(dot, Some(&arg_type), arg)?;
                if funcs::truth(&v) == (name == "or") {
                    // This value was already unwrapped by the .Interface().(reflect.Value).
                    return Ok(v);
                }
            }
            if !is_missing(final_) {
                // The last argument to and/or is coming from the pipeline.
                // We didn't short circuit on an earlier argument, so we are
                // going to return this one.
                v = self.validate_type(final_, Some(&arg_type))?;
            }
            return Ok(v);
        }

        // Build the arg list.
        let mut argv: Vec<Value> = vec![Value::nil(); num_in];
        // Args must be evaluated. Fixed args first.
        let mut i = 0;
        while i < num_fixed && i < args.len() {
            argv[i] = self.eval_arg(dot, Some(&sig.ins[i]), &args[i])?;
            i += 1;
        }
        // Now the ... args.
        if sig.variadic {
            let arg_type = sig.ins[sig.ins.len() - 1].elem().expect("variadic slice");
            while i < args.len() {
                argv[i] = self.eval_arg(dot, Some(&arg_type), &args[i])?;
                i += 1;
            }
        }
        // Add final value if necessary.
        if !is_missing(final_) {
            let mut t = sig.ins[sig.ins.len() - 1].clone();
            if sig.variadic {
                if num_in - 1 < num_fixed {
                    // The added final argument corresponds to a fixed
                    // parameter of the function. Validate against the type
                    // of the actual parameter.
                    t = sig.ins[num_in - 1].clone();
                } else {
                    // The added final argument corresponds to the variadic
                    // part. Validate against the type of the elements of the
                    // variadic slice.
                    t = t.elem().expect("variadic slice");
                }
            }
            argv[i] = self.validate_type(final_, Some(&t))?;
        }

        let result = if is_builtin && name == "call" {
            let callee_name = if args.is_empty() {
                final_.as_string()
            } else {
                args[0].to_string()
            };
            let f = argv[0].clone();
            funcs::call(&callee_name, &f, &argv[1..])
        } else {
            fun.call(&argv)
        };
        match result {
            Ok(v) => Ok(v),
            Err(e) => {
                self.node = Some(node);
                match e {
                    CallError::Error(g) => {
                        let msg = format!("error calling {name}: {g}");
                        self.errorf_wrap(msg, Some(Arc::new(g)))
                    }
                    CallError::Panic(m) => {
                        let msg = format!("error calling {name}: {m}");
                        self.errorf_wrap(msg, Some(Arc::new(FuncError::new(m))))
                    }
                }
            }
        }
    }

    /// Checks that the value can be passed where `typ` is expected,
    /// dereferencing or taking its address as needed.
    fn validate_type(&mut self, value: &Value, typ: Option<&Type>) -> R<Value> {
        if !value.is_valid() {
            let Some(typ) = typ else {
                // An untyped nil interface{}. Accept as a proper nil value.
                return Ok(Value::nil());
            };
            if can_be_nil(typ) {
                // Like above, but use the zero value of the non-nil type.
                if typ.is_reflect_value() {
                    return Ok(Value::nil());
                }
                return Ok(Value::zero(typ));
            }
            return self.errorf(format!("invalid value; expected {}", typ.type_string()));
        }
        let Some(typ) = typ else {
            return Ok(value.clone());
        };
        if typ.is_reflect_value() {
            // Arguments of this type are passed through unchanged.
            return Ok(value.clone());
        }
        let vt = value.type_().expect("valid").clone();
        let mut value = value.clone();
        if !vt.assignable_to(typ) {
            if value.kind() == Kind::Interface && !value.is_nil() {
                value = value.elem();
                if value.type_().expect("valid").assignable_to(typ) {
                    return Ok(value);
                }
                // Otherwise, the underlying value doesn't implement the
                // required interface. Fall through to the checks below.
            }
            let vt = value.type_().expect("valid").clone();
            if value.kind() == Kind::Pointer && vt.elem().expect("ptr").assignable_to(typ) {
                value = value.elem();
                if !value.is_valid() {
                    return self.errorf(format!(
                        "dereference of nil pointer of type {}",
                        typ.type_string()
                    ));
                }
            } else if Type::ptr_to(vt.clone()).assignable_to(typ) && value.can_addr() {
                value = value.addr();
            } else {
                return self.errorf(format!(
                    "wrong type for value; expected {}; got {}",
                    typ.type_string(),
                    vt.type_string()
                ));
            }
        }
        Ok(value)
    }

    fn eval_arg(&mut self, dot: &Value, typ: Option<&Type>, n: &'t Node) -> R<Value> {
        self.at(n);
        match n {
            Node::Dot(_) => return self.validate_type(dot, typ),
            Node::Nil(_) => {
                if let Some(t) = typ {
                    if can_be_nil(t) {
                        return Ok(if t.is_reflect_value() {
                            Value::nil()
                        } else {
                            Value::zero(t)
                        });
                    }
                }
                return self.errorf(format!(
                    "cannot assign nil to {}",
                    typ.map(Type::type_string).unwrap_or_default()
                ));
            }
            Node::Field(arg) => {
                let v = self.eval_field_node(dot, arg, std::slice::from_ref(n), &missing_val())?;
                return self.validate_type(&v, typ);
            }
            Node::Variable(arg) => {
                let v = self.eval_variable_node(dot, arg, None, &missing_val())?;
                return self.validate_type(&v, typ);
            }
            Node::Pipe(arg) => {
                let v = self.eval_pipeline(dot, Some(arg))?;
                return self.validate_type(&v, typ);
            }
            Node::Identifier(arg) => {
                let v = self.eval_function(dot, arg, n, None, &missing_val())?;
                return self.validate_type(&v, typ);
            }
            Node::Chain(arg) => {
                let v = self.eval_chain_node(dot, arg, &[], &missing_val())?;
                return self.validate_type(&v, typ);
            }
            _ => {}
        }
        let typ = typ.expect("constant arguments have a parameter type");
        match typ.kind() {
            Kind::Bool => self.eval_bool(typ, n),
            Kind::Complex64 | Kind::Complex128 => self.eval_complex(typ, n),
            Kind::Float32 | Kind::Float64 => self.eval_float(typ, n),
            k if k.is_int() => self.eval_integer(typ, n),
            Kind::Interface if typ.num_method() == 0 => self.eval_empty_interface(dot, n),
            Kind::Struct if typ.is_reflect_value() => self.eval_empty_interface(dot, n),
            Kind::String => self.eval_string(typ, n),
            k if k.is_uint() => self.eval_unsigned_integer(typ, n),
            _ => self.errorf(format!(
                "can't handle {n} for arg of type {}",
                typ.type_string()
            )),
        }
    }

    fn eval_bool(&mut self, typ: &Type, n: &'t Node) -> R<Value> {
        self.at(n);
        if let Node::Bool(b) = n {
            return Ok(Value::named(typ, Value::bool_(b.true_)));
        }
        self.errorf(format!("expected bool; found {n}"))
    }

    fn eval_string(&mut self, typ: &Type, n: &'t Node) -> R<Value> {
        self.at(n);
        if let Node::String(s) = n {
            return Ok(Value::string_of(typ, &s.text));
        }
        self.errorf(format!("expected string; found {n}"))
    }

    fn eval_integer(&mut self, typ: &Type, n: &'t Node) -> R<Value> {
        self.at(n);
        if let Node::Number(num) = n {
            if num.is_int {
                return Ok(Value::int_of(typ, num.int64));
            }
        }
        self.errorf(format!("expected integer; found {n}"))
    }

    fn eval_unsigned_integer(&mut self, typ: &Type, n: &'t Node) -> R<Value> {
        self.at(n);
        if let Node::Number(num) = n {
            if num.is_uint {
                return Ok(Value::uint_of(typ, num.uint64));
            }
        }
        self.errorf(format!("expected unsigned integer; found {n}"))
    }

    fn eval_float(&mut self, typ: &Type, n: &'t Node) -> R<Value> {
        self.at(n);
        if let Node::Number(num) = n {
            if num.is_float {
                return Ok(Value::float_of(typ, num.float64));
            }
        }
        self.errorf(format!("expected float; found {n}"))
    }

    fn eval_complex(&mut self, typ: &Type, n: &'t Node) -> R<Value> {
        if let Node::Number(num) = n {
            if num.is_complex {
                return Ok(Value::complex_of(typ, num.complex128.re, num.complex128.im));
            }
        }
        self.errorf(format!("expected complex; found {n}"))
    }

    fn eval_empty_interface(&mut self, dot: &Value, n: &'t Node) -> R<Value> {
        self.at(n);
        match n {
            Node::Bool(b) => Ok(Value::bool_(b.true_)),
            Node::Dot(_) => Ok(dot.clone()),
            Node::Field(f) => self.eval_field_node(dot, f, &[], &missing_val()),
            Node::Identifier(i) => self.eval_function(dot, i, n, None, &missing_val()),
            Node::Nil(_) => {
                // NilNode is handled in evalArg, the only place that calls
                // here.
                self.errorf("evalEmptyInterface: nil (can't happen)".to_owned())
            }
            Node::Number(num) => self.ideal_constant(num),
            Node::String(s) => Ok(Value::string(&s.text)),
            Node::Variable(v) => self.eval_variable_node(dot, v, None, &missing_val()),
            Node::Pipe(p) => self.eval_pipeline(dot, Some(p)),
            _ => self.errorf(format!(
                "can't handle assignment of {n} to empty interface argument"
            )),
        }
    }

    /// Prints a value for an action.
    fn print_value(&mut self, n: &'t Node, v: &Value) -> R<()> {
        self.at(n);
        let Some(iface) = printable_value(v) else {
            return self.errorf(format!(
                "can't print {n} of type {}",
                v.type_().map(Type::type_string).unwrap_or_default()
            ));
        };
        let s = verbs::sprint(&[iface]);
        self.wr.write_all(s.as_bytes()).map_err(Unwind::Write)
    }
}

fn fmt_v(v: &Value) -> String {
    verbs::sprintf("%v", std::slice::from_ref(v))
}

fn is_rune_int(s: &str) -> bool {
    s.starts_with('\'')
}

fn is_hex_int(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() > 2 && b[0] == b'0' && (b[1] == b'x' || b[1] == b'X') && !s.contains(['p', 'P'])
}

fn is_exported_name(name: &str) -> bool {
    name.chars().next().is_some_and(|c| {
        if c.is_ascii() {
            c.is_ascii_uppercase()
        } else {
            crate::unicode::is_upper(c as i32)
        }
    })
}

fn field_at_path(t: &Type, path: &[usize]) -> super::value::Field {
    let mut ty = t.clone();
    let mut field = None;
    for &i in path {
        if ty.kind() == Kind::Pointer {
            ty = ty.elem().expect("elem");
        }
        let f = ty.fields()[i].clone();
        ty = f.ty.clone();
        field = Some(f);
    }
    field.expect("non-empty path")
}
