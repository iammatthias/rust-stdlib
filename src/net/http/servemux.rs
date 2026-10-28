//! Go 1.22+ `ServeMux`: patterns with methods, hosts and wildcards, a routing
//! tree, conflict detection, redirects for clean paths and trailing slashes,
//! and `405` replies carrying `Allow`.
#![allow(clippy::type_complexity)]
use super::handler::{handler_func, Handler, ResponseWriter};
use super::header::BoxError;
use super::request::Request;
use super::util::{error, not_found_handler, redirect_handler};
use super::{status::*, status_text};
use crate::net::url::{self, Url};
use crate::strconv::quote;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, RwLock},
};

/// One path segment of a [`Pattern`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Segment {
    /// Literal, wildcard name, or "/" for `{$}`.
    pub s: String,
    pub wild: bool,
    pub multi: bool,
}

/// Go's unexported `pattern`.
#[derive(Debug)]
pub struct Pattern {
    pub(crate) str: String,
    pub(crate) method: String,
    pub(crate) host: String,
    pub(crate) segments: Vec<Segment>,
    pub(crate) loc: String,
}

impl std::fmt::Display for Pattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.str)
    }
}

fn valid_method(m: &str) -> bool {
    super::token(m)
}

/// Go's `cleanPath`.
pub(crate) fn clean_path(p: &str) -> String {
    if p.is_empty() {
        return "/".into();
    }
    let p = if p.starts_with('/') {
        p.to_owned()
    } else {
        format!("/{p}")
    };
    let mut np = crate::path::clean(&p);
    if p.ends_with('/') && np != "/" {
        if p.len() == np.len() + 1 && p.starts_with(&np) {
            np = p;
        } else {
            np.push('/');
        }
    }
    np
}

fn path_unescape(path: &str) -> String {
    url::path_unescape(path).unwrap_or_else(|_| path.to_owned())
}

fn is_valid_wildcard_name(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    for (i, c) in s.chars().enumerate() {
        if !c.is_alphabetic() && c != '_' && (i == 0 || !c.is_numeric()) {
            return false;
        }
    }
    true
}

impl Pattern {
    /// Go's `parsePattern`.
    pub(crate) fn parse(s: &str) -> Result<Pattern, BoxError> {
        if s.is_empty() {
            return Err("empty pattern".into());
        }
        let mut off = 0usize;
        let res = Self::parse_inner(s, &mut off);
        res.map_err(|e| format!("at offset {off}: {e}").into())
    }

    fn parse_inner(s: &str, off: &mut usize) -> Result<Pattern, String> {
        let (method, mut rest, found) = match s.find([' ', '\t']) {
            Some(i) => (&s[..i], s[i + 1..].trim_start_matches([' ', '\t']), true),
            None => ("", s, false),
        };
        if !method.is_empty() && !valid_method(method) {
            return Err(format!("invalid method {}", quote(method)));
        }
        let mut p = Pattern {
            str: s.to_owned(),
            method: method.to_owned(),
            host: String::new(),
            segments: Vec::new(),
            loc: String::new(),
        };
        if found {
            *off = method.len() + 1;
        }
        let Some(i) = rest.find('/') else {
            return Err("host/path missing /".into());
        };
        p.host = rest[..i].to_owned();
        rest = &rest[i..];
        if let Some(j) = p.host.find('{') {
            *off += j;
            return Err("host contains '{' (missing initial '/'?)".into());
        }
        *off += i;
        if !method.is_empty() && method != "CONNECT" && rest != clean_path(rest) {
            return Err("non-CONNECT pattern with unclean path can never match".into());
        }
        let mut seen: BTreeSet<String> = BTreeSet::new();
        while !rest.is_empty() {
            rest = &rest[1..];
            *off = s.len() - rest.len();
            if rest.is_empty() {
                p.segments.push(Segment {
                    s: String::new(),
                    wild: true,
                    multi: true,
                });
                break;
            }
            let i = rest.find('/').unwrap_or(rest.len());
            let (seg, r) = rest.split_at(i);
            rest = r;
            match seg.find('{') {
                None => p.segments.push(Segment {
                    s: path_unescape(seg),
                    wild: false,
                    multi: false,
                }),
                Some(i) => {
                    if i != 0 {
                        return Err("bad wildcard segment (must start with '{')".into());
                    }
                    if !seg.ends_with('}') {
                        return Err("bad wildcard segment (must end with '}')".into());
                    }
                    let name = &seg[1..seg.len() - 1];
                    if name == "$" {
                        if !rest.is_empty() {
                            return Err("{$} not at end".into());
                        }
                        p.segments.push(Segment {
                            s: "/".into(),
                            wild: false,
                            multi: false,
                        });
                        break;
                    }
                    let (name, multi) = match name.strip_suffix("...") {
                        Some(n) => (n, true),
                        None => (name, false),
                    };
                    if multi && !rest.is_empty() {
                        return Err("{...} wildcard not at end".into());
                    }
                    if name.is_empty() {
                        return Err("empty wildcard".into());
                    }
                    if !is_valid_wildcard_name(name) {
                        return Err(format!("bad wildcard name {}", quote(name)));
                    }
                    if !seen.insert(name.to_owned()) {
                        return Err(format!("duplicate wildcard name {}", quote(name)));
                    }
                    p.segments.push(Segment {
                        s: name.to_owned(),
                        wild: true,
                        multi,
                    });
                }
            }
        }
        Ok(p)
    }

    fn last_segment(&self) -> &Segment {
        &self.segments[self.segments.len() - 1]
    }

    /// Index of the named wildcard `name` among the pattern's named wildcards.
    pub(crate) fn wildcard_index(&self, name: &str) -> Option<usize> {
        let mut i = 0;
        for seg in &self.segments {
            if seg.wild && !seg.s.is_empty() {
                if name == seg.s {
                    return Some(i);
                }
                i += 1;
            }
        }
        None
    }

    fn conflicts_with(&self, p2: &Pattern) -> bool {
        if self.host != p2.host {
            return false;
        }
        let rel = self.compare_paths_and_methods(p2);
        rel == Rel::Equivalent || rel == Rel::Overlaps
    }

    fn compare_paths_and_methods(&self, p2: &Pattern) -> Rel {
        let mrel = self.compare_methods(p2);
        if mrel == Rel::Disjoint {
            return Rel::Disjoint;
        }
        combine(mrel, self.compare_paths(p2))
    }

    fn compare_methods(&self, p2: &Pattern) -> Rel {
        if self.method == p2.method {
            return Rel::Equivalent;
        }
        if self.method.is_empty() {
            return Rel::MoreGeneral;
        }
        if p2.method.is_empty() {
            return Rel::MoreSpecific;
        }
        if self.method == "GET" && p2.method == "HEAD" {
            return Rel::MoreGeneral;
        }
        if p2.method == "GET" && self.method == "HEAD" {
            return Rel::MoreSpecific;
        }
        Rel::Disjoint
    }

    fn compare_paths(&self, p2: &Pattern) -> Rel {
        if self.segments.len() != p2.segments.len()
            && !self.last_segment().multi
            && !p2.last_segment().multi
        {
            return Rel::Disjoint;
        }
        let mut rel = Rel::Equivalent;
        let (mut s1, mut s2) = (&self.segments[..], &p2.segments[..]);
        while !s1.is_empty() && !s2.is_empty() {
            rel = combine(rel, compare_segments(&s1[0], &s2[0]));
            if rel == Rel::Disjoint {
                return rel;
            }
            s1 = &s1[1..];
            s2 = &s2[1..];
        }
        if s1.is_empty() && s2.is_empty() {
            return rel;
        }
        if s1.len() < s2.len() && self.last_segment().multi {
            return combine(rel, Rel::MoreGeneral);
        }
        if s2.len() < s1.len() && p2.last_segment().multi {
            return combine(rel, Rel::MoreSpecific);
        }
        Rel::Disjoint
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rel {
    Equivalent,
    MoreGeneral,
    MoreSpecific,
    Disjoint,
    Overlaps,
}
impl Rel {
    fn name(self) -> &'static str {
        match self {
            Rel::Equivalent => "equivalent",
            Rel::MoreGeneral => "moreGeneral",
            Rel::MoreSpecific => "moreSpecific",
            Rel::Disjoint => "disjoint",
            Rel::Overlaps => "overlaps",
        }
    }
}

fn compare_segments(s1: &Segment, s2: &Segment) -> Rel {
    if s1.multi && s2.multi {
        return Rel::Equivalent;
    }
    if s1.multi {
        return Rel::MoreGeneral;
    }
    if s2.multi {
        return Rel::MoreSpecific;
    }
    if s1.wild && s2.wild {
        return Rel::Equivalent;
    }
    if s1.wild {
        return if s2.s == "/" {
            Rel::Disjoint
        } else {
            Rel::MoreGeneral
        };
    }
    if s2.wild {
        return if s1.s == "/" {
            Rel::Disjoint
        } else {
            Rel::MoreSpecific
        };
    }
    if s1.s == s2.s {
        Rel::Equivalent
    } else {
        Rel::Disjoint
    }
}

fn inverse(r: Rel) -> Rel {
    match r {
        Rel::MoreSpecific => Rel::MoreGeneral,
        Rel::MoreGeneral => Rel::MoreSpecific,
        o => o,
    }
}

fn combine(r1: Rel, r2: Rel) -> Rel {
    match r1 {
        Rel::Equivalent => r2,
        Rel::Disjoint => Rel::Disjoint,
        Rel::Overlaps => {
            if r2 == Rel::Disjoint {
                Rel::Disjoint
            } else {
                Rel::Overlaps
            }
        }
        Rel::MoreGeneral | Rel::MoreSpecific => {
            if r2 == Rel::Equivalent {
                r1
            } else if r2 == inverse(r1) {
                Rel::Overlaps
            } else {
                r2
            }
        }
    }
}

fn write_segment(b: &mut String, s: &Segment) {
    b.push('/');
    if !s.multi && s.s != "/" {
        b.push_str(&s.s);
    }
}
fn write_matching_path(b: &mut String, segs: &[Segment]) {
    for s in segs {
        write_segment(b, s);
    }
}
fn common_path(p1: &Pattern, p2: &Pattern) -> String {
    let mut b = String::new();
    let (mut s1, mut s2) = (&p1.segments[..], &p2.segments[..]);
    while !s1.is_empty() && !s2.is_empty() {
        if s1[0].wild {
            write_segment(&mut b, &s2[0]);
        } else {
            write_segment(&mut b, &s1[0]);
        }
        s1 = &s1[1..];
        s2 = &s2[1..];
    }
    if !s1.is_empty() {
        write_matching_path(&mut b, s1);
    } else if !s2.is_empty() {
        write_matching_path(&mut b, s2);
    }
    b
}
fn difference_path(p1: &Pattern, p2: &Pattern) -> String {
    let mut b = String::new();
    let (mut s1, mut s2) = (&p1.segments[..], &p2.segments[..]);
    while !s1.is_empty() && !s2.is_empty() {
        let (a, c) = (&s1[0], &s2[0]);
        if a.multi && c.multi {
            b.push('/');
            return b;
        }
        if a.multi && !c.multi {
            b.push('/');
            if c.s == "/" {
                if !a.s.is_empty() {
                    b.push_str(&a.s);
                } else {
                    b.push('x');
                }
            }
            return b;
        }
        // A wildcard against a literal that spells the same text needs a
        // longer path to tell them apart; every other pair shows the segment.
        if a.wild && !c.wild && !c.multi && a.s == c.s {
            b.push('/');
            b.push_str(&c.s);
            b.push('x');
        } else {
            write_segment(&mut b, a);
        }
        s1 = &s1[1..];
        s2 = &s2[1..];
    }
    if !s1.is_empty() {
        write_matching_path(&mut b, s1);
    } else if !s2.is_empty() {
        write_matching_path(&mut b, s2);
    }
    b
}

fn describe_conflict(p1: &Pattern, p2: &Pattern) -> String {
    let mrel = p1.compare_methods(p2);
    let prel = p1.compare_paths(p2);
    let rel = combine(mrel, prel);
    if rel == Rel::Equivalent {
        return format!("{p1} matches the same requests as {p2}");
    }
    if prel == Rel::Overlaps {
        return format!(
            "{p1} and {p2} both match some paths, like {}.\nBut neither is more specific than the other.\n{p1} matches {}, but {p2} doesn't.\n{p2} matches {}, but {p1} doesn't.",
            quote(common_path(p1, p2)),
            quote(difference_path(p1, p2)),
            quote(difference_path(p2, p1)),
        );
    }
    if mrel == Rel::MoreGeneral && prel == Rel::MoreSpecific {
        return format!(
            "{p1} matches more methods than {p2}, but has a more specific path pattern"
        );
    }
    if mrel == Rel::MoreSpecific && prel == Rel::MoreGeneral {
        return format!(
            "{p1} matches fewer methods than {p2}, but has a more general path pattern"
        );
    }
    format!(
        "bug: unexpected way for two patterns {p1} and {p2} to conflict: methods {}, paths {}",
        mrel.name(),
        prel.name()
    )
}

// ------------------------------------------------------------ routing tree

#[derive(Default)]
struct Node {
    pattern: Option<Arc<Pattern>>,
    handler: Option<Arc<dyn Handler>>,
    children: BTreeMap<String, Node>,
    multi_child: Option<Box<Node>>,
    empty_child: Option<Box<Node>>,
}

impl Node {
    fn add_pattern(&mut self, p: Arc<Pattern>, h: Arc<dyn Handler>) {
        let host = p.host.clone();
        let method = p.method.clone();
        let n = self.add_child(&host).add_child(&method);
        n.add_segments(&p.segments, &p, &h);
    }
    fn add_segments(&mut self, segs: &[Segment], p: &Arc<Pattern>, h: &Arc<dyn Handler>) {
        if segs.is_empty() {
            self.pattern = Some(p.clone());
            self.handler = Some(h.clone());
            return;
        }
        let seg = &segs[0];
        if seg.multi {
            let c = Node {
                pattern: Some(p.clone()),
                handler: Some(h.clone()),
                ..Node::default()
            };
            self.multi_child = Some(Box::new(c));
        } else if seg.wild {
            self.add_child("").add_segments(&segs[1..], p, h);
        } else {
            self.add_child(&seg.s).add_segments(&segs[1..], p, h);
        }
    }
    fn add_child(&mut self, key: &str) -> &mut Node {
        if key.is_empty() {
            return self.empty_child.get_or_insert_with(Box::default);
        }
        self.children.entry(key.to_owned()).or_default()
    }
    fn find_child(&self, key: &str) -> Option<&Node> {
        if key.is_empty() {
            return self.empty_child.as_deref();
        }
        self.children.get(key)
    }

    fn match_root(&self, host: &str, method: &str, path: &str) -> Option<(&Node, Vec<String>)> {
        if !host.is_empty() {
            if let Some(r) = self
                .find_child(host)
                .and_then(|n| n.match_method_and_path(method, path))
            {
                return Some(r);
            }
        }
        self.empty_child
            .as_deref()
            .and_then(|n| n.match_method_and_path(method, path))
    }

    fn match_method_and_path(&self, method: &str, path: &str) -> Option<(&Node, Vec<String>)> {
        if let Some(r) = self
            .find_child(method)
            .and_then(|n| n.match_path(path, Vec::new()))
        {
            return Some(r);
        }
        if method == "HEAD" {
            if let Some(r) = self
                .find_child("GET")
                .and_then(|n| n.match_path(path, Vec::new()))
            {
                return Some(r);
            }
        }
        self.empty_child
            .as_deref()
            .and_then(|n| n.match_path(path, Vec::new()))
    }

    fn match_path(&self, path: &str, matches: Vec<String>) -> Option<(&Node, Vec<String>)> {
        if path.is_empty() {
            return self.pattern.as_ref().map(|_| (self, matches));
        }
        let (seg, rest) = first_segment(path);
        if let Some(r) = self
            .find_child(&seg)
            .and_then(|n| n.match_path(&rest, matches.clone()))
        {
            return Some(r);
        }
        if seg != "/" {
            if let Some(e) = self.empty_child.as_deref() {
                let mut m = matches.clone();
                m.push(seg.clone());
                if let Some(r) = e.match_path(&rest, m) {
                    return Some(r);
                }
            }
        }
        if let Some(c) = self.multi_child.as_deref() {
            let mut m = matches;
            if c.pattern
                .as_ref()
                .is_some_and(|p| !p.last_segment().s.is_empty())
            {
                m.push(path_unescape(&path[1..]));
            }
            return Some((c, m));
        }
        None
    }

    fn matching_methods(&self, host: &str, path: &str, set: &mut BTreeSet<String>) {
        if !host.is_empty() {
            if let Some(n) = self.find_child(host) {
                n.matching_methods_path(path, set);
            }
        }
        if let Some(n) = self.empty_child.as_deref() {
            n.matching_methods_path(path, set);
        }
        if set.contains("GET") {
            set.insert("HEAD".into());
        }
    }
    fn matching_methods_path(&self, path: &str, set: &mut BTreeSet<String>) {
        for (method, c) in &self.children {
            if c.match_path(path, Vec::new()).is_some() {
                set.insert(method.clone());
            }
        }
    }
}

fn first_segment(path: &str) -> (String, String) {
    if path == "/" {
        return ("/".into(), String::new());
    }
    let path = &path[1..];
    let i = path.find('/').unwrap_or(path.len());
    (path_unescape(&path[..i]), path[i..].to_owned())
}

// ------------------------------------------------------------------ mux

/// Go's `http.ServeMux`.
#[derive(Default)]
pub struct ServeMux {
    state: RwLock<MuxState>,
}
#[derive(Default)]
struct MuxState {
    tree: Node,
    patterns: Vec<Arc<Pattern>>,
}

/// Go's `DefaultServeMux`.
pub static DEFAULT_SERVE_MUX: std::sync::LazyLock<ServeMux> =
    std::sync::LazyLock::new(ServeMux::default);

fn strip_host_port(h: &str) -> String {
    if !h.contains(':') {
        return h.to_owned();
    }
    match crate::net::split_host_port(h) {
        Ok((host, _)) => host,
        Err(_) => h.to_owned(),
    }
}

fn url_from_escaped(escaped: &str, raw_query: &str) -> Url {
    let unescaped = url::path_unescape(escaped).unwrap_or_else(|_| escaped.to_owned());
    Url {
        path: unescaped,
        raw_path: escaped.to_owned(),
        raw_query: raw_query.to_owned(),
        ..Url::default()
    }
}

fn exact_match(n: Option<&Node>, path: &str) -> bool {
    let Some(n) = n else { return false };
    let Some(p) = &n.pattern else { return false };
    if !p.last_segment().multi {
        return true;
    }
    if !path.is_empty() && !path.ends_with('/') {
        return false;
    }
    p.segments.len() == path.matches('/').count()
}

/// What `ServeMux::handler` resolves to.
pub struct Handled {
    pub handler: Arc<dyn Handler>,
    pub pattern: String,
    pub(crate) pat: Option<Arc<Pattern>>,
    pub(crate) matches: Vec<String>,
}

impl ServeMux {
    /// Go's `NewServeMux`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Go's `Handler`: the handler and registered pattern for the request.
    pub fn handler(&self, r: &Request) -> (Arc<dyn Handler>, String) {
        let h = self.find_handler(r);
        (h.handler, h.pattern)
    }

    fn match_or_redirect(
        &self,
        host: &str,
        method: &str,
        path: &str,
        u: Option<&Url>,
    ) -> (
        Option<(Arc<Pattern>, Arc<dyn Handler>)>,
        Vec<String>,
        Option<Url>,
    ) {
        let state = self.state.read().unwrap_or_else(|e| e.into_inner());
        let found = state.tree.match_root(host, method, path);
        let exact = exact_match(found.as_ref().map(|(n, _)| *n), path);
        if !exact && u.is_some() && !path.ends_with('/') && !path.is_empty() {
            let path2 = format!("{path}/");
            let n2 = state.tree.match_root(host, method, &path2);
            if exact_match(n2.as_ref().map(|(n, _)| *n), &path2) {
                if let Some((n, _)) = n2 {
                    let leaf = leaf(n);
                    return (
                        leaf,
                        Vec::new(),
                        Some(url_from_escaped(
                            &path2,
                            u.map(|u| u.raw_query.as_str()).unwrap_or(""),
                        )),
                    );
                }
            }
        }
        match found {
            Some((n, m)) => (leaf(n), m, None),
            None => (None, Vec::new(), None),
        }
    }

    fn matching_methods(&self, host: &str, path: &str) -> Vec<String> {
        let state = self.state.read().unwrap_or_else(|e| e.into_inner());
        let mut ms = BTreeSet::new();
        state.tree.matching_methods(host, path, &mut ms);
        if !path.ends_with('/') {
            state
                .tree
                .matching_methods(host, &format!("{path}/"), &mut ms);
        }
        ms.into_iter().collect()
    }

    pub(crate) fn find_handler(&self, r: &Request) -> Handled {
        let mut host = r.url.host.clone();
        let escaped_path = r.url.escaped_path();
        let mut path = escaped_path.clone();
        let (n, matches);
        if r.method == "CONNECT" {
            let (_, _, u) = self.match_or_redirect(&host, &r.method, &path, Some(&r.url));
            if let Some(u) = u {
                return Handled {
                    handler: redirect_handler(&u.to_string(), STATUS_TEMPORARY_REDIRECT),
                    pattern: u.path.clone(),
                    pat: None,
                    matches: Vec::new(),
                };
            }
            let (n1, m1, _) = self.match_or_redirect(&r.host, &r.method, &path, None);
            n = n1;
            matches = m1;
        } else {
            host = strip_host_port(&r.host);
            path = clean_path(&path);
            let (n1, m1, u) = self.match_or_redirect(&host, &r.method, &path, Some(&r.url));
            if let Some(u) = u {
                return Handled {
                    handler: redirect_handler(&u.to_string(), STATUS_TEMPORARY_REDIRECT),
                    pattern: n1.as_ref().map(|(p, _)| p.to_string()).unwrap_or_default(),
                    pat: None,
                    matches: Vec::new(),
                };
            }
            if path != escaped_path {
                let pat_str = n1.as_ref().map(|(p, _)| p.to_string()).unwrap_or_default();
                let u = url_from_escaped(&path, &r.url.raw_query);
                return Handled {
                    handler: redirect_handler(&u.to_string(), STATUS_TEMPORARY_REDIRECT),
                    pattern: pat_str,
                    pat: None,
                    matches: Vec::new(),
                };
            }
            n = n1;
            matches = m1;
        }
        match n {
            None => {
                let allowed = self.matching_methods(&host, &path);
                if !allowed.is_empty() {
                    let allow = allowed.join(", ");
                    return Handled {
                        handler: handler_func(move |w, _r| {
                            w.header().set("Allow", &allow);
                            error(
                                w,
                                status_text(STATUS_METHOD_NOT_ALLOWED),
                                STATUS_METHOD_NOT_ALLOWED,
                            );
                        }),
                        pattern: String::new(),
                        pat: None,
                        matches: Vec::new(),
                    };
                }
                Handled {
                    handler: not_found_handler(),
                    pattern: String::new(),
                    pat: None,
                    matches: Vec::new(),
                }
            }
            Some((pat, h)) => Handled {
                handler: h,
                pattern: pat.to_string(),
                pat: Some(pat),
                matches,
            },
        }
    }

    /// Go's `Handle`. Go panics on an invalid or conflicting pattern; here the
    /// error is returned.
    #[track_caller]
    pub fn handle(&self, pattern: &str, handler: Arc<dyn Handler>) -> Result<(), BoxError> {
        let loc = std::panic::Location::caller();
        let loc = format!("{}:{}", loc.file(), loc.line());
        self.register_err(pattern, handler, loc)
    }

    /// Go's `HandleFunc`.
    #[track_caller]
    pub fn handle_func<F>(&self, pattern: &str, f: F) -> Result<(), BoxError>
    where
        F: Fn(&mut dyn ResponseWriter, &mut Request) + Send + Sync + 'static,
    {
        let loc = std::panic::Location::caller();
        let loc = format!("{}:{}", loc.file(), loc.line());
        self.register_err(pattern, handler_func(f), loc)
    }

    fn register_err(
        &self,
        patstr: &str,
        handler: Arc<dyn Handler>,
        loc: String,
    ) -> Result<(), BoxError> {
        if patstr.is_empty() {
            return Err("http: invalid pattern".into());
        }
        let mut pat = Pattern::parse(patstr)
            .map_err(|e| -> BoxError { format!("parsing {}: {e}", quote(patstr)).into() })?;
        pat.loc = loc;
        let pat = Arc::new(pat);
        let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
        for pat2 in &state.patterns {
            if pat.conflicts_with(pat2) {
                let d = describe_conflict(&pat, pat2);
                return Err(format!(
                    "pattern {} (registered at {}) conflicts with pattern {} (registered at {}):\n{}",
                    quote(&pat.str),
                    pat.loc,
                    quote(&pat2.str),
                    pat2.loc,
                    d
                )
                .into());
            }
        }
        state.tree.add_pattern(pat.clone(), handler);
        state.patterns.push(pat);
        Ok(())
    }
}

fn leaf(n: &Node) -> Option<(Arc<Pattern>, Arc<dyn Handler>)> {
    match (&n.pattern, &n.handler) {
        (Some(p), Some(h)) => Some((p.clone(), h.clone())),
        _ => None,
    }
}

impl Handler for ServeMux {
    fn serve_http(&self, w: &mut dyn ResponseWriter, r: &mut Request) {
        if r.request_uri == "*" {
            if r.proto_at_least(1, 1) {
                w.header().set("Connection", "close");
            }
            w.write_header(STATUS_BAD_REQUEST);
            return;
        }
        let h = self.find_handler(r);
        r.pattern = h.pattern;
        r.set_matched(h.pat, h.matches);
        h.handler.serve_http(w, r);
    }
}

/// Go's package-level `Handle` on `DefaultServeMux`.
#[track_caller]
pub fn handle(pattern: &str, handler: Arc<dyn Handler>) -> Result<(), BoxError> {
    DEFAULT_SERVE_MUX.handle(pattern, handler)
}
/// Go's package-level `HandleFunc` on `DefaultServeMux`.
#[track_caller]
pub fn handle_func<F>(pattern: &str, f: F) -> Result<(), BoxError>
where
    F: Fn(&mut dyn ResponseWriter, &mut Request) + Send + Sync + 'static,
{
    DEFAULT_SERVE_MUX.handle_func(pattern, f)
}
