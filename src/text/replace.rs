//! Go's `strings.Replacer`, with Go's algorithm selection: a single-string
//! replacer, byte-to-byte and byte-to-string tables for one-byte keys, and the
//! generic trie replacer whose priority is argument order (leftmost-first).

use std::io::{self, Write};

use super::BytesExt;

/// Replaces a list of strings with replacements. Safe for concurrent use.
#[derive(Clone, Debug)]
pub struct Replacer {
    kind: Kind,
}

#[derive(Clone, Debug)]
enum Kind {
    Single { pattern: Vec<u8>, value: Vec<u8> },
    Byte(Box<[u8; 256]>),
    ByteString(Box<[Option<Vec<u8>>; 256]>),
    Generic(Box<Generic>),
}

impl Replacer {
    /// Go's `NewReplacer`: comparisons are done in argument order, so earlier
    /// pairs win over later ones, and matches are not overlapped.
    pub fn new<A: AsRef<[u8]>, B: AsRef<[u8]>>(pairs: &[(A, B)]) -> Replacer {
        let oldnew: Vec<Vec<u8>> = pairs
            .iter()
            .flat_map(|(a, b)| [a.as_ref().to_vec(), b.as_ref().to_vec()])
            .collect();
        Replacer {
            kind: build(&oldnew),
        }
    }

    /// Returns `s` with all replacements applied. The replacer works on bytes
    /// (an empty old string matches between bytes, not runes).
    pub fn replace(&self, s: impl AsRef<[u8]>) -> Vec<u8> {
        let s = s.as_ref();
        let mut out = Vec::with_capacity(s.len());
        let _ = self.write_bytes(&mut out, s);
        out
    }

    /// Writes `s` to `w` with all replacements applied (`Replacer.WriteString`).
    /// Returns the bytes written, which on an error is the count accepted
    /// before it, as in Go.
    pub fn write_to<W: Write + ?Sized>(
        &self,
        w: &mut W,
        s: impl AsRef<[u8]>,
    ) -> (usize, io::Result<()>) {
        let mut n = 0;
        let r = self.write_bytes_counted(w, s.as_ref(), &mut n);
        (n, r)
    }

    fn write_bytes<W: Write + ?Sized>(&self, w: &mut W, s: &[u8]) -> io::Result<()> {
        let mut n = 0;
        self.write_bytes_counted(w, s, &mut n)
    }

    fn write_bytes_counted<W: Write + ?Sized>(
        &self,
        w: &mut W,
        s: &[u8],
        n: &mut usize,
    ) -> io::Result<()> {
        match &self.kind {
            Kind::Single { pattern, value } => {
                let mut i = 0;
                while let Some(m) = s[i..].find_bytes(pattern) {
                    put(w, &s[i..i + m], n)?;
                    put(w, value, n)?;
                    i += m + pattern.len();
                }
                put(w, &s[i..], n)
            }
            Kind::Byte(table) => {
                let mut last = 0;
                for (i, &b) in s.iter().enumerate() {
                    if table[b as usize] == b {
                        continue;
                    }
                    put(w, &s[last..i], n)?;
                    last = i + 1;
                    put(w, &table[b as usize..=b as usize], n)?;
                }
                put(w, &s[last..], n)
            }
            Kind::ByteString(table) => {
                let mut last = 0;
                for (i, &b) in s.iter().enumerate() {
                    let Some(rep) = &table[b as usize] else {
                        continue;
                    };
                    put(w, &s[last..i], n)?;
                    last = i + 1;
                    put(w, rep, n)?;
                }
                put(w, &s[last..], n)
            }
            Kind::Generic(g) => g.write(w, s, n),
        }
    }
}

/// Writes all of `p`, adding the bytes accepted to `n` even on error.
fn put<W: Write + ?Sized>(w: &mut W, mut p: &[u8], n: &mut usize) -> io::Result<()> {
    while !p.is_empty() {
        match w.write(p) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "short write")),
            Ok(m) => {
                *n += m;
                p = &p[m..];
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn build(oldnew: &[Vec<u8>]) -> Kind {
    if oldnew.len() == 2 && oldnew[0].len() > 1 {
        return Kind::Single {
            pattern: oldnew[0].clone(),
            value: oldnew[1].clone(),
        };
    }
    let mut all_new_bytes = true;
    for pair in oldnew.chunks(2) {
        if pair[0].len() != 1 {
            return Kind::Generic(Box::new(Generic::new(oldnew)));
        }
        if pair[1].len() != 1 {
            all_new_bytes = false;
        }
    }
    if all_new_bytes {
        let mut table = Box::new([0u8; 256]);
        for (i, t) in table.iter_mut().enumerate() {
            *t = i as u8;
        }
        for pair in oldnew.chunks(2).rev() {
            table[pair[0][0] as usize] = pair[1][0];
        }
        return Kind::Byte(table);
    }
    let mut table: Box<[Option<Vec<u8>>; 256]> = Box::new(std::array::from_fn(|_| None));
    for pair in oldnew.chunks(2).rev() {
        table[pair[0][0] as usize] = Some(pair[1].clone());
    }
    Kind::ByteString(table)
}

// ---- generic trie replacer ----------------------------------------------

#[derive(Clone, Debug, Default)]
struct Node {
    value: Vec<u8>,
    /// Match priority: higher is earlier in the argument list; 0 = no value.
    priority: usize,
    prefix: Vec<u8>,
    next: Option<usize>,
    table: Option<Vec<Option<usize>>>,
}

#[derive(Clone, Debug)]
struct Generic {
    nodes: Vec<Node>,
    table_size: usize,
    mapping: [u8; 256],
}

impl Generic {
    fn new(oldnew: &[Vec<u8>]) -> Generic {
        let mut g = Generic {
            nodes: vec![Node::default()],
            table_size: 0,
            mapping: [0; 256],
        };
        for pair in oldnew.chunks(2) {
            for &b in &pair[0] {
                g.mapping[b as usize] = 1;
            }
        }
        g.table_size = g.mapping.iter().map(|&b| b as usize).sum();
        let mut index = 0u8;
        for m in g.mapping.iter_mut() {
            if *m == 0 {
                *m = g.table_size as u8;
            } else {
                *m = index;
                index = index.wrapping_add(1);
            }
        }
        g.nodes[0].table = Some(vec![None; g.table_size]);
        for (i, pair) in oldnew.chunks(2).enumerate() {
            g.add(0, &pair[0], &pair[1], oldnew.len() - 2 * i);
        }
        g
    }

    fn new_node(&mut self, node: Node) -> usize {
        self.nodes.push(node);
        self.nodes.len() - 1
    }

    fn add(&mut self, t: usize, key: &[u8], val: &[u8], priority: usize) {
        if key.is_empty() {
            if self.nodes[t].priority == 0 {
                self.nodes[t].value = val.to_vec();
                self.nodes[t].priority = priority;
            }
            return;
        }
        if !self.nodes[t].prefix.is_empty() {
            let prefix = self.nodes[t].prefix.clone();
            let n = prefix.iter().zip(key).take_while(|(a, b)| a == b).count();
            if n == prefix.len() {
                if let Some(next) = self.nodes[t].next {
                    self.add(next, &key[n..], val, priority);
                }
            } else if n == 0 {
                let next = self.nodes[t].next.take();
                let prefix_node = if prefix.len() == 1 {
                    next
                } else {
                    Some(self.new_node(Node {
                        prefix: prefix[1..].to_vec(),
                        next,
                        ..Node::default()
                    }))
                };
                let key_node = self.new_node(Node::default());
                let mut table = vec![None; self.table_size];
                table[self.mapping[prefix[0] as usize] as usize] = prefix_node;
                table[self.mapping[key[0] as usize] as usize] = Some(key_node);
                self.nodes[t].table = Some(table);
                self.nodes[t].prefix.clear();
                self.add(key_node, &key[1..], val, priority);
            } else {
                let next = self.new_node(Node {
                    prefix: prefix[n..].to_vec(),
                    next: self.nodes[t].next,
                    ..Node::default()
                });
                self.nodes[t].prefix.truncate(n);
                self.nodes[t].next = Some(next);
                self.add(next, &key[n..], val, priority);
            }
        } else if self.nodes[t].table.is_some() {
            let m = self.mapping[key[0] as usize] as usize;
            let child = match self.nodes[t].table.as_ref().and_then(|tb| tb[m]) {
                Some(c) => c,
                None => {
                    let c = self.new_node(Node::default());
                    if let Some(tb) = self.nodes[t].table.as_mut() {
                        tb[m] = Some(c);
                    }
                    c
                }
            };
            self.add(child, &key[1..], val, priority);
        } else {
            let next = self.new_node(Node::default());
            self.nodes[t].prefix = key.to_vec();
            self.nodes[t].next = Some(next);
            self.add(next, &[], val, priority);
        }
    }

    /// Returns the highest-priority `(value, key length)` among keys that are
    /// prefixes of `s`. With `ignore_root` the empty key is not considered.
    fn lookup(&self, mut s: &[u8], ignore_root: bool) -> Option<(&[u8], usize)> {
        let mut best_priority = 0;
        let mut best = None;
        let mut node = Some(0usize);
        let mut n = 0;
        while let Some(idx) = node {
            let nd = &self.nodes[idx];
            if nd.priority > best_priority && !(ignore_root && idx == 0) {
                best_priority = nd.priority;
                best = Some((nd.value.as_slice(), n));
            }
            if s.is_empty() {
                break;
            }
            if let Some(table) = &nd.table {
                let index = self.mapping[s[0] as usize] as usize;
                if index == self.table_size {
                    break;
                }
                node = table[index];
                s = &s[1..];
                n += 1;
            } else if !nd.prefix.is_empty() && s.starts_with(&nd.prefix) {
                n += nd.prefix.len();
                s = &s[nd.prefix.len()..];
                node = nd.next;
            } else {
                break;
            }
        }
        best
    }

    fn write<W: Write + ?Sized>(&self, w: &mut W, s: &[u8], n: &mut usize) -> io::Result<()> {
        let mut last = 0;
        let mut prev_match_empty = false;
        let mut i = 0;
        while i <= s.len() {
            if i != s.len() && self.nodes[0].priority == 0 {
                let index = self.mapping[s[i] as usize] as usize;
                let root_has = self.nodes[0]
                    .table
                    .as_ref()
                    .is_some_and(|t| index != self.table_size && t[index].is_some());
                if !root_has {
                    i += 1;
                    continue;
                }
            }
            match self.lookup(&s[i..], prev_match_empty) {
                Some((val, keylen)) => {
                    prev_match_empty = keylen == 0;
                    put(w, &s[last..i], n)?;
                    put(w, val, n)?;
                    i += keylen;
                    last = i;
                }
                None => {
                    prev_match_empty = false;
                    i += 1;
                }
            }
        }
        if last != s.len() {
            put(w, &s[last..], n)?;
        }
        Ok(())
    }
}
