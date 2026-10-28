//! The insertion-ordered object of a [`Value`](super::Value).
use std::{collections::BTreeMap, fmt, ops::Index};

use super::Value;

/// A JSON object that remembers the order its members were inserted in.
///
/// The order is the order [`Value`](super::Value) writes the members in.
/// Struct encodings insert their fields in declaration order; maps, and JSON
/// text decoded into a `Value`, insert their keys sorted, as Go's
/// `map[string]any` marshals. Equality ignores the order, as Go's
/// `reflect.DeepEqual` does for maps.
#[derive(Clone, Default)]
pub struct Map {
    entries: Vec<(String, Value)>,
    /// Whether `entries` is strictly ascending by key, which allows binary
    /// search.
    sorted: bool,
}

impl Map {
    /// An empty object.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            sorted: true,
        }
    }

    /// An empty object with room for `capacity` members.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
            sorted: true,
        }
    }

    /// The members of a sequence already sorted by key, without duplicates.
    pub(crate) fn from_sorted(entries: Vec<(String, Value)>) -> Self {
        debug_assert!(entries.windows(2).all(|w| w[0].0 < w[1].0));
        Self {
            entries,
            sorted: true,
        }
    }

    /// The members of a sequence in Go's map order: sorted by key, the last
    /// of equal keys winning.
    pub(crate) fn from_unsorted(mut entries: Vec<(String, Value)>) -> Self {
        // A stable sort keeps equal keys in arrival order, so the last wins.
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let mut out: Vec<(String, Value)> = Vec::with_capacity(entries.len());
        for e in entries {
            match out.last_mut() {
                Some(last) if last.0 == e.0 => *last = e,
                _ => out.push(e),
            }
        }
        Self::from_sorted(out)
    }

    fn position(&self, key: &str) -> Result<usize, usize> {
        if self.sorted {
            self.entries.binary_search_by(|(k, _)| k.as_str().cmp(key))
        } else {
            match self.entries.iter().position(|(k, _)| k == key) {
                Some(i) => Ok(i),
                None => Err(self.entries.len()),
            }
        }
    }

    /// The number of members.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no members.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The value of `key`.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.position(key).ok().map(|i| &self.entries[i].1)
    }

    /// The value of `key`, mutably.
    pub fn get_mut(&mut self, key: &str) -> Option<&mut Value> {
        match self.position(key) {
            Ok(i) => Some(&mut self.entries[i].1),
            Err(_) => None,
        }
    }

    /// Whether the object has a member named `key`.
    pub fn contains_key(&self, key: &str) -> bool {
        self.position(key).is_ok()
    }

    /// Sets `key`. A new key goes last; an existing key keeps its place.
    /// Returns the value it replaced.
    pub fn insert(&mut self, key: String, value: Value) -> Option<Value> {
        match self.position(&key) {
            Ok(i) => Some(std::mem::replace(&mut self.entries[i].1, value)),
            Err(_) => {
                if self.sorted && self.entries.last().is_some_and(|(last, _)| *last > key) {
                    self.sorted = false;
                }
                self.entries.push((key, value));
                None
            }
        }
    }

    /// Removes `key`, keeping the order of the other members.
    pub fn remove(&mut self, key: &str) -> Option<Value> {
        let i = self.position(key).ok()?;
        Some(self.entries.remove(i).1)
    }

    /// The members in order.
    pub fn iter(&self) -> Iter<'_> {
        Iter(self.entries.iter())
    }

    /// The members in order, with mutable values.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&String, &mut Value)> {
        self.entries.iter_mut().map(|(k, v)| (&*k, v))
    }

    /// The keys in order.
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.entries.iter().map(|(k, _)| k)
    }

    /// The values in order.
    pub fn values(&self) -> impl Iterator<Item = &Value> {
        self.entries.iter().map(|(_, v)| v)
    }
}

/// The iterator of [`Map::iter`].
pub struct Iter<'a>(std::slice::Iter<'a, (String, Value)>);

impl<'a> Iterator for Iter<'a> {
    type Item = (&'a String, &'a Value);
    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|(k, v)| (k, v))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

impl DoubleEndedIterator for Iter<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.0.next_back().map(|(k, v)| (k, v))
    }
}

impl ExactSizeIterator for Iter<'_> {}

impl<'a> IntoIterator for &'a Map {
    type Item = (&'a String, &'a Value);
    type IntoIter = Iter<'a>;
    fn into_iter(self) -> Iter<'a> {
        self.iter()
    }
}

impl IntoIterator for Map {
    type Item = (String, Value);
    type IntoIter = std::vec::IntoIter<(String, Value)>;
    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

impl FromIterator<(String, Value)> for Map {
    /// Inserts in iteration order; a repeated key keeps its first position
    /// and takes the last value.
    fn from_iter<I: IntoIterator<Item = (String, Value)>>(iter: I) -> Self {
        let mut m = Map::new();
        m.extend(iter);
        m
    }
}

impl Extend<(String, Value)> for Map {
    fn extend<I: IntoIterator<Item = (String, Value)>>(&mut self, iter: I) {
        for (k, v) in iter {
            self.insert(k, v);
        }
    }
}

impl<const N: usize> From<[(String, Value); N]> for Map {
    fn from(members: [(String, Value); N]) -> Self {
        members.into_iter().collect()
    }
}

impl From<BTreeMap<String, Value>> for Map {
    /// The keys are already in Go's map order.
    fn from(members: BTreeMap<String, Value>) -> Self {
        Self::from_sorted(members.into_iter().collect())
    }
}

impl Index<&str> for Map {
    type Output = Value;
    /// Panics when `key` is absent.
    fn index(&self, key: &str) -> &Value {
        self.get(key).expect("no member with that key")
    }
}

impl PartialEq for Map {
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len() && self.iter().all(|(k, v)| other.get(k) == Some(v))
    }
}

impl Eq for Map {}

impl fmt::Debug for Map {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}
