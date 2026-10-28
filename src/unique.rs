//! Canonicalization ("interning") of comparable values, Go's `unique` package.

use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, LazyLock, Mutex, Weak};

/// A globally unique identity for some value of type `T`. Two handles are
/// equal exactly when the values they were made from are equal, and comparing
/// them is a pointer comparison.
#[derive(Debug)]
pub struct Handle<T>(Arc<T>);

impl<T> Handle<T> {
    /// Returns the value the handle was made from.
    pub fn value(&self) -> &T {
        &self.0
    }
}

impl<T> Clone for Handle<T> {
    fn clone(&self) -> Self {
        Handle(Arc::clone(&self.0))
    }
}

impl<T> PartialEq for Handle<T> {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl<T> Eq for Handle<T> {}

impl<T> Hash for Handle<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        Arc::as_ptr(&self.0).hash(state);
    }
}

struct Interned<T> {
    live: HashMap<T, Weak<T>>,
    sweep_at: usize,
}

type Registry = Mutex<HashMap<TypeId, Box<dyn Any + Send>>>;

static REGISTRY: LazyLock<Registry> = LazyLock::new(|| Mutex::new(HashMap::new()));

impl<T> Handle<T> {
    /// Returns a handle for a value such that handles of equal values are equal.
    /// Entries whose handles are all dropped are swept as the table grows.
    pub fn new(value: T) -> Self
    where
        T: Eq + Hash + Clone + Send + Sync + 'static,
    {
        let mut registry = REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
        let slot = registry.entry(TypeId::of::<T>()).or_insert_with(|| {
            Box::new(Interned::<T> {
                live: HashMap::new(),
                sweep_at: 64,
            })
        });
        let table = slot
            .downcast_mut::<Interned<T>>()
            .expect("registry slot holds the table for its TypeId");
        if let Some(existing) = table.live.get(&value).and_then(Weak::upgrade) {
            return Handle(existing);
        }
        if table.live.len() >= table.sweep_at {
            table.live.retain(|_, w| w.strong_count() > 0);
            table.sweep_at = (table.live.len() * 2).max(64);
        }
        let canonical = Arc::new(value.clone());
        table.live.insert(value, Arc::downgrade(&canonical));
        Handle(canonical)
    }
}
