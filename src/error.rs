//! Error helpers std lacks, for Go's `errors` package.
//!
//! Most of `errors` is std: `New` is `Box<dyn Error>::from`, `Unwrap` is
//! [`std::error::Error::source`] and `As` is `dyn Error::downcast_ref`. What
//! std does not have is walking an error tree and joining errors: [`is`] and
//! [`find`] follow `source` chains and the errors of a [`Joined`] depth first,
//! and [`Joined`] is Go's `errors.Join`. Sentinel comparison (`==` in Go) is
//! identity of [`Message`] values, or the same object for any other type.
//!
//! Go lets an error type define `Is(error) bool` and `As(any) bool` methods
//! that [`is`] and [`find`] consult while walking the tree. Rust cannot ask a
//! `dyn Error` whether its concrete type implements a trait, so a type opts in
//! by implementing [`ErrorIs`] and/or [`ErrorAs`] and registering itself once
//! with [`register_is`] / [`register_as`].

use std::any::TypeId;
use std::error::Error as StdError;
use std::fmt;
use std::sync::{Arc, LazyLock, RwLock};

/// An error with a fixed text. Clones are the same error (they compare equal
/// in [`is`]); two calls to [`Message::new`] with equal text are different errors.
#[derive(Clone, Debug)]
pub struct Message(Arc<str>);

impl Message {
    /// Returns an error that formats as `text`, distinct from every other
    /// [`Message`].
    pub fn new(text: &str) -> Self {
        Message(Arc::from(text))
    }

    /// Go's `errors.ErrUnsupported`: the error that indicates a requested
    /// operation cannot be performed because it is unsupported. Compare with
    /// [`is`].
    pub fn unsupported() -> Self {
        static UNSUPPORTED: LazyLock<Message> =
            LazyLock::new(|| Message::new("unsupported operation"));
        UNSUPPORTED.clone()
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl StdError for Message {}

impl PartialEq for Message {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for Message {}

/// Several errors as one; formats as their texts separated by newlines
/// (Go's `errors.Join`).
#[derive(Debug)]
pub struct Joined {
    errs: Vec<Box<dyn StdError + Send + Sync>>,
}

impl Joined {
    /// Wraps the given errors, or returns `None` if there are none.
    pub fn new<I>(errs: I) -> Option<Self>
    where
        I: IntoIterator<Item = Box<dyn StdError + Send + Sync>>,
    {
        let errs: Vec<_> = errs.into_iter().collect();
        if errs.is_empty() {
            None
        } else {
            Some(Joined { errs })
        }
    }

    /// The wrapped errors (Go's `Unwrap() []error`).
    pub fn errors(&self) -> &[Box<dyn StdError + Send + Sync>] {
        &self.errs
    }
}

impl fmt::Display for Joined {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, e) in self.errs.iter().enumerate() {
            if i > 0 {
                f.write_str("\n")?;
            }
            write!(f, "{e}")?;
        }
        Ok(())
    }
}

impl StdError for Joined {}

fn same(a: &(dyn StdError + 'static), b: &(dyn StdError + 'static)) -> bool {
    if let (Some(x), Some(y)) = (a.downcast_ref::<Message>(), b.downcast_ref::<Message>()) {
        return x == y;
    }
    std::ptr::addr_eq(a, b) && std::mem::size_of_val(a) == std::mem::size_of_val(b)
}

/// Go's optional `Is(error) bool` method on an error type: reports whether
/// the error should be considered equal to `target`, in addition to identity.
/// Register the type with [`register_is`] so [`is`] consults it.
pub trait ErrorIs: StdError + 'static {
    /// Reports whether this error matches `target` (Go's `Is` method).
    fn is(&self, target: &(dyn StdError + 'static)) -> bool;
}

/// Go's optional `As(any) bool` method on an error type, in Rust's shape:
/// given the [`TypeId`] a caller of [`find`] wants, returns an error of that
/// concrete type (typically a field of `self`, or `self` converted) or `None`.
/// Register the type with [`register_as`] so [`find`] consults it.
pub trait ErrorAs: StdError + 'static {
    /// Returns the error of concrete type `want` this error stands for.
    fn as_error(&self, want: TypeId) -> Option<&(dyn StdError + 'static)>;
}

type IsHook = fn(&(dyn StdError + 'static), &(dyn StdError + 'static)) -> Option<bool>;
type AsHook =
    for<'a> fn(&'a (dyn StdError + 'static), TypeId) -> Option<&'a (dyn StdError + 'static)>;

static IS_HOOKS: RwLock<Vec<(TypeId, IsHook)>> = RwLock::new(Vec::new());
static AS_HOOKS: RwLock<Vec<(TypeId, AsHook)>> = RwLock::new(Vec::new());

/// Makes [`is`] consult `E`'s [`ErrorIs`] implementation for every error of
/// type `E` it meets, as Go consults an `Is` method. Registering a type twice
/// is harmless.
pub fn register_is<E: ErrorIs>() {
    let id = TypeId::of::<E>();
    let mut hooks = IS_HOOKS.write().unwrap_or_else(|e| e.into_inner());
    if hooks.iter().all(|(t, _)| *t != id) {
        hooks.push((id, |err, target| {
            err.downcast_ref::<E>().map(|e| e.is(target))
        }));
    }
}

/// Makes [`find`] consult `E`'s [`ErrorAs`] implementation for every error of
/// type `E` it meets, as Go consults an `As` method. Registering a type twice
/// is harmless.
pub fn register_as<E: ErrorAs>() {
    let id = TypeId::of::<E>();
    let mut hooks = AS_HOOKS.write().unwrap_or_else(|e| e.into_inner());
    if hooks.iter().all(|(t, _)| *t != id) {
        hooks.push((id, |err, want| {
            err.downcast_ref::<E>().and_then(|e| e.as_error(want))
        }));
    }
}

fn custom_is(err: &(dyn StdError + 'static), target: &(dyn StdError + 'static)) -> bool {
    // Copy the hooks out so a hook may itself call `is` or register types.
    let hooks: Vec<IsHook> = IS_HOOKS
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .map(|(_, h)| *h)
        .collect();
    hooks.into_iter().any(|h| h(err, target) == Some(true))
}

fn custom_as<'a>(
    err: &'a (dyn StdError + 'static),
    want: TypeId,
) -> Option<&'a (dyn StdError + 'static)> {
    let hooks: Vec<AsHook> = AS_HOOKS
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .map(|(_, h)| *h)
        .collect();
    hooks.into_iter().find_map(|h| h(err, want))
}

/// Go's `errors.Is`: reports whether any error in `err`'s tree matches
/// `target`. The tree is `err`, its `source` chain, and the errors of any
/// [`Joined`], depth first. An error matches when it is `target` or when its
/// registered [`ErrorIs`] implementation says so.
pub fn is(mut err: &(dyn StdError + 'static), target: &(dyn StdError + 'static)) -> bool {
    loop {
        if same(err, target) || custom_is(err, target) {
            return true;
        }
        if let Some(j) = err.downcast_ref::<Joined>() {
            return j.errs.iter().any(|e| is(e.as_ref(), target));
        }
        match err.source() {
            Some(next) => err = next,
            None => return false,
        }
    }
}

/// Go's `errors.AsType`: finds the first error in `err`'s tree (the order of
/// [`is`]) whose concrete type is `E`, or that stands for an `E` through its
/// registered [`ErrorAs`] implementation.
pub fn find<'a, E: StdError + 'static>(mut err: &'a (dyn StdError + 'static)) -> Option<&'a E> {
    loop {
        if let Some(e) = err.downcast_ref::<E>() {
            return Some(e);
        }
        if let Some(e) = custom_as(err, TypeId::of::<E>()).and_then(|e| e.downcast_ref::<E>()) {
            return Some(e);
        }
        if let Some(j) = err.downcast_ref::<Joined>() {
            return j.errs.iter().find_map(|e| find::<E>(e.as_ref()));
        }
        err = err.source()?;
    }
}
