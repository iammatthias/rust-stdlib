//! Ported from Go's errors tests (errors_test.go, wrap_test.go, join_test.go).
use rust_stdlib::error::{self, Joined, Message};
use std::error::Error;
use std::fmt;

type BoxError = Box<dyn Error + Send + Sync>;

#[derive(Debug)]
struct Wrapped {
    msg: String,
    err: Option<BoxError>,
}

impl fmt::Display for Wrapped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl Error for Wrapped {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.err.as_deref().map(|e| e as &(dyn Error + 'static))
    }
}

#[derive(Debug, PartialEq)]
struct PathError(&'static str);

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "path {}", self.0)
    }
}

impl Error for PathError {}

fn wrap(msg: &str, err: impl Error + Send + Sync + 'static) -> Wrapped {
    Wrapped {
        msg: msg.to_string(),
        err: Some(Box::new(err)),
    }
}

fn dynerr(e: &(impl Error + 'static)) -> &(dyn Error + 'static) {
    e
}

#[test]
fn new_is_distinct() {
    let a = Message::new("abc");
    let b = Message::new("abc");
    assert_eq!(a.to_string(), "abc");
    assert!(!error::is(dynerr(&a), dynerr(&b)));
    assert!(error::is(dynerr(&a), dynerr(&a)));
    assert!(error::is(dynerr(&a), dynerr(&a.clone())));
    assert_eq!(a, a.clone());
    assert_ne!(a, b);
    assert_eq!(Message::new("").to_string(), "");
}

#[test]
fn is_follows_chains() {
    let base = Message::new("base");
    let other = Message::new("other");
    let w1 = wrap("w1", base.clone());
    let w2 = wrap("w2", w1);
    assert!(error::is(dynerr(&w2), dynerr(&base)));
    assert!(!error::is(dynerr(&w2), dynerr(&other)));
    // The error itself.
    assert!(error::is(dynerr(&w2), dynerr(&w2)));
}

#[test]
fn source_is_one_level() {
    let base = Message::new("base");
    let w = wrap("w", base.clone());
    let inner = w.source().expect("wrapped error");
    assert!(error::is(inner, dynerr(&base)));
    assert!(base.source().is_none());
    let joined = Joined::new([Box::new(base.clone()) as BoxError]).unwrap();
    assert!(joined.source().is_none(), "Join has no single cause");
}

#[test]
fn find_returns_first_of_type() {
    let first = PathError("first");
    let w = wrap("outer", wrap("mid", first));
    assert_eq!(
        error::find::<PathError>(dynerr(&w)),
        Some(&PathError("first"))
    );
    let plain = Message::new("x");
    assert!(error::find::<PathError>(dynerr(&plain)).is_none());
    assert!(error::find::<Message>(dynerr(&w)).is_none());
    // The first match in depth-first order wins.
    let both = Joined::new([
        Box::new(PathError("a")) as BoxError,
        Box::new(PathError("b")) as BoxError,
    ])
    .unwrap();
    assert_eq!(
        error::find::<PathError>(dynerr(&both)),
        Some(&PathError("a"))
    );
}

#[test]
fn join_semantics() {
    assert!(Joined::new(Vec::<BoxError>::new()).is_none());
    let a = Message::new("a");
    let b = Message::new("b");
    let j = Joined::new([
        Box::new(a.clone()) as BoxError,
        Box::new(b.clone()) as BoxError,
    ])
    .unwrap();
    assert_eq!(j.to_string(), "a\nb");
    assert_eq!(j.errors().len(), 2);
    assert!(error::is(dynerr(&j), dynerr(&a)));
    assert!(error::is(dynerr(&j), dynerr(&b)));
    assert!(!error::is(dynerr(&j), dynerr(&Message::new("a"))));
    let nested = wrap("w", Joined::new([Box::new(j) as BoxError]).unwrap());
    assert!(error::is(dynerr(&nested), dynerr(&b)));
    let single: Joined = Joined::new([Box::new(a.clone()) as BoxError]).unwrap();
    assert_eq!(single.to_string(), "a");
}

#[test]
fn unsupported() {
    let e = Message::unsupported();
    assert_eq!(e.to_string(), "unsupported operation");
    let w = wrap("copy: not here", e);
    assert!(error::is(dynerr(&w), dynerr(&Message::unsupported())));
    assert!(!error::is(
        dynerr(&w),
        dynerr(&Message::new("unsupported operation"))
    ));
}

// Go's `Is(error) bool` and `As(any) bool` methods (the poser type of
// errors_test.go), opted into with register_is / register_as.
#[derive(Debug)]
struct Poser {
    msg: &'static str,
    matches: fn(&(dyn Error + 'static)) -> bool,
    inner: PathError,
}

impl fmt::Display for Poser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.msg)
    }
}

impl Error for Poser {}

impl error::ErrorIs for Poser {
    fn is(&self, target: &(dyn Error + 'static)) -> bool {
        (self.matches)(target)
    }
}

impl error::ErrorAs for Poser {
    fn as_error(&self, want: std::any::TypeId) -> Option<&(dyn Error + 'static)> {
        (want == std::any::TypeId::of::<PathError>()).then_some(&self.inner as _)
    }
}

#[test]
fn is_and_as_methods_participate() {
    error::register_is::<Poser>();
    error::register_is::<Poser>();
    error::register_as::<Poser>();
    let sentinel = Message::new("sentinel");
    let other = Message::new("other");
    let poser = Poser {
        msg: "poser",
        matches: |t| t.to_string() == "sentinel",
        inner: PathError("inner"),
    };
    assert!(error::is(&poser, &sentinel));
    assert!(!error::is(&poser, &other));
    // Found through a wrapper's source chain and through a Joined tree.
    let wrapped = wrap("wrapped", poser);
    assert!(error::is(&wrapped, &sentinel));
    assert!(!error::is(&wrapped, &other));
    let joined = Joined::new([Box::new(Message::new("x")) as BoxError, Box::new(wrapped)]).unwrap();
    assert!(error::is(&joined, &sentinel));
    assert_eq!(error::find::<PathError>(&joined), Some(&PathError("inner")));
    assert_eq!(
        error::find::<Message>(&joined).map(|m| m.to_string()),
        Some("x".into())
    );
    // A type without the hooks is unaffected.
    assert!(!error::is(&PathError("p"), &sentinel));
    assert!(error::find::<Poser>(&PathError("p")).is_none());
}
