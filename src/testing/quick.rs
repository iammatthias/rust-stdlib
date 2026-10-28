//! Go's `testing/quick`: utility functions for black box testing with
//! arbitrary values.
//!
//! Go builds arbitrary arguments for any function by reflection. Rust has no
//! run-time type information, so the types that can be generated implement
//! [`Generator`]: the primitive types, `String`, `Vec`, arrays, `Option`,
//! maps and tuples already do, following Go's algorithm and drawing from
//! [`crate::math::rand::v1`] in the same order, so a given seed produces the
//! same values as Go for those types. The property passed to [`check`] is a
//! closure with up to eight generatable arguments that returns `bool`.
//!
//! ```
//! use rust_stdlib::testing::quick;
//!
//! let reverse_twice = |v: Vec<i32>| {
//!     let mut w = v.clone();
//!     w.reverse();
//!     w.reverse();
//!     w == v
//! };
//! assert!(quick::check(reverse_twice, None).is_ok());
//! ```

use std::{
    any::Any,
    collections::{BTreeMap, HashMap},
    fmt,
    hash::Hash,
    sync::atomic::{AtomicUsize, Ordering},
};

use crate::math::rand::v1;

/// The random number generator type of this package: Go's `*rand.Rand` over
/// any source.
pub type Rand = v1::Rand<Box<dyn v1::Source>>;

/// Go's `rand.New(rand.NewSource(seed))`.
pub fn seeded_rand(seed: i64) -> Rand {
    v1::Rand::new(Box::new(v1::RngSource::new(seed)))
}

static DEFAULT_MAX_COUNT: AtomicUsize = AtomicUsize::new(0);

/// The default number of iterations for each check: Go's `-quickchecks` flag
/// (100 unless the process was started with `-quickchecks=N`).
pub fn default_max_count() -> usize {
    let cached = DEFAULT_MAX_COUNT.load(Ordering::Relaxed);
    if cached != 0 {
        return cached;
    }
    let mut n = 100;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].trim_start_matches('-');
        if let Some(v) = a.strip_prefix("quickchecks=") {
            n = v.parse().unwrap_or(n);
        } else if a == "quickchecks" && i + 1 < args.len() {
            n = args[i + 1].parse().unwrap_or(n);
            i += 1;
        }
        i += 1;
    }
    DEFAULT_MAX_COUNT.store(n, Ordering::Relaxed);
    n
}

/// Overrides [`default_max_count`].
pub fn set_default_max_count(n: usize) {
    DEFAULT_MAX_COUNT.store(n, Ordering::Relaxed);
}

/// The maximum length of arbitrary values that contain other values.
const COMPLEX_SIZE: usize = 50;

/// Go's `quick.Generator`: a type that can generate random values of its own
/// type. `size` is a hint for shrinking as a function of indirection level, so
/// that recursive data structures terminate.
pub trait Generator: Sized {
    /// Returns a random instance of the type using `size` as a size hint.
    fn generate(rand: &mut Rand, size: usize) -> Self;
}

/// Go's `quick.Value`: an arbitrary value of type `T`.
pub fn value<T: Generator>(rand: &mut Rand) -> T {
    T::generate(rand, COMPLEX_SIZE)
}

fn rand_f32(rand: &mut Rand) -> f32 {
    let mut f = rand.float64() * f64::from(f32::MAX);
    if rand.int() & 1 == 1 {
        f = -f;
    }
    f as f32
}

fn rand_f64(rand: &mut Rand) -> f64 {
    let mut f = rand.float64() * f64::MAX;
    if rand.int() & 1 == 1 {
        f = -f;
    }
    f
}

fn rand_i64(rand: &mut Rand) -> i64 {
    rand.uint64() as i64
}

macro_rules! int_generator {
    ($($t:ty),+) => {$(
        impl Generator for $t {
            fn generate(rand: &mut Rand, _size: usize) -> Self {
                rand_i64(rand) as $t
            }
        }
    )+};
}
int_generator!(i8, i16, i32, i64, isize, u8, u16, u32, u64, usize);

impl Generator for bool {
    fn generate(rand: &mut Rand, _size: usize) -> Self {
        rand.int() & 1 == 0
    }
}

impl Generator for f32 {
    fn generate(rand: &mut Rand, _size: usize) -> Self {
        rand_f32(rand)
    }
}

impl Generator for f64 {
    fn generate(rand: &mut Rand, _size: usize) -> Self {
        rand_f64(rand)
    }
}

impl Generator for String {
    fn generate(rand: &mut Rand, _size: usize) -> Self {
        let n = rand.intn(COMPLEX_SIZE as i64);
        (0..n)
            .map(|_| {
                let r = rand.intn(0x10ffff) as u32;
                char::from_u32(r).unwrap_or('\u{FFFD}')
            })
            .collect()
    }
}

impl<T: Generator> Generator for Vec<T> {
    fn generate(rand: &mut Rand, size: usize) -> Self {
        let n = rand.intn(size as i64) as usize;
        let size_left = size - n;
        (0..n).map(|_| T::generate(rand, size_left)).collect()
    }
}

impl<T: Generator, const N: usize> Generator for [T; N] {
    fn generate(rand: &mut Rand, size: usize) -> Self {
        std::array::from_fn(|_| T::generate(rand, size))
    }
}

/// Go's pointer: `None` (a nil pointer) with probability `1/size`.
impl<T: Generator> Generator for Option<T> {
    fn generate(rand: &mut Rand, size: usize) -> Self {
        if rand.intn(size as i64) == 0 {
            None
        } else {
            Some(T::generate(rand, size))
        }
    }
}

impl<K: Generator + Eq + Hash, V: Generator> Generator for HashMap<K, V> {
    fn generate(rand: &mut Rand, size: usize) -> Self {
        let n = rand.intn(size as i64);
        let mut m = HashMap::new();
        for _ in 0..n {
            let k = K::generate(rand, size);
            let v = V::generate(rand, size);
            m.insert(k, v);
        }
        m
    }
}

impl<K: Generator + Ord, V: Generator> Generator for BTreeMap<K, V> {
    fn generate(rand: &mut Rand, size: usize) -> Self {
        let n = rand.intn(size as i64);
        let mut m = BTreeMap::new();
        for _ in 0..n {
            let k = K::generate(rand, size);
            let v = V::generate(rand, size);
            m.insert(k, v);
        }
        m
    }
}

macro_rules! tuple_generator {
    ($($name:ident),*) => {
        impl<$($name: Generator),*> Generator for ($($name,)*) {
            #[allow(unused_variables, clippy::unused_unit)]
            fn generate(rand: &mut Rand, size: usize) -> Self {
                ($($name::generate(rand, size),)*)
            }
        }
    };
}
tuple_generator!();
tuple_generator!(A);
tuple_generator!(A, B);
tuple_generator!(A, B, C);
tuple_generator!(A, B, C, D);
tuple_generator!(A, B, C, D, E);
tuple_generator!(A, B, C, D, E, G);
tuple_generator!(A, B, C, D, E, G, H);
tuple_generator!(A, B, C, D, E, G, H, I);

/// A function Go's `Check` can test: `Fn(A, B, ...) -> bool` over the
/// arguments tuple `Args`.
pub trait Property<Args> {
    /// Calls the function with the arguments.
    fn call(&self, args: Args) -> bool;
}

/// A function [`check_equal`] can compare: `Fn(A, B, ...) -> R`.
pub trait Function<Args> {
    /// The result type.
    type Output;
    /// Calls the function with the arguments.
    fn call(&self, args: Args) -> Self::Output;
}

macro_rules! function_impls {
    ($($name:ident $idx:tt),*) => {
        impl<Func, Ret, $($name),*> Function<($($name,)*)> for Func
        where
            Func: Fn($($name),*) -> Ret,
        {
            type Output = Ret;
            #[allow(unused_variables)]
            fn call(&self, args: ($($name,)*)) -> Ret {
                self($(args.$idx),*)
            }
        }
        impl<Func, $($name),*> Property<($($name,)*)> for Func
        where
            Func: Fn($($name),*) -> bool,
        {
            #[allow(unused_variables)]
            fn call(&self, args: ($($name,)*)) -> bool {
                self($(args.$idx),*)
            }
        }
    };
}
function_impls!();
function_impls!(A 0);
function_impls!(A 0, B 1);
function_impls!(A 0, B 1, C 2);
function_impls!(A 0, B 1, C 2, D 3);
function_impls!(A 0, B 1, C 2, D 3, E 4);
function_impls!(A 0, B 1, C 2, D 3, E 4, G 5);
function_impls!(A 0, B 1, C 2, D 3, E 4, G 5, H 6);
function_impls!(A 0, B 1, C 2, D 3, E 4, G 5, H 6, I 7);

/// Splits an arguments tuple into its debug renderings (Go's `toString` of
/// `%#v` values; Rust prints `Debug`).
pub trait ArgsDebug {
    /// One rendering per argument.
    fn debug_values(&self) -> Vec<String>;
}

macro_rules! args_debug {
    ($($name:ident $idx:tt),*) => {
        impl<$($name: fmt::Debug),*> ArgsDebug for ($($name,)*) {
            fn debug_values(&self) -> Vec<String> {
                vec![$(format!("{:?}", self.$idx)),*]
            }
        }
    };
}
args_debug!();
args_debug!(A 0);
args_debug!(A 0, B 1);
args_debug!(A 0, B 1, C 2);
args_debug!(A 0, B 1, C 2, D 3);
args_debug!(A 0, B 1, C 2, D 3, E 4);
args_debug!(A 0, B 1, C 2, D 3, E 4, G 5);
args_debug!(A 0, B 1, C 2, D 3, E 4, G 5, H 6);
args_debug!(A 0, B 1, C 2, D 3, E 4, G 5, H 6, I 7);

/// A function that generates the arguments of one call (Go's `Config.Values`
/// writing reflect values): it returns the arguments tuple of the property
/// as a `Box<dyn Any>`.
pub type ValuesFn = Box<dyn FnMut(&mut Rand) -> Box<dyn Any>>;

/// Go's `quick.Config`: options for running a test.
#[derive(Default)]
pub struct Config {
    /// The maximum number of iterations. If zero, `max_count_scale` is used.
    pub max_count: usize,
    /// A non-negative scale factor applied to the default maximum
    /// ([`default_max_count`]). Zero implies the default.
    pub max_count_scale: f64,
    /// A source of random numbers. If `None`, a pseudo-random source seeded
    /// from the clock is used.
    pub rand: Option<Rand>,
    /// Generates the arguments tuple of each call instead of
    /// [`Generator`]. If `None`, [`value`] is used for each argument.
    pub values: Option<ValuesFn>,
}

impl Config {
    fn get_max_count(&self) -> usize {
        let mut max = self.max_count;
        if max == 0 {
            max = if self.max_count_scale != 0.0 {
                (self.max_count_scale * default_max_count() as f64) as usize
            } else {
                default_max_count()
            };
        }
        max
    }
}

/// Go's `quick.SetupError`: an error in the way a check is being used,
/// independent of the functions being tested.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetupError(pub String);

impl fmt::Display for SetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SetupError {}

/// Go's `quick.CheckError`: the result of [`check`] finding a failing input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckError {
    /// The 1-based iteration at which the failure happened.
    pub count: usize,
    /// The `Debug` rendering of each argument of the failing call.
    pub in_: Vec<String>,
}

impl fmt::Display for CheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "#{}: failed on input {}",
            self.count,
            self.in_.join(", ")
        )
    }
}

impl std::error::Error for CheckError {}

/// Go's `quick.CheckEqualError`: the result of [`check_equal`] finding an
/// input on which the functions differ.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckEqualError {
    /// The embedded `CheckError`.
    pub check_error: CheckError,
    /// The `Debug` rendering of the first function's results.
    pub out1: Vec<String>,
    /// The `Debug` rendering of the second function's results.
    pub out2: Vec<String>,
}

impl fmt::Display for CheckEqualError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "#{}: failed on input {}. Output 1: {}. Output 2: {}",
            self.check_error.count,
            self.check_error.in_.join(", "),
            self.out1.join(", "),
            self.out2.join(", ")
        )
    }
}

impl std::error::Error for CheckEqualError {}

/// The error returned by [`check`] and [`check_equal`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// A [`SetupError`].
    Setup(SetupError),
    /// A [`CheckError`].
    Check(CheckError),
    /// A [`CheckEqualError`].
    CheckEqual(CheckEqualError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Setup(e) => e.fmt(f),
            Error::Check(e) => e.fmt(f),
            Error::CheckEqual(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for Error {}

fn arbitrary_values<Args: Generator + 'static>(
    config: &mut Config,
    rand: &mut Rand,
) -> Result<Args, Error> {
    if let Some(values) = config.values.as_mut() {
        return match values(rand).downcast::<Args>() {
            Ok(a) => Ok(*a),
            Err(_) => Err(Error::Setup(SetupError(
                "Config.Values returned arguments of the wrong type".to_string(),
            ))),
        };
    }
    Ok(Args::generate(rand, COMPLEX_SIZE))
}

fn rand_of(config: &mut Config) -> Rand {
    config.rand.take().unwrap_or_else(|| {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as i64);
        seeded_rand(nanos)
    })
}

/// Go's `quick.Check`: looks for an input to `f` such that it returns false,
/// calling it repeatedly with arbitrary arguments. If `f` returns false on
/// some input, the input is returned as an [`Error::Check`].
///
/// `config` is `None` for the defaults. A `config.rand` is consumed (it is
/// restored in `config` when the check ends).
pub fn check<Args, F>(f: F, config: Option<&mut Config>) -> Result<(), Error>
where
    Args: Generator + Clone + ArgsDebug + 'static,
    F: Property<Args>,
{
    let mut default = Config::default();
    let config = config.unwrap_or(&mut default);
    let mut rand = rand_of(config);
    let max_count = config.get_max_count();
    let mut result = Ok(());
    for i in 0..max_count {
        let args = match arbitrary_values::<Args>(config, &mut rand) {
            Ok(a) => a,
            Err(e) => {
                result = Err(e);
                break;
            }
        };
        if !f.call(args.clone()) {
            result = Err(Error::Check(CheckError {
                count: i + 1,
                in_: args.debug_values(),
            }));
            break;
        }
    }
    config.rand = Some(rand);
    result
}

/// Go's `quick.CheckEqual`: looks for an input on which `f` and `g` return
/// different results (compared with `PartialEq`, like `reflect.DeepEqual`),
/// calling both repeatedly with arbitrary arguments. If they differ, the
/// input and both outputs are returned as an [`Error::CheckEqual`].
pub fn check_equal<Args, F, G, R>(f: F, g: G, config: Option<&mut Config>) -> Result<(), Error>
where
    Args: Generator + Clone + ArgsDebug + 'static,
    F: Function<Args, Output = R>,
    G: Function<Args, Output = R>,
    R: PartialEq + fmt::Debug,
{
    let mut default = Config::default();
    let config = config.unwrap_or(&mut default);
    let mut rand = rand_of(config);
    let max_count = config.get_max_count();
    let mut result = Ok(());
    for i in 0..max_count {
        let args = match arbitrary_values::<Args>(config, &mut rand) {
            Ok(a) => a,
            Err(e) => {
                result = Err(e);
                break;
            }
        };
        let x = f.call(args.clone());
        let y = g.call(args.clone());
        if x != y {
            result = Err(Error::CheckEqual(CheckEqualError {
                check_error: CheckError {
                    count: i + 1,
                    in_: args.debug_values(),
                },
                out1: vec![format!("{x:?}")],
                out2: vec![format!("{y:?}")],
            }));
            break;
        }
    }
    config.rand = Some(rand);
    result
}
