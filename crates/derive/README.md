# First-party JSON derives

`rust-stdlib-derive` has no external dependencies and uses Rust's compiler-owned
`proc_macro` token-tree API. It generates implementations of
`rust_stdlib::encoding::json::{Serialize, Deserialize}`.

Run the complete generic metadata example from the repository root:

```sh
cargo run --offline --locked --manifest-path tools/derive-check/Cargo.toml
```

Its output is:

```json
{"name":"contact-sheet","ratings":[3,5,1]}
```

## Supported syntax and wire formats

- Named structs follow Go's `encoding/json`: fields in declaration order,
  unknown members ignored when decoding, absent members take their zero value,
  names matched exactly and then ignoring case. Use `Decoder::disallow_unknown_fields`
  to reject unknown members. See "Go struct tags" below.
- Tuple structs become arrays with exact lengths; unit structs become null.
- Enum values use one externally tagged object entry; payloads follow those rules.
- Empty enums deserialize to a type error and have no serializable values.
- Type, lifetime and const parameters, bounds, defaults and where clauses work
  across named structs, tuple structs and enums. Defaults are removed from impl
  declarations and retained on the original type.
- Higher-ranked bounds, associated projections, generic associated types,
  nested generic field types, raw identifiers, restricted visibility and function
  type arrows are covered by actual consumer compilation and execution tests.
- Generated JSON bounds target generic field types. Recursive fields and
  lifetime-bearing generic wrappers bind their used type parameters to avoid
  cyclic or overlapping trait predicates. This can impose stronger bounds on
  unusual wrappers that serialize independently of their type parameters.
- Serialization supports borrowed fields when their types implement `Serialize`.
  Reference syntax in deserialized field types produces a specific compiler
  diagnostic; the JSON ownership model returns owned values. Type aliases are
  checked through their trait implementations by Rust's compiler.
- Generated locals use a namespace chosen against every input identifier;
  result types and constructors use absolute `core` paths.

## XML derives

`Marshal` and `Unmarshal` implement the typed traits of
`rust_stdlib::encoding::xml` for structs with named fields. Go reads
`xml:"..."` struct tags by reflection; here the same tag text is written
`#[xml("...")]` and the runtime interprets it exactly as Go does:

```rust
use rust_stdlib::encoding::xml::{self, Name};
use rust_stdlib_derive::{Marshal, Unmarshal};

#[derive(Default, Marshal, Unmarshal)]
struct Person {
    #[xml("person")] xml_name: Name,
    #[xml("id,attr")] id: isize,
    #[xml("name>first")] first_name: String,
    #[xml("name>last")] last_name: String,
    #[xml("height,omitempty")] height: f32,
    #[xml(",comment")] comment: String,
}
```

- Every tag option works: `attr`, `cdata`, `chardata`, `innerxml`, `comment`,
  `any`, `any,attr`, `omitempty`, `a>b>c` paths, `"namespace name"` prefixes and
  `"-"`. Tag mistakes surface as Go's error texts when the type is first used.
- A field named `xml_name` (or `XMLName`) of type `Name` is Go's `XMLName`.
- Without a name in the tag, the element or attribute is named by the Rust field
  identifier verbatim (Go uses the capitalized field name), and an element with
  no `XMLName` is named by the struct identifier.
- `#[xml(embed)]` marks an embedded struct whose fields are lifted into the outer
  struct (Go's anonymous fields), also behind `Option`. It combines with a tag
  string: `#[xml(embed, "-")]`.
- Field types must implement `Marshal` (respectively `Unmarshal`): primitives,
  `String`, `Vec<u8>`, `Vec<T>`, `Option<T>`, `Box<T>`, `Name`, `Attr`, other
  derived structs, and types with hand-written `Marshaler`/`Unmarshaler`/
  `TextMarshaler`/`MarshalerAttr` hooks. Elements of `Vec` and `Option` must be
  `Default`; derive `Default` on the struct.
- Types that need custom behaviour implement the trait by hand and return
  themselves from `xml_marshaler`/`xml_unmarshaler`/... (see the xml tests).
- The derives accept structs with named fields only; enums, tuple structs and
  generic parameters are compile errors. `#[xml(...)]` belongs on fields.
  `#[xml]` attributes are ignored by the JSON derives, so one struct can derive
  both.

## Reflect derives

`Reflect` writes the static type information behind `rust_stdlib::reflect`
(Rust has no run-time reflection). It supports structs (named, tuple, unit) and
unit-only enums (a Go `int` kind); type parameters get `Reflect` bounds, and
`Pair<A, B>` is named `Pair[A,B]` as Go names instantiations. Lifetime
parameters and enums with data are compile errors.

```rust
use rust_stdlib::reflect::{self, Reflect};
use rust_stdlib_derive::{reflect_methods, reflect_trait, Reflect};

#[derive(Reflect, Default)]
#[reflect(pkg = "main")]                // Go package path; default is module_path!()
struct Point {
    #[reflect("json:\"x\" db:\"px\"")]  // Go struct tag
    pub X: i32,
    #[reflect(name = "Why")]            // Go field name
    pub y: i32,
    secret: bool,                       // not `pub`: unexported, PkgPath set
    #[reflect(export)]                  // exported although private
    forced: u8,
    #[reflect(embed)]                   // Go anonymous field (named after its type)
    pub Base: Base,
    #[reflect(skip)]                    // left out; needs Default to rebuild
    cache: Vec<u8>,
}

#[reflect_methods]                       // registers this impl block's methods
impl Point {
    pub fn Sum(&self) -> i32 { self.X + self.y }
    pub fn Scale(&mut self, k: i32) { self.X *= k; self.y *= k }
}

#[reflect_trait(pkg = "main")]           // reflect::type_for::<dyn Summer>()
trait Summer { fn Sum(&self) -> i32; }
```

- A field is exported when it is plain `pub` (Go's capitalised name);
  `pub(crate)` and private fields are unexported.
- `#[reflect_methods]` registers `&self` and `&mut self` methods without type
  parameters, on one `impl` block per type; `&mut self` methods are in the
  pointer method set only, as Go's pointer-receiver methods are. Parameters and
  results must implement `Reflect` (`&str` and `&[T]` parameters are passed as
  `String` and `Vec<T>`); a tuple result becomes several Go results. Methods are
  exported when `pub` (always in a trait impl). `#[reflect(skip)]` leaves one out.
- `#[reflect_trait]` makes the trait's `&self`/`&mut self` methods a Go
  interface type for `Type::implements` and `Value::method`.
- `#[json(...)]` and `#[xml(...)]` attributes may sit beside `#[reflect(...)]`.

## Go struct tags

Fields of named structs take a `#[json(...)]` attribute. It holds either a Go
struct tag string, written exactly as in Go, or keywords, or both:

```rust
#[derive(Serialize, Deserialize)]
struct Record {
    #[json("id")]                         // rename
    key: u64,
    #[json("name,omitempty")]             // Go tag string
    name: String,
    #[json(rename = "n", string)]         // keywords
    count: u32,
    #[json(omitzero)]
    when: Option<u64>,
    #[json(skip)]                          // Go's `json:"-"`; needs Default
    cache: Vec<u8>,
    #[json(embedded)]                      // promote the fields of Base
    base: Base,
}
```

- Names follow Go 1.27 (v1 on top of v2): everything up to a comma, backslash
  or quote is the name, so `"x:y"` and `"a b"` are fine and `"a'b"` means `a`.
- `omitempty` omits false, 0, `None` and empty strings, vectors, arrays and maps;
  `omitzero` omits the zero value (implement `Serialize::is_zero_value` to mimic
  an `IsZero` method); `string` quotes numbers, booleans and strings (and
  `Option`/`Box` of them) and unquotes them when decoding; `case:strict` makes
  a field match its exact name only.
- `skip` (or the tag `-`) leaves the field out of the JSON; decoding fills it
  with `Default::default()`. The tag `-,` names a field `-`.
- `embedded` (or `flatten`) promotes the fields of a struct field, optionally
  wrapped in `Option` or `Box`, as Go does for embedded structs. Among fields
  with one name the shallowest wins, then the one with a tag name; otherwise all
  are dropped. A decoded `Option<Embedded>` is `Some` only if one of its
  members appears.
- Fields of enum variants and tuple structs do not take `json` attributes.
- `Vec<u8>` is an array of numbers; use `json::Bytes` for Go's base64 `[]byte`.

## Explicit boundaries

Only `doc`, `derive`, lint-level (`allow`, `warn`, `deny`, `forbid`, `expect`)
and, on fields of named structs, `json` attributes are accepted. Other custom
attributes, representation attributes, explicit enum integer discriminants and
unions produce compiler errors. Runtime crate renaming requires importing it as
`rust_stdlib`.

Run the syntax and diagnostic verification:

```sh
python3 tools/derive-check/check.py
```

The check compiles and executes the consumer against the real macros, then
checks unsupported cases through Cargo in a temporary consumer project.
