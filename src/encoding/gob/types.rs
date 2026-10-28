//! Type descriptors: Go's `type.go`.
//!
//! A process-wide table maps reflect types to gob types and hands out type
//! ids exactly as Go does (the predefined ids first, user ids from 64, in the
//! order types are first sent), so streams are byte-identical.

use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};

use crate::reflect::{self, Kind, Type};

use super::wire::{self, ArrayT, CommonType, MapT, SliceT, StructT, WireType};

pub(crate) const FIRST_USER_ID: i32 = 64;

pub(crate) const T_BOOL: i32 = 1;
pub(crate) const T_INT: i32 = 2;
pub(crate) const T_UINT: i32 = 3;
pub(crate) const T_FLOAT: i32 = 4;
pub(crate) const T_BYTES: i32 = 5;
pub(crate) const T_STRING: i32 = 6;
pub(crate) const T_COMPLEX: i32 = 7;
pub(crate) const T_INTERFACE: i32 = 8;
pub(crate) const T_WIRE_TYPE: i32 = 16;

pub(crate) const X_GOB: u8 = 1;
pub(crate) const X_BINARY: u8 = 2;
pub(crate) const X_TEXT: u8 = 3;

/// `gob: ` plus the message, as Go's `errorf`.
pub(crate) fn errorf(msg: impl AsRef<str>) -> io::Error {
    io::Error::other(format!("gob: {}", msg.as_ref()))
}

/// An error with exactly this text.
pub(crate) fn plain(msg: impl Into<String>) -> io::Error {
    io::Error::other(msg.into())
}

pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Go `isExported`: whether the name starts with an upper-case letter.
pub(crate) fn is_exported(name: &str) -> bool {
    name.chars()
        .next()
        .is_some_and(|c| crate::unicode::is_upper(c as i32))
}

// ---------------------------------------------------------------------------
// User types.

/// What gob knows about a type handed to it (Go `userTypeInfo`).
pub(crate) struct UserTypeInfo {
    pub user: Type,
    pub base: Type,
    pub indir: usize,
    pub external_enc: u8,
    pub external_dec: u8,
    pub enc_indir: i8,
    pub dec_indir: i8,
}

static USER_TYPES: LazyLock<Mutex<HashMap<Type, Arc<UserTypeInfo>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn method_iface(name: &str, ins: &[Type], outs: &[Type]) -> Type {
    reflect::interface_of(&[(name, reflect::func_of(ins, outs, false))])
}

fn bytes_type() -> Type {
    reflect::slice_of(&Type::basic(Kind::Uint8))
}

struct Ifaces {
    gob_encoder: Type,
    gob_decoder: Type,
    binary_marshaler: Type,
    binary_unmarshaler: Type,
}

static IFACES: LazyLock<Ifaces> = LazyLock::new(|| Ifaces {
    gob_encoder: method_iface("GobEncode", &[], &[bytes_type(), Type::error_type()]),
    gob_decoder: method_iface("GobDecode", &[bytes_type()], &[Type::error_type()]),
    binary_marshaler: method_iface("MarshalBinary", &[], &[bytes_type(), Type::error_type()]),
    binary_unmarshaler: method_iface("UnmarshalBinary", &[bytes_type()], &[Type::error_type()]),
});

/// Go `implementsInterface`.
fn implements_interface(typ: &Type, iface: &Type) -> Option<i8> {
    let mut indir: i8 = 0;
    let mut rt = typ.clone();
    loop {
        if rt.implements(iface) {
            return Some(indir);
        }
        if rt.kind() == Kind::Pointer {
            indir += 1;
            if indir > 100 {
                return None;
            }
            rt = rt.elem();
            continue;
        }
        break;
    }
    if typ.kind() != Kind::Pointer && reflect::pointer_to(typ).implements(iface) {
        return Some(-1);
    }
    None
}

/// Go `validUserType`.
pub(crate) fn valid_user_type(rt: &Type) -> Result<Arc<UserTypeInfo>, io::Error> {
    if let Some(ui) = lock(&USER_TYPES).get(rt) {
        return Ok(ui.clone());
    }
    let mut base = rt.clone();
    let mut indir = 0usize;
    while base.kind() == Kind::Pointer {
        base = base.elem();
        indir += 1;
        if indir > 10_000 {
            return Err(plain(format!(
                "can't represent recursive pointer type {base}"
            )));
        }
    }
    let ifaces = &*IFACES;
    let (mut external_enc, mut enc_indir) = (0, 0);
    let (mut external_dec, mut dec_indir) = (0, 0);
    if let Some(i) = implements_interface(rt, &ifaces.gob_encoder) {
        (external_enc, enc_indir) = (X_GOB, i);
    } else if let Some(i) = implements_interface(rt, &ifaces.binary_marshaler) {
        (external_enc, enc_indir) = (X_BINARY, i);
    }
    if let Some(i) = implements_interface(rt, &ifaces.gob_decoder) {
        (external_dec, dec_indir) = (X_GOB, i);
    } else if let Some(i) = implements_interface(rt, &ifaces.binary_unmarshaler) {
        (external_dec, dec_indir) = (X_BINARY, i);
    }
    let ut = Arc::new(UserTypeInfo {
        user: rt.clone(),
        base,
        indir,
        external_enc,
        external_dec,
        enc_indir,
        dec_indir,
    });
    Ok(lock(&USER_TYPES).entry(rt.clone()).or_insert(ut).clone())
}

/// Go `userType`.
pub(crate) fn user_type(rt: &Type) -> Result<Arc<UserTypeInfo>, io::Error> {
    valid_user_type(rt)
}

// ---------------------------------------------------------------------------
// Gob types.

pub(crate) enum GKind {
    Common,
    Array { elem: i32, len: i64 },
    Slice { elem: i32 },
    Map { key: i32, elem: i32 },
    Struct { fields: Vec<(String, i32)> },
    GobEncoder,
}

pub(crate) struct GNode {
    pub name: String,
    pub id: i32,
    pub kind: GKind,
}

/// What is known about a type once its descriptor exists (Go `typeInfo`).
pub(crate) struct TypeInfo {
    pub id: i32,
    pub wire: WireType,
}

pub(crate) struct Table {
    nodes: Vec<GNode>,
    types: HashMap<Type, usize>,
    id_to_node: Vec<Option<usize>>,
    builtin: Vec<Option<usize>>,
    infos: HashMap<Type, Arc<TypeInfo>>,
}

static TABLE: LazyLock<Mutex<Table>> = LazyLock::new(|| Mutex::new(Table::bootstrap()));

pub(crate) fn table() -> MutexGuard<'static, Table> {
    lock(&TABLE)
}

/// Go `getTypeInfo`.
pub(crate) fn get_type_info(ut: &UserTypeInfo) -> Result<Arc<TypeInfo>, io::Error> {
    table().get_type_info(ut)
}

impl Table {
    fn bootstrap() -> Table {
        let mut t = Table {
            nodes: Vec::new(),
            types: HashMap::new(),
            id_to_node: vec![None],
            builtin: Vec::new(),
            infos: HashMap::new(),
        };
        let basics: [(&str, Option<Type>); 15] = [
            ("bool", Some(Type::basic(Kind::Bool))),
            ("int", Some(Type::basic(Kind::Int))),
            ("uint", Some(Type::basic(Kind::Uint))),
            ("float", Some(Type::basic(Kind::Float64))),
            ("bytes", Some(bytes_type())),
            ("string", Some(Type::basic(Kind::String))),
            ("complex", Some(Type::basic(Kind::Complex128))),
            ("interface", Some(Type::any_type())),
            ("_reserved7", None),
            ("_reserved6", None),
            ("_reserved5", None),
            ("_reserved4", None),
            ("_reserved3", None),
            ("_reserved2", None),
            ("_reserved1", None),
        ];
        for (name, rt) in basics {
            let n = t.new_node(name, GKind::Common);
            if let Some(rt) = rt {
                t.types.insert(rt, n);
            }
            t.set_type_id(n);
        }
        let ut = match valid_user_type(&wire::types().wire_type) {
            Ok(ut) => ut,
            Err(e) => panic!("gob: bootstrap: {e}"),
        };
        let info = match t.get_type_info(&ut) {
            Ok(i) => i,
            Err(e) => panic!("gob: bootstrap: {e}"),
        };
        assert_eq!(info.id, 16, "bootstrap type wrong id");
        t.builtin = t.id_to_node.clone();
        t.builtin.resize(FIRST_USER_ID as usize, None);
        t.id_to_node.resize(FIRST_USER_ID as usize, None);
        t
    }

    fn new_node(&mut self, name: &str, kind: GKind) -> usize {
        self.nodes.push(GNode {
            name: name.to_string(),
            id: 0,
            kind,
        });
        self.nodes.len() - 1
    }

    /// Go `setTypeId`.
    fn set_type_id(&mut self, n: usize) {
        if self.nodes[n].id != 0 {
            return;
        }
        let id = self.id_to_node.len() as i32;
        self.nodes[n].id = id;
        self.id_to_node.push(Some(n));
    }

    pub(crate) fn node_by_id(&self, id: i32) -> Option<&GNode> {
        if id < 0 {
            return None;
        }
        self.id_to_node
            .get(id as usize)
            .copied()
            .flatten()
            .map(|n| &self.nodes[n])
    }

    pub(crate) fn builtin_by_id(&self, id: i32) -> Option<&GNode> {
        if id < 0 {
            return None;
        }
        self.builtin
            .get(id as usize)
            .copied()
            .flatten()
            .map(|n| &self.nodes[n])
    }

    /// The text of the type with this id (Go `typeId.string`).
    pub(crate) fn id_string(&self, id: i32) -> String {
        match self.node_by_id(id) {
            Some(_) => self.node_string(id, &mut HashSet::new()),
            None => "<nil>".to_string(),
        }
    }

    fn node_string(&self, id: i32, seen: &mut HashSet<i32>) -> String {
        let Some(n) = self.node_by_id(id) else {
            return "<nil>".to_string();
        };
        match &n.kind {
            GKind::Common | GKind::GobEncoder => n.name.clone(),
            GKind::Array { elem, len } => {
                if !seen.insert(n.id) {
                    return n.name.clone();
                }
                format!("[{}]{}", len, self.node_string(*elem, seen))
            }
            GKind::Slice { elem } => {
                if !seen.insert(n.id) {
                    return n.name.clone();
                }
                format!("[]{}", self.node_string(*elem, seen))
            }
            GKind::Map { key, elem } => {
                if !seen.insert(n.id) {
                    return n.name.clone();
                }
                let k = self.node_string(*key, seen);
                let e = self.node_string(*elem, seen);
                format!("map[{k}]{e}")
            }
            GKind::Struct { fields } => {
                if !seen.insert(n.id) {
                    return n.name.clone();
                }
                let mut s = format!("{} = struct {{ ", n.name);
                for (fname, fid) in fields {
                    s.push_str(&format!("{} {}; ", fname, self.node_string(*fid, seen)));
                }
                s.push('}');
                s
            }
        }
    }

    /// Go `getTypeInfo`.
    pub(crate) fn get_type_info(&mut self, ut: &UserTypeInfo) -> Result<Arc<TypeInfo>, io::Error> {
        let rt = if ut.external_enc != 0 {
            ut.user.clone()
        } else {
            ut.base.clone()
        };
        if let Some(info) = self.infos.get(&rt) {
            return Ok(info.clone());
        }
        self.build_type_info(ut, rt)
    }

    fn build_type_info(
        &mut self,
        ut: &UserTypeInfo,
        mut rt: Type,
    ) -> Result<Arc<TypeInfo>, io::Error> {
        let gt = self.get_base_type(&rt.name(), &rt)?;
        let id = self.nodes[gt].id;
        let mut wire = WireType::default();
        if ut.external_enc != 0 {
            let name = rt.name();
            let user_node = self.get_type(&name, ut, &rt)?;
            let uid = self.nodes[user_node].id;
            let common = match self.node_by_id(uid) {
                Some(n) if matches!(n.kind, GKind::GobEncoder) => CommonType {
                    name: n.name.clone(),
                    id: n.id,
                },
                _ => return Err(plain("gob: external type is not a GobEncoder type")),
            };
            match ut.external_enc {
                X_GOB => wire.gob_encoder_t = Some(common),
                X_BINARY => wire.binary_marshaler_t = Some(common),
                _ => wire.text_marshaler_t = Some(common),
            }
            rt = ut.user.clone();
        } else if let Some(n) = self.node_by_id(id) {
            let common = CommonType {
                name: n.name.clone(),
                id: n.id,
            };
            match (rt.kind(), &n.kind) {
                (Kind::Array, GKind::Array { elem, len }) => {
                    wire.array_t = Some(ArrayT {
                        common,
                        elem: *elem,
                        len: *len,
                    })
                }
                (Kind::Map, GKind::Map { key, elem }) => {
                    wire.map_t = Some(MapT {
                        common,
                        key: *key,
                        elem: *elem,
                    })
                }
                (Kind::Slice, GKind::Slice { elem }) => {
                    if rt.elem().kind() != Kind::Uint8 {
                        wire.slice_t = Some(SliceT {
                            common,
                            elem: *elem,
                        })
                    }
                }
                (Kind::Struct, GKind::Struct { fields }) => {
                    wire.struct_t = Some(StructT {
                        common,
                        fields: fields.clone(),
                    })
                }
                _ => {}
            }
        }
        let info = Arc::new(TypeInfo { id, wire });
        self.infos.insert(rt, info.clone());
        Ok(info)
    }

    /// Go `getBaseType`.
    fn get_base_type(&mut self, name: &str, rt: &Type) -> Result<usize, io::Error> {
        let ut = user_type(rt)?;
        self.get_type(name, &ut, &ut.base)
    }

    /// Go `getType`.
    fn get_type(&mut self, name: &str, ut: &UserTypeInfo, rt: &Type) -> Result<usize, io::Error> {
        if let Some(n) = self.types.get(rt) {
            return Ok(*n);
        }
        let n = self.new_type_object(name, ut, rt)?;
        self.types.insert(rt.clone(), n);
        Ok(n)
    }

    /// Go `newTypeObject`.
    fn new_type_object(
        &mut self,
        name: &str,
        ut: &UserTypeInfo,
        rt: &Type,
    ) -> Result<usize, io::Error> {
        if ut.external_enc != 0 {
            let n = self.new_node(name, GKind::GobEncoder);
            self.set_type_id(n);
            return Ok(n);
        }
        let r = self.new_type_object_inner(name, rt);
        if r.is_err() {
            self.types.remove(rt);
        }
        r
    }

    fn basic_node(&self, id: i32) -> usize {
        self.id_to_node[id as usize].unwrap_or(0)
    }

    fn new_type_object_inner(&mut self, name: &str, rt: &Type) -> Result<usize, io::Error> {
        match rt.kind() {
            Kind::Bool => Ok(self.basic_node(T_BOOL)),
            Kind::Int | Kind::Int8 | Kind::Int16 | Kind::Int32 | Kind::Int64 => {
                Ok(self.basic_node(T_INT))
            }
            Kind::Uint
            | Kind::Uint8
            | Kind::Uint16
            | Kind::Uint32
            | Kind::Uint64
            | Kind::Uintptr => Ok(self.basic_node(T_UINT)),
            Kind::Float32 | Kind::Float64 => Ok(self.basic_node(T_FLOAT)),
            Kind::Complex64 | Kind::Complex128 => Ok(self.basic_node(T_COMPLEX)),
            Kind::String => Ok(self.basic_node(T_STRING)),
            Kind::Interface => Ok(self.basic_node(T_INTERFACE)),
            Kind::Array => {
                let at = self.new_node(name, GKind::Array { elem: 0, len: 0 });
                self.types.insert(rt.clone(), at);
                let elem = self.get_base_type("", &rt.elem())?;
                // Set our type id before evaluating the element's, in case it
                // is our own.
                self.set_type_id(at);
                let elem_id = self.nodes[elem].id;
                self.nodes[at].kind = GKind::Array {
                    elem: elem_id,
                    len: rt.len() as i64,
                };
                Ok(at)
            }
            Kind::Map => {
                let mt = self.new_node(name, GKind::Map { key: 0, elem: 0 });
                self.types.insert(rt.clone(), mt);
                let key = self.get_base_type("", &rt.key())?;
                let elem = self.get_base_type("", &rt.elem())?;
                self.set_type_id(mt);
                let (kid, eid) = (self.nodes[key].id, self.nodes[elem].id);
                self.nodes[mt].kind = GKind::Map {
                    key: kid,
                    elem: eid,
                };
                Ok(mt)
            }
            Kind::Slice => {
                // []byte == []uint8 is a special case.
                if rt.elem().kind() == Kind::Uint8 {
                    return Ok(self.basic_node(T_BYTES));
                }
                let st = self.new_node(name, GKind::Slice { elem: 0 });
                self.types.insert(rt.clone(), st);
                let et = rt.elem();
                let elem = self.get_base_type(&et.name(), &et)?;
                self.set_type_id(st);
                // Only slices and structs have mutual recursion.
                if self.nodes[elem].id == 0 {
                    self.set_type_id(elem);
                }
                let eid = self.nodes[elem].id;
                self.nodes[st].kind = GKind::Slice { elem: eid };
                Ok(st)
            }
            Kind::Struct => {
                let st = self.new_node(name, GKind::Struct { fields: Vec::new() });
                self.set_type_id(st);
                self.types.insert(rt.clone(), st);
                for i in 0..rt.num_field() {
                    let f = rt.field(i);
                    if !is_sent(&f) {
                        continue;
                    }
                    let fut = user_type(&f.type_)?;
                    let typ = fut.base.clone();
                    let mut tname = typ.name();
                    if tname.is_empty() {
                        tname = typ.to_string();
                    }
                    let gt = self.get_base_type(&tname, &f.type_)?;
                    // Some mutually recursive types can cause us to be here
                    // while still defining the element.
                    if self.nodes[gt].id == 0 {
                        self.set_type_id(gt);
                    }
                    let gid = self.nodes[gt].id;
                    if let GKind::Struct { fields } = &mut self.nodes[st].kind {
                        fields.push((f.name.clone(), gid));
                    }
                }
                Ok(st)
            }
            _ => Err(plain(format!(
                "gob NewTypeObject can't handle type: {}",
                rt
            ))),
        }
    }
}

/// Go `isSent`: whether a struct field is transmitted.
pub(crate) fn is_sent(f: &reflect::StructField) -> bool {
    if !is_exported(&f.name) {
        return false;
    }
    let mut typ = f.type_.clone();
    while typ.kind() == Kind::Pointer {
        typ = typ.elem();
    }
    !matches!(typ.kind(), Kind::Chan | Kind::Func)
}

// ---------------------------------------------------------------------------
// Registered interface types.

struct Registry {
    name_to_type: HashMap<String, Type>,
    type_to_name: HashMap<Type, String>,
}

static REGISTRY: LazyLock<Mutex<Registry>> = LazyLock::new(|| {
    let mut r = Registry {
        name_to_type: HashMap::new(),
        type_to_name: HashMap::new(),
    };
    register_basics(&mut r);
    Mutex::new(r)
});

fn register_basics(r: &mut Registry) {
    let b = Type::basic;
    let mut types: Vec<Type> = Vec::new();
    for k in [
        Kind::Int,
        Kind::Int8,
        Kind::Int16,
        Kind::Int32,
        Kind::Int64,
        Kind::Uint,
        Kind::Uint8,
        Kind::Uint16,
        Kind::Uint32,
        Kind::Uint64,
        Kind::Float32,
        Kind::Float64,
        Kind::Complex64,
        Kind::Complex128,
        Kind::Uintptr,
        Kind::Bool,
        Kind::String,
    ] {
        types.push(b(k));
    }
    // []byte, then slices of the other basic kinds in Go's order.
    types.push(reflect::slice_of(&b(Kind::Uint8)));
    for k in [
        Kind::Int,
        Kind::Int8,
        Kind::Int16,
        Kind::Int32,
        Kind::Int64,
        Kind::Uint,
        Kind::Uint8,
        Kind::Uint16,
        Kind::Uint32,
        Kind::Uint64,
        Kind::Float32,
        Kind::Float64,
        Kind::Complex64,
        Kind::Complex128,
        Kind::Uintptr,
        Kind::Bool,
        Kind::String,
    ] {
        types.push(reflect::slice_of(&b(k)));
    }
    for t in types {
        let name = default_name(&t);
        if let Err(e) = register_name_in(r, &name, &t) {
            panic!("{e}");
        }
    }
}

/// The name `Register` gives a type.
fn default_name(rt0: &Type) -> String {
    let mut rt = rt0.clone();
    let mut name = rt.to_string();
    let mut star = "";
    if rt.name().is_empty() && rt.kind() == Kind::Pointer {
        star = "*";
        rt = rt0.clone();
    }
    if !rt.name().is_empty() {
        name = if rt.pkg_path().is_empty() {
            format!("{}{}", star, rt.name())
        } else {
            format!("{}{}.{}", star, rt.pkg_path(), rt.name())
        };
    }
    name
}

fn register_name_in(r: &mut Registry, name: &str, rt: &Type) -> Result<(), String> {
    if name.is_empty() {
        return Err("attempt to register empty name".to_string());
    }
    let ut = match valid_user_type(rt) {
        Ok(u) => u,
        Err(e) => return Err(e.to_string()),
    };
    if let Some(t) = r.name_to_type.get(name) {
        if *t != ut.user {
            return Err(format!(
                "gob: registering duplicate types for {}: {} != {}",
                crate::strconv::quote(name),
                t,
                ut.user
            ));
        }
    } else {
        r.name_to_type.insert(name.to_string(), rt.clone());
    }
    match r.type_to_name.get(&ut.base) {
        Some(n) if n != name => {
            let n = n.clone();
            r.name_to_type.remove(name);
            Err(format!(
                "gob: registering duplicate names for {}: {} != {}",
                ut.user,
                crate::strconv::quote(&n),
                crate::strconv::quote(name)
            ))
        }
        Some(_) => Ok(()),
        None => {
            r.type_to_name.insert(ut.base.clone(), name.to_string());
            Ok(())
        }
    }
}

/// Go `RegisterName` on a type: panics as Go does on an empty name or a
/// non-bijective registration.
pub(crate) fn register_type_name(name: &str, rt: &Type) {
    if let Err(e) = register_name_in(&mut lock(&REGISTRY), name, rt) {
        panic!("{e}");
    }
}

/// Go `Register` on a type.
pub(crate) fn register_type(rt: &Type) {
    register_type_name(&default_name(rt), rt);
}

pub(crate) fn concrete_type_to_name(base: &Type) -> Option<String> {
    lock(&REGISTRY).type_to_name.get(base).cloned()
}

pub(crate) fn name_to_concrete_type(name: &str) -> Option<Type> {
    lock(&REGISTRY).name_to_type.get(name).cloned()
}
