//! `&mut T` method parameters are Go's `*T` and `Result<(), String>` is Go's
//! `error`: the method shape `net/rpc` registers.
#![allow(non_snake_case, dead_code)]
use rust_stdlib::reflect::{self, Reflect};
use rust_stdlib_derive::{reflect_methods, Reflect};

#[derive(Reflect, Default, Clone, PartialEq, Debug)]
pub struct Args {
    pub A: i64,
    pub B: i64,
}

#[derive(Reflect, Default, Clone)]
pub struct Arith {
    pub calls: i64,
}

#[reflect_methods]
impl Arith {
    pub fn Multiply(&mut self, args: Args, reply: &mut i64) -> Result<(), String> {
        self.calls += 1;
        *reply = args.A * args.B;
        Ok(())
    }
    pub fn Fail(&mut self, _args: Args, _reply: &mut i64) -> Result<(), String> {
        Err("it failed".into())
    }
}

#[test]
fn signature_is_go_shaped() {
    let t = reflect::type_for::<Arith>();
    let pt = reflect::pointer_to(&t);
    let m = pt.method_by_name("Multiply").expect("method");
    assert_eq!(
        m.type_.to_string(),
        "func(*reflect_ptr_args.Arith, reflect_ptr_args.Args, *int64) error"
    );
}

#[test]
fn call_writes_through_pointer_and_returns_error() {
    let rcvr = reflect::new(&reflect::type_for::<Arith>());
    let reply = reflect::new(&reflect::type_for::<i64>());
    let args = Args { A: 6, B: 7 }.to_value();
    let out = rcvr
        .method_by_name("Multiply")
        .call(&[args.clone(), reply.clone()]);
    assert_eq!(reply.elem().int(), 42);
    assert!(out[0].is_nil());
    assert_eq!(rcvr.elem().field(0).int(), 1);
    let out = rcvr.method_by_name("Fail").call(&[args, reply]);
    assert!(!out[0].is_nil());
    assert_eq!(
        out[0].method_by_name("Error").call(&[])[0].text(),
        "it failed"
    );
}
