#![no_std]
#![no_main]

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::barrier_var;

/// UAPI struct xdp_md (linux/bpf.h).
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct xdp_md {
    pub data: u32,
    pub data_end: u32,
    pub data_meta: u32,
    pub ingress_ifindex: u32,
    pub rx_queue_index: u32,
    pub egress_ifindex: u32,
}

// __weak in C: a real (non-inlined) subprogram, so it gets its own BTF FUNC
// entry and its own bpf_prog_<tag>_token_ksym_subprog kallsyms symbol after
// load (see prog_tests/token.c kallsyms_has_bpf_func()). The C object's
// symbol binding is WEAK, not GLOBAL, so the build's keep-list (derived
// from GLOBAL FUNC/OBJECT symbols only) does not preserve external linkage
// for it here; it gets internalized like a static function. #[inline(never)]
// stops the inliner, but the trivial `return 0` body is still a compile-time
// constant IPSCCP would propagate straight into the caller, deleting the
// call (and the subprogram) entirely. Round the return value through an
// opaque asm self-move (bpf-rs-core::helpers::barrier_var, same trick as
// sink()) so IPSCCP can't prove the value and the call site survives as a
// real subprogram call.
#[no_mangle]
#[inline(never)]
pub extern "C" fn token_ksym_subprog() -> i32 {
    let mut v: usize = 0;
    barrier_var(&mut v);
    v as i32
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_main(_xdp: *const xdp_md) -> i32 {
    token_ksym_subprog()
}

bpf_object!("GPL");
