#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/tc_bpf2bpf.c
// (bpf-rs-core idiom).
//
// `entry_tc` (SEC("tc")) is a thin bpf2bpf caller into `subprog_tc`, which
// calls bpf_skb_change_proto() purely to teach the verifier that a subprog
// can change skb->data pointers.
//
// `subprog_tc` must survive as a real, separately-attachable BTF FUNC named
// "subprog_tc": prog_tests/tailcalls.c's test_tailcall_freplace and
// test_tailcall_bpf2bpf_freplace call
// bpf_program__set_attach_target(freplace_prog, tc_prog_fd, "subprog_tc")
// and attach an freplace extension prog directly to it by that BTF name.
// Its return value is a compile-time constant (always 1) independent of
// `skb`, which is exactly the shape that opt's IPSCCP can fold away even
// past #[inline(never)] (see the C original: it needs __sink(skb) and
// __sink(ret) too — confirmed via objdump on the clang-built object, whose
// subprog_tc round-trips both through the stack instead of returning the
// literal directly). Sink both here the same way to keep the call a real,
// standalone subprogram.

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{self, bpf_skb_change_proto};
use core::ffi::c_void;

#[no_mangle]
#[inline(never)]
extern "C" fn subprog_tc(skb: *const __sk_buff) -> i32 {
    let mut ret: i32 = 1;

    let mut skb_mut = skb as *mut __sk_buff;
    helpers::sink(&mut skb_mut);
    let mut ret_barrier = ret as usize;
    helpers::barrier_var(&mut ret_barrier);
    ret = ret_barrier as i32;

    // let verifier know that 'subprog_tc' can change pointers to skb->data
    bpf_skb_change_proto(skb as *const c_void, 0, 0);
    ret
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn entry_tc(skb: *const __sk_buff) -> i32 {
    subprog_tc(skb)
}

bpf_object!("GPL");
