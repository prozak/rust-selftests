#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/tc_dummy.c
// (bpf-rs-core idiom). Trivial TC program used as a tail-call target in
// tailcall_hierarchy tests; it always returns 1.

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;

#[link_section = "tc"]
#[no_mangle]
extern "C" fn entry(_skb: *const __sk_buff) -> i32 {
    1
}

bpf_object!("GPL");
