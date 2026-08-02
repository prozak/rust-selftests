#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/freplace_void.c,
// bpf-rs-core idiom.
//
// The target function `foo` (test_global_func7.c) is `void foo(struct
// __sk_buff *skb)`. freplace attach compat-checks the BTF FUNC_PROTO
// return type of the replacement against the target, so this must stay a
// void-returning function (not the usual `-> i32`) or the kernel rejects
// the load with a return-type mismatch, same as freplace_int_with_void.c
// demonstrates for the opposite mismatch.

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;

#[link_section = "freplace/foo"]
#[no_mangle]
extern "C" fn test_freplace_void(_skb: *const __sk_buff) {}

bpf_object!("GPL");
