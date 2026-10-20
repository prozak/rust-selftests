// SPDX-License-Identifier: GPL-2.0-only
#![no_std]
#![no_main]

// Translation of tools/testing/selftests/bpf/progs/test_global_func11.c,
// bpf-rs-core idiom.
//
// A NEGATIVE verifier test: the program's context pointer is passed to a
// global function expecting a pointer to `struct S` (the C casts it through
// `const void *`). The verifier checks the caller's argument against the
// callee's BTF parameter type and rejects the mismatch.

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::bpf_get_prandom_u32;
use bpf_rs_core::test_tags;

#[repr(C)]
struct S {
    x: i32,
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn foo(s: *const S) -> i32 {
    // C: return s ? bpf_get_prandom_u32() < s->x : 0;  (int vs u32 -> unsigned compare)
    if !s.is_null() {
        (bpf_get_prandom_u32() < unsafe { (*s).x } as u32) as i32
    } else {
        0
    }
}

test_tags! {
    global_func11: __failure, __msg("Caller passes invalid args into func#1");
}

#[link_section = "cgroup_skb/ingress"]
#[no_mangle]
pub extern "C" fn global_func11(skb: *const __sk_buff) -> i32 {
    foo(skb as *const S)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
