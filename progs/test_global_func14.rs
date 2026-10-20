// SPDX-License-Identifier: GPL-2.0-only
#![no_std]
#![no_main]
#![feature(extern_types)]

// Translation of tools/testing/selftests/bpf/progs/test_global_func14.c,
// bpf-rs-core idiom.
//
// A NEGATIVE verifier test: a global function takes a pointer to an
// INCOMPLETE struct (`struct S;`, a BTF FWD), whose size the verifier cannot
// determine when it checks the function's prototype. Rust has no incomplete
// types: an `extern type` is the closest (no size, no members) but rustc
// emits it as a memberless STRUCT of size 0, so `// BTF_FWD: S` has
// scripts/btf_rename.py rewrite that type's kind to FWD, which is what the
// expected message names.

// BTF_FWD: S

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::bpf_get_prandom_u32;
use bpf_rs_core::test_tags;

extern "C" {
    type S;
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn foo(s: *const S) -> i32 {
    // C: if (s) return bpf_get_prandom_u32() < *(const int *) s; return 0;
    if !s.is_null() {
        return (bpf_get_prandom_u32() < unsafe { *(s as *const i32) } as u32) as i32;
    }
    0
}

test_tags! {
    global_func14: __failure, __msg("reference type('FWD S') size cannot be determined");
}

#[link_section = "cgroup_skb/ingress"]
#[no_mangle]
pub extern "C" fn global_func14(_skb: *const __sk_buff) -> i32 {
    foo(core::ptr::null())
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
