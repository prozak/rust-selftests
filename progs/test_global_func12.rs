// SPDX-License-Identifier: GPL-2.0-only
#![no_std]
#![no_main]

// Translation of tools/testing/selftests/bpf/progs/test_global_func12.c,
// bpf-rs-core idiom.
//
// A NEGATIVE verifier test: the global function dereferences its `struct S *`
// argument without a null check. Checked on its own, the parameter is
// PTR_TO_MEM_OR_NULL, so the dereference is rejected.

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
    // C: return bpf_get_prandom_u32() < s->x;  (int vs u32 -> unsigned compare)
    (bpf_get_prandom_u32() < unsafe { (*s).x } as u32) as i32
}

test_tags! {
    global_func12: __failure, __msg("invalid mem access 'mem_or_null'");
}

#[link_section = "cgroup_skb/ingress"]
#[no_mangle]
pub extern "C" fn global_func12(skb: *const __sk_buff) -> i32 {
    // C: const struct S s = {.x = skb->len }; foo(&s); return 1;
    let s = S {
        x: unsafe { (*skb).len } as i32,
    };
    foo(&s);
    1
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
