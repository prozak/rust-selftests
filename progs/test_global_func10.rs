// SPDX-License-Identifier: GPL-2.0-only
#![no_std]
#![no_main]

// Translation of tools/testing/selftests/bpf/progs/test_global_func10.c,
// bpf-rs-core idiom.
//
// A NEGATIVE verifier test: an 8-byte stack struct is passed to a global
// function declaring a pointer to a 16-byte struct. The callee's read of
// the second member reaches past the caller's stack object, which the
// verifier rejects as an invalid read from stack.

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::bpf_get_prandom_u32;
use bpf_rs_core::test_tags;

#[repr(C)]
struct Small {
    x: i64,
}

#[repr(C)]
struct Big {
    x: i64,
    y: i64,
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn foo(big: *const Big) -> i32 {
    if big.is_null() {
        return 0;
    }
    // C: return bpf_get_prandom_u32() < big->y;  (u32 vs long -> signed 64-bit compare)
    ((bpf_get_prandom_u32() as i64) < unsafe { (*big).y }) as i32
}

test_tags! {
    global_func10: __failure, __msg("invalid read from stack");
}

#[link_section = "cgroup_skb/ingress"]
#[no_mangle]
pub extern "C" fn global_func10(skb: *const __sk_buff) -> i32 {
    // C: const struct Small small = {.x = skb->len }; return foo((struct Big *)&small) ? 1 : 0;
    let small = Small {
        x: unsafe { (*skb).len } as i64,
    };
    if foo(&small as *const Small as *const Big) != 0 {
        1
    } else {
        0
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
