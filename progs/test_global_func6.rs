// SPDX-License-Identifier: GPL-2.0-only
#![no_std]
#![no_main]

// Translation of tools/testing/selftests/bpf/progs/test_global_func6.c,
// bpf-rs-core idiom.
//
// A NEGATIVE verifier test: f2 passes `skb + 1`, a context pointer with a
// non-zero offset, where f3 declares a `struct __sk_buff *` (context)
// parameter. The verifier checks a global function's arguments at the call
// site and rejects the modified context pointer. Like test_global_func5.c
// the C object has no license section.

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::test_tags;

#[no_mangle]
#[inline(never)]
pub extern "C" fn f1(skb: *const __sk_buff) -> i32 {
    unsafe { (*skb).len as i32 }
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn f2(val: i32, skb: *const __sk_buff) -> i32 {
    // C: return f1(skb) + f3(val, skb + 1); /* type mismatch */
    f1(skb).wrapping_add(f3(val, skb.wrapping_add(1)))
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn f3(val: i32, skb: *const __sk_buff) -> i32 {
    (unsafe { (*skb).ifindex } as i32).wrapping_mul(val)
}

test_tags! {
    global_func6: __failure, __msg("modified ctx ptr R2");
}

#[link_section = "tc"]
#[no_mangle]
pub extern "C" fn global_func6(skb: *const __sk_buff) -> i32 {
    f1(skb).wrapping_add(f2(2, skb)).wrapping_add(f3(3, skb))
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
