// SPDX-License-Identifier: GPL-2.0-only
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Translation of tools/testing/selftests/bpf/progs/test_global_func3.c,
// bpf-rs-core idiom.
//
// A NEGATIVE verifier test: sixteen static noinline subprograms chained
// under the program make a call stack of 17 frames, beyond the verifier's
// limit of 8. Left to itself LLVM folds f1 away: it promotes f1's skb
// argument to the loaded `len`, after which f1 returns its argument and
// the call disappears. f1 therefore passes skb through a one-instruction
// asm (`r1 = r1`, like helpers::sink) that keeps the pointer opaque; the
// verifier counts frames, not instructions. Like the other
// test_global_func*.c files the C object has no license section.

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::test_tags;


#[inline(never)]
fn f1(mut skb: *const __sk_buff) -> i32 {
    unsafe { core::arch::asm!("{0} = {0}", inout(reg) skb, options(nostack, preserves_flags)) };
    unsafe { (*skb).len as i32 }
}

#[inline(never)]
fn f2(val: i32, skb: *const __sk_buff) -> i32 {
    f1(skb).wrapping_add(val)
}

#[inline(never)]
fn f3(val: i32, skb: *const __sk_buff, var: i32) -> i32 {
    f2(var, skb).wrapping_add(val)
}

#[inline(never)]
fn f4(skb: *const __sk_buff) -> i32 {
    f3(1, skb, 2)
}

#[inline(never)]
fn f5(skb: *const __sk_buff) -> i32 {
    f4(skb)
}

#[inline(never)]
fn f6(skb: *const __sk_buff) -> i32 {
    f5(skb)
}

#[inline(never)]
fn f7(skb: *const __sk_buff) -> i32 {
    f6(skb)
}

#[inline(never)]
fn f8(skb: *const __sk_buff) -> i32 {
    f7(skb)
}

#[inline(never)]
fn f9(skb: *const __sk_buff) -> i32 {
    f8(skb)
}

#[inline(never)]
fn f10(skb: *const __sk_buff) -> i32 {
    f9(skb)
}

#[inline(never)]
fn f11(skb: *const __sk_buff) -> i32 {
    f10(skb)
}

#[inline(never)]
fn f12(skb: *const __sk_buff) -> i32 {
    f11(skb)
}

#[inline(never)]
fn f13(skb: *const __sk_buff) -> i32 {
    f12(skb)
}

#[inline(never)]
fn f14(skb: *const __sk_buff) -> i32 {
    f13(skb)
}

#[inline(never)]
fn f15(skb: *const __sk_buff) -> i32 {
    f14(skb)
}

#[inline(never)]
fn f16(skb: *const __sk_buff) -> i32 {
    f15(skb)
}

test_tags! {
    global_func3: __failure, __msg("the call stack of 17 frames");
}

#[link_section = "tc"]
#[no_mangle]
pub extern "C" fn global_func3(skb: *const __sk_buff) -> i32 {
    f16(skb)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
