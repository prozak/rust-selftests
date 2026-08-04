#![no_std]
#![no_main]

// Translation of tools/testing/selftests/bpf/progs/test_global_func4.c
// (bpf-rs-core idiom). Positive (__success) test: a chain of noinline
// global functions f1..f7 feeding skb->len back up through global_func4.

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;

#[no_mangle]
#[inline(never)]
pub extern "C" fn f1(skb: *const __sk_buff) -> i32 {
    unsafe { (*skb).len as i32 }
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn f2(val: i32, skb: *const __sk_buff) -> i32 {
    f1(skb).wrapping_add(val)
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn f3(val: i32, skb: *const __sk_buff, var: i32) -> i32 {
    f2(var, skb).wrapping_add(val)
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn f4(skb: *const __sk_buff) -> i32 {
    f3(1, skb, 2)
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn f5(skb: *const __sk_buff) -> i32 {
    f4(skb)
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn f6(skb: *const __sk_buff) -> i32 {
    f5(skb)
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn f7(skb: *const __sk_buff) -> i32 {
    f6(skb)
}

#[link_section = "tc"]
#[no_mangle]
pub extern "C" fn global_func4(skb: *const __sk_buff) -> i32 {
    f7(skb)
}

bpf_object!("GPL");
