#![no_std]
#![no_main]

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;

// static in C; #[no_mangle] + #[inline(never)] keeps it a distinct global
// function (matching __noinline) instead of being folded into the caller.
#[no_mangle]
#[inline(never)]
extern "C" fn test_ctx_global_func(_skb: *const __sk_buff) -> i32 {
    // C: volatile int retval = 1; return retval;
    let mut retval: i32 = 1;
    unsafe {
        core::ptr::write_volatile(&mut retval, 1);
        core::ptr::read_volatile(&retval)
    }
}

#[link_section = "freplace/test_pkt_access"]
#[no_mangle]
extern "C" fn new_test_pkt_access(skb: *const __sk_buff) -> i32 {
    test_ctx_global_func(skb)
}

bpf_object!("GPL");
