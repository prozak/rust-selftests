#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/kfunc_module_order.c (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;

extern "C" {
    fn bpf_test_modorder_retx() -> i32;
    fn bpf_test_modorder_rety() -> i32;
}

#[link_section = "classifier"]
#[no_mangle]
extern "C" fn call_kfunc_xy(_skb: *const __sk_buff) -> i32 {
    let ret1 = unsafe { bpf_test_modorder_retx() };
    let ret2 = unsafe { bpf_test_modorder_rety() };

    if ret1 == b'x' as i32 && ret2 == b'y' as i32 {
        0
    } else {
        -1
    }
}

#[link_section = "classifier"]
#[no_mangle]
extern "C" fn call_kfunc_yx(_skb: *const __sk_buff) -> i32 {
    let ret1 = unsafe { bpf_test_modorder_rety() };
    let ret2 = unsafe { bpf_test_modorder_retx() };

    if ret1 == b'y' as i32 && ret2 == b'x' as i32 {
        0
    } else {
        -1
    }
}

bpf_object!("GPL");
