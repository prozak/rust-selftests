#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/kfunc_call_destructive.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;

extern "C" {
    fn bpf_kfunc_call_test_destructive();
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn kfunc_destructive_test(_skb: *const __sk_buff) -> i32 {
    unsafe { bpf_kfunc_call_test_destructive() };
    0
}

bpf_object!("GPL");
