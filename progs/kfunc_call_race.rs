#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/kfunc_call_race.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;

extern "C" {
    fn bpf_testmod_test_mod_kfunc(i: i32);
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn kfunc_call_fail(_ctx: *const __sk_buff) -> i32 {
    unsafe { bpf_testmod_test_mod_kfunc(0) };
    0
}

bpf_object!("GPL");
