#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/fmod_ret_freplace.c
// bpf-rs-core idiom.

use bpf_rs_core::bpf_object;

#[no_mangle]
static mut test_fmod_ret: u64 = 0;

#[link_section = "fmod_ret/security_new_get_constant"]
#[no_mangle]
extern "C" fn fmod_ret_test(_ctx: *const u64) -> i32 {
    unsafe { test_fmod_ret = 1 };
    120
}

bpf_object!("GPL");
