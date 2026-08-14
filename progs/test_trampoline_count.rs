#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_trampoline_count.c (bpf-rs-core
// idiom). Three no-op programs on the same attach point; the test counts
// trampolines rather than looking at what they compute.

use bpf_rs_core::bpf_object;

#[link_section = "fentry/bpf_testmod_trampoline_count_test"]
#[no_mangle]
extern "C" fn fentry_test(_ctx: *const u64) -> i32 {
    0
}

#[link_section = "fmod_ret/bpf_testmod_trampoline_count_test"]
#[no_mangle]
extern "C" fn fmod_ret_test(_ctx: *const u64) -> i32 {
    0
}

#[link_section = "fexit/bpf_testmod_trampoline_count_test"]
#[no_mangle]
extern "C" fn fexit_test(_ctx: *const u64) -> i32 {
    0
}

bpf_object!("GPL");
