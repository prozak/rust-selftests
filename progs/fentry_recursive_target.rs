#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/fentry_recursive_target.c (bpf-rs-core
// idiom). Both programs are dummies: one is the start of an fentry
// attachment chain, the other exists so an fentry program has an attach_btf
// to point at.

use bpf_rs_core::bpf_object;

#[link_section = "fentry/bpf_testmod_fentry_test1"]
#[no_mangle]
extern "C" fn test1(_ctx: *const u64) -> i32 {
    0
}

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn fentry_target(_ctx: *const u64) -> i32 {
    0
}

bpf_object!("GPL");
