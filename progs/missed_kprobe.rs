#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/missed_kprobe.c
// (bpf-rs-core idiom). None of the three programs dereference their ctx, so
// it stays opaque (`*const c_void`) as in kprobe_multi_override.rs.

use bpf_rs_core::bpf_object;
use core::ffi::c_void;

extern "C" {
    fn bpf_kfunc_common_test();
}

/*
 * No tests in here, just to trigger 'bpf_fentry_test*'
 * through tracing test_run
 */
#[link_section = "fentry/bpf_modify_return_test"]
#[no_mangle]
extern "C" fn trigger(_ctx: *const u64) -> i32 {
    0
}

#[link_section = "kprobe/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test1(_ctx: *const c_void) -> i32 {
    unsafe { bpf_kfunc_common_test() };
    0
}

#[link_section = "kprobe/bpf_kfunc_common_test"]
#[no_mangle]
extern "C" fn test2(_ctx: *const c_void) -> i32 {
    0
}

bpf_object!("GPL");
