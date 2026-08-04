#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/missed_kprobe_recursion.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use core::ffi::c_void;

extern "C" {
    fn bpf_kfunc_common_test();
}

// No tests in here, just to trigger 'bpf_fentry_test*'
// through tracing test_run
#[link_section = "fentry/bpf_modify_return_test"]
#[no_mangle]
extern "C" fn trigger(_ctx: *const u64) -> i32 {
    0
}

#[link_section = "kprobe.multi/bpf_fentry_test1"]
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

#[link_section = "kprobe/bpf_kfunc_common_test"]
#[no_mangle]
extern "C" fn test3(_ctx: *const c_void) -> i32 {
    0
}

#[link_section = "kprobe/bpf_kfunc_common_test"]
#[no_mangle]
extern "C" fn test4(_ctx: *const c_void) -> i32 {
    0
}

#[link_section = "kprobe.multi/bpf_kfunc_common_test"]
#[no_mangle]
extern "C" fn test5(_ctx: *const c_void) -> i32 {
    0
}

#[link_section = "kprobe.session/bpf_kfunc_common_test"]
#[no_mangle]
extern "C" fn test6(_ctx: *const c_void) -> i32 {
    0
}

bpf_object!("GPL");
