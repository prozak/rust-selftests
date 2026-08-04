#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/missed_tp_recursion.c
// (bpf-rs-core idiom). None of the programs dereference their ctx, so it
// stays opaque (`*const c_void`), same as missed_kprobe.rs.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_trace_printk;
use core::ffi::c_void;

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
    static FMT: [u8; 5] = *b"test\0";
    bpf_trace_printk(FMT.as_ptr() as *const c_void, FMT.len() as u32, 0, 0, 0);
    0
}

#[link_section = "tp/bpf_trace/bpf_trace_printk"]
#[no_mangle]
extern "C" fn test2(_ctx: *const c_void) -> i32 {
    0
}

#[link_section = "tp/bpf_trace/bpf_trace_printk"]
#[no_mangle]
extern "C" fn test3(_ctx: *const c_void) -> i32 {
    0
}

#[link_section = "tp/bpf_trace/bpf_trace_printk"]
#[no_mangle]
extern "C" fn test4(_ctx: *const c_void) -> i32 {
    0
}

bpf_object!("GPL");
