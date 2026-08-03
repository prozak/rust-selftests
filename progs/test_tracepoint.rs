#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_tracepoint.c
// bpf-rs-core idiom.

use bpf_rs_core::bpf_object;

#[link_section = "tracepoint/sched/sched_switch"]
#[no_mangle]
extern "C" fn oncpu(_ctx: *const core::ffi::c_void) -> i32 {
    0
}

bpf_object!("GPL");
