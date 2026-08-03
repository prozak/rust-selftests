#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/trace_dummy_st_ops.c
// bpf-rs-core idiom.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_probe_read_kernel;
use bpf_rs_core::progs::fentry_arg as arg;
use core::ffi::c_void;

#[no_mangle]
static mut val: i32 = 0;

#[link_section = "fentry/test_1"]
#[no_mangle]
extern "C" fn fentry_test_1(ctx: *const u64) -> i32 {
    // Read the traced st_ops arg1 which is a pointer
    let st_ops_ctx = arg(ctx, 0) as *const c_void;
    let mut state: u64 = 0;
    bpf_probe_read_kernel(&mut state, 8, st_ops_ctx);

    // Read state->val
    let mut v: i32 = 0;
    bpf_probe_read_kernel(&mut v, 4, state as *const c_void);
    unsafe { val = v };

    0
}

bpf_object!("GPL");
