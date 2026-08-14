#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_d_path_check_rdonly_mem.c
// (bpf-rs-core idiom).
//
// The program is MEANT to fail verification: `active` points into read-only
// per-cpu memory, and bpf_d_path writes through its second argument, so the
// verifier must reject it. prog_tests/d_path.c asserts the load fails.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_d_path, bpf_get_smp_processor_id, bpf_per_cpu_ptr};
use bpf_rs_core::progs::fentry_arg;
use core::ffi::c_void;

unsafe extern "C" {
    static bpf_prog_active: i32;
}

#[link_section = "fentry/security_inode_getattr"]
#[no_mangle]
extern "C" fn d_path_check_rdonly_mem(ctx: *const u64) -> i32 {
    let path = fentry_arg(ctx, 0) as *const c_void;
    let cpu = bpf_get_smp_processor_id();
    let active = bpf_per_cpu_ptr(
        core::ptr::addr_of!(bpf_prog_active) as *const c_void,
        cpu,
    );
    if !active.is_null() {
        // FAIL here: `active` points to readonly memory, and bpf helpers
        // that update their arguments cannot write into it
        bpf_d_path(path, active as *mut c_void, core::mem::size_of::<i32>() as u32);
    }
    0
}

bpf_object!("GPL");
