#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/tracing_multi_rollback.c
// (bpf-next 520d7d79), bpf-rs-core idiom.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_current_pid_tgid;

#[no_mangle]
static mut pid: i32 = 0;

#[no_mangle]
static mut test_result_fentry: u64 = 0;
#[no_mangle]
static mut test_result_fexit: u64 = 0;

#[link_section = "?fentry.multi"]
#[no_mangle]
extern "C" fn test_fentry(_ctx: *const u64) -> i32 {
    if (bpf_get_current_pid_tgid() >> 32) as i32 != unsafe { pid } {
        return 0;
    }
    unsafe { test_result_fentry += 1 };
    0
}

#[link_section = "?fexit.multi"]
#[no_mangle]
extern "C" fn test_fexit(_ctx: *const u64) -> i32 {
    if (bpf_get_current_pid_tgid() >> 32) as i32 != unsafe { pid } {
        return 0;
    }
    unsafe { test_result_fexit += 1 };
    0
}

#[link_section = "?fentry/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn extra(_ctx: *const u64) -> i32 {
    0
}

#[link_section = "?fentry/bpf_fentry_test10"]
#[no_mangle]
extern "C" fn filler(_ctx: *const u64) -> i32 {
    0
}

bpf_object!("GPL");
