// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/stacktrace_ips.c
// (bpf-rs-core idiom). prog_tests/stacktrace_ips.c attaches each program,
// triggers bpf_testmod and checks the stack the `stack_key` id names in
// `stackmap`; it skips the whole test unless `skel->kconfig->
// CONFIG_UNWINDER_ORC`, the C's weak `__kconfig` bool (`// BTF_KCONFIG:`
// below, scripts/ksym_vars.py mirrors the C object's declaration). Like
// the C, the global `unused()` subprog is its only reader, kept so the
// extern lands in the object's BTF.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_stackid;
use bpf_rs_core::maps::{self, BpfMap};
use core::ffi::c_void;

const PERF_MAX_STACK_DEPTH: usize = 127;

#[allow(non_camel_case_types)]
type stack_trace_t = [u64; PERF_MAX_STACK_DEPTH];

#[link_section = ".maps"]
#[no_mangle]
static stackmap: BpfMap<u32, stack_trace_t, { maps::STACK_TRACE }, 16384> = BpfMap::new();

// BTF_KCONFIG: CONFIG_UNWINDER_ORC
extern "C" {
    static CONFIG_UNWINDER_ORC: u8;
}

/*
 * This function is here to have CONFIG_UNWINDER_ORC
 * used and added to object BTF.
 */
#[no_mangle]
pub extern "C" fn unused() -> i32 {
    if unsafe { CONFIG_UNWINDER_ORC } != 0 {
        0
    } else {
        1
    }
}

#[no_mangle]
static mut stack_key: u32 = 0;

#[link_section = "kprobe"]
#[no_mangle]
extern "C" fn kprobe_test(ctx: *const c_void) -> i32 {
    unsafe { stack_key = bpf_get_stackid(ctx, &stackmap, 0) as u32 };
    0
}

#[link_section = "kprobe.multi"]
#[no_mangle]
extern "C" fn kprobe_multi_test(ctx: *const c_void) -> i32 {
    unsafe { stack_key = bpf_get_stackid(ctx, &stackmap, 0) as u32 };
    0
}

#[link_section = "raw_tp/bpf_testmod_test_read"]
#[no_mangle]
extern "C" fn rawtp_test(ctx: *const c_void) -> i32 {
    /* Skip ebpf program entry in the stack. */
    unsafe { stack_key = bpf_get_stackid(ctx, &stackmap, 0) as u32 };
    0
}

#[link_section = "fentry/bpf_testmod_stacktrace_test"]
#[no_mangle]
extern "C" fn fentry_test(ctx: *const c_void) -> i32 {
    /*
     * Skip 2 bpf_program/trampoline stack entries:
     * - bpf_prog_bd1f7a949f55fb03_fentry_test
     * - bpf_trampoline_182536277701
     */
    unsafe { stack_key = bpf_get_stackid(ctx, &stackmap, 2) as u32 };
    0
}

#[link_section = "fexit/bpf_testmod_stacktrace_test"]
#[no_mangle]
extern "C" fn fexit_test(ctx: *const c_void) -> i32 {
    /* Skip 2 bpf_program/trampoline stack entries, check fentry_test. */
    unsafe { stack_key = bpf_get_stackid(ctx, &stackmap, 2) as u32 };
    0
}

bpf_object!("GPL");
