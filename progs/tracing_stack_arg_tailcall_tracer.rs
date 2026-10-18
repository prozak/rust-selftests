// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/tracing_stack_arg_tailcall_tracer.c
// (bpf-rs-core idiom).
//
// prog_tests/tracing_struct.c's stack_arg_tailcall subtest retargets both
// programs at tracing_stack_arg_tailcall_tgt's static subprogram
// callee_stack, whose seventh and eighth arguments arrive on the stack:
// the fentry context still presents them as slots 6 and 7, and the fexit
// context carries the return value in slot 8.

use bpf_rs_core::bpf_object;
use bpf_rs_core::progs::fentry_arg as arg;

#[no_mangle]
static mut stack_g: i64 = 0;
#[no_mangle]
static mut stack_h: i64 = 0;
#[no_mangle]
static mut stack_ret: i64 = 0;

#[link_section = "fentry/callee_stack"]
#[no_mangle]
extern "C" fn stack_entry(ctx: *const u64) -> i32 {
    unsafe {
        stack_g = arg(ctx, 6) as i64;
        stack_h = arg(ctx, 7) as i64;
    }
    0
}

#[link_section = "fexit/callee_stack"]
#[no_mangle]
extern "C" fn stack_exit(ctx: *const u64) -> i32 {
    unsafe {
        stack_ret = arg(ctx, 8) as i64;
    }
    0
}

bpf_object!("GPL");
