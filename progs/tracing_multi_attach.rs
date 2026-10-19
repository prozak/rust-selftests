// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(non_upper_case_globals)]

// Direct translation of
// tools/testing/selftests/bpf/progs/tracing_multi_attach.c (bpf-rs-core
// idiom). The attach half of tracing_multi.skel.h (Makefile.skel:
// `tracing_multi.skel.h-deps := tracing_multi_attach.bpf.o
// tracing_multi_check.bpf.o`): prog_tests/tracing_multi.c attaches the
// four programs to bpf_fentry_test1..10 (skeleton, pattern and id APIs,
// with and without cookies) and expects FUNCS_CNT + 1 in each
// test_result_*. `tracing_multi_arg_check` is tracing_multi_check.c's
// global function, declared `__hidden extern` here: `// BTF_EXTERN:`
// (scripts/ksym_vars.py mirrors the C object's extern FUNC for the static
// linker) and the `.hidden` directive (test_skeleton.rs) that makes libbpf
// mark the linked function static before the kernel verifies it, as it
// takes the raw tracing ctx.

use bpf_rs_core::bpf_object;

// BTF_EXTERN: tracing_multi_arg_check
extern "C" {
    fn tracing_multi_arg_check(ctx: *mut u64, test_result: *mut u64, is_return: bool) -> i32;
}
core::arch::global_asm!(".hidden tracing_multi_arg_check");

#[no_mangle]
static mut test_result_fentry: u64 = 0;
#[no_mangle]
static mut test_result_fexit: u64 = 0;

#[link_section = "fentry.multi/bpf_fentry_test*"]
#[no_mangle]
extern "C" fn test_fentry(ctx: *mut u64) -> i32 {
    unsafe { tracing_multi_arg_check(ctx, core::ptr::addr_of_mut!(test_result_fentry), false) };
    0
}

#[link_section = "fexit.multi/bpf_fentry_test*"]
#[no_mangle]
extern "C" fn test_fexit(ctx: *mut u64) -> i32 {
    unsafe { tracing_multi_arg_check(ctx, core::ptr::addr_of_mut!(test_result_fexit), true) };
    0
}

#[link_section = "fentry.multi.s/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test_fentry_s(ctx: *mut u64) -> i32 {
    unsafe { tracing_multi_arg_check(ctx, core::ptr::addr_of_mut!(test_result_fentry), false) };
    0
}

#[link_section = "fexit.multi.s/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test_fexit_s(ctx: *mut u64) -> i32 {
    unsafe { tracing_multi_arg_check(ctx, core::ptr::addr_of_mut!(test_result_fexit), true) };
    0
}

bpf_object!("GPL");
