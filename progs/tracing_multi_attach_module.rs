// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(non_upper_case_globals)]

// Direct translation of
// tools/testing/selftests/bpf/progs/tracing_multi_attach_module.c
// (bpf-rs-core idiom). The attach half of tracing_multi_module.skel.h
// (Makefile.skel: `tracing_multi_module.skel.h-deps :=
// tracing_multi_attach_module.bpf.o tracing_multi_check.bpf.o`):
// prog_tests/tracing_multi.c's module_* subtests attach the two programs
// to bpf_testmod's bpf_testmod_fentry_test* and expect 5 in each
// test_result_*. `tracing_multi_arg_check` is tracing_multi_check.c's
// global function, `__hidden extern` here (`// BTF_EXTERN:` + `.hidden`,
// see tracing_multi_attach.rs).

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

#[link_section = "fentry.multi/bpf_testmod:bpf_testmod_fentry_test*"]
#[no_mangle]
extern "C" fn test_fentry(ctx: *mut u64) -> i32 {
    unsafe { tracing_multi_arg_check(ctx, core::ptr::addr_of_mut!(test_result_fentry), false) };
    0
}

#[link_section = "fexit.multi/bpf_testmod:bpf_testmod_fentry_test*"]
#[no_mangle]
extern "C" fn test_fexit(ctx: *mut u64) -> i32 {
    unsafe { tracing_multi_arg_check(ctx, core::ptr::addr_of_mut!(test_result_fexit), true) };
    0
}

bpf_object!("GPL");
