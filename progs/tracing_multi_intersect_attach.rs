// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(non_upper_case_globals)]

// Direct translation of
// tools/testing/selftests/bpf/progs/tracing_multi_intersect_attach.c
// (bpf-rs-core idiom). The attach half of tracing_multi_intersect.skel.h
// (Makefile.skel: `tracing_multi_intersect.skel.h-deps :=
// tracing_multi_intersect_attach.bpf.o tracing_multi_check.bpf.o`):
// prog_tests/tracing_multi.c's intersect subtest attaches the four
// `.multi` programs (no target in the section name: the test passes the
// function ids) to overlapping bpf_fentry_test* sets, plus the plain
// fentry on bpf_fentry_test1, and checks each test_result_*.
// `tracing_multi_arg_check` is tracing_multi_check.c's global function,
// `__hidden extern` here (`// BTF_EXTERN:` + `.hidden`, see
// tracing_multi_attach.rs).

use bpf_rs_core::bpf_object;

// BTF_EXTERN: tracing_multi_arg_check
extern "C" {
    fn tracing_multi_arg_check(ctx: *mut u64, test_result: *mut u64, is_return: bool) -> i32;
}
core::arch::global_asm!(".hidden tracing_multi_arg_check");

#[no_mangle]
static mut test_result_fentry_1: u64 = 0;
#[no_mangle]
static mut test_result_fentry_2: u64 = 0;
#[no_mangle]
static mut test_result_fexit_1: u64 = 0;
#[no_mangle]
static mut test_result_fexit_2: u64 = 0;
#[no_mangle]
static mut test_result_fentry: u64 = 0;

#[link_section = "fentry/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn fentry(ctx: *mut u64) -> i32 {
    unsafe { tracing_multi_arg_check(ctx, core::ptr::addr_of_mut!(test_result_fentry), false) };
    0
}

#[link_section = "fentry.multi"]
#[no_mangle]
extern "C" fn fentry_1(ctx: *mut u64) -> i32 {
    unsafe { tracing_multi_arg_check(ctx, core::ptr::addr_of_mut!(test_result_fentry_1), false) };
    0
}

#[link_section = "fentry.multi"]
#[no_mangle]
extern "C" fn fentry_2(ctx: *mut u64) -> i32 {
    unsafe { tracing_multi_arg_check(ctx, core::ptr::addr_of_mut!(test_result_fentry_2), false) };
    0
}

#[link_section = "fexit.multi"]
#[no_mangle]
extern "C" fn fexit_1(ctx: *mut u64) -> i32 {
    unsafe { tracing_multi_arg_check(ctx, core::ptr::addr_of_mut!(test_result_fexit_1), true) };
    0
}

#[link_section = "fexit.multi"]
#[no_mangle]
extern "C" fn fexit_2(ctx: *mut u64) -> i32 {
    unsafe { tracing_multi_arg_check(ctx, core::ptr::addr_of_mut!(test_result_fexit_2), true) };
    0
}

bpf_object!("GPL");
