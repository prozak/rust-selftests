// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/struct_ops_maybe_null_fail.c,
// bpf-rs-core idiom.
//
// bpf_testmod_ops.test_maybe_null's `task` argument is tagged nullable by
// the kernel module's own BTF (bpf_testmod.c's stub names it
// `task__nullable`; see kernel/bpf/bpf_struct_ops.c's MAYBE_NULL_SUFFIX
// handling) — that tagging is entirely kernel-side and independent of
// this program's source language. prog_tests/test_struct_ops_maybe_null.c's
// maybe_null_fail() expects open_and_load() to FAIL: this program
// dereferences `task` without a null check, same as the C original, so
// the verifier's PTR_MAYBE_NULL check rejects the load exactly as it
// would for the clang-built object.

use bpf_rs_core::bpf_object;
use bpf_rs_core::progs::fentry_arg as arg;
use btf_macros::btf;

#[btf]
struct task_struct {
    tgid: i32,
}

#[no_mangle]
static mut tgid: i32 = 0;

#[link_section = "struct_ops/test_maybe_null_struct_ptr"]
#[no_mangle]
extern "C" fn test_maybe_null_struct_ptr(ctx: *const u64) -> i32 {
    let task = arg(ctx, 1) as *mut task_struct;
    unsafe { tgid = *(&*task).tgid().get().unwrap() };
    0
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_testmod_ops {
    test_maybe_null: extern "C" fn(*const u64) -> i32,
}

unsafe impl Sync for bpf_testmod_ops {}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static testmod_struct_ptr: bpf_testmod_ops = bpf_testmod_ops {
    test_maybe_null: test_maybe_null_struct_ptr,
};

bpf_object!("GPL");
