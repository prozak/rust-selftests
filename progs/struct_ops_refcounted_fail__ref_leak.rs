// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Translation of tools/testing/selftests/bpf/progs/struct_ops_refcounted_fail__ref_leak.c,
// bpf-rs-core idiom.
//
// A NEGATIVE verifier test: bpf_testmod_ops.test_refcounted's `task` is a
// referenced kptr (the module's BTF stub names it `task__ref`, see
// struct_ops_refcounted.rs), acquired for the program on entry. This
// program returns without releasing it, and the verifier rejects the leak
// with the message declared below.

use bpf_rs_core::bpf_object;
use bpf_rs_core::test_tags;

test_tags! {
    refcounted_fail__ref_leak: __failure, __msg("Unreleased reference id=1 alloc_insn=0");
}

#[link_section = "struct_ops/test_refcounted"]
#[no_mangle]
extern "C" fn refcounted_fail__ref_leak(_ctx: *const u64) -> i32 {
    0
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_testmod_ops {
    test_refcounted: extern "C" fn(*const u64) -> i32,
}

unsafe impl Sync for bpf_testmod_ops {}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static testmod_ref_acquire: bpf_testmod_ops = bpf_testmod_ops {
    test_refcounted: refcounted_fail__ref_leak,
};

bpf_object!("GPL");
