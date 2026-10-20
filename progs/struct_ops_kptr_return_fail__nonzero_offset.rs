// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/struct_ops_kptr_return_fail__nonzero_offset.c,
// bpf-rs-core idiom.
//
// A NEGATIVE verifier test: bpf_testmod_ops.test_return_ref_kptr returns a
// referenced kptr (the module's BTF stub names its argument `task__ref`,
// see struct_ops_kptr_return.rs). This program returns `&task->jobctl`, a
// modified (offset) trusted pointer, and the verifier rejects it with the
// message declared below. The C's unused bpf_cgroup_acquire /
// bpf_task_release __ksym declarations have no BTF in the C object either.

use bpf_rs_core::bpf_object;
use bpf_rs_core::progs::fentry_arg as arg;
use bpf_rs_core::test_tags;
use btf_macros::btf;

test_tags! {
    kptr_return_fail__nonzero_offset: __failure, __msg("dereference of modified trusted_ptr_ ptr R0 off={{[0-9]+}} disallowed");
}

// `&task->jobctl` is a CO-RE field-offset relocation on the kernel's
// task_struct (vmlinux.h); jobctl is `unsigned long`.
#[btf]
struct task_struct {
    jobctl: u64,
}

#[link_section = "struct_ops/test_return_ref_kptr"]
#[no_mangle]
extern "C" fn kptr_return_fail__nonzero_offset(ctx: *const u64) -> *mut task_struct {
    let task = arg(ctx, 1) as *mut task_struct;
    unsafe { &*task }.jobctl().as_ptr() as *mut task_struct
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_testmod_ops {
    test_return_ref_kptr: extern "C" fn(*const u64) -> *mut task_struct,
}

unsafe impl Sync for bpf_testmod_ops {}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static testmod_kptr_return: bpf_testmod_ops = bpf_testmod_ops {
    test_return_ref_kptr: kptr_return_fail__nonzero_offset,
};

bpf_object!("GPL");
