// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/struct_ops_kptr_return_fail__wrong_type.c,
// bpf-rs-core idiom.
//
// A NEGATIVE verifier test: bpf_testmod_ops.test_return_ref_kptr must return
// a task_struct reference or NULL (see struct_ops_kptr_return.rs). This
// program releases the task and returns an acquired cgroup reference cast to
// task_struct; the verifier rejects the wrong referenced type at exit with
// the message declared below.

use bpf_rs_core::bpf_object;
use bpf_rs_core::progs::fentry_arg as arg;
use bpf_rs_core::test_tags;

test_tags! {
    kptr_return_fail__wrong_type: __failure, __msg("At program exit the register R0 is not a known value (trusted_ptr_or_null_)");
}

#[repr(C)]
struct task_struct {
    _priv: [u8; 0],
}

#[repr(C)]
struct cgroup {
    _priv: [u8; 0],
}

extern "C" {
    fn bpf_cgroup_acquire(p: *mut cgroup) -> *mut cgroup;
    fn bpf_task_release(p: *mut task_struct);
}

#[link_section = "struct_ops/test_return_ref_kptr"]
#[no_mangle]
extern "C" fn kptr_return_fail__wrong_type(ctx: *const u64) -> *mut task_struct {
    let task = arg(ctx, 1) as *mut task_struct;
    let cgrp = arg(ctx, 2) as *mut cgroup;

    let ret = unsafe { bpf_cgroup_acquire(cgrp) } as *mut task_struct;
    unsafe { bpf_task_release(task) };

    ret
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
    test_return_ref_kptr: kptr_return_fail__wrong_type,
};

bpf_object!("GPL");
