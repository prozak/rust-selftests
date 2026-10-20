// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/struct_ops_kptr_return_fail__invalid_scalar.c,
// bpf-rs-core idiom.
//
// A NEGATIVE verifier test: bpf_testmod_ops.test_return_ref_kptr may return
// the acquired `task` or NULL (see struct_ops_kptr_return.rs). This program
// releases the task and returns the scalar 1 as a pointer; the verifier
// rejects the non-zero scalar at exit with the message declared below.

use bpf_rs_core::bpf_object;
use bpf_rs_core::progs::fentry_arg as arg;
use bpf_rs_core::test_tags;

test_tags! {
    kptr_return_fail__invalid_scalar: __failure, __msg("At program exit the register R0 has smin=1 smax=1 should have been in [0, 0]");
}

#[repr(C)]
struct task_struct {
    _priv: [u8; 0],
}

extern "C" {
    fn bpf_task_release(p: *mut task_struct);
}

#[link_section = "struct_ops/test_return_ref_kptr"]
#[no_mangle]
extern "C" fn kptr_return_fail__invalid_scalar(ctx: *const u64) -> *mut task_struct {
    let task = arg(ctx, 1) as *mut task_struct;
    unsafe { bpf_task_release(task) };
    1 as *mut task_struct
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
    test_return_ref_kptr: kptr_return_fail__invalid_scalar,
};

bpf_object!("GPL");
