// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/struct_ops_kptr_return_fail__local_kptr.c,
// bpf-rs-core idiom.
//
// A NEGATIVE verifier test: bpf_testmod_ops.test_return_ref_kptr must return
// the kernel-owned task reference or NULL (see struct_ops_kptr_return.rs).
// This program releases the task and returns a freshly bpf_obj_new()ed local
// task_struct instead; the verifier rejects the local kptr at exit with the
// message declared below. C's bpf_obj_new(typeof(*task)) is
// bpf_obj_new_impl(bpf_core_type_id_local(struct task_struct), NULL): the
// local type id is imported with the BTF_TYPE_ID marker (TRANSLATING.md).

use bpf_rs_core::bpf_object;
use bpf_rs_core::progs::fentry_arg as arg;
use bpf_rs_core::test_tags;
use core::ffi::c_void;

test_tags! {
    kptr_return_fail__local_kptr: __failure, __msg("At program exit the register R0 is not a known value (ptr_or_null_)");
}

#[repr(C)]
struct task_struct {
    _priv: [u8; 0],
}

// BTF_TYPE_ID: task_struct_id local struct task_struct
extern "C" {
    fn task_struct_id() -> u64;
    fn bpf_task_release(p: *mut task_struct);
    fn bpf_obj_new_impl(local_type_id: u64, meta: *mut c_void) -> *mut c_void;
}

#[link_section = "struct_ops/test_return_ref_kptr"]
#[no_mangle]
extern "C" fn kptr_return_fail__local_kptr(ctx: *const u64) -> *mut task_struct {
    let task = arg(ctx, 1) as *mut task_struct;

    unsafe { bpf_task_release(task) };

    let t = unsafe { bpf_obj_new_impl(task_struct_id(), core::ptr::null_mut()) } as *mut task_struct;
    if t.is_null() {
        return core::ptr::null_mut();
    }

    t
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
    test_return_ref_kptr: kptr_return_fail__local_kptr,
};

bpf_object!("GPL");
