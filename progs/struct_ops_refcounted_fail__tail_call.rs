// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Translation of tools/testing/selftests/bpf/progs/struct_ops_refcounted_fail__tail_call.c,
// bpf-rs-core idiom.
//
// A NEGATIVE verifier test: a struct_ops program whose `task` argument is a
// referenced kptr (bpf_testmod_ops.test_refcounted, `task__ref` in the
// module's BTF) releases it and then tail calls. The verifier refuses tail
// calls from a program with a `__ref` argument, with the message declared
// below.

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_tail_call;
use bpf_rs_core::maps;
use bpf_rs_core::test_tags;
use core::ffi::c_void;

#[repr(C)]
struct task_struct {
    _opaque: [u8; 0],
}

extern "C" {
    fn bpf_task_release(p: *mut task_struct);
}

// C: BPF_MAP_TYPE_PROG_ARRAY, max_entries 1, key_size/value_size 4.
bpf_map! {
    prog_array {
        r#type: *const [i32; maps::PROG_ARRAY],
        max_entries: *const [i32; 1],
        key_size: *const [i32; 4],
        value_size: *const [i32; 4],
    }
}

test_tags! {
    refcounted_fail__tail_call: __failure, __msg("program with __ref argument cannot tail call");
}

#[link_section = "struct_ops/test_refcounted"]
#[no_mangle]
extern "C" fn refcounted_fail__tail_call(ctx: *const u64) -> i32 {
    // C: struct task_struct *task = (struct task_struct *)ctx[1];
    let task = unsafe { *ctx.add(1) } as *mut task_struct;

    unsafe { bpf_task_release(task) };
    bpf_tail_call(ctx as *const c_void, &prog_array, 0);

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
    test_refcounted: refcounted_fail__tail_call,
};

bpf_object!("GPL");
