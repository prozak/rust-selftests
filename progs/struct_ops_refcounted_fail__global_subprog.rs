// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/struct_ops_refcounted_fail__global_subprog.c,
// bpf-rs-core idiom.
//
// A NEGATIVE verifier test: bpf_testmod_ops.test_refcounted's `task` is a
// referenced kptr acquired for the program on entry (see
// struct_ops_refcounted.rs). The main program releases it and then calls a
// global subprogram taking the ctx (`__u64 *ctx __arg_ctx`, the arg:ctx decl
// tag declared with arg_tags! below); validating that subprogram on its own,
// the verifier refuses the ctx[1] load because the reference it carries may
// already be released, with the log-level-2 messages declared below.

use bpf_rs_core::bpf_object;
use bpf_rs_core::test_tags;

test_tags! {
    refcounted_fail__global_subprog: __failure, __log_level(2), __msg("Validating subprog_release() func#1..."), __msg("invalid bpf_context access off=8. Reference may already be released");
}

#[repr(C)]
struct task_struct {
    _priv: [u8; 0],
}

extern "C" {
    fn bpf_task_release(p: *mut task_struct);
}

#[inline(never)]
#[no_mangle]
extern "C" fn subprog_release(ctx: *mut u64) -> i32 {
    let task = unsafe { *ctx.add(1) } as *mut task_struct;
    let dummy = unsafe { *ctx } as i32;

    unsafe { bpf_task_release(task) };

    dummy.wrapping_add(1)
}

#[link_section = "struct_ops/test_refcounted"]
#[no_mangle]
extern "C" fn refcounted_fail__global_subprog(ctx: *mut u64) -> i32 {
    let task = unsafe { *ctx.add(1) } as *mut task_struct;

    unsafe { bpf_task_release(task) };

    subprog_release(ctx)
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_testmod_ops {
    test_refcounted: extern "C" fn(*mut u64) -> i32,
}

unsafe impl Sync for bpf_testmod_ops {}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static testmod_ref_acquire: bpf_testmod_ops = bpf_testmod_ops {
    test_refcounted: refcounted_fail__global_subprog,
};

bpf_rs_core::arg_tags! {
    subprog_release: 0: "arg:ctx";
}

bpf_object!("GPL");
