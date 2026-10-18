// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/struct_ops_multi_args.c
// (bpf-rs-core idiom).
//
// prog_tests/test_struct_ops_multi_args.c expects test_refcounted_multi to
// be REJECTED at load ("program with __ref argument cannot tail call": the
// member's third argument is a referenced task and the program tail
// calls), a load-time negative test without decl tags; the second subtest
// disables that program's autoload and checks that the ninth, stack-passed
// argument of test_trampoline_stack_args reaches the program (C's
// BPF_PROG reads it as `int` from ctx[8] and widens it into the u64).
// Only the two members this object sets are declared in the struct_ops
// type; libbpf matches them against bpf_testmod_ops by name (see
// struct_ops_kptr_return.rs).

use core::ffi::c_void;

use bpf_rs_core::helpers::bpf_tail_call;
use bpf_rs_core::progs::fentry_arg as arg;
use bpf_rs_core::{bpf_map, bpf_object};

bpf_map! {
    prog_array {
        r#type: *const [i32; 3], // BPF_MAP_TYPE_PROG_ARRAY
        max_entries: *const [i32; 1],
        key_size: *const [i32; 4],
        value_size: *const [i32; 4],
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct task_struct {
    _priv: [u8; 0],
}

extern "C" {
    fn bpf_task_release(p: *mut task_struct);
}

#[link_section = "struct_ops/test_refcounted_multi"]
#[no_mangle]
extern "C" fn test_refcounted_multi(ctx: *const u64) -> i32 {
    /* ctx[2] is used because the refcounted variable is the third argument */
    let refcounted_task = arg(ctx, 2) as *mut task_struct;

    unsafe { bpf_task_release(refcounted_task) };
    bpf_tail_call(ctx as *const c_void, &prog_array, 0);

    0
}

#[no_mangle]
static mut trampoline_stack_arg9: u64 = 0;

// BPF_PROG(test_trampoline_stack_args, arg1, ..., arg9)
#[link_section = "struct_ops/test_trampoline_stack_args"]
#[no_mangle]
extern "C" fn test_trampoline_stack_args(ctx: *const u64) -> i32 {
    let arg9 = arg(ctx, 8) as i32;

    unsafe { trampoline_stack_arg9 = arg9 as i64 as u64 };

    0
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_testmod_ops {
    test_refcounted_multi: extern "C" fn(*const u64) -> i32,
    test_trampoline_stack_args: extern "C" fn(*const u64) -> i32,
}

unsafe impl Sync for bpf_testmod_ops {}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static testmod_ref_acquire: bpf_testmod_ops = bpf_testmod_ops {
    test_refcounted_multi: test_refcounted_multi,
    test_trampoline_stack_args: test_trampoline_stack_args,
};

bpf_object!("GPL");
