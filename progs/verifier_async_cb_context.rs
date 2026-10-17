// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(linkage)]

// Translation of tools/testing/selftests/bpf/progs/verifier_async_cb_context.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_async_cb_context.rs
// (include!d below): timer_cb, timer_non_sleepable_prog, timer_sleepable_prog, timer_sys_bpf_cb, timer_sys_bpf_prog, timer_sys_close_cb, timer_sys_close_prog, timer_btf_find_cb, timer_btf_find_prog, syscall_sys_bpf_prog, syscall_sys_close_prog, syscall_btf_find_prog, wq_cb, wq_non_sleepable_prog, wq_sleepable_prog, wq_global_acquire, wq_global_rcu_cb, wq_global_rcu_prog, wq_global_rcu_lock_cb, wq_global_rcu_lock_prog, wq_global_no_rcu, wq_global_no_rcu_cb, wq_global_no_rcu_prog, task_work_cb, task_work_non_sleepable_prog, task_work_sleepable_prog.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_async_cb_context` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: timer_cb timer_non_sleepable_prog timer_sleepable_prog timer_sys_bpf_cb timer_sys_bpf_prog timer_sys_close_cb timer_sys_close_prog timer_btf_find_cb timer_btf_find_prog syscall_sys_bpf_prog syscall_sys_close_prog syscall_btf_find_prog wq_cb wq_non_sleepable_prog wq_sleepable_prog wq_global_acquire wq_global_rcu_cb wq_global_rcu_prog wq_global_rcu_lock_cb wq_global_rcu_lock_prog wq_global_no_rcu wq_global_no_rcu_cb wq_global_no_rcu_prog task_work_cb task_work_non_sleepable_prog task_work_sleepable_prog

use bpf_rs_core::{bpf_map, bpf_object, btf_type_tags, test_tags};
use btf_macros::btf;
use core::ffi::c_void;

test_tags! {
    timer_non_sleepable_prog:
        __failure,
        __msg("sleepable helper bpf_copy_from_user#{{[0-9]+}} in non-sleepable prog");
    timer_sleepable_prog:
        __failure,
        __msg("sleepable helper bpf_copy_from_user#{{[0-9]+}} in non-sleepable prog");
    timer_sys_bpf_prog:
        __failure,
        __msg("sleepable helper bpf_sys_bpf#{{[0-9]+}} in non-sleepable prog");
    timer_sys_close_prog:
        __failure,
        __msg("sleepable helper bpf_sys_close#{{[0-9]+}} in non-sleepable prog");
    timer_btf_find_prog:
        __failure,
        __msg("sleepable helper bpf_btf_find_by_name_kind#{{[0-9]+}} in non-sleepable prog");
    syscall_sys_bpf_prog:
        __success;
    syscall_sys_close_prog:
        __success;
    syscall_btf_find_prog:
        __success;
    wq_non_sleepable_prog:
        __success;
    wq_sleepable_prog:
        __success;
    wq_global_rcu_prog:
        __failure,
        __msg("R1 must be a rcu pointer");
    wq_global_rcu_lock_prog:
        __success;
    wq_global_no_rcu_prog:
        __success,
        __log_level("4"),
        __msg("subprog {{[0-9]+}} (wq_global_no_rcu) global insns_self 4 insns_total 4 stack 0");
    task_work_non_sleepable_prog:
        __success;
    task_work_sleepable_prog:
        __success;
}

// Map key/value types, shaped like the C object's BTF (the kernel
// checks some of them member by member, so no explicit padding).
// translint: allow(padding)
btf_type_tags! {
    wq_elem.task: kptr;
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct bpf_timer {
    __opaque: [u64; 2],
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct timer_elem {
    t: bpf_timer,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct bpf_wq {
    __opaque: [u64; 2],
}

/// An opaque stand-in for the kernel's: only pointed at.
#[allow(non_camel_case_types)]
#[btf]
struct task_struct {}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct wq_elem {
    w: bpf_wq,
    task: *mut task_struct,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct bpf_task_work {
    __opaque: u64,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct task_work_elem {
    tw: bpf_task_work,
}

bpf_map! {
    timer_map {
        r#type: *const [i32; 2],
        max_entries: *const [i32; 1],
        key: *const i32,
        value: *const timer_elem,
    }
}

bpf_map! {
    wq_map {
        r#type: *const [i32; 2],
        max_entries: *const [i32; 1],
        key: *const i32,
        value: *const wq_elem,
    }
}

bpf_map! {
    task_work_map {
        r#type: *const [i32; 2],
        max_entries: *const [i32; 1],
        key: *const i32,
        value: *const task_work_elem,
    }
}

extern "C" {
    fn bpf_wq_init(a0: *mut c_void, a1: *mut c_void, a2: u32) -> i32;
    fn bpf_wq_set_callback(a0: *mut c_void, a1: *mut c_void, a2: u32) -> i32;
    fn bpf_task_acquire(a0: *mut c_void) -> *mut c_void;
    fn bpf_task_release(a0: *mut c_void);
    fn bpf_rcu_read_lock();
    fn bpf_rcu_read_unlock();
    fn bpf_task_work_schedule_resume(a0: *mut c_void, a1: *mut c_void, a2: *mut c_void, a3: *mut c_void) -> i32;
}

include!("hand/verifier_async_cb_context.rs");

bpf_object!("GPL");
