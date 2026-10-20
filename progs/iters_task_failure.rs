// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Direct translation of tools/testing/selftests/bpf/progs/iters_task_failure.c
// (bpf-rs-core idiom).
//
// RCU-protection rejections for the task/css/css_task open-coded
// iterators (prog_tests/iters.c: RUN_TESTS(iters_task_failure)). Each
// bpf_for_each() is the kfunc new/next/destroy triple as in iters_task.rs
// and iters_css.rs; `&cgrp->self` is the offset-0 member cast of
// iters_css.rs. iter_tasks_rcu_state_pruning is the C's asm volatile
// block: asm! with the iterator's address in(reg), kfuncs as sym, the
// helper by number (call 7) and r0-r5 clobbered (__clobber_common).

use bpf_rs_core::helpers::bpf_get_current_cgroup_id;
use bpf_rs_core::{bpf_object, test_tags};
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ptr::null_mut;

#[allow(non_camel_case_types)]
#[repr(C)]
struct task_struct {
    _opaque: [u8; 0],
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct cgroup {
    _opaque: [u8; 0],
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct cgroup_subsys_state {
    _opaque: [u8; 0],
}

// struct bpf_iter_task { __u64 __opaque[3]; } __attribute__((aligned(8)));
#[allow(non_camel_case_types)]
#[repr(C, align(8))]
struct bpf_iter_task {
    __opaque: [u64; 3],
}

// struct bpf_iter_css { __u64 __opaque[3]; } __attribute__((aligned(8)));
#[allow(non_camel_case_types)]
#[repr(C, align(8))]
struct bpf_iter_css {
    __opaque: [u64; 3],
}

// struct bpf_iter_css_task { __u64 __opaque[1]; } __attribute__((aligned(8)));
#[allow(non_camel_case_types)]
#[repr(C, align(8))]
struct bpf_iter_css_task {
    __opaque: [u64; 1],
}

extern "C" {
    fn bpf_cgroup_from_id(cgid: u64) -> *mut cgroup;
    fn bpf_cgroup_release(p: *mut cgroup);
    fn bpf_rcu_read_lock();
    fn bpf_rcu_read_unlock();
    fn bpf_iter_task_new(it: *mut bpf_iter_task, task: *mut task_struct, flags: u32) -> i32;
    fn bpf_iter_task_next(it: *mut bpf_iter_task) -> *mut task_struct;
    fn bpf_iter_task_destroy(it: *mut bpf_iter_task);
    fn bpf_iter_css_new(
        it: *mut bpf_iter_css,
        start: *mut cgroup_subsys_state,
        flags: u32,
    ) -> i32;
    fn bpf_iter_css_next(it: *mut bpf_iter_css) -> *mut cgroup_subsys_state;
    fn bpf_iter_css_destroy(it: *mut bpf_iter_css);
    fn bpf_iter_css_task_new(
        it: *mut bpf_iter_css_task,
        css: *mut cgroup_subsys_state,
        flags: u32,
    ) -> i32;
    fn bpf_iter_css_task_next(it: *mut bpf_iter_css_task) -> *mut task_struct;
    fn bpf_iter_css_task_destroy(it: *mut bpf_iter_css_task);
}

const BPF_TASK_ITER_ALL_PROCS: u32 = 0;
const BPF_CGROUP_ITER_DESCENDANTS_POST: u32 = 3;
const CSS_TASK_ITER_PROCS: u32 = 1;

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn iter_tasks_without_lock(_ctx: *mut c_void) -> i32 {
    unsafe {
        let mut it = bpf_iter_task { __opaque: [0; 3] };
        bpf_iter_task_new(&mut it, null_mut(), BPF_TASK_ITER_ALL_PROCS);
        loop {
            let pos = bpf_iter_task_next(&mut it);
            if pos.is_null() {
                break;
            }
        }
        bpf_iter_task_destroy(&mut it);
    }
    0
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn iter_css_without_lock(_ctx: *mut c_void) -> i32 {
    unsafe {
        let cg_id = bpf_get_current_cgroup_id();
        let cgrp = bpf_cgroup_from_id(cg_id);

        if cgrp.is_null() {
            return 0;
        }
        // root_css = &cgrp->self (offset 0)
        let root_css = cgrp as *mut cgroup_subsys_state;

        let mut it = bpf_iter_css { __opaque: [0; 3] };
        bpf_iter_css_new(&mut it, root_css, BPF_CGROUP_ITER_DESCENDANTS_POST);
        loop {
            let pos = bpf_iter_css_next(&mut it);
            if pos.is_null() {
                break;
            }
        }
        bpf_iter_css_destroy(&mut it);
        bpf_cgroup_release(cgrp);
    }
    0
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn iter_tasks_lock_and_unlock(_ctx: *mut c_void) -> i32 {
    unsafe {
        bpf_rcu_read_lock();
        let mut it = bpf_iter_task { __opaque: [0; 3] };
        bpf_iter_task_new(&mut it, null_mut(), BPF_TASK_ITER_ALL_PROCS);
        loop {
            let pos = bpf_iter_task_next(&mut it);
            if pos.is_null() {
                break;
            }
            bpf_rcu_read_unlock();

            bpf_rcu_read_lock();
        }
        bpf_iter_task_destroy(&mut it);
        bpf_rcu_read_unlock();
    }
    0
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn iter_tasks_rcu_state_pruning(_ctx: *mut c_void) -> i32 {
    let mut it = MaybeUninit::<bpf_iter_task>::uninit();

    unsafe {
        core::arch::asm!(
            "call {bpf_rcu_read_lock}",
            "r1 = {it}",
            "r2 = 0",
            "r3 = 0", // BPF_TASK_ITER_ALL_PROCS
            "call {bpf_iter_task_new}",

            "call 7", // bpf_get_prandom_u32
            "if w0 == 0 goto 1f",

            // Keep the outer RCU lock active on the straight-line path.
            "call {bpf_rcu_read_lock}",
            "call {bpf_rcu_read_unlock}",
            "goto 2f",

            "1:",
            // Create an unprotected gap on the taken path.
            "call {bpf_rcu_read_unlock}",
            "call {bpf_rcu_read_lock}",

            "2:",
            "r1 = {it}",
            "call {bpf_iter_task_next}",
            "r1 = {it}",
            "call {bpf_iter_task_destroy}",
            "call {bpf_rcu_read_unlock}",
            it = in(reg) it.as_mut_ptr(),
            bpf_iter_task_new = sym bpf_iter_task_new,
            bpf_iter_task_next = sym bpf_iter_task_next,
            bpf_iter_task_destroy = sym bpf_iter_task_destroy,
            bpf_rcu_read_lock = sym bpf_rcu_read_lock,
            bpf_rcu_read_unlock = sym bpf_rcu_read_unlock,
            out("r0") _,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
        );
    }

    0
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn iter_css_lock_and_unlock(_ctx: *mut c_void) -> i32 {
    unsafe {
        let cg_id = bpf_get_current_cgroup_id();
        let cgrp = bpf_cgroup_from_id(cg_id);

        if cgrp.is_null() {
            return 0;
        }
        let root_css = cgrp as *mut cgroup_subsys_state;

        bpf_rcu_read_lock();
        let mut it = bpf_iter_css { __opaque: [0; 3] };
        bpf_iter_css_new(&mut it, root_css, BPF_CGROUP_ITER_DESCENDANTS_POST);
        loop {
            let pos = bpf_iter_css_next(&mut it);
            if pos.is_null() {
                break;
            }
            bpf_rcu_read_unlock();

            bpf_rcu_read_lock();
        }
        bpf_iter_css_destroy(&mut it);
        bpf_rcu_read_unlock();
        bpf_cgroup_release(cgrp);
    }
    0
}

#[link_section = "?fentry/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn iter_css_task_for_each(_ctx: *mut c_void) -> i32 {
    unsafe {
        let cg_id = bpf_get_current_cgroup_id();
        let cgrp = bpf_cgroup_from_id(cg_id);

        if cgrp.is_null() {
            return 0;
        }
        let css = cgrp as *mut cgroup_subsys_state;

        let mut it = bpf_iter_css_task { __opaque: [0; 1] };
        bpf_iter_css_task_new(&mut it, css, CSS_TASK_ITER_PROCS);
        loop {
            let task = bpf_iter_css_task_next(&mut it);
            if task.is_null() {
                break;
            }
        }
        bpf_iter_css_task_destroy(&mut it);
        bpf_cgroup_release(cgrp);
    }
    0
}

test_tags! {
    iter_tasks_without_lock: __failure, __msg("kernel func bpf_iter_task_new requires RCU critical section protection");
    iter_css_without_lock: __failure, __msg("kernel func bpf_iter_css_new requires RCU critical section protection");
    iter_tasks_lock_and_unlock: __failure, __msg("expected an RCU CS when using bpf_iter_task_next");
    iter_tasks_rcu_state_pruning: __failure, __msg("expected an RCU CS when using bpf_iter_task_next"), __flag(BPF_F_TEST_STATE_FREQ);
    iter_css_lock_and_unlock: __failure, __msg("expected an RCU CS when using bpf_iter_css_next");
    iter_css_task_for_each: __failure, __msg("css_task_iter is only allowed in bpf_lsm, bpf_iter and sleepable progs");
}

bpf_object!("GPL");
