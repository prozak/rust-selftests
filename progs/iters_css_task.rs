#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/iters_css_task.c
// (bpf-rs-core idiom).
//
// `&cgrp->self` is the same address as `cgrp` reinterpreted as
// `cgroup_subsys_state *` -- `self` is the first field of `struct cgroup`
// (offset 0), same shortcut as cgroup_iter_memcg.rs.
//
// `bpf_for_each(css_task, task, css, CSS_TASK_ITER_PROCS)` is translated as
// the open-coded iterator it desugars to: extern kfuncs
// bpf_iter_css_task_new/next/destroy, same pattern as iters_task.rs's
// bpf_iter_task and iters_task_vma.rs's bpf_iter_task_vma.

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_get_current_cgroup_id, bpf_get_current_task_btf, bpf_seq_printf};
use bpf_rs_core::progs::fentry_arg as arg;
use btf_macros::btf;

#[btf]
struct task_struct {
    pid: i32,
}

#[btf]
struct kernfs_node {
    id: u64,
}

#[btf]
struct cgroup {
    kn: *mut kernfs_node,
}

#[repr(C)]
struct cgroup_subsys_state {
    _opaque: [u8; 0],
}

// struct bpf_iter_css_task { __u64 __opaque[1]; } __attribute__((aligned(8)));
#[repr(C, align(8))]
struct bpf_iter_css_task {
    __opaque: [u64; 1],
}

#[repr(C)]
struct bpf_iter_meta {
    seq: *mut c_void,
    session_id: u64,
    seq_num: u64,
}

#[repr(C)]
struct bpf_iter__cgroup {
    meta: *mut bpf_iter_meta,
    cgroup: *mut cgroup,
}

extern "C" {
    fn bpf_cgroup_from_id(cgid: u64) -> *mut cgroup;
    fn bpf_cgroup_release(p: *mut cgroup);
    fn bpf_iter_css_task_new(
        it: *mut bpf_iter_css_task,
        css: *mut cgroup_subsys_state,
        flags: u32,
    ) -> i32;
    fn bpf_iter_css_task_next(it: *mut bpf_iter_css_task) -> *mut task_struct;
    fn bpf_iter_css_task_destroy(it: *mut bpf_iter_css_task);
}

const CSS_TASK_ITER_PROCS: u32 = 1;
const EPERM: i32 = 1;

#[no_mangle]
static mut target_pid: i32 = 0;
#[no_mangle]
static mut css_task_cnt: i32 = 0;
#[no_mangle]
static mut cg_id: u64 = 0;

fn cgroup_id(cgrp: *mut cgroup) -> u64 {
    let kn = *unsafe { &*cgrp }.kn().get().unwrap();
    *unsafe { &*kn }.id().get().unwrap()
}

#[link_section = "lsm/file_mprotect"]
#[no_mangle]
extern "C" fn iter_css_task_for_each(ctx: *const u64) -> i32 {
    let ret = arg(ctx, 3) as i32;
    let cur_task: *mut task_struct = bpf_get_current_task_btf();

    if *unsafe { &*cur_task }.pid().get().unwrap() != unsafe { target_pid } {
        return ret;
    }

    let cgrp = unsafe { bpf_cgroup_from_id(cg_id) };
    if cgrp.is_null() {
        return -EPERM;
    }

    let css = cgrp as *mut cgroup_subsys_state;
    unsafe { css_task_cnt = 0 };

    let mut it = bpf_iter_css_task { __opaque: [0; 1] };
    unsafe { bpf_iter_css_task_new(&mut it, css, CSS_TASK_ITER_PROCS) };
    loop {
        let task = unsafe { bpf_iter_css_task_next(&mut it) };
        if task.is_null() {
            break;
        }
        let pid = *unsafe { &*task }.pid().get().unwrap();
        if pid == unsafe { target_pid } {
            unsafe { css_task_cnt += 1 };
        }
    }
    unsafe { bpf_iter_css_task_destroy(&mut it) };

    unsafe { bpf_cgroup_release(cgrp) };

    -EPERM
}

#[link_section = "?iter/cgroup"]
#[no_mangle]
extern "C" fn cgroup_id_printer(ctx: *const bpf_iter__cgroup) -> i32 {
    let ctx_ref = unsafe { &*ctx };
    let meta = unsafe { &*ctx_ref.meta };
    let seq = meta.seq;
    let cgrp = ctx_ref.cgroup;

    if cgrp.is_null() {
        static FMT: [u8; 10] = *b"epilogue\n\0";
        bpf_seq_printf(
            seq,
            FMT.as_ptr() as *const c_void,
            FMT.len() as u32,
            core::ptr::null(),
            0,
        );
        return 0;
    }

    if meta.seq_num == 0 {
        static FMT: [u8; 10] = *b"prologue\n\0";
        bpf_seq_printf(
            seq,
            FMT.as_ptr() as *const c_void,
            FMT.len() as u32,
            core::ptr::null(),
            0,
        );
    }

    static ID_FMT: [u8; 7] = *b"%8llu\n\0";
    let id_params: [u64; 1] = [cgroup_id(cgrp)];
    bpf_seq_printf(
        seq,
        ID_FMT.as_ptr() as *const c_void,
        ID_FMT.len() as u32,
        id_params.as_ptr() as *const c_void,
        core::mem::size_of_val(&id_params) as u32,
    );

    let css = cgrp as *mut cgroup_subsys_state;
    unsafe { css_task_cnt = 0 };

    let mut it = bpf_iter_css_task { __opaque: [0; 1] };
    unsafe { bpf_iter_css_task_new(&mut it, css, CSS_TASK_ITER_PROCS) };
    loop {
        let task = unsafe { bpf_iter_css_task_next(&mut it) };
        if task.is_null() {
            break;
        }
        let pid = *unsafe { &*task }.pid().get().unwrap();
        if pid == unsafe { target_pid } {
            unsafe { css_task_cnt += 1 };
        }
    }
    unsafe { bpf_iter_css_task_destroy(&mut it) };

    0
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn iter_css_task_for_each_sleep(_ctx: *const c_void) -> i32 {
    let cgrp_id = bpf_get_current_cgroup_id();
    let cgrp = unsafe { bpf_cgroup_from_id(cgrp_id) };
    if cgrp.is_null() {
        return 0;
    }
    let css = cgrp as *mut cgroup_subsys_state;

    let mut it = bpf_iter_css_task { __opaque: [0; 1] };
    unsafe { bpf_iter_css_task_new(&mut it, css, CSS_TASK_ITER_PROCS) };
    loop {
        let task = unsafe { bpf_iter_css_task_next(&mut it) };
        if task.is_null() {
            break;
        }
    }
    unsafe { bpf_iter_css_task_destroy(&mut it) };

    unsafe { bpf_cgroup_release(cgrp) };
    0
}

bpf_object!("GPL");
