#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/iters_css.c
// (bpf-rs-core idiom). Same open-coded bpf_iter_css_new/next/destroy kfunc
// triple and `&cgrp->self` offset-0 pointer-cast pattern as
// read_cgroupfs_xattr.rs / iters_css_task.

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_current_task_btf;
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

#[btf]
struct cgroup_subsys_state {
    cgroup: *mut cgroup,
}

// struct bpf_iter_css { __u64 __opaque[3]; } __attribute__((aligned(8)));
#[repr(C, align(8))]
struct bpf_iter_css {
    __opaque: [u64; 3],
}

extern "C" {
    fn bpf_iter_css_new(
        it: *mut bpf_iter_css,
        start: *mut cgroup_subsys_state,
        flags: u32,
    ) -> i32;
    fn bpf_iter_css_next(it: *mut bpf_iter_css) -> *mut cgroup_subsys_state;
    fn bpf_iter_css_destroy(it: *mut bpf_iter_css);
    fn bpf_cgroup_from_id(cgid: u64) -> *mut cgroup;
    fn bpf_cgroup_release(cgrp: *mut cgroup);
    fn bpf_rcu_read_lock();
    fn bpf_rcu_read_unlock();
}

const BPF_CGROUP_ITER_DESCENDANTS_PRE: u32 = 2;
const BPF_CGROUP_ITER_DESCENDANTS_POST: u32 = 3;
const BPF_CGROUP_ITER_ANCESTORS_UP: u32 = 4;
const BPF_CGROUP_ITER_CHILDREN: u32 = 5;

#[no_mangle]
static mut target_pid: i32 = 0;
#[no_mangle]
static mut root_cg_id: u64 = 0;
#[no_mangle]
static mut leaf_cg_id: u64 = 0;
#[no_mangle]
static mut first_cg_id: u64 = 0;
#[no_mangle]
static mut last_cg_id: u64 = 0;
#[no_mangle]
static mut pre_order_cnt: i32 = 0;
#[no_mangle]
static mut post_order_cnt: i32 = 0;
#[no_mangle]
static mut children_cnt: i32 = 0;
#[no_mangle]
static mut tree_high: i32 = 0;

fn cgroup_id(cgrp: *mut cgroup) -> u64 {
    let kn = unsafe { *(&*cgrp).kn().as_ptr() };
    unsafe { *(&*kn).id().as_ptr() }
}

#[link_section = "fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn iter_css_for_each(_ctx: *const c_void) -> i32 {
    let cur_task: *mut task_struct = bpf_get_current_task_btf();

    if *unsafe { &*cur_task }.pid().get().unwrap() != unsafe { target_pid } {
        return 0;
    }

    let root_cgrp = unsafe { bpf_cgroup_from_id(root_cg_id) };
    if root_cgrp.is_null() {
        return 0;
    }

    let leaf_cgrp = unsafe { bpf_cgroup_from_id(leaf_cg_id) };
    if leaf_cgrp.is_null() {
        unsafe { bpf_cgroup_release(root_cgrp) };
        return 0;
    }

    // `self` is the first (offset-0) member of `struct cgroup`, so a plain
    // pointer cast is `&cgrp->self` without needing a CO-RE field access.
    let root_css = root_cgrp as *mut cgroup_subsys_state;
    let leaf_css = leaf_cgrp as *mut cgroup_subsys_state;

    unsafe {
        pre_order_cnt = 0;
        post_order_cnt = 0;
        children_cnt = 0;
        tree_high = 0;
        first_cg_id = 0;
        last_cg_id = 0;
    }

    unsafe { bpf_rcu_read_lock() };

    let mut it = bpf_iter_css { __opaque: [0; 3] };
    unsafe { bpf_iter_css_new(&mut it, root_css, BPF_CGROUP_ITER_DESCENDANTS_POST) };
    loop {
        let pos = unsafe { bpf_iter_css_next(&mut it) };
        if pos.is_null() {
            break;
        }
        let cur_cgrp = unsafe { *(&*pos).cgroup().as_ptr() };
        unsafe { post_order_cnt += 1 };
        unsafe { last_cg_id = cgroup_id(cur_cgrp) };
    }
    unsafe { bpf_iter_css_destroy(&mut it) };

    let mut it = bpf_iter_css { __opaque: [0; 3] };
    unsafe { bpf_iter_css_new(&mut it, root_css, BPF_CGROUP_ITER_DESCENDANTS_PRE) };
    loop {
        let pos = unsafe { bpf_iter_css_next(&mut it) };
        if pos.is_null() {
            break;
        }
        let cur_cgrp = unsafe { *(&*pos).cgroup().as_ptr() };
        unsafe { pre_order_cnt += 1 };
        if unsafe { first_cg_id } == 0 {
            unsafe { first_cg_id = cgroup_id(cur_cgrp) };
        }
    }
    unsafe { bpf_iter_css_destroy(&mut it) };

    let mut it = bpf_iter_css { __opaque: [0; 3] };
    unsafe { bpf_iter_css_new(&mut it, root_css, BPF_CGROUP_ITER_CHILDREN) };
    loop {
        let pos = unsafe { bpf_iter_css_next(&mut it) };
        if pos.is_null() {
            break;
        }
        unsafe { children_cnt += 1 };
    }
    unsafe { bpf_iter_css_destroy(&mut it) };

    let mut it = bpf_iter_css { __opaque: [0; 3] };
    unsafe { bpf_iter_css_new(&mut it, leaf_css, BPF_CGROUP_ITER_ANCESTORS_UP) };
    loop {
        let pos = unsafe { bpf_iter_css_next(&mut it) };
        if pos.is_null() {
            break;
        }
        unsafe { tree_high += 1 };
    }
    unsafe { bpf_iter_css_destroy(&mut it) };

    let mut it = bpf_iter_css { __opaque: [0; 3] };
    unsafe { bpf_iter_css_new(&mut it, root_css, BPF_CGROUP_ITER_ANCESTORS_UP) };
    loop {
        let pos = unsafe { bpf_iter_css_next(&mut it) };
        if pos.is_null() {
            break;
        }
        unsafe { tree_high -= 1 };
    }
    unsafe { bpf_iter_css_destroy(&mut it) };

    unsafe { bpf_rcu_read_unlock() };
    unsafe { bpf_cgroup_release(root_cgrp) };
    unsafe { bpf_cgroup_release(leaf_cgrp) };

    0
}

bpf_object!("GPL");
