#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_cgroup1_hierarchy.c
// (bpf-next), bpf-rs-core idiom.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_current_task_btf;
use bpf_rs_core::progs::fentry_arg as arg;
use btf_macros::btf;

const BPF_LINK_CREATE: i32 = 28;

#[btf]
struct kernfs_node {
    id: u64,
}

#[btf]
struct cgroup {
    kn: *mut kernfs_node,
}

#[btf]
struct task_struct {
    pid: i32,
}

extern "C" {
    fn bpf_task_get_cgroup1(task: *mut task_struct, hierarchy_id: i32) -> *mut cgroup;
    fn bpf_cgroup_ancestor(cgrp: *mut cgroup, level: i32) -> *mut cgroup;
    fn bpf_cgroup_release(cgrp: *mut cgroup);
}

#[no_mangle]
static mut target_ancestor_level: u32 = 0;
#[no_mangle]
static mut target_ancestor_cgid: u64 = 0;
#[no_mangle]
static mut target_pid: i32 = 0;
#[no_mangle]
static mut target_hid: i32 = 0;

fn cgroup_id(cgrp: *mut cgroup) -> u64 {
    let kn = unsafe { *(&*cgrp).kn().as_ptr() };
    unsafe { *(&*kn).id().as_ptr() }
}

fn bpf_link_create_verify(cmd: i32) -> i32 {
    if cmd != BPF_LINK_CREATE {
        return 0;
    }

    let task: *mut task_struct = bpf_get_current_task_btf();
    let task_pid = unsafe { *(&*task).pid().as_ptr() };
    if task_pid != unsafe { target_pid } {
        return 0;
    }

    let cgrp = unsafe { bpf_task_get_cgroup1(task, target_hid) };
    if cgrp.is_null() {
        return 0;
    }

    let mut ret: i32 = 0;

    if cgroup_id(cgrp) == unsafe { target_ancestor_cgid } {
        ret = -1;
    }

    let ancestor = unsafe { bpf_cgroup_ancestor(cgrp, target_ancestor_level as i32) };
    if !ancestor.is_null() {
        if cgroup_id(ancestor) == unsafe { target_ancestor_cgid } {
            ret = -1;
        }
        unsafe { bpf_cgroup_release(ancestor) };
    }

    unsafe { bpf_cgroup_release(cgrp) };
    ret
}

#[link_section = "lsm/bpf"]
#[no_mangle]
extern "C" fn lsm_run(ctx: *const u64) -> i32 {
    // int cmd, union bpf_attr *attr, unsigned int size, bool kernel
    let cmd = arg(ctx, 0) as i32;
    bpf_link_create_verify(cmd)
}

#[link_section = "lsm.s/bpf"]
#[no_mangle]
extern "C" fn lsm_s_run(ctx: *const u64) -> i32 {
    // int cmd, union bpf_attr *attr, unsigned int size, bool kernel
    let cmd = arg(ctx, 0) as i32;
    bpf_link_create_verify(cmd)
}

#[link_section = "fentry"]
#[no_mangle]
extern "C" fn fentry_run(_ctx: *const u64) -> i32 {
    0
}

bpf_object!("GPL");
