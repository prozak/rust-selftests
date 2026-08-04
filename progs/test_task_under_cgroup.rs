#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_task_under_cgroup.c,
// bpf-rs-core idiom.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_current_pid_tgid;
use bpf_rs_core::helpers::bpf_get_current_task_btf;
use bpf_rs_core::progs::fentry_arg;
use btf_macros::btf;

const BPF_LINK_CREATE: i32 = 28;

#[btf]
struct task_struct {
    pid: i32,
    tgid: i32,
}

struct cgroup;

extern "C" {
    fn bpf_cgroup_from_id(cgid: u64) -> *mut cgroup;
    fn bpf_task_under_cgroup(task: *mut task_struct, ancestor: *mut cgroup) -> i64;
    fn bpf_cgroup_release(p: *mut cgroup);
    fn bpf_task_acquire(p: *mut task_struct) -> *mut task_struct;
    fn bpf_task_release(p: *mut task_struct);
}

#[link_section = ".rodata"]
#[no_mangle]
static local_pid: i32 = 0;

#[link_section = ".rodata"]
#[no_mangle]
static cgid: u64 = 0;

#[no_mangle]
static mut remote_pid: i32 = 0;

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn tp_btf_run(ctx: *const u64) -> i32 {
    let cur_local_pid = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(local_pid)) };
    let cur_cgid = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(cgid)) };

    if cur_local_pid as u64 != (bpf_get_current_pid_tgid() >> 32) {
        return 0;
    }

    let task = fentry_arg(ctx, 0) as *mut task_struct;

    let acquired = unsafe { bpf_task_acquire(task) };
    if acquired.is_null() {
        return 0;
    }

    let acquired_tgid = *unsafe { &*acquired }.tgid().get().unwrap();

    let mut cgrp: *mut cgroup = core::ptr::null_mut();
    if cur_local_pid != acquired_tgid {
        cgrp = unsafe { bpf_cgroup_from_id(cur_cgid) };
        if !cgrp.is_null() && unsafe { bpf_task_under_cgroup(acquired, cgrp) } != 0 {
            unsafe { remote_pid = acquired_tgid };
        }
    }

    if !cgrp.is_null() {
        unsafe { bpf_cgroup_release(cgrp) };
    }
    unsafe { bpf_task_release(acquired) };

    0
}

#[link_section = "lsm.s/bpf"]
#[no_mangle]
extern "C" fn lsm_run(ctx: *const u64) -> i32 {
    let cur_local_pid = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(local_pid)) };

    let task: *mut task_struct = bpf_get_current_task_btf();
    let task_pid = *unsafe { &*task }.pid().get().unwrap();
    if cur_local_pid != task_pid {
        return 0;
    }

    let cmd = fentry_arg(ctx, 0) as i32;
    if cmd != BPF_LINK_CREATE {
        return 0;
    }

    let mut ret: i32 = 0;

    let cgrp = unsafe { bpf_cgroup_from_id(1) };
    if !cgrp.is_null() {
        if unsafe { bpf_task_under_cgroup(task, cgrp) } == 0 {
            ret = -1;
        }
        unsafe { bpf_cgroup_release(cgrp) };
    }

    ret
}

bpf_object!("GPL");
