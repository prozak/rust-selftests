#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/cgrp_ls_tp_btf.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_cgrp_storage_delete, bpf_cgrp_storage_get, bpf_get_current_task_btf, sync_fetch_and_add_i32,
};
use btf_macros::btf;

const MAGIC_VALUE: i64 = 0xabcd1234;
const BPF_LOCAL_STORAGE_GET_F_CREATE: u64 = 1;

bpf_map! {
    map_a {
        r#type: *const [i32; 32],   // BPF_MAP_TYPE_CGRP_STORAGE
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        key: *const i32,
        value: *const i64,
    }
}

bpf_map! {
    map_b {
        r#type: *const [i32; 32],   // BPF_MAP_TYPE_CGRP_STORAGE
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        key: *const i32,
        value: *const i64,
    }
}

#[no_mangle]
static mut target_pid: i32 = 0;
#[no_mangle]
static mut mismatch_cnt: i32 = 0;
#[no_mangle]
static mut enter_cnt: i32 = 0;
#[no_mangle]
static mut exit_cnt: i32 = 0;
#[no_mangle]
static mut target_hid: i32 = 0;
#[no_mangle]
static mut is_cgroup1: bool = false;

#[btf]
struct cgroup {}

#[btf]
struct css_set {
    dfl_cgrp: *mut cgroup,
}

#[btf]
struct task_struct {
    pid: i32,
    cgroups: *mut css_set,
}

extern "C" {
    fn bpf_task_get_cgroup1(task: *mut task_struct, hierarchy_id: i32) -> *mut cgroup;
    fn bpf_cgroup_release(cgrp: *mut cgroup);
}

#[inline(never)]
fn on_enter_inner(cgrp: *mut cgroup) {
    // populate value 0
    let mut ptr = bpf_cgrp_storage_get(
        &map_a,
        cgrp,
        core::ptr::null_mut(),
        BPF_LOCAL_STORAGE_GET_F_CREATE,
    );
    if ptr.is_null() {
        return;
    }

    // delete value 0
    let err = bpf_cgrp_storage_delete(&map_a, cgrp);
    if err != 0 {
        return;
    }

    // value is not available
    ptr = bpf_cgrp_storage_get(&map_a, cgrp, core::ptr::null_mut(), 0);
    if !ptr.is_null() {
        return;
    }

    // re-populate the value
    ptr = bpf_cgrp_storage_get(
        &map_a,
        cgrp,
        core::ptr::null_mut(),
        BPF_LOCAL_STORAGE_GET_F_CREATE,
    );
    if ptr.is_null() {
        return;
    }
    sync_fetch_and_add_i32(core::ptr::addr_of_mut!(enter_cnt), 1);
    unsafe { *(ptr as *mut i64) = MAGIC_VALUE + enter_cnt as i64 };
}

#[inline(never)]
fn on_exit_inner(cgrp: *mut cgroup) {
    let ptr = bpf_cgrp_storage_get(
        &map_a,
        cgrp,
        core::ptr::null_mut(),
        BPF_LOCAL_STORAGE_GET_F_CREATE,
    );
    if ptr.is_null() {
        return;
    }

    sync_fetch_and_add_i32(core::ptr::addr_of_mut!(exit_cnt), 1);
    if unsafe { *(ptr as *mut i64) } != MAGIC_VALUE + unsafe { exit_cnt } as i64 {
        sync_fetch_and_add_i32(core::ptr::addr_of_mut!(mismatch_cnt), 1);
    }
}

#[link_section = "tp_btf/sys_enter"]
#[no_mangle]
extern "C" fn on_enter(_ctx: *const u64) -> i32 {
    let task: *mut task_struct = bpf_get_current_task_btf();
    let task_pid = unsafe { *(&*task).pid().as_ptr() };
    if task_pid != unsafe { target_pid } {
        return 0;
    }

    if unsafe { is_cgroup1 } {
        let cgrp = unsafe { bpf_task_get_cgroup1(task, target_hid) };
        if cgrp.is_null() {
            return 0;
        }

        on_enter_inner(cgrp);
        unsafe { bpf_cgroup_release(cgrp) };
        return 0;
    }

    let cgroups = unsafe { *(&*task).cgroups().as_ptr() };
    let dfl_cgrp = unsafe { *(&*cgroups).dfl_cgrp().as_ptr() };
    on_enter_inner(dfl_cgrp);
    0
}

#[link_section = "tp_btf/sys_exit"]
#[no_mangle]
extern "C" fn on_exit(_ctx: *const u64) -> i32 {
    let task: *mut task_struct = bpf_get_current_task_btf();
    let task_pid = unsafe { *(&*task).pid().as_ptr() };
    if task_pid != unsafe { target_pid } {
        return 0;
    }

    if unsafe { is_cgroup1 } {
        let cgrp = unsafe { bpf_task_get_cgroup1(task, target_hid) };
        if cgrp.is_null() {
            return 0;
        }

        on_exit_inner(cgrp);
        unsafe { bpf_cgroup_release(cgrp) };
        return 0;
    }

    let cgroups = unsafe { *(&*task).cgroups().as_ptr() };
    let dfl_cgrp = unsafe { *(&*cgroups).dfl_cgrp().as_ptr() };
    on_exit_inner(dfl_cgrp);
    0
}

bpf_object!("GPL");
