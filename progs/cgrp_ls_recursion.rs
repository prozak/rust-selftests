#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/cgrp_ls_recursion.c
// (bpf-rs-core idiom).
//
// map_a/map_b are BPF_MAP_TYPE_CGRP_STORAGE (no max_entries -> bpf_map!
// escape hatch, same shape as task_storage_nodeadlock.rs's task_storage).
// task->cgroups->dfl_cgrp is a direct trusted-pointer chase (matching the C
// original's plain dereference, not BPF_CORE_READ), so it uses the same
// `.field().get().unwrap()` pattern as find_vma.rs/iters_task.rs rather than
// probe-read cread().

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_cgrp_storage_get, bpf_get_current_task_btf};
use btf_macros::btf;

const CGRP_STORAGE: usize = 32; // enum bpf_map_type BPF_MAP_TYPE_CGRP_STORAGE
const NO_PREALLOC: usize = 1; // BPF_F_NO_PREALLOC
const BPF_LOCAL_STORAGE_GET_F_CREATE: u64 = 1;

bpf_map! {
    map_a {
        r#type: *const [i32; CGRP_STORAGE],
        map_flags: *const [i32; NO_PREALLOC],
        key: *const i32,
        value: *const i64,
    }
}

bpf_map! {
    map_b {
        r#type: *const [i32; CGRP_STORAGE],
        map_flags: *const [i32; NO_PREALLOC],
        key: *const i32,
        value: *const i64,
    }
}

#[no_mangle]
static mut target_hid: i32 = 0;
#[no_mangle]
// C compares the _Bool byte == 1 (jne 1 in the object); a Rust `if bool`
// tests != 0 and diverges for out-of-range bytes -- mirror the C compare.
static mut is_cgroup1: u8 = 0;

#[btf]
struct task_struct {
    cgroups: *mut css_set,
}

#[btf]
struct css_set {
    dfl_cgrp: *mut cgroup,
}

#[btf]
struct cgroup {}

extern "C" {
    fn bpf_task_get_cgroup1(task: *mut task_struct, hierarchy_id: i32) -> *mut cgroup;
    fn bpf_cgroup_release(cgrp: *mut cgroup);
}

#[inline(never)]
fn __on_update(cgrp: *mut cgroup) {
    let ptr = bpf_cgrp_storage_get(&map_a, cgrp, core::ptr::null_mut(), BPF_LOCAL_STORAGE_GET_F_CREATE)
        as *mut i64;
    if !ptr.is_null() {
        unsafe { *ptr += 1 };
    }

    let ptr = bpf_cgrp_storage_get(&map_b, cgrp, core::ptr::null_mut(), BPF_LOCAL_STORAGE_GET_F_CREATE)
        as *mut i64;
    if !ptr.is_null() {
        unsafe { *ptr += 1 };
    }
}

#[link_section = "fentry/bpf_local_storage_update"]
#[no_mangle]
extern "C" fn on_update(_ctx: *const u64) -> i32 {
    let task: *mut task_struct = bpf_get_current_task_btf();

    if unsafe { is_cgroup1 } == 1 {
        let cgrp = unsafe { bpf_task_get_cgroup1(task, target_hid) };
        if cgrp.is_null() {
            return 0;
        }

        __on_update(cgrp);
        unsafe { bpf_cgroup_release(cgrp) };
        return 0;
    }

    let cgroups_ptr = *unsafe { &*task }.cgroups().get().unwrap();
    let dfl_cgrp = *unsafe { &*cgroups_ptr }.dfl_cgrp().get().unwrap();
    __on_update(dfl_cgrp);
    0
}

#[inline(never)]
fn __on_enter(cgrp: *mut cgroup) {
    let ptr = bpf_cgrp_storage_get(&map_a, cgrp, core::ptr::null_mut(), BPF_LOCAL_STORAGE_GET_F_CREATE)
        as *mut i64;
    if !ptr.is_null() {
        unsafe { *ptr = 200 };
    }

    let ptr = bpf_cgrp_storage_get(&map_b, cgrp, core::ptr::null_mut(), BPF_LOCAL_STORAGE_GET_F_CREATE)
        as *mut i64;
    if !ptr.is_null() {
        unsafe { *ptr = 100 };
    }
}

#[link_section = "tp_btf/sys_enter"]
#[no_mangle]
extern "C" fn on_enter(_ctx: *const u64) -> i32 {
    let task: *mut task_struct = bpf_get_current_task_btf();

    if unsafe { is_cgroup1 } == 1 {
        let cgrp = unsafe { bpf_task_get_cgroup1(task, target_hid) };
        if cgrp.is_null() {
            return 0;
        }

        __on_enter(cgrp);
        unsafe { bpf_cgroup_release(cgrp) };
        return 0;
    }

    let cgroups_ptr = *unsafe { &*task }.cgroups().get().unwrap();
    let dfl_cgrp = *unsafe { &*cgroups_ptr }.dfl_cgrp().get().unwrap();
    __on_enter(dfl_cgrp);
    0
}

bpf_object!("GPL");
