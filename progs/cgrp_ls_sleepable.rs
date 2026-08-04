#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/cgrp_ls_sleepable.c,
// bpf-rs-core idiom.
//
// `no_rcu_lock` is a genuine load-time negative test (not a `__failure`/`__msg`
// one): `task->cgroups` is an rcu-tagged field in the real kernel BTF, so a
// CO-RE read of it outside a `bpf_rcu_read_lock()` critical section yields an
// untrusted pointer at the verifier level; walking to `->dfl_cgrp` and passing
// it to `bpf_cgrp_storage_get` (which wants a trusted `PTR_TO_BTF_ID`) is then
// rejected. This is independent of our local BTF shape -- the verifier's
// trust decision is keyed off the real target field's type tag, resolved by
// name through the CO-RE relocation -- so the translation reproduces the same
// rejection as the C source without any decl-tag trickery.

use bpf_rs_core::helpers::{bpf_cgrp_storage_get, bpf_get_current_task_btf};
use bpf_rs_core::progs::fentry_arg;
use bpf_rs_core::{bpf_map, bpf_object};
use btf_macros::btf;
use core::ffi::c_void;

const BPF_LOCAL_STORAGE_GET_F_CREATE: u64 = 1;
const BPF_MAP_TYPE_CGRP_STORAGE: i32 = 32;
const MAX_ERRNO: u64 = 4095;

#[btf]
struct kernfs_node {
    id: u64,
}

#[btf]
struct cgroup {
    kn: *mut kernfs_node,
}

#[btf]
struct css_set {
    dfl_cgrp: *mut cgroup,
}

#[btf]
struct task_struct {
    pid: i32,
    cgroups: *mut css_set,
}

#[repr(C)]
struct bpf_iter__cgroup {
    meta: *mut c_void,
    cgroup: *mut c_void,
}

extern "C" {
    fn bpf_task_get_cgroup1(task: *mut task_struct, hierarchy_id: i32) -> *mut cgroup;
    fn bpf_cgroup_release(cgrp: *mut cgroup);
    fn bpf_rcu_read_lock();
    fn bpf_rcu_read_unlock();
}

bpf_map! {
    map_a {
        r#type: *const [i32; BPF_MAP_TYPE_CGRP_STORAGE as usize],
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        key: *const i32,
        value: *const isize,
    }
}

#[no_mangle]
static mut target_pid: i32 = 0;
#[no_mangle]
static mut cgroup_id: u64 = 0;
#[no_mangle]
static mut update_err: isize = 0;
#[no_mangle]
static mut target_hid: i32 = 0;
#[no_mangle]
static mut is_cgroup1: bool = false;

#[inline(never)]
fn store_cgroup_id_via_storage(cgrp: *mut cgroup) {
    let ptr = bpf_cgrp_storage_get(
        &map_a,
        cgrp,
        core::ptr::null_mut(),
        BPF_LOCAL_STORAGE_GET_F_CREATE,
    );
    if !ptr.is_null() {
        let kn = *unsafe { &*cgrp }.kn().get().unwrap();
        let id = *unsafe { &*kn }.id().get().unwrap();
        unsafe { cgroup_id = id };
    }
}

#[link_section = "?iter.s/cgroup"]
#[no_mangle]
extern "C" fn cgroup_iter(ctx: *const bpf_iter__cgroup) -> i32 {
    let ctx = unsafe { &*ctx };
    let cgrp = ctx.cgroup as *mut cgroup;

    if cgrp.is_null() {
        return 0;
    }

    let ptr = bpf_cgrp_storage_get(
        &map_a,
        cgrp,
        core::ptr::null_mut(),
        BPF_LOCAL_STORAGE_GET_F_CREATE,
    );
    if !ptr.is_null() {
        let kn = *unsafe { &*cgrp }.kn().get().unwrap();
        let id = *unsafe { &*kn }.id().get().unwrap();
        unsafe { cgroup_id = id };
    }
    0
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn cgrp1_no_rcu_lock(_ctx: *const u64) -> i32 {
    let task: *mut task_struct = bpf_get_current_task_btf();
    if *unsafe { &*task }.pid().get().unwrap() != unsafe { target_pid } {
        return 0;
    }

    let hid = unsafe { target_hid };
    let cgrp = unsafe { bpf_task_get_cgroup1(task, hid) };
    if cgrp.is_null() {
        return 0;
    }

    store_cgroup_id_via_storage(cgrp);
    unsafe { bpf_cgroup_release(cgrp) };
    0
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn no_rcu_lock(_ctx: *const u64) -> i32 {
    let task: *mut task_struct = bpf_get_current_task_btf();
    if *unsafe { &*task }.pid().get().unwrap() != unsafe { target_pid } {
        return 0;
    }

    // `task->cgroups` is untrusted outside an RCU critical section in
    // sleepable progs -- see the module doc comment above.
    let cgroups = *unsafe { &*task }.cgroups().get().unwrap();
    let dfl_cgrp = *unsafe { &*cgroups }.dfl_cgrp().get().unwrap();
    store_cgroup_id_via_storage(dfl_cgrp);
    0
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn yes_rcu_lock(_ctx: *const u64) -> i32 {
    let task: *mut task_struct = bpf_get_current_task_btf();
    if *unsafe { &*task }.pid().get().unwrap() != unsafe { target_pid } {
        return 0;
    }

    if unsafe { is_cgroup1 } {
        unsafe { bpf_rcu_read_lock() };
        let hid = unsafe { target_hid };
        let cgrp = unsafe { bpf_task_get_cgroup1(task, hid) };
        if cgrp.is_null() {
            unsafe { bpf_rcu_read_unlock() };
            return 0;
        }

        store_cgroup_id_via_storage(cgrp);
        unsafe { bpf_cgroup_release(cgrp) };
        unsafe { bpf_rcu_read_unlock() };
        return 0;
    }

    unsafe { bpf_rcu_read_lock() };
    let cgroups = *unsafe { &*task }.cgroups().get().unwrap();
    let cgrp = *unsafe { &*cgroups }.dfl_cgrp().get().unwrap();
    // `cgrp` is trusted here: read under the RCU critical section above.
    store_cgroup_id_via_storage(cgrp);
    unsafe { bpf_rcu_read_unlock() };
    0
}

#[link_section = "fexit/bpf_local_storage_update"]
#[no_mangle]
extern "C" fn fexit_update(ctx: *const u64) -> i32 {
    let task: *mut task_struct = bpf_get_current_task_btf();
    if *unsafe { &*task }.pid().get().unwrap() != unsafe { target_pid } {
        return 0;
    }

    let ret = fentry_arg(ctx, 5);
    if ret >= 0u64.wrapping_sub(MAX_ERRNO) {
        unsafe { update_err = ret as i64 as isize };
    }
    0
}

bpf_object!("GPL");
