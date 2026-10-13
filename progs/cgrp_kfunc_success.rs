// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/cgrp_kfunc_success.c
// (+ cgrp_kfunc_common.h), bpf-rs-core idiom.
//
// The map value's `cgrp` field is `__kptr` in the C; the tag comes from the
// btf_type_tags! declaration at the bottom.

use bpf_rs_core::helpers::{
    bpf_get_current_pid_tgid, bpf_kptr_xchg, bpf_map_delete_elem, bpf_map_lookup_elem,
    bpf_map_update_elem, bpf_probe_read_kernel, sync_fetch_and_add_u32,
};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::progs::fentry_arg;
use bpf_rs_core::{bpf_object, btf_type_tags};
use btf_macros::btf;

#[btf]
struct kernfs_node {
    id: u64,
}

#[btf]
struct cgroup_subsys_state {
    id: i32,
}

#[btf]
struct cgroup {
    level: i32,
    kn: *mut kernfs_node,
}

extern "C" {
    fn bpf_cgroup_acquire(p: *mut cgroup) -> *mut cgroup;
    fn bpf_cgroup_release(p: *mut cgroup);
    fn bpf_cgroup_ancestor(cgrp: *mut cgroup, level: i32) -> *mut cgroup;
    fn bpf_cgroup_from_id(cgid: u64) -> *mut cgroup;
    fn bpf_rcu_read_lock();
    fn bpf_rcu_read_unlock();
}

#[repr(C)]
struct __cgrps_kfunc_map_value {
    cgrp: *mut cgroup,
}

#[link_section = ".maps"]
#[no_mangle]
static __cgrps_kfunc_map: BpfMap<i32, __cgrps_kfunc_map_value, { maps::HASH }, 1> = BpfMap::new();

#[no_mangle]
static mut err: i32 = 0;
#[no_mangle]
static mut pid: i32 = 0;
#[no_mangle]
static mut invocations: i32 = 0;

// `self` can't be declared as a struct field (Rust forbids it even as a raw
// identifier), so `cgrp->self.id` is read via the well-known C idiom of
// `struct cgroup_subsys_state self` being cgroup's first member (offset 0):
// reinterpret the pointer as `*mut cgroup_subsys_state` and read `id`
// directly off it, same effective CO-RE byte-offset relocation target.
#[inline(never)]
fn cgrp_self_id(cgrp: *mut cgroup) -> i32 {
    let css = cgrp as *mut cgroup_subsys_state;
    *unsafe { &*css }.id().get().unwrap()
}

#[inline(never)]
fn cgrp_level(cgrp: *mut cgroup) -> i32 {
    *unsafe { &*cgrp }.level().get().unwrap()
}

#[inline(never)]
fn cgrp_kn(cgrp: *mut cgroup) -> *mut kernfs_node {
    *unsafe { &*cgrp }.kn().get().unwrap()
}

#[inline(never)]
fn kn_id(kn: *mut kernfs_node) -> u64 {
    *unsafe { &*kn }.id().get().unwrap()
}

const ENOENT: i64 = 2;
const EEXIST: i64 = 17;
const BPF_NOEXIST: u64 = 1;

/// C: bpf_probe_read_kernel(&id, sizeof(id), &cgrp->self.id)
#[inline(always)]
fn read_self_id(cgrp: *mut cgroup, id: &mut i32) -> i64 {
    let css = cgrp as *mut cgroup_subsys_state;
    bpf_probe_read_kernel(id, 4, unsafe { &*css }.id().as_ptr().cast())
}

#[inline(always)]
fn cgrps_kfunc_map_value_lookup(cgrp: *mut cgroup) -> *mut __cgrps_kfunc_map_value {
    let mut id: i32 = 0;
    if read_self_id(cgrp, &mut id) != 0 {
        return core::ptr::null_mut();
    }
    bpf_map_lookup_elem(&__cgrps_kfunc_map, &id).cast()
}

#[inline(always)]
fn cgrps_kfunc_map_insert(cgrp: *mut cgroup) -> i64 {
    let mut id: i32 = 0;
    let status = read_self_id(cgrp, &mut id);
    if status != 0 {
        return status;
    }

    let local = __cgrps_kfunc_map_value {
        cgrp: core::ptr::null_mut(),
    };
    let status = bpf_map_update_elem(&__cgrps_kfunc_map, &id, &local, BPF_NOEXIST);
    if status != 0 {
        return status;
    }

    let v: *mut __cgrps_kfunc_map_value = bpf_map_lookup_elem(&__cgrps_kfunc_map, &id).cast();
    if v.is_null() {
        bpf_map_delete_elem(&__cgrps_kfunc_map, &id);
        return -ENOENT;
    }

    let acquired = unsafe { bpf_cgroup_acquire(cgrp) };
    if acquired.is_null() {
        bpf_map_delete_elem(&__cgrps_kfunc_map, &id);
        return -ENOENT;
    }

    let old: *mut cgroup =
        bpf_kptr_xchg(unsafe { core::ptr::addr_of_mut!((*v).cgrp) }.cast(), acquired.cast()).cast();
    if !old.is_null() {
        unsafe { bpf_cgroup_release(old) };
        return -EEXIST;
    }

    0
}

#[inline(always)]
fn is_test_kfunc_task() -> bool {
    let cur_pid = (bpf_get_current_pid_tgid() >> 32) as i32;
    let same = unsafe { pid } == cur_pid;
    if same {
        sync_fetch_and_add_u32(core::ptr::addr_of_mut!(invocations) as *mut u32, 1);
    }
    same
}

#[link_section = "tp_btf/cgroup_mkdir"]
#[no_mangle]
extern "C" fn test_cgrp_acquire_release_argument(ctx: *const u64) -> i32 {
    if !is_test_kfunc_task() {
        return 0;
    }
    let cgrp = fentry_arg(ctx, 0) as *mut cgroup;

    let acquired = unsafe { bpf_cgroup_acquire(cgrp) };
    if acquired.is_null() {
        unsafe { err = 1 };
    } else {
        unsafe { bpf_cgroup_release(acquired) };
    }

    0
}

#[link_section = "tp_btf/cgroup_mkdir"]
#[no_mangle]
extern "C" fn test_cgrp_acquire_leave_in_map(ctx: *const u64) -> i32 {
    if !is_test_kfunc_task() {
        return 0;
    }
    let cgrp = fentry_arg(ctx, 0) as *mut cgroup;

    let status = cgrps_kfunc_map_insert(cgrp);
    if status != 0 {
        unsafe { err = 1 };
    }

    0
}

#[link_section = "tp_btf/cgroup_mkdir"]
#[no_mangle]
extern "C" fn test_cgrp_xchg_release(ctx: *const u64) -> i32 {
    if !is_test_kfunc_task() {
        return 0;
    }
    let cgrp = fentry_arg(ctx, 0) as *mut cgroup;

    let status = cgrps_kfunc_map_insert(cgrp);
    if status != 0 {
        unsafe { err = 1 };
        return 0;
    }

    let v = cgrps_kfunc_map_value_lookup(cgrp);
    if v.is_null() {
        unsafe { err = 2 };
        return 0;
    }

    let mut kptr = unsafe { (*v).cgrp };
    if kptr.is_null() {
        unsafe { err = 4 };
        return 0;
    }

    let cg = unsafe { bpf_cgroup_ancestor(kptr, 1) };
    if !cg.is_null() {
        // verifier only check
        unsafe { bpf_cgroup_release(cg) };
    }

    kptr = bpf_kptr_xchg(
        unsafe { core::ptr::addr_of_mut!((*v).cgrp) }.cast(),
        core::ptr::null_mut(),
    )
    .cast();
    if kptr.is_null() {
        unsafe { err = 3 };
        return 0;
    }

    unsafe { bpf_cgroup_release(kptr) };

    0
}

#[link_section = "tp_btf/cgroup_mkdir"]
#[no_mangle]
extern "C" fn test_cgrp_get_release(ctx: *const u64) -> i32 {
    if !is_test_kfunc_task() {
        return 0;
    }
    let cgrp = fentry_arg(ctx, 0) as *mut cgroup;

    let status = cgrps_kfunc_map_insert(cgrp);
    if status != 0 {
        unsafe { err = 1 };
        return 0;
    }

    let v = cgrps_kfunc_map_value_lookup(cgrp);
    if v.is_null() {
        unsafe { err = 2 };
        return 0;
    }

    unsafe {
        bpf_rcu_read_lock();
        let kptr = (*v).cgrp;
        if kptr.is_null() {
            err = 3;
        }
        bpf_rcu_read_unlock();
    }

    0
}

#[link_section = "tp_btf/cgroup_mkdir"]
#[no_mangle]
extern "C" fn test_cgrp_get_ancestors(ctx: *const u64) -> i32 {
    if !is_test_kfunc_task() {
        return 0;
    }
    let cgrp = fentry_arg(ctx, 0) as *mut cgroup;

    let level = cgrp_level(cgrp);

    let self_cg = unsafe { bpf_cgroup_ancestor(cgrp, level) };
    if self_cg.is_null() {
        unsafe { err = 1 };
        return 0;
    }
    if cgrp_self_id(self_cg) != cgrp_self_id(cgrp) {
        unsafe { bpf_cgroup_release(self_cg) };
        unsafe { err = 2 };
        return 0;
    }
    unsafe { bpf_cgroup_release(self_cg) };

    let ancestor1 = unsafe { bpf_cgroup_ancestor(cgrp, level - 1) };
    if ancestor1.is_null() {
        unsafe { err = 3 };
        return 0;
    }
    unsafe { bpf_cgroup_release(ancestor1) };

    let invalid = unsafe { bpf_cgroup_ancestor(cgrp, 10000) };
    if !invalid.is_null() {
        unsafe { bpf_cgroup_release(invalid) };
        unsafe { err = 4 };
        return 0;
    }

    let invalid = unsafe { bpf_cgroup_ancestor(cgrp, -1) };
    if !invalid.is_null() {
        unsafe { bpf_cgroup_release(invalid) };
        unsafe { err = 5 };
        return 0;
    }

    0
}

#[link_section = "tp_btf/cgroup_mkdir"]
#[no_mangle]
extern "C" fn test_cgrp_from_id(ctx: *const u64) -> i32 {
    if !is_test_kfunc_task() {
        return 0;
    }
    let cgrp = fentry_arg(ctx, 0) as *mut cgroup;

    let level = cgrp_level(cgrp);

    // @cgrp's ID is not visible yet, let's test with the parent.
    let parent = unsafe { bpf_cgroup_ancestor(cgrp, level - 1) };
    if parent.is_null() {
        unsafe { err = 1 };
        return 0;
    }

    let kn = cgrp_kn(parent);
    let parent_cgid = kn_id(kn);
    unsafe { bpf_cgroup_release(parent) };

    let res = unsafe { bpf_cgroup_from_id(parent_cgid) };
    if res.is_null() {
        unsafe { err = 2 };
        return 0;
    }
    unsafe { bpf_cgroup_release(res) };

    if res != parent {
        unsafe { err = 3 };
        return 0;
    }

    let res = unsafe { bpf_cgroup_from_id(u64::MAX) };
    if !res.is_null() {
        unsafe { bpf_cgroup_release(res) };
        unsafe { err = 4 };
        return 0;
    }

    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_cgrp_from_id_ns(_ctx: *const core::ffi::c_void) -> i32 {
    let cg = unsafe { bpf_cgroup_from_id(1) };
    if cg.is_null() {
        return 42;
    }
    unsafe { bpf_cgroup_release(cg) };
    0
}

btf_type_tags! {
    __cgrps_kfunc_map_value.cgrp: kptr;
}

bpf_object!("GPL");
