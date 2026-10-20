// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![allow(non_camel_case_types, non_upper_case_globals)]

// Direct translation of tools/testing/selftests/bpf/progs/cgrp_kfunc_failure.c
// (+ cgrp_kfunc_common.h), bpf-rs-core idiom.
//
// bpf_cgroup_acquire()/bpf_cgroup_release() misuse rejections
// (prog_tests/cgrp_kfunc.c: RUN_TESTS(cgrp_kfunc_failure)). The common
// header's map, kfunc externs and insert/lookup helpers are those of
// cgrp_kfunc_success.rs (`cgrp->self.id` through the offset-0
// cgroup_subsys_state cast; the map value's `cgrp` is __kptr via
// btf_type_tags!). BPF_PROG's arguments are fentry_arg(ctx, i); the
// "frame pointer" arguments are the address of the local `path` copy,
// as in the C. `__sink(acquired)` is helpers::sink.

use bpf_rs_core::helpers::{
    bpf_kptr_xchg, bpf_map_delete_elem, bpf_map_lookup_elem, bpf_map_update_elem,
    bpf_probe_read_kernel, sink,
};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::progs::fentry_arg;
use bpf_rs_core::{bpf_object, btf_type_tags, test_tags};
use btf_macros::btf;
use core::ptr::{addr_of_mut, null_mut};

#[btf]
struct cgroup_subsys_state {
    id: i32,
}

#[btf]
struct cgroup {
    old_dom_cgrp: *mut cgroup,
}

extern "C" {
    fn bpf_cgroup_acquire(p: *mut cgroup) -> *mut cgroup;
    fn bpf_cgroup_release(p: *mut cgroup);
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

btf_type_tags! {
    __cgrps_kfunc_map_value.cgrp: kptr;
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
fn cgrp_old_dom_cgrp(cgrp: *mut cgroup) -> *mut cgroup {
    *unsafe { &*cgrp }.old_dom_cgrp().get().unwrap()
}

#[inline(always)]
fn cgrps_kfunc_map_value_lookup(cgrp: *mut cgroup) -> *mut __cgrps_kfunc_map_value {
    let mut id: i32 = 0;
    if read_self_id(cgrp, &mut id) != 0 {
        return null_mut();
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

    let local = __cgrps_kfunc_map_value { cgrp: null_mut() };
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
        bpf_kptr_xchg(unsafe { addr_of_mut!((*v).cgrp) }.cast(), acquired.cast()).cast();
    if !old.is_null() {
        unsafe { bpf_cgroup_release(old) };
        return -EEXIST;
    }

    0
}

fn insert_lookup_cgrp(cgrp: *mut cgroup) -> *mut __cgrps_kfunc_map_value {
    let status = cgrps_kfunc_map_insert(cgrp);
    if status != 0 {
        return null_mut();
    }

    cgrps_kfunc_map_value_lookup(cgrp)
}

// Prototype for all of the program trace events below:
//
// TRACE_EVENT(cgroup_mkdir,
//         TP_PROTO(struct cgroup *cgrp, const char *path),
//         TP_ARGS(cgrp, path)

#[link_section = "tp_btf/cgroup_mkdir"]
#[no_mangle]
extern "C" fn cgrp_kfunc_acquire_untrusted(ctx: *const u64) -> i32 {
    let cgrp = fentry_arg(ctx, 0) as *mut cgroup;

    let v = insert_lookup_cgrp(cgrp);
    if v.is_null() {
        return 0;
    }

    unsafe {
        // Can't invoke bpf_cgroup_acquire() on an untrusted pointer.
        let acquired = bpf_cgroup_acquire((*v).cgrp);
        if !acquired.is_null() {
            bpf_cgroup_release(acquired);
        }
    }

    0
}

#[link_section = "tp_btf/cgroup_mkdir"]
#[no_mangle]
extern "C" fn cgrp_kfunc_acquire_no_null_check(ctx: *const u64) -> i32 {
    let cgrp = fentry_arg(ctx, 0) as *mut cgroup;

    unsafe {
        let acquired = bpf_cgroup_acquire(cgrp);
        // Can't invoke bpf_cgroup_release() without checking the return value
        // of bpf_cgroup_acquire().
        bpf_cgroup_release(acquired);
    }

    0
}

#[link_section = "tp_btf/cgroup_mkdir"]
#[no_mangle]
extern "C" fn cgrp_kfunc_acquire_fp(ctx: *const u64) -> i32 {
    let mut path = fentry_arg(ctx, 1);
    let mut stack_cgrp = &mut path as *mut u64 as *mut cgroup;

    unsafe {
        // Can't invoke bpf_cgroup_acquire() on a random frame pointer.
        let acquired = bpf_cgroup_acquire(&mut stack_cgrp as *mut *mut cgroup as *mut cgroup);
        if !acquired.is_null() {
            bpf_cgroup_release(acquired);
        }
    }

    0
}

#[link_section = "kretprobe/cgroup_destroy_locked"]
#[no_mangle]
extern "C" fn cgrp_kfunc_acquire_unsafe_kretprobe(ctx: *const u64) -> i32 {
    let cgrp = fentry_arg(ctx, 0) as *mut cgroup;

    unsafe {
        // Can't acquire an untrusted struct cgroup * pointer.
        let acquired = bpf_cgroup_acquire(cgrp);
        if !acquired.is_null() {
            bpf_cgroup_release(acquired);
        }
    }

    0
}

#[link_section = "tp_btf/cgroup_mkdir"]
#[no_mangle]
extern "C" fn cgrp_kfunc_acquire_trusted_walked(ctx: *const u64) -> i32 {
    let cgrp = fentry_arg(ctx, 0) as *mut cgroup;

    unsafe {
        // Can't invoke bpf_cgroup_acquire() on a pointer obtained from walking a trusted cgroup.
        let acquired = bpf_cgroup_acquire(cgrp_old_dom_cgrp(cgrp));
        if !acquired.is_null() {
            bpf_cgroup_release(acquired);
        }
    }

    0
}

#[link_section = "tp_btf/cgroup_mkdir"]
#[no_mangle]
extern "C" fn cgrp_kfunc_acquire_null(_ctx: *const u64) -> i32 {
    unsafe {
        // Can't invoke bpf_cgroup_acquire() on a NULL pointer.
        let acquired = bpf_cgroup_acquire(null_mut());
        if !acquired.is_null() {
            bpf_cgroup_release(acquired);
        }
    }

    0
}

#[link_section = "tp_btf/cgroup_mkdir"]
#[no_mangle]
extern "C" fn cgrp_kfunc_acquire_unreleased(ctx: *const u64) -> i32 {
    let cgrp = fentry_arg(ctx, 0) as *mut cgroup;

    let mut acquired = unsafe { bpf_cgroup_acquire(cgrp) };

    // Acquired cgroup is never released.
    sink(&mut acquired);

    0
}

#[link_section = "tp_btf/cgroup_mkdir"]
#[no_mangle]
extern "C" fn cgrp_kfunc_xchg_unreleased(ctx: *const u64) -> i32 {
    let cgrp = fentry_arg(ctx, 0) as *mut cgroup;

    let v = insert_lookup_cgrp(cgrp);
    if v.is_null() {
        return 0;
    }

    let kptr: *mut cgroup =
        bpf_kptr_xchg(unsafe { addr_of_mut!((*v).cgrp) }.cast(), null_mut()).cast();
    if kptr.is_null() {
        return 0;
    }

    // Kptr retrieved from map is never released.

    0
}

#[link_section = "tp_btf/cgroup_mkdir"]
#[no_mangle]
extern "C" fn cgrp_kfunc_rcu_get_release(ctx: *const u64) -> i32 {
    let cgrp = fentry_arg(ctx, 0) as *mut cgroup;

    let v = insert_lookup_cgrp(cgrp);
    if v.is_null() {
        return 0;
    }

    unsafe {
        bpf_rcu_read_lock();
        let kptr = (*v).cgrp;
        if !kptr.is_null() {
            // Can't release a cgroup kptr stored in a map.
            bpf_cgroup_release(kptr);
        }
        bpf_rcu_read_unlock();
    }

    0
}

#[link_section = "tp_btf/cgroup_mkdir"]
#[no_mangle]
extern "C" fn cgrp_kfunc_release_untrusted(ctx: *const u64) -> i32 {
    let cgrp = fentry_arg(ctx, 0) as *mut cgroup;

    let v = insert_lookup_cgrp(cgrp);
    if v.is_null() {
        return 0;
    }

    unsafe {
        // Can't invoke bpf_cgroup_release() on an untrusted pointer.
        bpf_cgroup_release((*v).cgrp);
    }

    0
}

#[link_section = "tp_btf/cgroup_mkdir"]
#[no_mangle]
extern "C" fn cgrp_kfunc_release_fp(ctx: *const u64) -> i32 {
    let mut path = fentry_arg(ctx, 1);
    let acquired = &mut path as *mut u64 as *mut cgroup;

    // Cannot release random frame pointer.
    unsafe { bpf_cgroup_release(acquired) };

    0
}

#[link_section = "tp_btf/cgroup_mkdir"]
#[no_mangle]
extern "C" fn cgrp_kfunc_release_null(ctx: *const u64) -> i32 {
    let cgrp = fentry_arg(ctx, 0) as *mut cgroup;
    let mut id: i32 = 0;

    let status = read_self_id(cgrp, &mut id);
    if status != 0 {
        return 0;
    }

    let local = __cgrps_kfunc_map_value { cgrp: null_mut() };
    let status = bpf_map_update_elem(&__cgrps_kfunc_map, &id, &local, BPF_NOEXIST);
    if status != 0 {
        return status as i32;
    }

    let v: *mut __cgrps_kfunc_map_value = bpf_map_lookup_elem(&__cgrps_kfunc_map, &id).cast();
    if v.is_null() {
        return -ENOENT as i32;
    }

    unsafe {
        let acquired = bpf_cgroup_acquire(cgrp);
        if acquired.is_null() {
            return -ENOENT as i32;
        }

        let old: *mut cgroup =
            bpf_kptr_xchg(addr_of_mut!((*v).cgrp).cast(), acquired.cast()).cast();

        // old cannot be passed to bpf_cgroup_release() without a NULL check.
        bpf_cgroup_release(old);
    }

    0
}

#[link_section = "tp_btf/cgroup_mkdir"]
#[no_mangle]
extern "C" fn cgrp_kfunc_release_unacquired(ctx: *const u64) -> i32 {
    let cgrp = fentry_arg(ctx, 0) as *mut cgroup;

    // Cannot release trusted cgroup pointer which was not acquired.
    unsafe { bpf_cgroup_release(cgrp) };

    0
}

test_tags! {
    cgrp_kfunc_acquire_untrusted: __failure, __msg("Possibly NULL pointer passed to trusted R1");
    cgrp_kfunc_acquire_no_null_check: __failure, __msg("Possibly NULL pointer passed to trusted R1");
    cgrp_kfunc_acquire_fp: __failure, __msg("R1 type=fp expected=ptr_, trusted_ptr_, rcu_ptr_");
    cgrp_kfunc_acquire_unsafe_kretprobe: __failure, __msg("calling kernel function bpf_cgroup_acquire is not allowed");
    cgrp_kfunc_acquire_trusted_walked: __failure, __msg("cgrp_kfunc_acquire_trusted_walked");
    cgrp_kfunc_acquire_null: __failure, __msg("Possibly NULL pointer passed to trusted R1");
    cgrp_kfunc_acquire_unreleased: __failure, __msg("Unreleased reference");
    cgrp_kfunc_xchg_unreleased: __failure, __msg("Unreleased reference");
    cgrp_kfunc_rcu_get_release: __failure, __msg("release function bpf_cgroup_release expects referenced PTR_TO_BTF_ID passed to R1");
    cgrp_kfunc_release_untrusted: __failure, __msg("Possibly NULL pointer passed to trusted R1");
    cgrp_kfunc_release_fp: __failure, __msg("R1 type=fp expected=ptr_, trusted_ptr_, rcu_ptr_");
    cgrp_kfunc_release_null: __failure, __msg("Possibly NULL pointer passed to trusted R1");
    cgrp_kfunc_release_unacquired: __failure, __msg("release function bpf_cgroup_release expects referenced PTR_TO_BTF_ID passed to R1");
}

bpf_object!("GPL");
