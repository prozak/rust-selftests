// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/cgroup_read_xattr.c
// (bpf-rs-core idiom): bpf_cgroup_read_xattr on a trusted cgroup pointer
// from sleepable and non-sleepable LSM hooks and a cgroup/sendmsg4 program,
// through bpf_cgroup_from_id, the css ancestors iterator (which a sleepable
// program must wrap in bpf_rcu_read_lock) and bpf_cgroup_ancestor. Same
// `&cgrp->self` offset-0 cast and css->cgroup CO-RE read as
// read_cgroupfs_xattr.rs. The test_loader decl tags are declared with
// test_tags! and appended to the object's BTF by scripts/btf_test_tags.py.

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_dynptr_from_mem, bpf_get_current_cgroup_id};
use bpf_rs_core::test_tags;
use btf_macros::btf;

const BPF_CGROUP_ITER_ANCESTORS_UP: u32 = 4;

#[btf]
struct cgroup {}

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
    fn bpf_iter_css_new(it: *mut bpf_iter_css, start: *mut cgroup_subsys_state, flags: u32) -> i32;
    fn bpf_iter_css_next(it: *mut bpf_iter_css) -> *mut cgroup_subsys_state;
    fn bpf_iter_css_destroy(it: *mut bpf_iter_css);
    fn bpf_rcu_read_lock();
    fn bpf_rcu_read_unlock();
    fn bpf_cgroup_from_id(cgid: u64) -> *mut cgroup;
    fn bpf_cgroup_ancestor(cgrp: *mut cgroup, level: i32) -> *mut cgroup;
    fn bpf_cgroup_release(cgrp: *mut cgroup);
    fn bpf_cgroup_read_xattr(cgroup: *mut cgroup, name: *const u8, value_p: *mut c_void) -> i64;
}

test_tags! {
    trusted_cgroup_ptr_sleepable: __success;
    trusted_cgroup_ptr_non_sleepable: __success;
    use_css_iter_non_sleepable: __success;
    use_css_iter_sleepable_missing_rcu_lock: __failure, __msg("kernel func bpf_iter_css_new requires RCU critical section protection");
    use_css_iter_sleepable_with_rcu_lock: __success;
    use_bpf_cgroup_ancestor: __success;
    cgroup_skb: __success;
}

// C: char value[16];
#[no_mangle]
static mut value: [u8; 16] = [0; 16];

const XATTR_NAME: &[u8] = b"user.bpf_test\0";

// C: static __always_inline void read_xattr(struct cgroup *cgroup)
#[inline(always)]
fn read_xattr(cgrp: *mut cgroup) {
    let mut value_ptr: [u64; 2] = [0; 2];

    bpf_dynptr_from_mem(
        core::ptr::addr_of_mut!(value) as *mut c_void,
        core::mem::size_of_val(unsafe { &value }) as u64,
        0,
        core::ptr::addr_of_mut!(value_ptr) as *mut c_void,
    );
    unsafe {
        bpf_cgroup_read_xattr(
            cgrp,
            XATTR_NAME.as_ptr(),
            core::ptr::addr_of_mut!(value_ptr) as *mut c_void,
        )
    };
}

// C: bpf_for_each(css, css, &cgrp->self, BPF_CGROUP_ITER_ANCESTORS_UP)
//        read_xattr(css->cgroup);
#[inline(always)]
fn read_xattr_ancestors(cgrp: *mut cgroup) {
    // `self` is the first (offset-0) member of `struct cgroup`, so a plain
    // pointer cast is `&cgrp->self` without needing a CO-RE field access.
    let start = cgrp as *mut cgroup_subsys_state;
    let mut it = bpf_iter_css { __opaque: [0; 3] };

    unsafe { bpf_iter_css_new(&mut it, start, BPF_CGROUP_ITER_ANCESTORS_UP) };
    loop {
        let css = unsafe { bpf_iter_css_next(&mut it) };
        if css.is_null() {
            break;
        }
        let css_cgroup = unsafe { *(&*css).cgroup().as_ptr() };
        read_xattr(css_cgroup);
    }
    unsafe { bpf_iter_css_destroy(&mut it) };
}

#[link_section = "lsm.s/socket_connect"]
#[no_mangle]
extern "C" fn trusted_cgroup_ptr_sleepable(_ctx: *const u64) -> i32 {
    let cgrp_id = bpf_get_current_cgroup_id();

    let cgrp = unsafe { bpf_cgroup_from_id(cgrp_id) };
    if cgrp.is_null() {
        return 0;
    }

    read_xattr(cgrp);
    unsafe { bpf_cgroup_release(cgrp) };
    0
}

#[link_section = "lsm/socket_connect"]
#[no_mangle]
extern "C" fn trusted_cgroup_ptr_non_sleepable(_ctx: *const u64) -> i32 {
    let cgrp_id = bpf_get_current_cgroup_id();

    let cgrp = unsafe { bpf_cgroup_from_id(cgrp_id) };
    if cgrp.is_null() {
        return 0;
    }

    read_xattr(cgrp);
    unsafe { bpf_cgroup_release(cgrp) };
    0
}

#[link_section = "lsm/socket_connect"]
#[no_mangle]
extern "C" fn use_css_iter_non_sleepable(_ctx: *const u64) -> i32 {
    let cgrp_id = bpf_get_current_cgroup_id();

    let cgrp = unsafe { bpf_cgroup_from_id(cgrp_id) };
    if cgrp.is_null() {
        return 0;
    }

    read_xattr_ancestors(cgrp);

    unsafe { bpf_cgroup_release(cgrp) };
    0
}

#[link_section = "lsm.s/socket_connect"]
#[no_mangle]
extern "C" fn use_css_iter_sleepable_missing_rcu_lock(_ctx: *const u64) -> i32 {
    let cgrp_id = bpf_get_current_cgroup_id();

    let cgrp = unsafe { bpf_cgroup_from_id(cgrp_id) };
    if cgrp.is_null() {
        return 0;
    }

    read_xattr_ancestors(cgrp);

    unsafe { bpf_cgroup_release(cgrp) };
    0
}

#[link_section = "lsm.s/socket_connect"]
#[no_mangle]
extern "C" fn use_css_iter_sleepable_with_rcu_lock(_ctx: *const u64) -> i32 {
    let cgrp_id = bpf_get_current_cgroup_id();

    unsafe { bpf_rcu_read_lock() };
    let cgrp = unsafe { bpf_cgroup_from_id(cgrp_id) };
    if !cgrp.is_null() {
        read_xattr_ancestors(cgrp);

        unsafe { bpf_cgroup_release(cgrp) };
    }
    unsafe { bpf_rcu_read_unlock() };
    0
}

#[link_section = "lsm/socket_connect"]
#[no_mangle]
extern "C" fn use_bpf_cgroup_ancestor(_ctx: *const u64) -> i32 {
    let cgrp_id = bpf_get_current_cgroup_id();

    let cgrp = unsafe { bpf_cgroup_from_id(cgrp_id) };
    if cgrp.is_null() {
        return 0;
    }

    let ancestor = unsafe { bpf_cgroup_ancestor(cgrp, 1) };
    if !ancestor.is_null() {
        read_xattr(cgrp);
        unsafe { bpf_cgroup_release(ancestor) };
    }
    unsafe { bpf_cgroup_release(cgrp) };
    0
}

#[link_section = "cgroup/sendmsg4"]
#[no_mangle]
extern "C" fn cgroup_skb(_ctx: *const u64) -> i32 {
    let cgrp_id = bpf_get_current_cgroup_id();

    let cgrp = unsafe { bpf_cgroup_from_id(cgrp_id) };
    if cgrp.is_null() {
        return 0;
    }

    let ancestor = unsafe { bpf_cgroup_ancestor(cgrp, 1) };
    if !ancestor.is_null() {
        read_xattr(cgrp);
        unsafe { bpf_cgroup_release(ancestor) };
    }
    unsafe { bpf_cgroup_release(cgrp) };
    0
}

bpf_object!("GPL");
