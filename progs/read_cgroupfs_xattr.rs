#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/read_cgroupfs_xattr.c
// (bpf-rs-core idiom).

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_dynptr_from_mem, bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_strncmp,
};
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
    fn bpf_iter_css_new(
        it: *mut bpf_iter_css,
        start: *mut cgroup_subsys_state,
        flags: u32,
    ) -> i32;
    fn bpf_iter_css_next(it: *mut bpf_iter_css) -> *mut cgroup_subsys_state;
    fn bpf_iter_css_destroy(it: *mut bpf_iter_css);
    fn bpf_rcu_read_lock();
    fn bpf_rcu_read_unlock();
    fn bpf_cgroup_from_id(cgid: u64) -> *mut cgroup;
    fn bpf_cgroup_release(cgrp: *mut cgroup);
    fn bpf_cgroup_read_xattr(cgroup: *mut cgroup, name: *const u8, value_p: *mut c_void) -> i64;
}

const EXPECTED_VALUE_A: &[u8] = b"bpf_selftest_value_a\0";
const EXPECTED_VALUE_B: &[u8] = b"bpf_selftest_value_b\0";
const XATTR_NAME: &[u8] = b"user.bpf_test\0";

#[no_mangle]
static mut target_pid: i32 = 0;

#[no_mangle]
static mut xattr_value: [u8; 64] = [0; 64];

#[no_mangle]
static mut found_value_a: bool = false;
#[no_mangle]
static mut found_value_b: bool = false;

#[link_section = "lsm.s/file_open"]
#[no_mangle]
extern "C" fn test_file_open(_ctx: *const u64) -> i32 {
    let cgrp_id = bpf_get_current_cgroup_id();

    if (bpf_get_current_pid_tgid() >> 32) != unsafe { target_pid } as u64 {
        return 0;
    }

    unsafe { bpf_rcu_read_lock() };

    let cgrp = unsafe { bpf_cgroup_from_id(cgrp_id) };
    if cgrp.is_null() {
        unsafe { bpf_rcu_read_unlock() };
        return 0;
    }

    // `self` is the first (offset-0) member of `struct cgroup`, so a plain
    // pointer cast is `&cgrp->self` without needing a CO-RE field access.
    let css = cgrp as *mut cgroup_subsys_state;

    let mut value_ptr: [u64; 2] = [0; 2];
    bpf_dynptr_from_mem(
        core::ptr::addr_of_mut!(xattr_value) as *mut c_void,
        core::mem::size_of_val(unsafe { &xattr_value }) as u64,
        0,
        core::ptr::addr_of_mut!(value_ptr) as *mut c_void,
    );

    let mut it = bpf_iter_css { __opaque: [0; 3] };
    unsafe { bpf_iter_css_new(&mut it, css, BPF_CGROUP_ITER_ANCESTORS_UP) };
    loop {
        let tmp = unsafe { bpf_iter_css_next(&mut it) };
        if tmp.is_null() {
            break;
        }

        let tmp_cgroup = unsafe { *(&*tmp).cgroup().as_ptr() };
        let ret = unsafe {
            bpf_cgroup_read_xattr(
                tmp_cgroup,
                XATTR_NAME.as_ptr(),
                core::ptr::addr_of_mut!(value_ptr) as *mut c_void,
            )
        };
        if ret < 0 {
            continue;
        }

        if ret == EXPECTED_VALUE_A.len() as i64
            && bpf_strncmp(
                core::ptr::addr_of!(xattr_value) as *const c_void,
                EXPECTED_VALUE_A.len() as u32,
                EXPECTED_VALUE_A.as_ptr() as *const c_void,
            ) == 0
        {
            unsafe { found_value_a = true };
        }
        if ret == EXPECTED_VALUE_B.len() as i64
            && bpf_strncmp(
                core::ptr::addr_of!(xattr_value) as *const c_void,
                EXPECTED_VALUE_B.len() as u32,
                EXPECTED_VALUE_B.as_ptr() as *const c_void,
            ) == 0
        {
            unsafe { found_value_b = true };
        }
    }
    unsafe { bpf_iter_css_destroy(&mut it) };

    unsafe { bpf_rcu_read_unlock() };
    unsafe { bpf_cgroup_release(cgrp) };

    0
}

bpf_object!("GPL");
