// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_get_xattr.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_dynptr_from_mem, bpf_get_current_pid_tgid, bpf_strncmp};
use bpf_rs_core::progs::fentry_arg as arg;
use core::ffi::c_void;

const EXPECTED_LEN: i32 = 6; // sizeof("hello") including NUL

#[repr(C, align(8))]
struct bpf_dynptr {
    opaque: [u64; 2],
}

#[no_mangle]
static mut monitored_pid: u32 = 0;
#[no_mangle]
static mut found_xattr_from_file: u32 = 0;
#[no_mangle]
static mut found_xattr_from_dentry: u32 = 0;

#[link_section = ".rodata"]
#[no_mangle]
static expected_value: [u8; 6] = *b"hello\0";

#[no_mangle]
static mut value1: [u8; 32] = [0; 32];
#[no_mangle]
static mut value2: [u8; 32] = [0; 32];

// xattr_names[] in the C source; matches prog_tests/fs_kfuncs.c's
// test_get_xattr() caller comment. Each candidate must live in .rodata:
// bpf_get_{file,dentry}_xattr's `name` arg is checked by the verifier as a
// constant, read-only, NUL-terminated string (same requirement bpf_strncmp
// has on its args, see strncmp_test.rs).
#[link_section = ".rodata"]
#[no_mangle]
static xattr_name_0: [u8; 12] = *b"user.kfuncs\0";
#[link_section = ".rodata"]
#[no_mangle]
static xattr_name_1: [u8; 17] = *b"security.bpf.xxx\0";
#[link_section = ".rodata"]
#[no_mangle]
static xattr_name_2: [u8; 13] = *b"security.bpf\0";
#[link_section = ".rodata"]
#[no_mangle]
static xattr_name_3: [u8; 17] = *b"security.selinux\0";

extern "C" {
    fn bpf_get_file_xattr(file: *mut c_void, name: *const u8, value_ptr: *mut c_void) -> i32;
    fn bpf_get_dentry_xattr(dentry: *mut c_void, name: *const u8, value_ptr: *mut c_void) -> i32;
}

#[link_section = "lsm.s/file_open"]
#[no_mangle]
extern "C" fn test_file_open(ctx: *const u64) -> i32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if pid != unsafe { monitored_pid } {
        return 0;
    }

    let file = arg(ctx, 0) as *mut c_void;
    let mut value_ptr = bpf_dynptr { opaque: [0; 2] };
    unsafe {
        bpf_dynptr_from_mem(
            core::ptr::addr_of_mut!(value1) as *mut c_void,
            32,
            0,
            &mut value_ptr as *mut bpf_dynptr as *mut c_void,
        );
    }

    let vp = &mut value_ptr as *mut bpf_dynptr as *mut c_void;
    let mut ret = unsafe { bpf_get_file_xattr(file, xattr_name_0.as_ptr(), vp) };
    if ret != EXPECTED_LEN {
        ret = unsafe { bpf_get_file_xattr(file, xattr_name_1.as_ptr(), vp) };
    }
    if ret != EXPECTED_LEN {
        ret = unsafe { bpf_get_file_xattr(file, xattr_name_2.as_ptr(), vp) };
    }
    if ret != EXPECTED_LEN {
        ret = unsafe { bpf_get_file_xattr(file, xattr_name_3.as_ptr(), vp) };
    }

    if ret != EXPECTED_LEN {
        return 0;
    }
    let cmp = bpf_strncmp(
        unsafe { core::ptr::addr_of!(value1) as *const c_void },
        ret as u32,
        unsafe { core::ptr::addr_of!(expected_value) as *const c_void },
    );
    if cmp != 0 {
        return 0;
    }
    unsafe { found_xattr_from_file = 1 };
    0
}

#[link_section = "lsm.s/inode_getxattr"]
#[no_mangle]
extern "C" fn test_inode_getxattr(ctx: *const u64) -> i32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if pid != unsafe { monitored_pid } {
        return 0;
    }

    let dentry = arg(ctx, 0) as *mut c_void;
    let mut value_ptr = bpf_dynptr { opaque: [0; 2] };
    unsafe {
        bpf_dynptr_from_mem(
            core::ptr::addr_of_mut!(value2) as *mut c_void,
            32,
            0,
            &mut value_ptr as *mut bpf_dynptr as *mut c_void,
        );
    }

    let vp = &mut value_ptr as *mut bpf_dynptr as *mut c_void;
    let mut ret = unsafe { bpf_get_dentry_xattr(dentry, xattr_name_0.as_ptr(), vp) };
    if ret != EXPECTED_LEN {
        ret = unsafe { bpf_get_dentry_xattr(dentry, xattr_name_1.as_ptr(), vp) };
    }
    if ret != EXPECTED_LEN {
        ret = unsafe { bpf_get_dentry_xattr(dentry, xattr_name_2.as_ptr(), vp) };
    }
    if ret != EXPECTED_LEN {
        ret = unsafe { bpf_get_dentry_xattr(dentry, xattr_name_3.as_ptr(), vp) };
    }

    if ret != EXPECTED_LEN {
        return 0;
    }
    let cmp = bpf_strncmp(
        unsafe { core::ptr::addr_of!(value2) as *const c_void },
        ret as u32,
        unsafe { core::ptr::addr_of!(expected_value) as *const c_void },
    );
    if cmp != 0 {
        return 0;
    }
    unsafe { found_xattr_from_dentry = 1 };

    // return non-zero to fail getxattr from user space
    -22
}

bpf_object!("GPL");
