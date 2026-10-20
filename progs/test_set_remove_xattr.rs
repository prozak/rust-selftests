// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_set_remove_xattr.c
// (bpf-rs-core idiom). prog_tests/fs_kfuncs.c (test_set_remove_xattr)
// sets `monitored_pid`, then gets/sets the security.bpf.foo xattr of a
// file: the two sleepable LSM programs, on that name only, read
// security.bpf.bar through a dynptr and either set it (and try the
// forbidden security.selinux) or remove it, recording the outcomes in
// the bool globals. NO-ORACLE here: fs_kfuncs is in scripts/known-bad-tests
// (the guest's root is the host filesystem over virtiofs, which has no
// security xattrs, so the pristine C object fails the same way as
// test_fsverity/test_get_xattr). The xattr names are .rodata in the C's
// order (`// C_LAYOUT:`, `xattr_selinux` is the C's static); `name_buf`
// and the bools are .bss in the C's order. The strings are C `char`
// arrays.
// BTF_C_CHAR: u8
// C_LAYOUT: .rodata .bss

#![allow(non_upper_case_globals)]

use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ptr::{addr_of, addr_of_mut};

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_dynptr_from_mem, bpf_get_current_pid_tgid, bpf_probe_read_kernel_raw, bpf_strncmp,
};
use bpf_rs_core::progs::fentry_arg as arg;

// UAPI struct bpf_dynptr (linux/bpf.h): opaque, aligned(8).
#[repr(C, align(8))]
struct bpf_dynptr {
    __opaque: [u64; 2],
}

extern "C" {
    fn bpf_get_dentry_xattr(dentry: *mut c_void, name__str: *const u8, value_p: *mut bpf_dynptr) -> i32;
    fn bpf_set_dentry_xattr(dentry: *mut c_void, name__str: *const u8, value_p: *const bpf_dynptr, flags: i32) -> i32;
    fn bpf_remove_dentry_xattr(dentry: *mut c_void, name__str: *const u8) -> i32;
}

#[no_mangle]
static mut monitored_pid: u32 = 0;

#[link_section = ".rodata"]
#[no_mangle]
static xattr_foo: [u8; 17] = *b"security.bpf.foo\0";
#[link_section = ".rodata"]
#[no_mangle]
static xattr_bar: [u8; 17] = *b"security.bpf.bar\0";
#[link_section = ".rodata"]
#[export_name = "xattr_selinux"]
static xattr_selinux: [u8; 17] = *b"security.selinux\0";
#[no_mangle]
static mut value_bar: [u8; 6] = *b"world\0";
#[no_mangle]
static mut read_value: [u8; 32] = [0; 32];

#[no_mangle]
static mut set_security_bpf_bar_success: bool = false;
#[no_mangle]
static mut remove_security_bpf_bar_success: bool = false;
#[no_mangle]
static mut set_security_selinux_fail: bool = false;
#[no_mangle]
static mut remove_security_selinux_fail: bool = false;

#[no_mangle]
static mut name_buf: [u8; 32] = [0; 32];

#[inline(always)]
fn name_match_foo(name: *const c_void) -> bool {
    unsafe {
        bpf_probe_read_kernel_raw(addr_of_mut!(name_buf) as *mut c_void, 32, name);
        bpf_strncmp(addr_of!(name_buf) as *const c_void, 17, addr_of!(xattr_foo) as *const c_void) == 0
    }
}

/* Test bpf_set_dentry_xattr and bpf_remove_dentry_xattr */
#[link_section = "lsm.s/inode_getxattr"]
#[no_mangle]
extern "C" fn test_inode_getxattr(ctx: *const u64) -> i32 {
    let dentry = arg(ctx, 0) as *mut c_void;
    let name = arg(ctx, 1) as *const c_void;
    let mut value_ptr = MaybeUninit::<bpf_dynptr>::uninit();

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if pid != unsafe { monitored_pid } {
        return 0;
    }

    /* Only do the following for security.bpf.foo */
    if !name_match_foo(name) {
        return 0;
    }

    unsafe {
        bpf_dynptr_from_mem(addr_of_mut!(read_value) as *mut c_void, 32, 0, value_ptr.as_mut_ptr() as *mut c_void);

        /* read security.bpf.bar */
        let ret = bpf_get_dentry_xattr(dentry, xattr_bar.as_ptr(), value_ptr.as_mut_ptr());
        if ret < 0 {
            /* If security.bpf.bar doesn't exist, set it */
            bpf_dynptr_from_mem(addr_of_mut!(value_bar) as *mut c_void, 6, 0, value_ptr.as_mut_ptr() as *mut c_void);
            let ret = bpf_set_dentry_xattr(dentry, xattr_bar.as_ptr(), value_ptr.as_ptr(), 0);
            if ret == 0 {
                set_security_bpf_bar_success = true;
            }
            let ret = bpf_set_dentry_xattr(dentry, xattr_selinux.as_ptr(), value_ptr.as_ptr(), 0);
            if ret != 0 {
                set_security_selinux_fail = true;
            }
        } else {
            /* If security.bpf.bar exists, remove it */
            let ret = bpf_remove_dentry_xattr(dentry, xattr_bar.as_ptr());
            if ret == 0 {
                remove_security_bpf_bar_success = true;
            }
            let ret = bpf_remove_dentry_xattr(dentry, xattr_selinux.as_ptr());
            if ret != 0 {
                remove_security_selinux_fail = true;
            }
        }
    }
    0
}

#[no_mangle]
static mut locked_set_security_bpf_bar_success: bool = false;
#[no_mangle]
static mut locked_remove_security_bpf_bar_success: bool = false;
#[no_mangle]
static mut locked_set_security_selinux_fail: bool = false;
#[no_mangle]
static mut locked_remove_security_selinux_fail: bool = false;

/* Test bpf_set_dentry_xattr_locked and bpf_remove_dentry_xattr_locked.
 * It not necessary to differentiate the _locked version and the
 * not-_locked version in the BPF program. The verifier will fix them up
 * properly.
 */
#[link_section = "lsm.s/inode_setxattr"]
#[no_mangle]
extern "C" fn test_inode_setxattr(ctx: *const u64) -> i32 {
    let dentry = arg(ctx, 1) as *mut c_void;
    let name = arg(ctx, 2) as *const c_void;
    let mut value_ptr = MaybeUninit::<bpf_dynptr>::uninit();

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if pid != unsafe { monitored_pid } {
        return 0;
    }

    /* Only do the following for security.bpf.foo */
    if !name_match_foo(name) {
        return 0;
    }

    unsafe {
        bpf_dynptr_from_mem(addr_of_mut!(read_value) as *mut c_void, 32, 0, value_ptr.as_mut_ptr() as *mut c_void);

        /* read security.bpf.bar */
        let ret = bpf_get_dentry_xattr(dentry, xattr_bar.as_ptr(), value_ptr.as_mut_ptr());
        if ret < 0 {
            /* If security.bpf.bar doesn't exist, set it */
            bpf_dynptr_from_mem(addr_of_mut!(value_bar) as *mut c_void, 6, 0, value_ptr.as_mut_ptr() as *mut c_void);
            let ret = bpf_set_dentry_xattr(dentry, xattr_bar.as_ptr(), value_ptr.as_ptr(), 0);
            if ret == 0 {
                locked_set_security_bpf_bar_success = true;
            }
            let ret = bpf_set_dentry_xattr(dentry, xattr_selinux.as_ptr(), value_ptr.as_ptr(), 0);
            if ret != 0 {
                locked_set_security_selinux_fail = true;
            }
        } else {
            /* If security.bpf.bar exists, remove it */
            let ret = bpf_remove_dentry_xattr(dentry, xattr_bar.as_ptr());
            if ret == 0 {
                locked_remove_security_bpf_bar_success = true;
            }
            let ret = bpf_remove_dentry_xattr(dentry, xattr_selinux.as_ptr());
            if ret != 0 {
                locked_remove_security_selinux_fail = true;
            }
        }
    }
    0
}

bpf_object!("GPL");
