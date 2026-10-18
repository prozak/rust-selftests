// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/lsm_inode_init_xattr.c
// (bpf-rs-core idiom). prog_tests/lsm_inode_init_xattr.c creates files on
// a tmpfs (and a ramfs, whose inode_init_security passes no xattrs) under
// this hook and reads the security.bpf.* labels back; a parent directory's
// label in the inode storage is inherited. C's memcpy of "default" into
// zone_scratch is one eight-byte store here, and the copy from the parent's
// label is four u64 moves; the 32-byte memset is expanded inline by LLVM.
// All byte storage is C `char` (BTF_C_CHAR); the dynptr local stays
// uninitialized, as in C.

// BTF_C_CHAR: u8

use core::ffi::c_void;
use core::mem::MaybeUninit;

use bpf_rs_core::helpers::{bpf_dynptr_from_mem, bpf_get_current_pid_tgid, bpf_inode_storage_get};
use bpf_rs_core::{bpf_map, bpf_object};

const EOPNOTSUPP: i32 = 95;
const LABEL_MAX: usize = 32;
const BPF_MAP_TYPE_INODE_STORAGE: i32 = 28;

#[allow(non_camel_case_types)]
#[repr(C, align(8))]
struct bpf_dynptr {
    __opaque: [u64; 2],
}

extern "C" {
    fn bpf_inode_init_xattr(
        xattrs: *mut c_void,
        xattr_count: *mut c_void,
        name: *const c_void,
        value: *const bpf_dynptr,
    ) -> i32;
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct label {
    v: [u8; LABEL_MAX],
    len: u32,
}

bpf_map! {
    inode_zone {
        r#type: *const [i32; BPF_MAP_TYPE_INODE_STORAGE as usize],
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        key: *const i32,
        value: *const label,
    }
}

#[no_mangle]
static mut monitored_pid: u32 = 0;

#[link_section = ".rodata"]
#[no_mangle]
static xattr_zone: [u8; 18] = *b"security.bpf.zone\0";
#[link_section = ".rodata"]
#[no_mangle]
static xattr_origin: [u8; 20] = *b"security.bpf.origin\0";
#[link_section = ".rodata"]
#[no_mangle]
static xattr_overflow: [u8; 22] = *b"security.bpf.overflow\0";
/* One byte over XATTR_NAME_MAX once "security." is prepended again. */
#[link_section = ".rodata"]
#[no_mangle]
static xattr_toolong: [u8; 257] = *b"security.bpf.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\0";
#[link_section = ".rodata"]
#[no_mangle]
static xattr_selinux: [u8; 17] = *b"security.selinux\0";
#[link_section = ".rodata"]
#[no_mangle]
static xattr_user: [u8; 10] = *b"user.zone\0";

#[no_mangle]
static mut zone_scratch: [u8; LABEL_MAX] = [0; LABEL_MAX];
#[no_mangle]
static mut origin_value: [u8; 8] = *b"created\0";

#[no_mangle]
static mut hook_ran: u32 = 0;
#[no_mangle]
static mut zone_err: i32 = 1;
#[no_mangle]
static mut origin_err: i32 = 1;
#[no_mangle]
static mut overflow_err: i32 = 1;
#[no_mangle]
static mut toolong_err: i32 = 1;
#[no_mangle]
static mut selinux_err: i32 = 1;
#[no_mangle]
static mut user_err: i32 = 1;
#[no_mangle]
static mut inherited: u32 = 0;

// BPF_PROG(init_label, inode, dir, qstr, xattrs, xattr_count)
#[link_section = "lsm/inode_init_security"]
#[no_mangle]
extern "C" fn init_label(ctx: *mut u64) -> i32 {
    let dir = unsafe { *ctx.add(1) } as *mut c_void;
    let xattrs = unsafe { *ctx.add(3) } as *mut c_void;
    let xattr_count = unsafe { *ctx.add(4) } as *mut c_void;
    let mut value = MaybeUninit::<bpf_dynptr>::uninit();
    let mut len: i32 = 0;

    if (bpf_get_current_pid_tgid() >> 32) as u32 != unsafe { monitored_pid } {
        return 0;
    }

    unsafe { hook_ran = 1 };
    if xattrs.is_null() {
        /* The filesystem takes no xattrs at inode creation. */
        unsafe { zone_err = -EOPNOTSUPP };
        return 0;
    }
    let scratch = core::ptr::addr_of_mut!(zone_scratch) as *mut u8;
    unsafe { core::ptr::write_bytes(scratch, 0, LABEL_MAX) };

    if !dir.is_null() {
        let parent = bpf_inode_storage_get(&inode_zone, dir, core::ptr::null(), 0) as *mut label;
        if !parent.is_null() {
            let plen = unsafe { (*parent).len };
            if plen > 0 && plen <= LABEL_MAX as u32 {
                len = plen as i32;
                /* C's 32-byte memcpy: four u64 moves, as clang expands it
                 * (a copy_nonoverlapping here becomes a bpf_arena_memcpy
                 * kfunc call). */
                let src = unsafe { (*parent).v.as_ptr() } as *const u64;
                let dst = scratch as *mut u64;
                let mut i = 0;
                while i < LABEL_MAX / 8 {
                    unsafe { core::ptr::write_unaligned(dst.add(i), core::ptr::read_unaligned(src.add(i))) };
                    i += 1;
                }
                unsafe { inherited = 1 };
            }
        }
    }
    if len == 0 {
        unsafe { core::ptr::write(scratch as *mut u64, u64::from_le_bytes(*b"default\0")) };
        len = 8;
    }

    bpf_dynptr_from_mem(scratch as *mut c_void, len as u64, 0, value.as_mut_ptr() as *mut c_void);
    unsafe {
        /* Refused before a slot is claimed, so the budget below is intact. */
        toolong_err = bpf_inode_init_xattr(
            xattrs,
            xattr_count,
            core::ptr::addr_of!(xattr_toolong) as *const c_void,
            value.as_ptr(),
        );
        zone_err = bpf_inode_init_xattr(
            xattrs,
            xattr_count,
            core::ptr::addr_of!(xattr_zone) as *const c_void,
            value.as_ptr(),
        );
    }

    bpf_dynptr_from_mem(
        core::ptr::addr_of_mut!(origin_value) as *mut c_void,
        8,
        0,
        value.as_mut_ptr() as *mut c_void,
    );
    unsafe {
        origin_err = bpf_inode_init_xattr(
            xattrs,
            xattr_count,
            core::ptr::addr_of!(xattr_origin) as *const c_void,
            value.as_ptr(),
        );
        overflow_err = bpf_inode_init_xattr(
            xattrs,
            xattr_count,
            core::ptr::addr_of!(xattr_overflow) as *const c_void,
            value.as_ptr(),
        );
        selinux_err = bpf_inode_init_xattr(
            xattrs,
            xattr_count,
            core::ptr::addr_of!(xattr_selinux) as *const c_void,
            value.as_ptr(),
        );
        user_err = bpf_inode_init_xattr(
            xattrs,
            xattr_count,
            core::ptr::addr_of!(xattr_user) as *const c_void,
            value.as_ptr(),
        );
    }
    0
}

bpf_object!("GPL");
