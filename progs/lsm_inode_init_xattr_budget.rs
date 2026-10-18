// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/lsm_inode_init_xattr_budget.c
// (bpf-rs-core idiom). prog_tests/lsm_inode_init_xattr.c's shared_budget
// subtest loads three copies, each with its own xattr_name written into
// .rodata before load (snprintf into the skeleton's `char xattr_name[32]`,
// hence BTF_C_CHAR), and expects two claims to succeed and one to be
// refused with -ENOSPC. The dynptr local stays uninitialized, as in C.

// BTF_C_CHAR: u8

use core::ffi::c_void;
use core::mem::MaybeUninit;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_dynptr_from_mem, bpf_get_current_pid_tgid};

const EOPNOTSUPP: i32 = 95;

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

#[link_section = ".rodata"]
#[no_mangle]
static xattr_name: [u8; 32] = {
    let mut n = [0u8; 32];
    let s = b"security.bpf.slot";
    let mut i = 0;
    while i < s.len() {
        n[i] = s[i];
        i += 1;
    }
    n
};

#[no_mangle]
static mut monitored_pid: u32 = 0;
#[no_mangle]
static mut hook_ran: u32 = 0;
#[no_mangle]
static mut claim_err: i32 = 1;

#[no_mangle]
static mut claim_value: [u8; 2] = *b"v\0";

// BPF_PROG(claim_one, inode, dir, qstr, xattrs, xattr_count)
#[link_section = "lsm/inode_init_security"]
#[no_mangle]
extern "C" fn claim_one(ctx: *mut u64) -> i32 {
    let xattrs = unsafe { *ctx.add(3) } as *mut c_void;
    let xattr_count = unsafe { *ctx.add(4) } as *mut c_void;
    let mut value = MaybeUninit::<bpf_dynptr>::uninit();

    if (bpf_get_current_pid_tgid() >> 32) as u32 != unsafe { monitored_pid } {
        return 0;
    }

    unsafe { hook_ran = 1 };
    if xattrs.is_null() {
        unsafe { claim_err = -EOPNOTSUPP };
        return 0;
    }
    bpf_dynptr_from_mem(
        core::ptr::addr_of_mut!(claim_value) as *mut c_void,
        2,
        0,
        value.as_mut_ptr() as *mut c_void,
    );
    unsafe {
        claim_err = bpf_inode_init_xattr(
            xattrs,
            xattr_count,
            core::ptr::addr_of!(xattr_name) as *const c_void,
            value.as_ptr(),
        );
    }
    0
}

bpf_object!("GPL");
