// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/lsm_inode_init_xattr_value.c
// (bpf-rs-core idiom). prog_tests/lsm_inode_init_xattr.c's value_shapes
// subtest sets the three `const volatile` knobs in .rodata before each
// load: the value length, the dynptr flags handed to bpf_dynptr_from_mem
// and the hook's return value. The dynptr local stays uninitialized, as
// in C; all byte storage is C `char` (BTF_C_CHAR).

// BTF_C_CHAR: u8

use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ptr::{addr_of, read_volatile};

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_dynptr_from_mem, bpf_get_current_pid_tgid};

const EOPNOTSUPP: i32 = 95;
const VALUE_MAX: u32 = 64 * 1024 + 1;

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
static xattr_value: [u8; 19] = *b"security.bpf.value\0";

/* Shape of the value handed to the kfunc, and what the hook returns after. */
#[link_section = ".rodata"]
#[no_mangle]
static value_len: u32 = 0;
#[link_section = ".rodata"]
#[no_mangle]
static dynptr_flags: u64 = 0;
#[link_section = ".rodata"]
#[no_mangle]
static hook_retval: i32 = 0;

#[no_mangle]
static mut value_src: [u8; VALUE_MAX as usize] = [0; VALUE_MAX as usize];

#[no_mangle]
static mut monitored_pid: u32 = 0;
#[no_mangle]
static mut hook_ran: u32 = 0;
#[no_mangle]
static mut claim_err: i32 = 1;

// BPF_PROG(claim_value, inode, dir, qstr, xattrs, xattr_count)
#[link_section = "lsm/inode_init_security"]
#[no_mangle]
extern "C" fn claim_value(ctx: *mut u64) -> i32 {
    let xattrs = unsafe { *ctx.add(3) } as *mut c_void;
    let xattr_count = unsafe { *ctx.add(4) } as *mut c_void;
    let mut value = MaybeUninit::<bpf_dynptr>::uninit();
    let len = unsafe { read_volatile(addr_of!(value_len)) };

    if (bpf_get_current_pid_tgid() >> 32) as u32 != unsafe { monitored_pid } {
        return 0;
    }
    if len > VALUE_MAX {
        return 0;
    }

    unsafe { hook_ran = 1 };
    if xattrs.is_null() {
        unsafe { claim_err = -EOPNOTSUPP };
        return 0;
    }
    bpf_dynptr_from_mem(
        core::ptr::addr_of_mut!(value_src) as *mut c_void,
        len as u64,
        unsafe { read_volatile(addr_of!(dynptr_flags)) },
        value.as_mut_ptr() as *mut c_void,
    );
    unsafe {
        claim_err = bpf_inode_init_xattr(
            xattrs,
            xattr_count,
            core::ptr::addr_of!(xattr_value) as *const c_void,
            value.as_ptr(),
        );
    }
    unsafe { read_volatile(addr_of!(hook_retval)) }
}

bpf_object!("GPL");
