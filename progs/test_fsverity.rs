// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_fsverity.c
// (bpf-next), bpf-rs-core idiom.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_dynptr_from_mem, bpf_get_current_pid_tgid};
use bpf_rs_core::progs::fentry_arg as arg;
use core::ffi::c_void;

const SHA256_DIGEST_SIZE: usize = 32;
const SIZEOF_STRUCT_FSVERITY_DIGEST: usize = 4;
const DIGEST_LEN: usize = SIZEOF_STRUCT_FSVERITY_DIGEST + SHA256_DIGEST_SIZE;

#[allow(non_camel_case_types)]
#[repr(C)]
struct file {
    _priv: [u8; 0],
}

extern "C" {
    fn bpf_get_fsverity_digest(file: *mut file, digest_ptr: *mut c_void) -> i32;
}

#[no_mangle]
static mut expected_digest: [u8; DIGEST_LEN] = [0; DIGEST_LEN];
#[no_mangle]
static mut digest: [u8; DIGEST_LEN] = [0; DIGEST_LEN];
#[no_mangle]
static mut monitored_pid: u32 = 0;
#[no_mangle]
static mut got_fsverity: u32 = 0;
#[no_mangle]
static mut digest_matches: u32 = 0;

#[link_section = "lsm.s/file_open"]
#[no_mangle]
extern "C" fn test_file_open(ctx: *const u64) -> i32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if pid != unsafe { monitored_pid } {
        return 0;
    }

    let f = arg(ctx, 0) as *mut file;

    let mut digest_ptr: [u64; 2] = [0; 2];
    bpf_dynptr_from_mem(
        core::ptr::addr_of_mut!(digest) as *mut c_void,
        DIGEST_LEN as u64,
        0,
        core::ptr::addr_of_mut!(digest_ptr) as *mut c_void,
    );

    let ret = unsafe {
        bpf_get_fsverity_digest(f, core::ptr::addr_of_mut!(digest_ptr) as *mut c_void)
    };
    if ret < 0 {
        return 0;
    }
    unsafe { got_fsverity = 1 };

    let mut i = 0usize;
    while i < DIGEST_LEN {
        let d = unsafe { digest[i] };
        let e = unsafe { expected_digest[i] };
        if d != e {
            return 0;
        }
        i += 1;
    }

    unsafe { digest_matches = 1 };
    0
}

bpf_object!("GPL");
