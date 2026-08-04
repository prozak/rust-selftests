#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_sig_in_xattr.c
// (bpf-rs-core idiom).

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_dynptr_from_mem, bpf_get_current_pid_tgid};
use bpf_rs_core::progs::fentry_arg as arg;

const SHA256_DIGEST_SIZE: usize = 32;
const MAX_SIG_SIZE: usize = 1024;
const MAGIC_SIZE: usize = 8;
const SIZEOF_STRUCT_FSVERITY_DIGEST: usize = 4;
const DIGEST_SIZE: usize = MAGIC_SIZE + SIZEOF_STRUCT_FSVERITY_DIGEST + SHA256_DIGEST_SIZE;

const EPERM: i32 = 1;
const ENOENT: i32 = 2;
const EFAULT: i32 = 14;

#[allow(non_camel_case_types)]
#[repr(C)]
struct file {
    _unused: [u8; 0],
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_key {
    _unused: [u8; 0],
}

#[allow(non_camel_case_types)]
#[repr(C, align(8))]
struct bpf_dynptr {
    opaque: [u64; 2],
}

extern "C" {
    fn bpf_get_file_xattr(file: *mut file, name: *const u8, value_ptr: *mut bpf_dynptr) -> i32;
    fn bpf_get_fsverity_digest(file: *mut file, digest_ptr: *const bpf_dynptr) -> i32;
    fn bpf_lookup_user_key(serial: i32, flags: u64) -> *mut bpf_key;
    fn bpf_key_put(key: *mut bpf_key);
    fn bpf_verify_pkcs7_signature(
        data_ptr: *const bpf_dynptr,
        sig_ptr: *const bpf_dynptr,
        trusted_keyring: *mut bpf_key,
    ) -> i32;
}

#[no_mangle]
static mut digest: [u8; DIGEST_SIZE] = [0; DIGEST_SIZE];

#[no_mangle]
static mut monitored_pid: u32 = 0;

#[no_mangle]
static mut sig: [u8; MAX_SIG_SIZE] = [0; MAX_SIG_SIZE];

#[no_mangle]
static mut sig_size: u32 = 0;

#[no_mangle]
static mut user_keyring_serial: i32 = 0;

#[link_section = "lsm.s/file_open"]
#[no_mangle]
extern "C" fn test_file_open(ctx: *const u64) -> i32 {
    let f = arg(ctx, 0) as *mut file;

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if pid != unsafe { monitored_pid } {
        return 0;
    }

    let mut digest_ptr = bpf_dynptr { opaque: [0u64; 2] };
    let mut sig_ptr = bpf_dynptr { opaque: [0u64; 2] };

    // digest_ptr points to fsverity_digest
    unsafe {
        bpf_dynptr_from_mem(
            core::ptr::addr_of_mut!(digest)
                .cast::<u8>()
                .add(MAGIC_SIZE) as *mut c_void,
            (DIGEST_SIZE - MAGIC_SIZE) as u64,
            0,
            &mut digest_ptr as *mut bpf_dynptr as *mut c_void,
        );
    }

    let ret = unsafe { bpf_get_fsverity_digest(f, &digest_ptr as *const bpf_dynptr) };
    // No verity, allow access
    if ret < 0 {
        return 0;
    }

    // Move digest_ptr to fsverity_formatted_digest
    unsafe {
        bpf_dynptr_from_mem(
            core::ptr::addr_of_mut!(digest) as *mut c_void,
            DIGEST_SIZE as u64,
            0,
            &mut digest_ptr as *mut bpf_dynptr as *mut c_void,
        );
    }

    // Read signature from xattr
    unsafe {
        bpf_dynptr_from_mem(
            core::ptr::addr_of_mut!(sig) as *mut c_void,
            MAX_SIG_SIZE as u64,
            0,
            &mut sig_ptr as *mut bpf_dynptr as *mut c_void,
        );
    }
    let ret =
        unsafe { bpf_get_file_xattr(f, b"user.sig\0".as_ptr(), &mut sig_ptr as *mut bpf_dynptr) };
    // No signature, reject access
    if ret < 0 {
        return -EPERM;
    }

    let trusted_keyring = unsafe { bpf_lookup_user_key(user_keyring_serial, 0) };
    if trusted_keyring.is_null() {
        return -ENOENT;
    }

    // Verify signature
    let mut ret = unsafe {
        bpf_verify_pkcs7_signature(
            &digest_ptr as *const bpf_dynptr,
            &sig_ptr as *const bpf_dynptr,
            trusted_keyring,
        )
    };

    unsafe { bpf_key_put(trusted_keyring) };

    if ret < -4095 || ret > 0 {
        ret = -EFAULT;
    }

    ret
}

bpf_object!("GPL");
