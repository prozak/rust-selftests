// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/strncmp_test.c
// (bpf-rs-core idiom). prog_tests/test_strncmp.c enables one program at a
// time: do_strncmp compares the bss string the test fills with the rodata
// target and stores the result in cmp_ret; the three strncmp_bad_* programs
// must be REJECTED by the verifier (non-constant size, writable target,
// target without a NUL), which the test asserts through a failing load.
// All the strings are C `char` arrays (the test takes `char *` to them).
// BTF_C_CHAR: u8
// The verifier accepts a bpf_strncmp target only when a NUL follows it in
// its .rodata map value: no_str_target must be the LAST thing in .rodata,
// as in the C object (rustc would sort it before target by name).
// C_LAYOUT: .rodata

use core::ffi::c_void;
use core::ptr::addr_of;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_get_current_pid_tgid, bpf_strncmp};

const STRNCMP_STR_SZ: u32 = 8;

#[link_section = ".rodata"]
#[no_mangle]
static target: [u8; 8] = *b"EEEEEEE\0";
// `str` is a Rust keyword: the C symbol name comes from export_name.
#[export_name = "str"]
static mut str_: [u8; 8] = [0; 8];
#[no_mangle]
static mut cmp_ret: i32 = 0;
#[no_mangle]
static mut target_pid: i32 = 0;

#[link_section = ".rodata"]
#[no_mangle]
static no_str_target: [u8; 8] = *b"12345678";
#[no_mangle]
static mut writable_target: [u8; 8] = [0; 8];
#[no_mangle]
static mut no_const_str_size: u32 = STRNCMP_STR_SZ;

#[link_section = "?tp/syscalls/sys_enter_nanosleep"]
#[no_mangle]
extern "C" fn do_strncmp(_ctx: *mut c_void) -> i32 {
    unsafe {
        if (bpf_get_current_pid_tgid() >> 32) != target_pid as i64 as u64 {
            return 0;
        }

        cmp_ret = bpf_strncmp(
            addr_of!(str_) as *const c_void,
            STRNCMP_STR_SZ,
            addr_of!(target) as *const c_void,
        ) as i32;
    }
    0
}

#[link_section = "?tp/syscalls/sys_enter_nanosleep"]
#[no_mangle]
extern "C" fn strncmp_bad_not_const_str_size(_ctx: *mut c_void) -> i32 {
    unsafe {
        /* The value of string size is not const, so will fail */
        cmp_ret = bpf_strncmp(
            addr_of!(str_) as *const c_void,
            no_const_str_size,
            addr_of!(target) as *const c_void,
        ) as i32;
    }
    0
}

#[link_section = "?tp/syscalls/sys_enter_nanosleep"]
#[no_mangle]
extern "C" fn strncmp_bad_writable_target(_ctx: *mut c_void) -> i32 {
    unsafe {
        /* Compared target is not read-only, so will fail */
        cmp_ret = bpf_strncmp(
            addr_of!(str_) as *const c_void,
            STRNCMP_STR_SZ,
            addr_of!(writable_target) as *const c_void,
        ) as i32;
    }
    0
}

#[link_section = "?tp/syscalls/sys_enter_nanosleep"]
#[no_mangle]
extern "C" fn strncmp_bad_not_null_term_target(_ctx: *mut c_void) -> i32 {
    unsafe {
        /* Compared target is not null-terminated, so will fail */
        cmp_ret = bpf_strncmp(
            addr_of!(str_) as *const c_void,
            STRNCMP_STR_SZ,
            addr_of!(no_str_target) as *const c_void,
        ) as i32;
    }
    0
}

bpf_object!("GPL");
