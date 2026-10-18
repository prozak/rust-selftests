// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/tramp_prog_detach.c
// (bpf-rs-core idiom). prog_tests/tramp_prog_detach.c autoloads one program
// at a time (the `?` sections), holds a task in the sleepable one with
// userfaultfd through bpf_copy_from_user, detaches the other programs of
// the trampoline meanwhile and lets the task continue. `fault_addr` is the
// C's `void *`: BTF_C_VOID keeps the skeleton member a void pointer.

// BTF_C_VOID: c_void

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_copy_from_user, bpf_get_current_pid_tgid, bpf_ktime_get_ns};

#[no_mangle]
static mut pid: i32 = 0;
#[no_mangle]
static mut fault_addr: *mut c_void = core::ptr::null_mut();
#[no_mangle]
static mut ts: u64 = 0;

#[inline(always)]
fn do_sleepable() -> i32 {
    let mut dst: u8 = 0;

    if (bpf_get_current_pid_tgid() >> 32) as i32 != unsafe { pid } {
        return 0;
    }

    unsafe { ts = bpf_ktime_get_ns() };
    /* blocks for as long as user space wants when fault_addr is armed */
    bpf_copy_from_user(&mut dst as *mut u8 as *mut c_void, 1, unsafe { fault_addr });
    0
}

#[inline(always)]
fn do_victim() -> i32 {
    if (bpf_get_current_pid_tgid() >> 32) as i32 != unsafe { pid } {
        return 0;
    }

    unsafe { ts = bpf_ktime_get_ns() };
    0
}

#[link_section = "?fentry.s/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn fentry_sleepable(_ctx: *const u64) -> i32 {
    do_sleepable()
}

#[link_section = "?fentry/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn fentry_victim(_ctx: *const u64) -> i32 {
    do_victim()
}

#[link_section = "?fexit.s/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn fexit_sleepable(_ctx: *const u64) -> i32 {
    do_sleepable()
}

#[link_section = "?fexit/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn fexit_victim(_ctx: *const u64) -> i32 {
    do_victim()
}

bpf_object!("GPL");
