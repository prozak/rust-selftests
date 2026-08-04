#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/modify_return.c
// (Copyright 2020 Google LLC), bpf-rs-core idiom.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_current_pid_tgid;
use bpf_rs_core::progs::fentry_arg as arg;

static mut sequence: i32 = 0;
#[no_mangle]
static mut input_retval: i32 = 0;
#[no_mangle]
static mut test_pid: u32 = 0;

#[no_mangle]
static mut fentry_result: u64 = 0;
#[link_section = "fentry/bpf_modify_return_test"]
#[no_mangle]
extern "C" fn fentry_test(ctx: *const u64) -> i32 {
    if (bpf_get_current_pid_tgid() >> 32) as u32 != unsafe { test_pid } {
        return 0;
    }
    unsafe {
        sequence += 1;
        fentry_result = (sequence == 1) as u64;
    }
    0
}

#[no_mangle]
static mut fmod_ret_result: u64 = 0;
#[link_section = "fmod_ret/bpf_modify_return_test"]
#[no_mangle]
extern "C" fn fmod_ret_test(ctx: *const u64) -> i32 {
    let ret = arg(ctx, 2) as i32;
    if (bpf_get_current_pid_tgid() >> 32) as u32 != unsafe { test_pid } {
        return ret;
    }
    unsafe {
        sequence += 1;
        fmod_ret_result = (sequence == 2 && ret == 0) as u64;
        input_retval
    }
}

#[no_mangle]
static mut fexit_result: u64 = 0;
#[link_section = "fexit/bpf_modify_return_test"]
#[no_mangle]
extern "C" fn fexit_test(ctx: *const u64) -> i32 {
    let ret = arg(ctx, 2) as i32;
    if (bpf_get_current_pid_tgid() >> 32) as u32 != unsafe { test_pid } {
        return 0;
    }
    unsafe {
        sequence += 1;
        if input_retval != 0 {
            fexit_result = (sequence == 3 && ret == input_retval) as u64;
        } else {
            fexit_result = (sequence == 3 && ret == 4) as u64;
        }
    }
    0
}

static mut sequence2: i32 = 0;

#[no_mangle]
static mut fentry_result2: u64 = 0;
#[link_section = "fentry/bpf_modify_return_test2"]
#[no_mangle]
extern "C" fn fentry_test2(ctx: *const u64) -> i32 {
    if (bpf_get_current_pid_tgid() >> 32) as u32 != unsafe { test_pid } {
        return 0;
    }
    unsafe {
        sequence2 += 1;
        fentry_result2 = (sequence2 == 1) as u64;
    }
    0
}

#[no_mangle]
static mut fmod_ret_result2: u64 = 0;
#[link_section = "fmod_ret/bpf_modify_return_test2"]
#[no_mangle]
extern "C" fn fmod_ret_test2(ctx: *const u64) -> i32 {
    let ret = arg(ctx, 7) as i32;
    if (bpf_get_current_pid_tgid() >> 32) as u32 != unsafe { test_pid } {
        return ret;
    }
    unsafe {
        sequence2 += 1;
        fmod_ret_result2 = (sequence2 == 2 && ret == 0) as u64;
        input_retval
    }
}

#[no_mangle]
static mut fexit_result2: u64 = 0;
#[link_section = "fexit/bpf_modify_return_test2"]
#[no_mangle]
extern "C" fn fexit_test2(ctx: *const u64) -> i32 {
    let ret = arg(ctx, 7) as i32;
    if (bpf_get_current_pid_tgid() >> 32) as u32 != unsafe { test_pid } {
        return 0;
    }
    unsafe {
        sequence2 += 1;
        if input_retval != 0 {
            fexit_result2 = (sequence2 == 3 && ret == input_retval) as u64;
        } else {
            fexit_result2 = (sequence2 == 3 && ret == 29) as u64;
        }
    }
    0
}

bpf_object!("GPL");
