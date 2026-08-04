#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/get_func_args_fsession_test.c
// bpf-rs-core idiom.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_get_func_arg, bpf_get_func_arg_cnt, bpf_get_func_ret};
use core::ffi::c_void;

extern "C" {
    fn bpf_session_is_return(ctx: *mut c_void) -> bool;
}

#[no_mangle]
static mut test1_result: u64 = 0;

const EINVAL: i64 = -22;

#[link_section = "fsession/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test1(ctx: *const u64) -> i32 {
    let cnt = bpf_get_func_arg_cnt(ctx as *const c_void);
    let mut a: u64 = 0;
    let mut z: u64 = 0;
    let mut ret: u64 = 0;

    let mut result = (cnt == 1) as u64;

    /* valid arguments */
    let err = bpf_get_func_arg(ctx as *const c_void, 0, &mut a);
    result &= (err == 0 && (a as i32) == 1) as u64;

    /* not valid argument */
    let err = bpf_get_func_arg(ctx as *const c_void, 1, &mut z);
    result &= (err == EINVAL) as u64;

    if unsafe { bpf_session_is_return(ctx as *mut c_void) } {
        let err = bpf_get_func_ret(ctx as *const c_void, &mut ret);
        result &= (err == 0 && ret == 2) as u64;
    } else {
        let err = bpf_get_func_ret(ctx as *const c_void, &mut ret);
        result &= (err == 0 && ret == 0) as u64;
    }

    unsafe { test1_result = result };

    0
}

bpf_object!("GPL");
