#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/get_func_args_test.c
// bpf-rs-core idiom.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_get_func_arg, bpf_get_func_arg_cnt, bpf_get_func_ret};
use bpf_rs_core::progs::fentry_arg;
use core::ffi::c_void;

const EINVAL: i64 = -22;
const EOPNOTSUPP: i64 = -95;

#[no_mangle]
static mut test1_result: u64 = 0;

#[link_section = "fentry/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test1(ctx: *const u64) -> i32 {
    let vctx = ctx as *const c_void;
    let cnt = bpf_get_func_arg_cnt(vctx);
    let mut a: u64 = 0;
    let mut z: u64 = 0;
    let mut ret: u64 = 0;

    unsafe { test1_result = (cnt == 1) as u64 };

    let err = bpf_get_func_arg(vctx, 0, &mut a);
    unsafe { test1_result &= (err == 0 && (a as i32 == 1)) as u64 };

    let err = bpf_get_func_arg(vctx, 1, &mut z);
    unsafe { test1_result &= (err == EINVAL) as u64 };

    let err = bpf_get_func_ret(vctx, &mut ret);
    unsafe { test1_result &= (err == EOPNOTSUPP) as u64 };

    0
}

#[no_mangle]
static mut test2_result: u64 = 0;

#[link_section = "fexit/bpf_fentry_test2"]
#[no_mangle]
extern "C" fn test2(ctx: *const u64) -> i32 {
    let vctx = ctx as *const c_void;
    let cnt = bpf_get_func_arg_cnt(vctx);
    let mut a: u64 = 0;
    let mut b: u64 = 0;
    let mut z: u64 = 0;
    let mut ret: u64 = 0;

    unsafe { test2_result = (cnt == 2) as u64 };

    let err = bpf_get_func_arg(vctx, 0, &mut a);
    unsafe { test2_result &= (err == 0 && (a as i32 == 2)) as u64 };

    let err = bpf_get_func_arg(vctx, 1, &mut b);
    unsafe { test2_result &= (err == 0 && b == 3) as u64 };

    let err = bpf_get_func_arg(vctx, 2, &mut z);
    unsafe { test2_result &= (err == EINVAL) as u64 };

    let err = bpf_get_func_ret(vctx, &mut ret);
    unsafe { test2_result &= (err == 0 && ret == 5) as u64 };

    0
}

#[no_mangle]
static mut test3_result: u64 = 0;

#[link_section = "fmod_ret/bpf_modify_return_test"]
#[no_mangle]
extern "C" fn fmod_ret_test(ctx: *const u64) -> i32 {
    let vctx = ctx as *const c_void;
    let cnt = bpf_get_func_arg_cnt(vctx);
    let mut a: u64 = 0;
    let mut b: u64 = 0;
    let mut z: u64 = 0;
    let mut ret: u64 = 0;

    unsafe { test3_result = (cnt == 2) as u64 };

    let err = bpf_get_func_arg(vctx, 0, &mut a);
    unsafe { test3_result &= (err == 0 && (a as i32 == 1)) as u64 };

    let err = bpf_get_func_arg(vctx, 1, &mut b);
    let raw_b = fentry_arg(ctx, 1);
    unsafe { test3_result &= (err == 0 && b == raw_b) as u64 };

    let err = bpf_get_func_arg(vctx, 2, &mut z);
    unsafe { test3_result &= (err == EINVAL) as u64 };

    let err = bpf_get_func_ret(vctx, &mut ret);
    unsafe { test3_result &= (err == 0 && ret == 0) as u64 };

    1234
}

#[no_mangle]
static mut test4_result: u64 = 0;

#[link_section = "fexit/bpf_modify_return_test"]
#[no_mangle]
extern "C" fn fexit_test(ctx: *const u64) -> i32 {
    let vctx = ctx as *const c_void;
    let cnt = bpf_get_func_arg_cnt(vctx);
    let mut a: u64 = 0;
    let mut b: u64 = 0;
    let mut z: u64 = 0;
    let mut ret: u64 = 0;

    unsafe { test4_result = (cnt == 2) as u64 };

    let err = bpf_get_func_arg(vctx, 0, &mut a);
    unsafe { test4_result &= (err == 0 && (a as i32 == 1)) as u64 };

    let err = bpf_get_func_arg(vctx, 1, &mut b);
    let raw_b = fentry_arg(ctx, 1);
    unsafe { test4_result &= (err == 0 && b == raw_b) as u64 };

    let err = bpf_get_func_arg(vctx, 2, &mut z);
    unsafe { test4_result &= (err == EINVAL) as u64 };

    let err = bpf_get_func_ret(vctx, &mut ret);
    unsafe { test4_result &= (err == 0 && ret == 1234) as u64 };

    0
}

#[no_mangle]
static mut test5_result: u64 = 0;

#[link_section = "tp_btf/bpf_testmod_fentry_test1_tp"]
#[no_mangle]
extern "C" fn tp_test1(ctx: *const u64) -> i32 {
    let vctx = ctx as *const c_void;
    let cnt = bpf_get_func_arg_cnt(vctx);
    let mut a: u64 = 0;
    let mut z: u64 = 0;

    unsafe { test5_result = (cnt == 1) as u64 };

    let err = bpf_get_func_arg(vctx, 0, &mut a);
    unsafe { test5_result &= (err == 0 && (a as i32 == 1)) as u64 };

    let err = bpf_get_func_arg(vctx, 1, &mut z);
    unsafe { test5_result &= (err == EINVAL) as u64 };

    0
}

#[no_mangle]
static mut test6_result: u64 = 0;

#[link_section = "tp_btf/bpf_testmod_fentry_test2_tp"]
#[no_mangle]
extern "C" fn tp_test2(ctx: *const u64) -> i32 {
    let vctx = ctx as *const c_void;
    let cnt = bpf_get_func_arg_cnt(vctx);
    let mut a: u64 = 0;
    let mut b: u64 = 0;
    let mut z: u64 = 0;

    unsafe { test6_result = (cnt == 2) as u64 };

    let err = bpf_get_func_arg(vctx, 0, &mut a);
    unsafe { test6_result &= (err == 0 && (a as i32 == 2)) as u64 };

    let err = bpf_get_func_arg(vctx, 1, &mut b);
    unsafe { test6_result &= (err == 0 && b == 3) as u64 };

    let err = bpf_get_func_arg(vctx, 2, &mut z);
    unsafe { test6_result &= (err == EINVAL) as u64 };

    0
}

bpf_object!("GPL");
