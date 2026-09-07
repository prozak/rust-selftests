#![no_std]
#![no_main]

use core::{ffi::c_void, ptr::addr_of_mut};
use bpf_rs_core::helpers::{bpf_get_func_arg, bpf_get_func_arg_cnt, bpf_get_func_ret};

extern "C" { fn bpf_kfunc_implicit_arg(a: i32) -> i32; }

#[inline(always)]
unsafe fn check_implicit_args(ctx: *const c_void, arg_cnt: *mut u64, aux_arg: *mut u64) -> u64 {
    let (mut a, mut aux, mut z) = (0, 0, 0);
    *arg_cnt = bpf_get_func_arg_cnt(ctx) as u64;
    let mut result = (*arg_cnt == 2) as u64;
    let err = bpf_get_func_arg(ctx, 0, &mut a);
    result &= (err == 0 && a as i32 == 5) as u64;
    let err = bpf_get_func_arg(ctx, 1, &mut aux);
    *aux_arg = aux;
    result &= (err == 0 && aux != 0) as u64;
    let err = bpf_get_func_arg(ctx, 2, &mut z);
    result & (err == -22) as u64
}

#[no_mangle]
static mut fentry_result: u64 = 0;
#[no_mangle]
static mut fentry_arg_cnt: u64 = 0;
#[no_mangle]
static mut fentry_aux_arg: u64 = 0;
#[no_mangle]
static mut fexit_result: u64 = 0;
#[no_mangle]
static mut fexit_arg_cnt: u64 = 0;
#[no_mangle]
static mut fexit_aux_arg: u64 = 0;

#[no_mangle]
#[link_section = "fentry/bpf_kfunc_implicit_arg"]
extern "C" fn trace_implicit_arg_fentry(ctx: *const u64) -> i32 {
    let mut ret = 0;
    unsafe {
        fentry_result = check_implicit_args(ctx.cast(), addr_of_mut!(fentry_arg_cnt), addr_of_mut!(fentry_aux_arg));
        let err = bpf_get_func_ret(ctx.cast(), &mut ret);
        fentry_result &= (err == -95) as u64;
    }
    0
}

#[no_mangle]
#[link_section = "fexit/bpf_kfunc_implicit_arg"]
extern "C" fn trace_implicit_arg_fexit(ctx: *const u64) -> i32 {
    let mut ret = 0;
    unsafe {
        fexit_result = check_implicit_args(ctx.cast(), addr_of_mut!(fexit_arg_cnt), addr_of_mut!(fexit_aux_arg));
        let err = bpf_get_func_ret(ctx.cast(), &mut ret);
        fexit_result &= (err == 0 && ret == 5) as u64;
    }
    0
}

#[no_mangle]
#[link_section = "syscall"]
extern "C" fn trigger_implicit_arg(_arg0: *const c_void) -> i32 {
    unsafe { bpf_kfunc_implicit_arg(5) }
}

bpf_rs_core::bpf_object!("GPL");
