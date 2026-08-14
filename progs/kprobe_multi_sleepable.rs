#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/kprobe_multi_sleepable.c (bpf-rs-core
// idiom). The point of the test is that bpf_copy_from_user — a sleepable
// helper — is callable from a kprobe.multi.s program, so `a` exists only
// to give the copy a destination and is kept alive by barrier_var.

#![allow(non_upper_case_globals)]

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{barrier_var, bpf_copy_from_user};
use core::ffi::c_void;

#[no_mangle]
static mut user_ptr: *const c_void = core::ptr::null();

#[link_section = "kprobe.multi"]
#[no_mangle]
extern "C" fn handle_kprobe_multi_sleepable(_ctx: *const u64) -> i32 {
    let mut a: i32 = 0;
    let err = bpf_copy_from_user(
        &mut a as *mut i32 as *mut c_void,
        core::mem::size_of::<i32>() as u32,
        unsafe { user_ptr },
    );
    let mut keep = a as usize;
    barrier_var(&mut keep);
    err as i32
}

#[link_section = "fentry/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn fentry(_ctx: *const u64) -> i32 {
    0
}

bpf_object!("GPL");
