#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_static_linked2.c (bpf-rs-core
// idiom). The other half of the static-linking test: same `subprog` name
// as test_static_linked1.c, different formula, and deliberately different
// alignments for the .data/.rodata variables.

#![allow(non_upper_case_globals)]

use bpf_rs_core::bpf_object;
use core::ffi::c_void;

// 4-byte aligned .data
#[no_mangle]
static mut static_var1: i32 = 5;
#[no_mangle]
static mut static_var2: i32 = 6;

#[no_mangle]
static mut var2: i32 = -1;

// 8-byte aligned .rodata
#[link_section = ".rodata"]
#[no_mangle]
static rovar2: i64 = 0;

#[inline(never)]
fn subprog(x: i32) -> i32 {
    x * 3
}

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn handler2(_ctx: *const c_void) -> i32 {
    unsafe {
        let ro = core::ptr::read_volatile(core::ptr::addr_of!(rovar2));
        let s1 = core::ptr::read_volatile(core::ptr::addr_of!(static_var1));
        let s2 = core::ptr::read_volatile(core::ptr::addr_of!(static_var2));
        var2 = subprog(ro as i32) + s1 + s2;
    }
    0
}

#[link_section = "version"]
#[no_mangle]
static _version: i32 = 1;

bpf_object!("GPL");
