#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_static_linked1.c (bpf-rs-core
// idiom).
//
// Half of a static-linking test: test_static_linked2.c is the other half,
// and the point is that both files define a static `subprog` with the SAME
// name but a DIFFERENT formula, so the linker has to keep them apart. The
// statics are `volatile` so the reads are not folded away.

#![allow(non_upper_case_globals)]

use bpf_rs_core::bpf_object;
use core::ffi::c_void;

// 8-byte aligned .data
#[no_mangle]
static mut static_var1: i64 = 2;
#[no_mangle]
static mut static_var2: i32 = 3;

#[no_mangle]
static mut var1: i32 = -1;

// 4-byte aligned .rodata
#[link_section = ".rodata"]
#[no_mangle]
static rovar1: i32 = 0;

#[inline(never)]
fn subprog(x: i32) -> i32 {
    x * 2
}

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn handler1(_ctx: *const c_void) -> i32 {
    unsafe {
        let ro = core::ptr::read_volatile(core::ptr::addr_of!(rovar1));
        let s1 = core::ptr::read_volatile(core::ptr::addr_of!(static_var1));
        let s2 = core::ptr::read_volatile(core::ptr::addr_of!(static_var2));
        var1 = subprog(ro) + s1 as i32 + s2;
    }
    0
}

#[link_section = "version"]
#[no_mangle]
static VERSION: i32 = 1;

bpf_object!("GPL");
