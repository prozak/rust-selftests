// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// BTF_KSYM: bpf_prog_active

// Direct translation of tools/testing/selftests/bpf/progs/test_ksyms_btf_write_check.c
// (bpf-rs-core idiom): writes through pointers to the read-only per-cpu
// kernel variable `bpf_prog_active` (BTF_KSYM), which the verifier rejects;
// prog_tests/ksyms_btf.c expects the loads to fail.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_get_smp_processor_id, bpf_per_cpu_ptr, bpf_this_cpu_ptr};

extern "C" {
    static bpf_prog_active: i32;
}

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn handler1(_ctx: *const core::ffi::c_void) -> i32 {
    let cpu = bpf_get_smp_processor_id();
    let active = bpf_per_cpu_ptr(
        core::ptr::addr_of!(bpf_prog_active) as *const core::ffi::c_void,
        cpu,
    ) as *mut i32;
    if !active.is_null() {
        unsafe { core::ptr::write_volatile(active, -1) };
    }
    0
}

#[inline(never)]
extern "C" fn write_active(p: *mut i32) -> i32 {
    if p.is_null() {
        0
    } else {
        unsafe { *p = 42 };
        42
    }
}

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn handler2(_ctx: *const core::ffi::c_void) -> i32 {
    let active = bpf_this_cpu_ptr(core::ptr::addr_of!(bpf_prog_active) as *const core::ffi::c_void) as *mut i32;
    write_active(active);
    0
}

bpf_object!("GPL");
