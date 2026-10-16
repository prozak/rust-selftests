// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// BTF_KSYM: runqueues
// BTF_KSYM: bpf_prog_active

// Direct translation of tools/testing/selftests/bpf/progs/test_ksyms_btf.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_get_smp_processor_id, bpf_per_cpu_ptr, bpf_this_cpu_ptr};
use btf_macros::btf;
use core::ffi::c_void;

#[btf]
struct rq {
    cpu: i32,
}

extern "C" {
    static runqueues: rq;
    static bpf_prog_active: i32;
}

#[no_mangle]
static mut out__runqueues_addr: u64 = u64::MAX;
#[no_mangle]
static mut out__bpf_prog_active_addr: u64 = u64::MAX;

#[no_mangle]
static mut out__rq_cpu: u32 = u32::MAX;
#[no_mangle]
static mut out__bpf_prog_active: i32 = -1;

#[no_mangle]
static mut out__this_rq_cpu: u32 = u32::MAX;
#[no_mangle]
static mut out__this_bpf_prog_active: i32 = -1;

#[no_mangle]
static mut out__cpu_0_rq_cpu: u32 = u32::MAX;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn handler(_ctx: *const c_void) -> i32 {
    unsafe {
        out__runqueues_addr = core::ptr::addr_of!(runqueues) as u64;
        out__bpf_prog_active_addr = core::ptr::addr_of!(bpf_prog_active) as u64;
    }

    let cpu = bpf_get_smp_processor_id();

    let rq_ptr = bpf_per_cpu_ptr(unsafe { core::ptr::addr_of!(runqueues) as *const c_void }, cpu)
        as *mut rq;
    if !rq_ptr.is_null() {
        let v = *unsafe { &*rq_ptr }.cpu().get().unwrap();
        unsafe { out__rq_cpu = v as u32 };
    }
    let active = bpf_per_cpu_ptr(
        unsafe { core::ptr::addr_of!(bpf_prog_active) as *const c_void },
        cpu,
    ) as *mut i32;
    if !active.is_null() {
        unsafe { out__bpf_prog_active = core::ptr::read_volatile(active) };
    }

    let rq0_ptr = bpf_per_cpu_ptr(unsafe { core::ptr::addr_of!(runqueues) as *const c_void }, 0)
        as *mut rq;
    if !rq0_ptr.is_null() {
        let v = *unsafe { &*rq0_ptr }.cpu().get().unwrap();
        unsafe { out__cpu_0_rq_cpu = v as u32 };
    }

    let this_rq_ptr =
        bpf_this_cpu_ptr(unsafe { core::ptr::addr_of!(runqueues) as *const c_void }) as *mut rq;
    let v = *unsafe { &*this_rq_ptr }.cpu().get().unwrap();
    unsafe { out__this_rq_cpu = v as u32 };
    let this_active =
        bpf_this_cpu_ptr(unsafe { core::ptr::addr_of!(bpf_prog_active) as *const c_void })
            as *mut i32;
    unsafe { out__this_bpf_prog_active = core::ptr::read_volatile(this_active) };

    0
}

bpf_object!("GPL");
