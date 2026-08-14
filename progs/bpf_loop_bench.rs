#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_loop_bench.c
// (bpf-rs-core idiom). A benchmark: an outer bpf_loop of 1000 iterations,
// each running an inner bpf_loop of nr_loops empty callbacks, counting the
// total in `hits`.

#![allow(non_upper_case_globals)]

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_loop, sync_fetch_and_add_u64};
use core::ffi::c_void;

#[no_mangle]
static mut nr_loops: u32 = 0;
#[no_mangle]
static mut hits: i64 = 0;

extern "C" fn empty_callback(_index: u64, _data: *mut c_void) -> i64 {
    0
}

extern "C" fn outer_loop(_index: u64, _data: *mut c_void) -> i64 {
    unsafe {
        bpf_loop(nr_loops, empty_callback as extern "C" fn(u64, *mut c_void) -> i64,
                 core::ptr::null_mut(), 0);
        sync_fetch_and_add_u64(core::ptr::addr_of_mut!(hits) as *mut u64,
                               nr_loops as u64);
    }
    0
}

#[link_section = "fentry/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn benchmark(_ctx: *const c_void) -> i32 {
    bpf_loop(1000, outer_loop as extern "C" fn(u64, *mut c_void) -> i64,
             core::ptr::null_mut(), 0);
    0
}

bpf_object!("GPL");
