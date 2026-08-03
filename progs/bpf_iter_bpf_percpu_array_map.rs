#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_iter_bpf_percpu_array_map.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::maps::{self, BpfMap};
use core::ffi::c_void;

#[repr(C)]
struct bpf_iter_meta {
    seq: *mut c_void,
    session_id: u64,
    seq_num: u64,
}

#[repr(C)]
struct bpf_iter__bpf_map_elem {
    meta: *mut bpf_iter_meta,
    map: *mut c_void,
    key: *mut c_void,
    value: *mut c_void,
}

#[link_section = ".maps"]
#[no_mangle]
static arraymap1: BpfMap<u32, u32, { maps::PERCPU_ARRAY }, 3> = BpfMap::new();

#[link_section = ".rodata"]
#[no_mangle]
static num_cpus: u32 = 0;

#[no_mangle]
static mut key_sum: u32 = 0;
#[no_mangle]
static mut val_sum: u32 = 0;

#[link_section = "iter/bpf_map_elem"]
#[no_mangle]
extern "C" fn dump_bpf_percpu_array_map(ctx: *const bpf_iter__bpf_map_elem) -> i32 {
    let ctx = unsafe { &*ctx };

    let key = ctx.key as *const u32;
    let mut pptr = ctx.value as *const u8;

    if key.is_null() || pptr.is_null() {
        return 0;
    }

    unsafe {
        key_sum += *key;
    }

    let n = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(num_cpus)) };
    let step: usize = 8;
    let mut i: u32 = 0;
    while i < n {
        let v = unsafe { *(pptr as *const u32) };
        unsafe {
            val_sum += v;
        }
        pptr = unsafe { pptr.add(step) };
        i += 1;
    }

    0
}

bpf_object!("GPL");
