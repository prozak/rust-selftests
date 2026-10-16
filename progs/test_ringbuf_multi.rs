// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_ringbuf_multi.c
// (bpf-rs-core idiom).

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_map_lookup_elem, bpf_ringbuf_reserve,
    bpf_ringbuf_submit,
};

#[repr(C)]
struct sample {
    pid: i32,
    seq: i32,
    value: i64,
    comm: [u8; 16],
}

// struct ringbuf_map { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1000); }
#[allow(non_camel_case_types)]
#[repr(C)]
struct ringbuf_map {
    r#type: *const [i32; 27], // BPF_MAP_TYPE_RINGBUF
    max_entries: *const [i32; 1000],
}
unsafe impl Sync for ringbuf_map {}

#[link_section = ".maps"]
#[no_mangle]
static ringbuf1: ringbuf_map = ringbuf_map {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
};

#[link_section = ".maps"]
#[no_mangle]
static ringbuf2: ringbuf_map = ringbuf_map {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
};

// struct { __uint(type, ARRAY_OF_MAPS); __uint(max_entries, 4); __type(key,
// int); __array(values, struct ringbuf_map); } ringbuf_arr = { .values = {
// [0] = &ringbuf1, [2] = &ringbuf2 } };
//
// rustc can't replicate Clang's flexible-array-member static initializer for
// the `values` slots: `[*const ringbuf_map; 4]` with nulls in the empty
// slots emits the storage and the .rel.maps entries, and
// scripts/btf_map_slots.py rewrites the BTF member to the zero-length array
// libbpf demands.
#[allow(non_camel_case_types)]
#[repr(C)]
struct ringbuf_arr_def {
    r#type: *const [i32; 12], // BPF_MAP_TYPE_ARRAY_OF_MAPS
    max_entries: *const [i32; 4],
    key: *const i32,
    values: [*const ringbuf_map; 4],
}
unsafe impl Sync for ringbuf_arr_def {}

#[link_section = ".maps"]
#[no_mangle]
static ringbuf_arr: ringbuf_arr_def = ringbuf_arr_def {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key: core::ptr::null(),
    values: [&ringbuf1, core::ptr::null(), &ringbuf2, core::ptr::null()],
};

// struct { __uint(type, HASH_OF_MAPS); __uint(max_entries, 1); __type(key,
// int); __array(values, struct ringbuf_map); } ringbuf_hash = { .values = {
// [0] = &ringbuf1 } }; slot 0 is populated the same way.
#[allow(non_camel_case_types)]
#[repr(C)]
struct ringbuf_hash_def {
    r#type: *const [i32; 13], // BPF_MAP_TYPE_HASH_OF_MAPS
    max_entries: *const [i32; 1],
    key: *const i32,
    values: [*const ringbuf_map; 1],
}
unsafe impl Sync for ringbuf_hash_def {}

#[link_section = ".maps"]
#[no_mangle]
static ringbuf_hash: ringbuf_hash_def = ringbuf_hash_def {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key: core::ptr::null(),
    values: [&ringbuf1],
};

/* inputs */
#[no_mangle]
static mut pid: i32 = 0;
#[no_mangle]
static mut target_ring: i32 = 0;
#[no_mangle]
static mut value: isize = 0;

/* outputs */
#[no_mangle]
static mut total: isize = 0;
#[no_mangle]
static mut dropped: isize = 0;
#[no_mangle]
static mut skipped: isize = 0;

#[link_section = "tp/syscalls/sys_enter_getpgid"]
#[no_mangle]
extern "C" fn test_ringbuf(_ctx: *const c_void) -> i32 {
    let cur_pid = (bpf_get_current_pid_tgid() >> 32) as i32;

    if cur_pid != unsafe { pid } {
        return 0;
    }

    let target = unsafe { target_ring };
    let rb = bpf_map_lookup_elem(&ringbuf_arr, &target);
    if rb.is_null() {
        unsafe { skipped += 1 };
        return 1;
    }

    let sample =
        bpf_ringbuf_reserve(rb as *const c_void, core::mem::size_of::<sample>() as u64, 0)
            as *mut sample;
    if sample.is_null() {
        unsafe { dropped += 1 };
        return 1;
    }

    unsafe {
        (*sample).pid = pid;
        bpf_get_current_comm((*sample).comm.as_mut_ptr() as *mut c_void, 16);
        (*sample).value = value as i64;

        (*sample).seq = total as i32;
        total += 1;
    }

    bpf_ringbuf_submit(sample as *mut c_void, 0);

    0
}

bpf_object!("GPL");
