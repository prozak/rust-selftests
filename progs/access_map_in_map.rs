// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/access_map_in_map.c
// (bpf-rs-core idiom).

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_get_current_pid_tgid, bpf_map_lookup_elem, bpf_map_update_elem};

// struct inner_map_type { __uint(type, ARRAY); __uint(key_size, 4);
// __uint(value_size, 4); __uint(max_entries, 1); }
#[allow(non_camel_case_types)]
#[repr(C)]
struct inner_map_type {
    r#type: *const [i32; 2], // BPF_MAP_TYPE_ARRAY
    key_size: *const [i32; 4],
    value_size: *const [i32; 4],
    max_entries: *const [i32; 1],
}
unsafe impl Sync for inner_map_type {}

#[link_section = ".maps"]
#[no_mangle]
static inner_map: inner_map_type = inner_map_type {
    r#type: core::ptr::null(),
    key_size: core::ptr::null(),
    value_size: core::ptr::null(),
    max_entries: core::ptr::null(),
};

// struct { __uint(type, ARRAY_OF_MAPS); __type(key, int); __type(value,
// int); __uint(max_entries, 1); __array(values, struct inner_map_type); }
// outer_array_map = { .values = { [0] = &inner_map } };
//
// `[T; 1]` emits the slot storage and its .rel.maps entry;
// scripts/btf_map_slots.py rewrites the BTF member to the zero-length array
// libbpf demands.
#[allow(non_camel_case_types)]
#[repr(C)]
struct outer_array_map_def {
    r#type: *const [i32; 12], // BPF_MAP_TYPE_ARRAY_OF_MAPS
    key: *const i32,
    value: *const i32,
    max_entries: *const [i32; 1],
    values: [*const inner_map_type; 1],
}
unsafe impl Sync for outer_array_map_def {}

#[link_section = ".maps"]
#[no_mangle]
static outer_array_map: outer_array_map_def = outer_array_map_def {
    r#type: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
    max_entries: core::ptr::null(),
    values: [&inner_map],
};

// struct { __uint(type, HASH_OF_MAPS); ... } outer_htab_map = { .values =
// { [0] = &inner_map } };
#[allow(non_camel_case_types)]
#[repr(C)]
struct outer_htab_map_def {
    r#type: *const [i32; 13], // BPF_MAP_TYPE_HASH_OF_MAPS
    key: *const i32,
    value: *const i32,
    max_entries: *const [i32; 1],
    values: [*const inner_map_type; 1],
}
unsafe impl Sync for outer_htab_map_def {}

#[link_section = ".maps"]
#[no_mangle]
static outer_htab_map: outer_htab_map_def = outer_htab_map_def {
    r#type: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
    max_entries: core::ptr::null(),
    values: [&inner_map],
};

#[no_mangle]
static mut tgid: i32 = 0;

fn acc_map_in_map<M>(outer_map: *const M) -> i32 {
    if (bpf_get_current_pid_tgid() >> 32) != unsafe { tgid } as u64 {
        return 0;
    }

    // Find nonexistent inner map
    let mut key: i32 = 1;
    let found = bpf_map_lookup_elem(outer_map, &key);
    if !found.is_null() {
        return 0;
    }

    // Find the old inner map
    key = 0;
    let inner = bpf_map_lookup_elem(outer_map, &key);
    if inner.is_null() {
        return 0;
    }

    // Wait for the old inner map to be replaced
    let value: u32 = 0xdeadbeef;
    for _ in 0..2048 {
        bpf_map_update_elem(inner as *const c_void, &key, &value, 0);
    }

    0
}

#[link_section = "?kprobe/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn access_map_in_array(_ctx: *const c_void) -> i32 {
    acc_map_in_map(&outer_array_map)
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn sleepable_access_map_in_array(_ctx: *const c_void) -> i32 {
    acc_map_in_map(&outer_array_map)
}

#[link_section = "?kprobe/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn access_map_in_htab(_ctx: *const c_void) -> i32 {
    acc_map_in_map(&outer_htab_map)
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn sleepable_access_map_in_htab(_ctx: *const c_void) -> i32 {
    acc_map_in_map(&outer_htab_map)
}

bpf_object!("GPL");
