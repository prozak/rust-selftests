// SPDX-License-Identifier: GPL-2.0-only
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/inner_array_lookup.c
// (bpf-rs-core idiom).
//
// outer_map1 is a HASH_OF_MAPS whose slot 2 is statically &inner_map1
// (`.values = { [2] = &inner_map1 }`): `[*const InnerMap; 3]` emits the slot
// storage and the .rel.maps entry, and scripts/btf_map_slots.py rewrites the
// BTF member to the zero-length array libbpf demands (test_btf_map_in_map.rs).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_map_lookup_elem;
use bpf_rs_core::maps::{self, BpfMap};
use core::ffi::c_void;

// struct inner_map { __uint(type, ARRAY); __uint(max_entries, 5);
// __type(key, int); __type(value, int); } inner_map1 SEC(".maps");
type InnerMap = BpfMap<i32, i32, { maps::ARRAY }, 5>;

#[link_section = ".maps"]
#[no_mangle]
static inner_map1: InnerMap = InnerMap::new();

// struct outer_map { __uint(type, HASH_OF_MAPS); __uint(max_entries, 3);
// __type(key, int); __array(values, struct inner_map); }
#[allow(non_camel_case_types)]
#[repr(C)]
struct outer_map {
    r#type: *const [i32; 13], // BPF_MAP_TYPE_HASH_OF_MAPS
    max_entries: *const [i32; 3],
    key: *const i32,
    values: [*const InnerMap; 3],
}
unsafe impl Sync for outer_map {}

#[link_section = ".maps"]
#[no_mangle]
static outer_map1: outer_map = outer_map {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key: core::ptr::null(),
    values: [core::ptr::null(), core::ptr::null(), &inner_map1],
};

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn handle__sys_enter(_ctx: *const c_void) -> i32 {
    let outer_key: i32 = 2;
    let inner_key: i32 = 3;

    let map = bpf_map_lookup_elem(&outer_map1, &outer_key);
    if map.is_null() {
        return 1;
    }

    let val = bpf_map_lookup_elem(map, &inner_key) as *mut i32;
    if val.is_null() {
        return 1;
    }

    unsafe {
        if *val == 1 {
            *val = 2;
        }
    }
    0
}

bpf_object!("GPL");
