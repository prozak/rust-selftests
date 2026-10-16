// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/timer_mim.c
// (bpf-rs-core idiom).
//
// outer_arr's slot ARRAY_KEY is statically &inner_htab (`.values = {
// [ARRAY_KEY] = &inner_htab }`): `[*const InnerHtab; 2]` with a null slot 0
// emits the storage and the .rel.maps entry, and scripts/btf_map_slots.py
// rewrites the BTF member to the zero-length array libbpf demands. test1's
// `struct hmap_elem init = {}` is core::mem::zeroed() so the padding bytes
// that reach the map are zero as in C.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_map_lookup_elem, bpf_map_update_elem, bpf_timer_init, bpf_timer_set_callback,
    bpf_timer_start,
};
use bpf_rs_core::maps::{self, BpfMap};
use core::ffi::c_void;

const ARRAY_KEY: i32 = 1;
const HASH_KEY: i32 = 1234;
const CLOCK_MONOTONIC: u64 = 1;
// enum bpf_map_type: BPF_MAP_TYPE_ARRAY_OF_MAPS (not exported by
// bpf_rs_core::maps, which only covers the constants its existing
// translations needed).
const ARRAY_OF_MAPS: usize = 12;

// struct bpf_timer { __u64 __opaque[2]; } __attribute__((aligned(8)));
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_timer {
    __opaque: [u64; 2],
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct hmap_elem {
    pad: i32,
    timer: bpf_timer,
}

type InnerHtab = BpfMap<i32, hmap_elem, { maps::HASH }, 1024>;

#[link_section = ".maps"]
#[no_mangle]
static inner_htab: InnerHtab = BpfMap::new();

#[allow(non_camel_case_types)]
#[repr(C)]
struct outer_arr_def {
    r#type: *const [i32; ARRAY_OF_MAPS],
    max_entries: *const [i32; 2],
    key_size: *const [i32; 4],
    value_size: *const [i32; 4],
    values: [*const InnerHtab; 2],
}
unsafe impl Sync for outer_arr_def {}

#[link_section = ".maps"]
#[no_mangle]
static outer_arr: outer_arr_def = outer_arr_def {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key_size: core::ptr::null(),
    value_size: core::ptr::null(),
    values: [core::ptr::null(), &inner_htab],
};

#[no_mangle]
static mut err: u64 = 0;
#[no_mangle]
static mut ok: u64 = 0;
#[no_mangle]
static mut cnt: u64 = 0;

extern "C" fn timer_cb2(_map: *mut c_void, _key: *mut i32, val: *mut hmap_elem) -> i64 {
    unsafe {
        cnt += 1;
        bpf_timer_set_callback(core::ptr::addr_of_mut!((*val).timer), timer_cb1);
        if bpf_timer_start(core::ptr::addr_of_mut!((*val).timer), 1000, 0) != 0 {
            err |= 1;
        }
        ok |= 1;
    }
    0
}

/// callback for inner hash map
extern "C" fn timer_cb1(map: *mut c_void, key: *mut i32, val: *mut hmap_elem) -> i64 {
    unsafe {
        cnt += 1;
        bpf_timer_set_callback(core::ptr::addr_of_mut!((*val).timer), timer_cb2);
        if bpf_timer_start(core::ptr::addr_of_mut!((*val).timer), 1000, 0) != 0 {
            err |= 2;
        }
        // Do a lookup to make sure 'map' and 'key' pointers are correct.
        bpf_map_lookup_elem(map, &*key);
        ok |= 2;
    }
    0
}

#[link_section = "fentry/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test1(_ctx: *const u64) -> i32 {
    let array_key: i32 = ARRAY_KEY;
    let hash_key: i32 = HASH_KEY;
    // struct hmap_elem init = {}: C zeroes the 4 padding bytes after `pad`
    // too, and they reach the map through bpf_map_update_elem
    let init: hmap_elem = unsafe { core::mem::zeroed() };

    let inner_map = bpf_map_lookup_elem(&outer_arr, &array_key);
    if inner_map.is_null() {
        return 0;
    }

    bpf_map_update_elem(inner_map, &hash_key, &init, 0);
    let val = bpf_map_lookup_elem(inner_map, &hash_key) as *mut hmap_elem;
    if val.is_null() {
        return 0;
    }

    unsafe {
        bpf_timer_init(core::ptr::addr_of_mut!((*val).timer), inner_map, CLOCK_MONOTONIC);
        if bpf_timer_set_callback(core::ptr::addr_of_mut!((*val).timer), timer_cb1) != 0 {
            err |= 4;
        }
        if bpf_timer_start(core::ptr::addr_of_mut!((*val).timer), 0, 0) != 0 {
            err |= 8;
        }
    }
    0
}

bpf_object!("GPL");
