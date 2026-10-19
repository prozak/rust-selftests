// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_map_in_map.c
// (bpf-rs-core idiom). An array-of-maps and a hash-of-maps whose inner
// maps test_maps.c sets up, plus two more with a perf-event-array inner
// map preset (prog_tests/map_in_map.c and map_tests/map_in_map_batch_ops.c
// only reuse the object's map definitions).

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_map_lookup_elem, bpf_map_update_elem};
use bpf_rs_core::maps;

const ARRAY_OF_MAPS: usize = 12;
const HASH_OF_MAPS: usize = 13;
const XDP_DROP: i32 = 1;
const XDP_PASS: i32 = 2;

// __uint(map_flags, 0) is a pointer to a zero-length array.
#[allow(non_camel_case_types)]
#[repr(C)]
struct mim_array_def {
    r#type: *const [i32; ARRAY_OF_MAPS],
    max_entries: *const [i32; 1],
    map_flags: *const [i32; 0],
    key: *const u32,
    value: *const u32,
}
unsafe impl Sync for mim_array_def {}

#[link_section = ".maps"]
#[no_mangle]
static mim_array: mim_array_def = mim_array_def {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    map_flags: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
};

#[allow(non_camel_case_types)]
#[repr(C)]
struct mim_hash_def {
    r#type: *const [i32; HASH_OF_MAPS],
    max_entries: *const [i32; 1],
    map_flags: *const [i32; 0],
    key: *const i32,
    value: *const u32,
}
unsafe impl Sync for mim_hash_def {}

#[link_section = ".maps"]
#[no_mangle]
static mim_hash: mim_hash_def = mim_hash_def {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    map_flags: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
};

/* The following three maps are used to test
 * perf_event_array map can be an inner
 * map of hash/array_of_maps.
 */
#[allow(non_camel_case_types)]
#[repr(C)]
struct perf_event_array {
    r#type: *const [i32; maps::PERF_EVENT_ARRAY],
    key: *const u32,
    value: *const u32,
}
unsafe impl Sync for perf_event_array {}

#[link_section = ".maps"]
#[no_mangle]
static inner_map0: perf_event_array = perf_event_array {
    r#type: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
};

// .values = {&inner_map0}: scripts/btf_map_slots.py makes the BTF member
// the zero-length array libbpf wants.
#[allow(non_camel_case_types)]
#[repr(C)]
struct mim_array_pe_def {
    r#type: *const [i32; ARRAY_OF_MAPS],
    max_entries: *const [i32; 1],
    key: *const u32,
    values: [*const perf_event_array; 1],
}
unsafe impl Sync for mim_array_pe_def {}

#[link_section = ".maps"]
#[no_mangle]
static mim_array_pe: mim_array_pe_def = mim_array_pe_def {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key: core::ptr::null(),
    values: [&inner_map0],
};

#[allow(non_camel_case_types)]
#[repr(C)]
struct mim_hash_pe_def {
    r#type: *const [i32; HASH_OF_MAPS],
    max_entries: *const [i32; 1],
    key: *const u32,
    values: [*const perf_event_array; 1],
}
unsafe impl Sync for mim_hash_pe_def {}

#[link_section = ".maps"]
#[no_mangle]
static mim_hash_pe: mim_hash_pe_def = mim_hash_pe_def {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key: core::ptr::null(),
    values: [&inner_map0],
};

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct xdp_md {
    pub data: u32,
    pub data_end: u32,
    pub data_meta: u32,
    pub ingress_ifindex: u32,
    pub rx_queue_index: u32,
    pub egress_ifindex: u32,
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_mimtest0(_ctx: *mut xdp_md) -> i32 {
    let value: i32 = 123;
    let key: i32 = 0;

    let map = bpf_map_lookup_elem(&mim_array, &key);
    if map.is_null() {
        return XDP_DROP;
    }

    bpf_map_update_elem(map as *const c_void, &key, &value, 0);
    let value_p = bpf_map_lookup_elem(map as *const c_void, &key) as *mut i32;
    if value_p.is_null() || unsafe { *value_p } != 123 {
        return XDP_DROP;
    }

    let map = bpf_map_lookup_elem(&mim_hash, &key);
    if map.is_null() {
        return XDP_DROP;
    }

    bpf_map_update_elem(map as *const c_void, &key, &value, 0);

    XDP_PASS
}

bpf_object!("GPL");
