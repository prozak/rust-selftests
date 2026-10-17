// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/timer_mim_reject.c
// (bpf-rs-core idiom).
//
// This is a negative-verifier-load test consumed by prog_tests/timer_mim.c's
// serial_test_timer_mim(): timer_mim_reject__open_and_load() must fail
// (ASSERT_ERR_PTR), because test1 initializes a timer stored in the map
// value looked up from outer_arr[ARRAY_KEY] (inner_htab) but passes
// inner_map2 (looked up from outer_arr[ARRAY_KEY2]) as the owning map to
// bpf_timer_init() — a map-identity mismatch the verifier must reject at
// load time, independent of the null checks' runtime reachability.
//
// outer_arr is BPF_MAP_TYPE_ARRAY_OF_MAPS with `.values = {[ARRAY_KEY] =
// &inner_htab}`, declared as `values: [*const InnerMap; 2]` with slot 0
// null; scripts/btf_map_slots.py rewrites the BTF member to the zero-length
// array libbpf demands.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_for_each_map_elem, bpf_map_lookup_elem, bpf_map_update_elem, bpf_timer_init,
    bpf_timer_set_callback, bpf_timer_start,
};
use core::ffi::c_void;
use bpf_rs_core::maps::{self, BpfMap};

const CLOCK_MONOTONIC: u64 = 1;
const ARRAY_KEY: i32 = 1;
const ARRAY_KEY2: i32 = 2;
const HASH_KEY: i32 = 1234;

// struct bpf_timer { __u64 __opaque[2]; } __attribute__((aligned(8)));
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_timer {
    __opaque: [u64; 2],
}

// struct hmap_elem { int pad; struct bpf_timer timer; };
#[allow(non_camel_case_types, dead_code)]
#[repr(C)]
struct hmap_elem {
    pad: i32,
    timer: bpf_timer,
}

// struct inner_map { __uint(type, HASH); __uint(max_entries, 1024);
// __type(key, int); __type(value, struct hmap_elem); } inner_htab SEC(".maps");
type InnerMap = BpfMap<i32, hmap_elem, { maps::HASH }, 1024>;

#[link_section = ".maps"]
#[no_mangle]
static inner_htab: InnerMap = InnerMap::new();

// struct outer_arr { __uint(type, ARRAY_OF_MAPS); __uint(max_entries, 2);
// __uint(key_size, sizeof(int)); __uint(value_size, sizeof(int));
// __array(values, struct inner_map); } outer_arr SEC(".maps") = {
//     .values = { [ARRAY_KEY] = &inner_htab },
// };
#[allow(non_camel_case_types)]
#[repr(C)]
struct outer_arr_def {
    r#type: *const [i32; 12], // BPF_MAP_TYPE_ARRAY_OF_MAPS
    max_entries: *const [i32; 2],
    key_size: *const [i32; 4],
    value_size: *const [i32; 4],
    values: [*const InnerMap; 2],
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

/// callback for inner hash map
extern "C" fn timer_cb(_map: *mut InnerMap, _key: *mut i32, _val: *mut hmap_elem) -> i64 {
    0
}

/// BPF_PROG(test1, int a)
#[link_section = "?fentry/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test1(_ctx: *const u64) -> i32 {
    // C: `struct hmap_elem init = {};` zeroes the padding after `pad` too.
    let init: hmap_elem = unsafe { core::mem::zeroed() };
    let array_key: i32 = ARRAY_KEY;
    let array_key2: i32 = ARRAY_KEY2;
    let hash_key: i32 = HASH_KEY;

    let inner_map = bpf_map_lookup_elem(&outer_arr, &array_key) as *mut InnerMap;
    if inner_map.is_null() {
        return 0;
    }

    let inner_map2 = bpf_map_lookup_elem(&outer_arr, &array_key2) as *mut InnerMap;
    if inner_map2.is_null() {
        return 0;
    }
    bpf_map_update_elem(inner_map, &hash_key, &init, 0);
    let val = bpf_map_lookup_elem(inner_map, &hash_key) as *mut hmap_elem;
    if val.is_null() {
        return 0;
    }

    unsafe {
        bpf_timer_init(
            core::ptr::addr_of_mut!((*val).timer),
            inner_map2,
            CLOCK_MONOTONIC,
        );
        if bpf_timer_set_callback(core::ptr::addr_of_mut!((*val).timer), timer_cb) != 0 {
            err |= 4;
        }
        if bpf_timer_start(core::ptr::addr_of_mut!((*val).timer), 0, 0) != 0 {
            err |= 8;
        }
    }
    0
}

#[repr(C)]
struct callback_ctx {
    map: *mut c_void,
}

extern "C" fn mismatch_iter_cb(
    _map: *mut InnerMap,
    _key: *mut i32,
    val: *mut hmap_elem,
    ctx: *mut callback_ctx,
) -> i64 {
    unsafe {
        bpf_timer_init(
            core::ptr::addr_of_mut!((*val).timer),
            (*ctx).map as *const c_void,
            CLOCK_MONOTONIC,
        );
    }
    0
}

extern "C" fn timer_mismatch_cb(map: *mut InnerMap, _key: *mut i32, _val: *mut hmap_elem) -> i64 {
    let mut ctx = callback_ctx { map: map as *mut c_void };
    let array_key2: i32 = ARRAY_KEY2;

    let inner_map2 = bpf_map_lookup_elem(&outer_arr, &array_key2) as *mut InnerMap;
    if inner_map2.is_null() {
        return 0;
    }
    bpf_for_each_map_elem(inner_map2, mismatch_iter_cb, &mut ctx, 0);
    0
}

extern "C" fn match_iter_cb(
    map: *mut InnerMap,
    _key: *mut i32,
    val: *mut hmap_elem,
    _ctx: *mut callback_ctx,
) -> i64 {
    unsafe {
        bpf_timer_init(core::ptr::addr_of_mut!((*val).timer), map, CLOCK_MONOTONIC);
    }
    0
}

extern "C" fn timer_match_cb(_map: *mut InnerMap, _key: *mut i32, _val: *mut hmap_elem) -> i64 {
    let mut ctx = callback_ctx { map: core::ptr::null_mut() };
    let array_key2: i32 = ARRAY_KEY2;

    let inner_map2 = bpf_map_lookup_elem(&outer_arr, &array_key2) as *mut InnerMap;
    if inner_map2.is_null() {
        return 0;
    }
    bpf_for_each_map_elem(inner_map2, match_iter_cb, &mut ctx, 0);
    0
}

/// BPF_PROG(callback_map_uid_mismatch, int a)
#[link_section = "?fentry/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn callback_map_uid_mismatch(_ctx: *const u64) -> i32 {
    let array_key: i32 = ARRAY_KEY;
    let hash_key: i32 = HASH_KEY;

    let inner_map = bpf_map_lookup_elem(&outer_arr, &array_key) as *mut InnerMap;
    if inner_map.is_null() {
        return 0;
    }
    let val = bpf_map_lookup_elem(inner_map, &hash_key) as *mut hmap_elem;
    if val.is_null() {
        return 0;
    }

    unsafe {
        bpf_timer_init(core::ptr::addr_of_mut!((*val).timer), inner_map, CLOCK_MONOTONIC);
        bpf_timer_set_callback(core::ptr::addr_of_mut!((*val).timer), timer_mismatch_cb);
    }
    0
}

/// BPF_PROG(callback_map_uid_match, int a)
#[link_section = "?fentry/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn callback_map_uid_match(_ctx: *const u64) -> i32 {
    let array_key: i32 = ARRAY_KEY;
    let hash_key: i32 = HASH_KEY;

    let inner_map = bpf_map_lookup_elem(&outer_arr, &array_key) as *mut InnerMap;
    if inner_map.is_null() {
        return 0;
    }
    let val = bpf_map_lookup_elem(inner_map, &hash_key) as *mut hmap_elem;
    if val.is_null() {
        return 0;
    }

    unsafe {
        bpf_timer_init(core::ptr::addr_of_mut!((*val).timer), inner_map, CLOCK_MONOTONIC);
        bpf_timer_set_callback(core::ptr::addr_of_mut!((*val).timer), timer_match_cb);
    }
    0
}

bpf_object!("GPL");
