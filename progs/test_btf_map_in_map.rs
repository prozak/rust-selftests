// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_btf_map_in_map.c.
//
// Every outer map here (`outer_arr`, `outer_hash`, `outer_arr_dyn`,
// `outer_sockarr`) has a C `.values = {...}` initializer that fills slots at
// load time. Each `values` member is declared with its real length and
// targets (null where the C leaves a hole), and scripts/btf_map_slots.py
// rewrites the BTF member to the zero-length array libbpf demands. The C
// casts a target to `void *` where its type is not the declared inner type;
// the pointer casts below are those.

use bpf_rs_core::helpers::{bpf_map_lookup_elem, bpf_map_update_elem};
use bpf_rs_core::{bpf_map, bpf_object};
use bpf_rs_core::maps::{self, BpfMap};
use core::ffi::c_void;

const ARRAY_OF_MAPS: usize = 12;
const HASH_OF_MAPS: usize = 13;
const REUSEPORT_SOCKARRAY: usize = 20;
const BPF_F_INNER_MAP: usize = 1 << 12;

// struct inner_map { __uint(type, ARRAY); __uint(max_entries, 1);
// __type(key, int); __type(value, int); } inner_map1, inner_map2 SEC(".maps");
type InnerMap = BpfMap<i32, i32, { maps::ARRAY }, 1>;

#[link_section = ".maps"]
#[no_mangle]
static inner_map1: InnerMap = InnerMap::new();

#[link_section = ".maps"]
#[no_mangle]
static inner_map2: InnerMap = InnerMap::new();

// struct inner_map_sz2 { __uint(type, ARRAY); __uint(max_entries, 2);
// __type(key, int); __type(value, int); } inner_map_sz2 SEC(".maps");
type InnerMapSz2 = BpfMap<i32, i32, { maps::ARRAY }, 2>;

#[link_section = ".maps"]
#[no_mangle]
static inner_map_sz2: InnerMapSz2 = InnerMapSz2::new();

// struct outer_arr { __uint(type, ARRAY_OF_MAPS); __uint(max_entries, 3);
// __type(key, int); __type(value, int);
// __array(values, struct { ...same shape as struct inner_map... });
// } outer_arr SEC(".maps") = { .values = { &inner_map1, 0, &inner_map2 } };
#[repr(C)]
struct outer_arr_def {
    r#type: *const [i32; ARRAY_OF_MAPS],
    max_entries: *const [i32; 3],
    key: *const i32,
    value: *const i32,
    values: [*const InnerMap; 3],
}
unsafe impl Sync for outer_arr_def {}

#[link_section = ".maps"]
#[no_mangle]
static outer_arr: outer_arr_def = outer_arr_def {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
    values: [&inner_map1, core::ptr::null(), &inner_map2],
};

// struct inner_map_sz3 { __uint(type, ARRAY); __uint(map_flags, BPF_F_INNER_MAP);
// __uint(max_entries, 3); __type(key, int); __type(value, int);
// } inner_map3, inner_map4 SEC(".maps");
bpf_map! {
    inner_map3 {
        r#type: *const [i32; maps::ARRAY],
        map_flags: *const [i32; BPF_F_INNER_MAP],
        max_entries: *const [i32; 3],
        key: *const i32,
        value: *const i32,
    }
}

bpf_map! {
    inner_map4 {
        r#type: *const [i32; maps::ARRAY],
        map_flags: *const [i32; BPF_F_INNER_MAP],
        max_entries: *const [i32; 3],
        key: *const i32,
        value: *const i32,
    }
}

// struct inner_map_sz4 { __uint(type, ARRAY); __uint(map_flags, BPF_F_INNER_MAP);
// __uint(max_entries, 5); __type(key, int); __type(value, int);
// } inner_map5 SEC(".maps");
bpf_map! {
    inner_map5 {
        r#type: *const [i32; maps::ARRAY],
        map_flags: *const [i32; BPF_F_INNER_MAP],
        max_entries: *const [i32; 5],
        key: *const i32,
        value: *const i32,
    }
}

// outer_arr_dyn's anonymous `__array(values, struct {...})` template: ARRAY,
// BPF_F_INNER_MAP, max_entries 1 — distinct from inner_map3/4/5's own shape
// (max_entries 3/3/5); it is the `values` pointee type.
#[allow(non_camel_case_types)]
#[repr(C)]
struct inner_map_dyn_tmpl {
    r#type: *const [i32; maps::ARRAY],
    map_flags: *const [i32; BPF_F_INNER_MAP],
    max_entries: *const [i32; 1],
    key: *const i32,
    value: *const i32,
}

// struct outer_arr_dyn { __uint(type, ARRAY_OF_MAPS); __uint(max_entries, 3);
// __type(key, int); __type(value, int); __array(values, struct {...});
// } outer_arr_dyn SEC(".maps") = {
//     .values = { [0] = &inner_map3, [1] = &inner_map4, [2] = &inner_map5 },
// };
#[repr(C)]
struct outer_arr_dyn_def {
    r#type: *const [i32; ARRAY_OF_MAPS],
    max_entries: *const [i32; 3],
    key: *const i32,
    value: *const i32,
    values: [*const inner_map_dyn_tmpl; 3],
}
unsafe impl Sync for outer_arr_dyn_def {}

#[link_section = ".maps"]
#[no_mangle]
static outer_arr_dyn: outer_arr_dyn_def = outer_arr_dyn_def {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
    values: [
        &inner_map3 as *const inner_map3 as *const inner_map_dyn_tmpl,
        &inner_map4 as *const inner_map4 as *const inner_map_dyn_tmpl,
        &inner_map5 as *const inner_map5 as *const inner_map_dyn_tmpl,
    ],
};

// struct outer_hash { __uint(type, HASH_OF_MAPS); __uint(max_entries, 5);
// __type(key, int); __array(values, struct inner_map);
// } outer_hash SEC(".maps") = { .values = { [0] = &inner_map2, [4] = &inner_map1 } };
#[repr(C)]
struct outer_hash_def {
    r#type: *const [i32; HASH_OF_MAPS],
    max_entries: *const [i32; 5],
    key: *const i32,
    values: [*const InnerMap; 5],
}
unsafe impl Sync for outer_hash_def {}

#[link_section = ".maps"]
#[no_mangle]
static outer_hash: outer_hash_def = outer_hash_def {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key: core::ptr::null(),
    values: [
        &inner_map2,
        core::ptr::null(),
        core::ptr::null(),
        core::ptr::null(),
        &inner_map1,
    ],
};

// struct sockarr_sz1/sz2 { __uint(type, REUSEPORT_SOCKARRAY);
// __uint(max_entries, 1/2); __type(key, int); __type(value, int); }
type SockArrSz1 = BpfMap<i32, i32, REUSEPORT_SOCKARRAY, 1>;
type SockArrSz2 = BpfMap<i32, i32, REUSEPORT_SOCKARRAY, 2>;

#[link_section = ".maps"]
#[no_mangle]
static sockarr_sz1: SockArrSz1 = SockArrSz1::new();

#[link_section = ".maps"]
#[no_mangle]
static sockarr_sz2: SockArrSz2 = SockArrSz2::new();

// struct outer_sockarr_sz1 { __uint(type, ARRAY_OF_MAPS); __uint(max_entries, 1);
// __type(key, int); __type(value, int); __array(values, struct sockarr_sz1);
// } outer_sockarr SEC(".maps") = { .values = { &sockarr_sz1 } };
#[repr(C)]
struct outer_sockarr_def {
    r#type: *const [i32; ARRAY_OF_MAPS],
    max_entries: *const [i32; 1],
    key: *const i32,
    value: *const i32,
    values: [*const SockArrSz1; 1],
}
unsafe impl Sync for outer_sockarr_def {}

#[link_section = ".maps"]
#[no_mangle]
static outer_sockarr: outer_sockarr_def = outer_sockarr_def {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
    values: [&sockarr_sz1],
};

// int input = 0;
#[no_mangle]
static mut input: i32 = 0;

// SEC("raw_tp/sys_enter")
// int handle__sys_enter(void *ctx)
#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn handle__sys_enter(_ctx: *const c_void) -> i32 {
    let key: i32 = 0;

    let inner = bpf_map_lookup_elem(&outer_arr, &key);
    if inner.is_null() {
        return 1;
    }
    let val: i32 = unsafe { input };
    bpf_map_update_elem(inner as *const c_void, &key, &val, 0);

    let inner = bpf_map_lookup_elem(&outer_hash, &key);
    if inner.is_null() {
        return 1;
    }
    let val: i32 = unsafe { input } + 1;
    bpf_map_update_elem(inner as *const c_void, &key, &val, 0);

    let inner = bpf_map_lookup_elem(&outer_arr_dyn, &key);
    if inner.is_null() {
        return 1;
    }
    let val: i32 = unsafe { input } + 2;
    bpf_map_update_elem(inner as *const c_void, &key, &val, 0);

    0
}

bpf_object!("GPL");
