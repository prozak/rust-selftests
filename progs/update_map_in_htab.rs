#![no_std]
#![no_main]

use bpf_rs_core::bpf_object;

// struct inner_map_type { __uint(type, ARRAY); __uint(key_size, 4);
// __uint(value_size, 4); __uint(max_entries, 1); } — sized map def, no
// __type(key/value), so this needs the raw member encoding rather than the
// BpfMap<K, V, TYPE, MAX> generic (which assumes typed key/value).
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

// struct { __uint(type, HASH_OF_MAPS); __type(key, int); __type(value, int);
// __uint(max_entries, 2); __array(values, struct inner_map_type); } —
// __array(values, val) expands to `typeof(val) *values[]`: a flexible array
// member of pointers to the inner map's def struct, encoded here as a
// zero-length Rust array of the same pointer type.
#[allow(non_camel_case_types)]
#[repr(C)]
struct outer_htab_map_def {
    r#type: *const [i32; 13], // BPF_MAP_TYPE_HASH_OF_MAPS
    key: *const i32,
    value: *const i32,
    max_entries: *const [i32; 2],
    values: [*const inner_map_type; 0],
}
unsafe impl Sync for outer_htab_map_def {}

#[link_section = ".maps"]
#[no_mangle]
static outer_htab_map: outer_htab_map_def = outer_htab_map_def {
    r#type: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
    max_entries: core::ptr::null(),
    values: [],
};

// struct { __uint(type, HASH_OF_MAPS); __uint(map_flags, BPF_F_NO_PREALLOC);
// __type(key, int); __type(value, int); __uint(max_entries, 2);
// __array(values, struct inner_map_type); }
#[allow(non_camel_case_types)]
#[repr(C)]
struct outer_alloc_htab_map_def {
    r#type: *const [i32; 13], // BPF_MAP_TYPE_HASH_OF_MAPS
    map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
    key: *const i32,
    value: *const i32,
    max_entries: *const [i32; 2],
    values: [*const inner_map_type; 0],
}
unsafe impl Sync for outer_alloc_htab_map_def {}

#[link_section = ".maps"]
#[no_mangle]
static outer_alloc_htab_map: outer_alloc_htab_map_def = outer_alloc_htab_map_def {
    r#type: core::ptr::null(),
    map_flags: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
    max_entries: core::ptr::null(),
    values: [],
};

bpf_object!("GPL");
