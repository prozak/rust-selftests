// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/fd_htab_lookup.c, bpf-rs-core idiom.
//
// Maps-only object: no programs. `outer_map` is a BPF_MAP_TYPE_HASH_OF_MAPS
// whose `__array(values, struct inner_map_type)` member tells libbpf the
// inner map's layout, and whose `.values = { [0] = &inner_map }` initializer
// stores inner_map under key 0 at load time. It is written out by hand
// because `bpf_map!` null-initializes every field. `[T; 1]` emits the slot
// storage and its .rel.maps entry; scripts/btf_map_slots.py rewrites the BTF
// member to the zero-length array libbpf demands.

use bpf_rs_core::bpf_object;
use bpf_rs_core::maps;

const HASH_OF_MAPS: usize = 13;

#[repr(C)]
struct InnerMapDef {
    r#type: *const [i32; maps::ARRAY],
    key_size: *const [i32; 4],
    value_size: *const [i32; 4],
    max_entries: *const [i32; 1],
}
unsafe impl Sync for InnerMapDef {}

#[link_section = ".maps"]
#[no_mangle]
static inner_map: InnerMapDef = InnerMapDef {
    r#type: core::ptr::null(),
    key_size: core::ptr::null(),
    value_size: core::ptr::null(),
    max_entries: core::ptr::null(),
};

#[repr(C)]
struct OuterMapDef {
    r#type: *const [i32; HASH_OF_MAPS],
    max_entries: *const [i32; 64],
    key: *const i32,
    value: *const i32,
    values: [*const InnerMapDef; 1],
}
unsafe impl Sync for OuterMapDef {}

#[link_section = ".maps"]
#[no_mangle]
static outer_map: OuterMapDef = OuterMapDef {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
    values: [&inner_map],
};

bpf_object!("GPL");
