#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/fd_htab_lookup.c, bpf-rs-core idiom.
//
// Maps-only object: no programs. `outer_map` is a BPF_MAP_TYPE_HASH_OF_MAPS
// whose `__array(values, struct inner_map_type)` member tells libbpf the
// inner map's layout (type/key_size/value_size/max_entries) so it can
// allocate a template inner map at outer-map-creation time — this can't use
// the `bpf_map!` escape hatch (which null-pointer-initializes every field)
// because `values` is a genuine zero-length *array* field (C's incomplete
// `typeof(val) *name[]`), not a `__uint`/`__type` pointer-encoded field. The
// C source's `.values = { [0] = &inner_map }` initializer additionally
// pre-populates outer_map[0] via an ELF relocation, but prog_tests.c's
// setup_htab() unconditionally overwrites keys 0..entries with fresh inner
// maps right after load, so the pre-population is inert and only the BTF
// shape (a real zero-element array, matching C's unpopulated flexible-array
// case) needs replicating.

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
    values: [*const InnerMapDef; 0],
}
unsafe impl Sync for OuterMapDef {}

#[link_section = ".maps"]
#[no_mangle]
static outer_map: OuterMapDef = OuterMapDef {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
    values: [],
};

bpf_object!("GPL");
