#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_map_in_map_invalid.c (bpf-rs-core
// idiom).
//
// The ARRAY_OF_MAPS declares max_entries 0, which makes map CREATION fail —
// that is the whole point of the test (prog_tests/map_in_map.c's
// test_map_in_map_create_fail). The single program is a no-op that exists
// only so the object has something to load. Map definitions use the
// explicit-struct form, as access_map_in_map.rs does, because the typed
// wrapper has no `values` member.

use bpf_rs_core::bpf_object;

const XDP_PASS: i32 = 2;

/// UAPI struct xdp_md (linux/bpf.h).
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

#[allow(non_camel_case_types)]
#[repr(C)]
struct inner {
    r#type: *const [i32; 2], // BPF_MAP_TYPE_ARRAY
    key: *const u32,
    value: *const i32,
    max_entries: *const [i32; 4],
}
unsafe impl Sync for inner {}

#[allow(non_camel_case_types)]
#[repr(C)]
struct mim_def {
    r#type: *const [i32; 12], // BPF_MAP_TYPE_ARRAY_OF_MAPS
    // 0 entries: the map is MEANT to fail creation
    max_entries: *const [i32; 0],
    key: *const u32,
    values: [*const inner; 0],
}
unsafe impl Sync for mim_def {}

#[link_section = ".maps"]
#[no_mangle]
static mim: mim_def = mim_def {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key: core::ptr::null(),
    values: [],
};

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_noop0(_ctx: *const xdp_md) -> i32 {
    XDP_PASS
}

bpf_object!("GPL");
