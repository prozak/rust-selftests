#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_xdp_devmap_tailcall.c, bpf-rs-core
// idiom.
//
// prog_tests/xdp_devmap_attach.c's test_xdp_devmap_tailcall() opens, sets
// expected_attach_type on both progs, then loads, asserting accept/reject
// per attach-type combo. The kernel decides that via PROG_ARRAY map
// ownership (kernel/bpf/core.c __bpf_prog_map_compatible /
// bpf_check_tail_call): the first program that references xdp_map through
// a real bpf_tail_call sets map->owner->expected_attach_type, and every
// later program referencing the same map must match it exactly.
//
// The C source establishes that ownership by pre-populating the map via
// `.values = { [0] = &xdp_devmap }` (an ELF relocation into a BTF
// zero-length array member — Rust can't reproduce a flexible-array-member
// field whose BTF type says 0 elements while its ELF data holds a real
// pointer, so that exact mechanism isn't portable here). Instead,
// xdp_devmap performs its own harmless out-of-range bpf_tail_call(..., 1)
// (index 1 is never populated, so it always falls through) purely so it
// also becomes a used_maps referrer of xdp_map. Since xdp_devmap is the
// first program loaded, it becomes xdp_map's owner with its own
// expected_attach_type, and xdp_entry's later bpf_tail_call is checked
// against it — reproducing the same four accept/reject outcomes as the C
// original's map-population approach.

use bpf_rs_core::helpers::bpf_tail_call;
use bpf_rs_core::{bpf_map, bpf_object, maps, vload};

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

bpf_map! {
    xdp_map {
        r#type: *const [i32; maps::PROG_ARRAY],
        max_entries: *const [i32; 1],
        key_size: *const [i32; 4],
        value_size: *const [i32; 4],
    }
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_devmap(ctx: *const xdp_md) -> i32 {
    bpf_tail_call(ctx as *const core::ffi::c_void, &xdp_map, 1);
    vload!((*ctx).egress_ifindex) as i32
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_entry(ctx: *const xdp_md) -> i32 {
    bpf_tail_call(ctx as *const core::ffi::c_void, &xdp_map, 0);
    0
}

bpf_object!("GPL");
