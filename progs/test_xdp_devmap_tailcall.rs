// SPDX-License-Identifier: GPL-2.0
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
// The C source establishes that ownership by pre-populating the map with
// `.values = { [0] = &xdp_devmap }`: libbpf stores xdp_devmap in slot 0 at
// load time, which makes it the owner, and xdp_entry's bpf_tail_call is then
// checked against it. `values: [XdpFn; 1]` emits the same .maps storage and
// .rel.maps entry as clang, and scripts/btf_map_slots.py rewrites the BTF
// member to the zero-length array libbpf demands (see TRANSLATING.md,
// "Statically-initialized `values` slots").

use bpf_rs_core::helpers::bpf_tail_call;
use bpf_rs_core::{bpf_object, maps, vload};

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

type XdpFn = extern "C" fn(*const xdp_md) -> i32;

#[allow(non_camel_case_types)]
#[repr(C)]
struct xdp_map {
    r#type: *const [i32; maps::PROG_ARRAY],
    max_entries: *const [i32; 1],
    key_size: *const [i32; 4],
    values: [XdpFn; 1],
}
unsafe impl Sync for xdp_map {}

#[link_section = ".maps"]
#[no_mangle]
static xdp_map: xdp_map = xdp_map {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key_size: core::ptr::null(),
    values: [xdp_devmap],
};

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_devmap(ctx: *const xdp_md) -> i32 {
    vload!((*ctx).egress_ifindex) as i32
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_entry(ctx: *const xdp_md) -> i32 {
    bpf_tail_call(ctx as *const core::ffi::c_void, &xdp_map, 0);
    0
}

bpf_object!("GPL");
