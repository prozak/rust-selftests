#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_xdp_with_devmap_frags_helpers.c,
// bpf-rs-core idiom.
//
// dm_ports uses key_size/value_size (not __type) in the C source, so its
// BTF map struct is the bpf_map! escape hatch (type/key_size/value_size/
// max_entries members, same __uint(...) pointer-array encoding as
// xdp_redirect_map.rs). value_size = sizeof(struct bpf_devmap_val) = 8
// (u32 ifindex + union{int fd; __u32 id} bpf_prog).

use bpf_rs_core::bpf_map;
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

bpf_map! {
    dm_ports {
        r#type: *const [i32; 14], // BPF_MAP_TYPE_DEVMAP = 14
        key_size: *const [i32; 4],
        value_size: *const [i32; 8],
        max_entries: *const [i32; 4],
    }
}

#[link_section = "xdp/devmap"]
#[no_mangle]
extern "C" fn xdp_dummy_dm(_ctx: *const xdp_md) -> i32 {
    XDP_PASS
}

#[link_section = "xdp.frags/devmap"]
#[no_mangle]
extern "C" fn xdp_dummy_dm_frags(_ctx: *const xdp_md) -> i32 {
    XDP_PASS
}

bpf_object!("GPL");
