#![no_std]
#![no_main]

use bpf_rs_core::bpf_object;

const XDP_DROP: i32 = 1;

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

#[link_section = "freplace/xdp_prog1"]
#[no_mangle]
extern "C" fn new_xdp_prog2(_xd: *const xdp_md) -> i32 {
    XDP_DROP
}

bpf_object!("GPL");
