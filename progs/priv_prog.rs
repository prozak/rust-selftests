#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/priv_prog.c,
// bpf-rs-core idiom. Trivial XDP program used as a token/privilege-check
// target (token.c's obj_priv_prog* subtests) and as an freplace attach
// target (priv_freplace_prog.c targets "xdp_prog1").

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

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_prog1(_xdp: *const xdp_md) -> i32 {
    XDP_DROP
}

bpf_object!("GPL");
