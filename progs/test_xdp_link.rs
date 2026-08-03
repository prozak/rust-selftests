#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_xdp_link.c
// (bpf-rs-core idiom). Two no-op programs used by prog_tests/xdp_link.c to
// exercise BPF_LINK_TYPE_XDP attach/detach/update semantics; the program
// bodies are irrelevant to the test, only their section types and names.

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;

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
extern "C" fn xdp_handler(_xdp: *const xdp_md) -> i32 {
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn tc_handler(_skb: *const __sk_buff) -> i32 {
    0
}

bpf_object!("GPL");
