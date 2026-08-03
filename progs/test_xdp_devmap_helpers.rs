#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_xdp_devmap_helpers.c
// (bpf-rs-core idiom).
//
// fails to load without expected_attach_type = BPF_XDP_DEVMAP because of
// access to egress_ifindex

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_trace_printk;
use bpf_rs_core::vload;

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

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdpdm_devlog(ctx: *const xdp_md) -> i32 {
    let fmt: [u8; 42] = *b"devmap redirect: dev %u -> dev %u len %u\n\0";
    let data_end = vload!((*ctx).data_end) as usize;
    let data = vload!((*ctx).data) as usize;
    let len = (data_end - data) as u32;

    let ingress_ifindex = vload!((*ctx).ingress_ifindex);
    let egress_ifindex = vload!((*ctx).egress_ifindex);

    bpf_trace_printk(
        fmt.as_ptr() as *const core::ffi::c_void,
        fmt.len() as u32,
        ingress_ifindex as u64,
        egress_ifindex as u64,
        len as u64,
    );

    XDP_PASS
}

bpf_object!("GPL");
