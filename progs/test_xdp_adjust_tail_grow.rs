#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_xdp_adjust_tail_grow.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_xdp_adjust_tail, bpf_xdp_get_buff_len};

const XDP_DROP: i32 = 1;
const XDP_TX: i32 = 3;
const XDP_ABORTED: i32 = 0;

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
extern "C" fn _xdp_adjust_tail_grow(ctx: *const xdp_md) -> i32 {
    let data_len = bpf_xdp_get_buff_len(ctx as *mut xdp_md) as i32;
    let offset;

    /* SKB_DATA_ALIGN(sizeof(struct skb_shared_info)) */
    let tailroom: i32 = 320;

    /* Data length determine test case */
    if data_len == 54 {
        /* sizeof(pkt_v4) */
        offset = 4096; /* test too large offset, 4k page size */
    } else if data_len == 53 {
        /* sizeof(pkt_v4) - 1 */
        offset = 65536; /* test too large offset, 64k page size */
    } else if data_len == 74 {
        /* sizeof(pkt_v6) */
        offset = 40;
    } else if data_len == 64 {
        offset = 128;
    } else if data_len == 128 {
        /* Max tail grow 3520 */
        offset = 4096 - 256 - tailroom - data_len;
    } else if data_len == 9000 {
        offset = 10;
    } else if data_len == 9001 {
        offset = 4096;
    } else if data_len == 90000 {
        offset = 10; /* test a small offset, 64k page size */
    } else if data_len == 90001 {
        offset = 65536; /* test too large offset, 64k page size */
    } else {
        return XDP_ABORTED; /* No matching test */
    }

    if bpf_xdp_adjust_tail(ctx as *mut xdp_md, offset) != 0 {
        return XDP_DROP;
    }
    XDP_TX
}

bpf_object!("GPL");
