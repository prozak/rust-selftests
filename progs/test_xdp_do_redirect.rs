#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_xdp_do_redirect.c
// (bpf-rs-core idiom).

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_redirect, bpf_xdp_adjust_meta};
use bpf_rs_core::{bpf_object, vload};

const XDP_ABORTED: i32 = 0;
const XDP_DROP: i32 = 1;
const XDP_PASS: i32 = 2;
const XDP_REDIRECT: i32 = 4;

const IPPROTO_UDP: u8 = 17;

// enum frame_mark
const MARK_XMIT: u8 = 0x00;
const MARK_IN: u8 = 0x42;
const MARK_SKB: u8 = 0x45;

const ETH_HDR_SZ: usize = 14;
const IPV6_HDR_SZ: usize = 40;
const UDP_HDR_SZ: usize = 8;
const HDR_SZ: usize = ETH_HDR_SZ + IPV6_HDR_SZ + UDP_HDR_SZ;
// Offset of struct ipv6hdr.nexthdr within the packet (1 byte version/priority
// + 3 bytes flow_lbl + 2 bytes payload_len precede it).
const IPV6_NEXTHDR_OFF: usize = ETH_HDR_SZ + 6;

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

#[link_section = ".rodata"]
#[no_mangle]
static ifindex_out: i32 = 0;

#[link_section = ".rodata"]
#[no_mangle]
static ifindex_in: i32 = 0;

#[link_section = ".rodata"]
#[no_mangle]
static expect_dst: [u8; 6] = [0; 6];

#[no_mangle]
static mut pkts_seen_xdp: i32 = 0;

#[no_mangle]
static mut pkts_seen_zero: i32 = 0;

#[no_mangle]
static mut pkts_seen_tc: i32 = 0;

#[no_mangle]
static mut retcode: i32 = XDP_REDIRECT;

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_redirect(xdp: *const xdp_md) -> i32 {
    let data_meta = vload!((*xdp).data_meta) as usize;
    let data_end = vload!((*xdp).data_end) as usize;
    let data = vload!((*xdp).data) as usize;
    let ingress_ifindex = vload!((*xdp).ingress_ifindex);

    let payload = data + HDR_SZ;
    let ret = unsafe { retcode };

    if payload + 1 > data_end {
        return XDP_ABORTED;
    }

    let want_in = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(ifindex_in)) };
    if ingress_ifindex != want_in as u32 {
        return XDP_ABORTED;
    }

    if data_meta + core::mem::size_of::<u32>() > data {
        return XDP_ABORTED;
    }

    let meta_val = unsafe { core::ptr::read_volatile(data_meta as *const u32) };
    if meta_val != 0x42 {
        return XDP_ABORTED;
    }

    let payload_ptr = payload as *mut u8;
    let payload_val = unsafe { core::ptr::read_volatile(payload_ptr) };
    if payload_val == MARK_XMIT {
        unsafe { pkts_seen_zero += 1 };
    }

    unsafe { core::ptr::write_volatile(payload_ptr, MARK_IN) };

    if bpf_xdp_adjust_meta(xdp as *mut xdp_md, core::mem::size_of::<u64>() as i32) != 0 {
        return XDP_ABORTED;
    }

    if ret > XDP_PASS {
        unsafe { retcode = ret - 1 };
    }

    if ret == XDP_REDIRECT {
        let want_out = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(ifindex_out)) };
        return bpf_redirect(want_out as u32, 0) as i32;
    }

    ret
}

#[inline(always)]
fn check_pkt(data: usize, data_end: usize, mark: u8) -> bool {
    let payload = data + HDR_SZ;

    if payload + 1 > data_end {
        return false;
    }

    let nexthdr = unsafe { core::ptr::read_volatile((data + IPV6_NEXTHDR_OFF) as *const u8) };
    let payload_ptr = payload as *mut u8;
    let payload_val = unsafe { core::ptr::read_volatile(payload_ptr) };

    if nexthdr != IPPROTO_UDP || payload_val != MARK_IN {
        return false;
    }

    // Reset the payload so the same packet doesn't get counted twice when it
    // cycles back through the kernel path and out the dst veth.
    unsafe { core::ptr::write_volatile(payload_ptr, mark) };
    true
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_count_pkts(xdp: *const xdp_md) -> i32 {
    let data = vload!((*xdp).data) as usize;
    let data_end = vload!((*xdp).data_end) as usize;

    if check_pkt(data, data_end, MARK_XMIT) {
        unsafe { pkts_seen_xdp += 1 };
    }

    XDP_DROP
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_redirect_to_111(_xdp: *const xdp_md) -> i32 {
    bpf_redirect(111, 0) as i32
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_redirect_to_222(_xdp: *const xdp_md) -> i32 {
    bpf_redirect(222, 0) as i32
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn tc_count_pkts(skb: *const __sk_buff) -> i32 {
    let data = vload!((*skb).data) as usize;
    let data_end = vload!((*skb).data_end) as usize;

    if check_pkt(data, data_end, MARK_SKB) {
        unsafe { pkts_seen_tc += 1 };
    }

    0
}

bpf_object!("GPL");
