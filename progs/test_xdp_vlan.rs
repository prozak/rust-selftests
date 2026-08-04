#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_xdp_vlan.c
// (bpf-rs-core idiom).

use bpf_rs_core::ctx::{__sk_buff, TC_ACT_OK};
use bpf_rs_core::helpers::{bpf_skb_vlan_push, bpf_xdp_adjust_head};
use bpf_rs_core::{bpf_object, vload};

const XDP_ABORTED: i32 = 0;
const XDP_PASS: i32 = 2;

const ETH_P_8021Q: u16 = 0x8100;
const ETH_P_8021AD: u16 = 0x88A8;

const VLAN_VID_MASK: u16 = 0x0fff;

const ETH_ALEN: usize = 6;
const VLAN_HDR_SZ: usize = 4;

const TESTVLAN: u16 = 4011; /* 0xFAB */
const TO_VLAN: u16 = 0;

#[inline(always)]
fn htons(x: u16) -> u16 {
    x.to_be()
}

#[inline(always)]
fn ntohs(x: u16) -> u16 {
    u16::from_be(x)
}

/// Byte-at-a-time volatile copy, used as a backward (high-to-low) memmove:
/// dst > src overlapping forward shifts must copy from the tail first, else
/// bytes get clobbered before they're read. Plain slice/array copies of
/// this size also risk LLVM's MemCpyOpt rewriting them into an extern
/// bpf_arena_memcpy kfunc call, which doesn't resolve outside arena progs.
#[inline(always)]
unsafe fn vmove_fwd(dst: *mut u8, src: *const u8, len: usize) {
    let mut i = len;
    while i > 0 {
        i -= 1;
        core::ptr::write_volatile(dst.add(i), core::ptr::read_volatile(src.add(i)));
    }
}

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

// struct ethhdr (linux/if_ether.h) — packed, purely local (packet-payload
// pointer arithmetic, never matched against kernel BTF by name).
#[repr(C, packed)]
struct EthHdr {
    h_dest: [u8; ETH_ALEN],
    h_source: [u8; ETH_ALEN],
    h_proto: u16,
}

// struct _vlan_hdr (test_xdp_vlan.c's own mirror of the non-UAPI VLAN
// header) — packed.
#[repr(C, packed)]
struct VlanHdr {
    h_vlan_tci: u16,
    h_vlan_encapsulated_proto: u16,
}

// struct parse_pkt (test_xdp_vlan.c) — a purely local scratch struct, never
// touched by userspace.
#[derive(Clone, Copy)]
struct ParsePkt {
    l3_proto: u16,
    l3_offset: u16,
    vlan_outer: u16,
    vlan_inner: u16,
    vlan_outer_offset: u8,
    vlan_inner_offset: u8,
}

const PARSE_PKT_ZERO: ParsePkt = ParsePkt {
    l3_proto: 0,
    l3_offset: 0,
    vlan_outer: 0,
    vlan_inner: 0,
    vlan_outer_offset: 0,
    vlan_inner_offset: 0,
};

#[inline(always)]
fn parse_eth_frame(eth: *const u8, data_end: *const u8, pkt: &mut ParsePkt) -> bool {
    let mut offset: u8 = core::mem::size_of::<EthHdr>() as u8;

    // Make sure packet is large enough for parsing eth + 2 VLAN headers.
    if unsafe { eth.add(offset as usize).add(2 * core::mem::size_of::<VlanHdr>()) } > data_end {
        return false;
    }

    let eth_hdr = eth as *const EthHdr;
    let mut eth_type: u16 = unsafe { (*eth_hdr).h_proto };

    // Handle outer VLAN tag.
    if eth_type == htons(ETH_P_8021Q) || eth_type == htons(ETH_P_8021AD) {
        let vlan_hdr = unsafe { eth.add(offset as usize) } as *const VlanHdr;
        pkt.vlan_outer_offset = offset;
        pkt.vlan_outer = ntohs(unsafe { (*vlan_hdr).h_vlan_tci }) & VLAN_VID_MASK;
        eth_type = unsafe { (*vlan_hdr).h_vlan_encapsulated_proto };
        offset += core::mem::size_of::<VlanHdr>() as u8;
    }

    // Handle inner (double) VLAN tag.
    if eth_type == htons(ETH_P_8021Q) || eth_type == htons(ETH_P_8021AD) {
        let vlan_hdr = unsafe { eth.add(offset as usize) } as *const VlanHdr;
        pkt.vlan_inner_offset = offset;
        pkt.vlan_inner = ntohs(unsafe { (*vlan_hdr).h_vlan_tci }) & VLAN_VID_MASK;
        eth_type = unsafe { (*vlan_hdr).h_vlan_encapsulated_proto };
        offset += core::mem::size_of::<VlanHdr>() as u8;
    }

    pkt.l3_proto = ntohs(eth_type); /* Convert to host-byte-order */
    pkt.l3_offset = offset as u16;

    true
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_drop_vlan_4011(ctx: *const xdp_md) -> i32 {
    let data_end = vload!((*ctx).data_end) as usize as *const u8;
    let data = vload!((*ctx).data) as usize as *const u8;
    let mut pkt = PARSE_PKT_ZERO;

    if !parse_eth_frame(data, data_end, &mut pkt) {
        return XDP_ABORTED;
    }

    /* Drop specific VLAN ID example */
    if pkt.vlan_outer == TESTVLAN {
        return XDP_ABORTED;
    }

    XDP_PASS
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_vlan_change(ctx: *const xdp_md) -> i32 {
    let data_end = vload!((*ctx).data_end) as usize as *const u8;
    let data = vload!((*ctx).data) as usize as *const u8;
    let mut pkt = PARSE_PKT_ZERO;

    if !parse_eth_frame(data, data_end, &mut pkt) {
        return XDP_ABORTED;
    }

    /* Change specific VLAN ID */
    if pkt.vlan_outer == TESTVLAN {
        let vlan_hdr = unsafe { data.add(pkt.vlan_outer_offset as usize) } as *mut VlanHdr;

        /* Modifying VLAN, preserve top 4 bits */
        let cur = unsafe { (*vlan_hdr).h_vlan_tci };
        unsafe {
            (*vlan_hdr).h_vlan_tci = htons((ntohs(cur) & 0xf000u16) | TO_VLAN);
        }
    }

    XDP_PASS
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_vlan_remove_outer(ctx: *mut xdp_md) -> i32 {
    let data_end = vload!((*ctx).data_end) as usize as *const u8;
    let data = vload!((*ctx).data) as usize as *const u8;
    let mut pkt = PARSE_PKT_ZERO;

    if !parse_eth_frame(data, data_end, &mut pkt) {
        return XDP_ABORTED;
    }

    /* Skip packet if no outer VLAN was detected */
    if pkt.vlan_outer_offset == 0 {
        return XDP_PASS;
    }

    /* Moving Ethernet header, dest overlap with src, memmove handle this */
    let dest = unsafe { data.add(VLAN_HDR_SZ) } as *mut u8;
    /*
     * Notice: Taking over vlan_hdr->h_vlan_encapsulated_proto, by
     * only moving two MAC addrs (12 bytes), not overwriting last 2 bytes
     */
    unsafe { vmove_fwd(dest, data, ETH_ALEN * 2) };

    /* Move start of packet header seen by Linux kernel stack */
    bpf_xdp_adjust_head(ctx, VLAN_HDR_SZ as i32);

    XDP_PASS
}

#[inline(always)]
fn shift_mac_4bytes_32bit(data: *mut u8) {
    /* Assuming VLAN hdr present. The 4 bytes in p[3] that gets
     * overwritten, is ethhdr->h_proto and vlan_hdr->h_vlan_TCI.
     * The vlan_hdr->h_vlan_encapsulated_proto take over role as
     * ethhdr->h_proto.
     */
    unsafe { vmove_fwd(data.add(VLAN_HDR_SZ), data, ETH_ALEN * 2) };
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_vlan_remove_outer2(ctx: *mut xdp_md) -> i32 {
    let data_end = vload!((*ctx).data_end) as usize as *const u8;
    let data = vload!((*ctx).data) as usize as *const u8;
    let mut pkt = PARSE_PKT_ZERO;

    if !parse_eth_frame(data, data_end, &mut pkt) {
        return XDP_ABORTED;
    }

    /* Skip packet if no outer VLAN was detected */
    if pkt.vlan_outer_offset == 0 {
        return XDP_PASS;
    }

    /* Simply shift down MAC addrs 4 bytes, overwrite h_proto + TCI */
    shift_mac_4bytes_32bit(data as *mut u8);

    /* Move start of packet header seen by Linux kernel stack */
    bpf_xdp_adjust_head(ctx, VLAN_HDR_SZ as i32);

    XDP_PASS
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn tc_vlan_push(ctx: *mut __sk_buff) -> i32 {
    bpf_skb_vlan_push(ctx, htons(ETH_P_8021Q), TESTVLAN);

    TC_ACT_OK
}

bpf_object!("GPL");
