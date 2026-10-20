// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/xdp_hw_metadata.c
// (bpf-rs-core idiom, after xdp_metadata.rs). The xdp_hw_metadata user
// program attaches `rx` to a real NIC and reads the per-packet RX metadata
// the program exports in front of the frames it redirects to AF_XDP (UDP
// port 9091 only, VLAN tags skipped): the HW timestamp, hash and VLAN tag
// kfuncs' results or errors, and the `pkts_*` counters. NO-ORACLE: it
// needs hardware with RX metadata support; the prover is the evidence.
//
// struct xdp_meta (xdp_metadata.h) is field-for-field offset-identical to
// the C's anonymous unions (each union's size is its largest member); the
// `*_err` members alias the fields they report on, so they are written
// through the same offsets. The packet walk keeps the C's pointer
// comparisons as usize arithmetic (xdp_metadata.rs).

use core::ptr::{addr_of, addr_of_mut, read_unaligned};

use bpf_rs_core::helpers::{bpf_ktime_get_tai_ns, bpf_redirect_map, bpf_xdp_adjust_meta, sync_fetch_and_add_u64};
use bpf_rs_core::maps::BpfMap;
use bpf_rs_core::{bpf_object, vload};

const XDP_PASS: i32 = 2;

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const ETH_P_8021Q: u16 = 0x8100;
const ETH_P_8021AD: u16 = 0x88A8;
const IPPROTO_UDP: u8 = 17;

/* enum xdp_meta_field */
const XDP_META_FIELD_TS: u32 = 1 << 0;
const XDP_META_FIELD_RSS: u32 = 1 << 1;
const XDP_META_FIELD_VLAN_TAG: u32 = 1 << 2;

#[inline(always)]
fn htons(x: u16) -> u16 {
    x.to_be()
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

#[repr(C, packed)]
struct ethhdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

#[repr(C, packed)]
struct vlan_hdr {
    h_vlan_tci: u16,
    h_vlan_encapsulated_proto: u16,
}

#[repr(C, packed)]
struct iphdr {
    ihl_version: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    check: u16,
    saddr: u32,
    daddr: u32,
}

#[repr(C, packed)]
struct ipv6hdr {
    version_priority: u8,
    flow_lbl: [u8; 3],
    payload_len: u16,
    nexthdr: u8,
    hop_limit: u8,
    saddr: [u8; 16],
    daddr: [u8; 16],
}

#[repr(C, packed)]
struct udphdr {
    source: u16,
    dest: u16,
    len: u16,
    check: u16,
}

/// struct xdp_meta (xdp_metadata.h), see the module comment.
#[repr(C)]
struct xdp_meta {
    rx_timestamp: u64, // union with __s32 rx_timestamp_err
    xdp_timestamp: u64,
    rx_hash: u32,
    rx_hash_type: u32, // union with __s32 rx_hash_err
    rx_vlan_proto: u16, // union { struct { rx_vlan_proto, rx_vlan_tci }; __s32 rx_vlan_tag_err }
    rx_vlan_tci: u16,
    hint_valid: u32,
}

#[link_section = ".maps"]
#[no_mangle]
static xsk: BpfMap<u32, u32, 17, 256> = BpfMap::new(); // BPF_MAP_TYPE_XSKMAP = 17

#[no_mangle]
static mut pkts_skip: u64 = 0;
#[no_mangle]
static mut pkts_fail: u64 = 0;
#[no_mangle]
static mut pkts_redir: u64 = 0;

extern "C" {
    fn bpf_xdp_metadata_rx_timestamp(ctx: *const xdp_md, timestamp: *mut u64) -> i32;
    // enum xdp_rss_hash_type has underlying type int, same layout as u32.
    fn bpf_xdp_metadata_rx_hash(ctx: *const xdp_md, hash: *mut u32, rss_type: *mut u32) -> i32;
    fn bpf_xdp_metadata_rx_vlan_tag(ctx: *const xdp_md, vlan_proto: *mut u16, vlan_tci: *mut u16) -> i32;
}

#[link_section = "xdp.frags"]
#[no_mangle]
extern "C" fn rx(ctx: *const xdp_md) -> i32 {
    let data = vload!((*ctx).data) as usize;
    let data_end = vload!((*ctx).data_end) as usize;

    let mut eth = data;
    let mut udp: usize = 0;

    if eth + core::mem::size_of::<ethhdr>() < data_end {
        let h_proto = unsafe { read_unaligned(addr_of!((*(eth as *const ethhdr)).h_proto)) };
        if h_proto == htons(ETH_P_8021AD) || h_proto == htons(ETH_P_8021Q) {
            eth += core::mem::size_of::<vlan_hdr>();
        }
    }

    if eth + core::mem::size_of::<ethhdr>() < data_end
        && unsafe { read_unaligned(addr_of!((*(eth as *const ethhdr)).h_proto)) } == htons(ETH_P_8021Q)
    {
        eth += core::mem::size_of::<vlan_hdr>();
    }

    if eth + core::mem::size_of::<ethhdr>() < data_end {
        let h_proto = unsafe { read_unaligned(addr_of!((*(eth as *const ethhdr)).h_proto)) };

        if h_proto == htons(ETH_P_IP) {
            let iph_addr = eth + core::mem::size_of::<ethhdr>();
            if iph_addr + core::mem::size_of::<iphdr>() < data_end
                && unsafe { read_unaligned(addr_of!((*(iph_addr as *const iphdr)).protocol)) } == IPPROTO_UDP
            {
                udp = iph_addr + core::mem::size_of::<iphdr>();
            }
        }
        if h_proto == htons(ETH_P_IPV6) {
            let ip6h_addr = eth + core::mem::size_of::<ethhdr>();
            if ip6h_addr + core::mem::size_of::<ipv6hdr>() < data_end
                && unsafe { read_unaligned(addr_of!((*(ip6h_addr as *const ipv6hdr)).nexthdr)) } == IPPROTO_UDP
            {
                udp = ip6h_addr + core::mem::size_of::<ipv6hdr>();
            }
        }
        if udp != 0 && udp + core::mem::size_of::<udphdr>() > data_end {
            udp = 0;
        }
    }

    if udp == 0 {
        sync_fetch_and_add_u64(unsafe { addr_of_mut!(pkts_skip) }, 1);
        return XDP_PASS;
    }

    /* Forwarding UDP:9091 to AF_XDP */
    let dest = unsafe { read_unaligned(addr_of!((*(udp as *const udphdr)).dest)) };
    if dest != htons(9091) {
        sync_fetch_and_add_u64(unsafe { addr_of_mut!(pkts_skip) }, 1);
        return XDP_PASS;
    }

    let err = bpf_xdp_adjust_meta(ctx as *mut xdp_md, -(core::mem::size_of::<xdp_meta>() as i32));
    if err != 0 {
        sync_fetch_and_add_u64(unsafe { addr_of_mut!(pkts_fail) }, 1);
        return XDP_PASS;
    }

    let data = vload!((*ctx).data) as usize;
    let data_meta = vload!((*ctx).data_meta) as usize;
    let meta = data_meta as *mut xdp_meta;

    if data_meta + core::mem::size_of::<xdp_meta>() > data {
        sync_fetch_and_add_u64(unsafe { addr_of_mut!(pkts_fail) }, 1);
        return XDP_PASS;
    }

    unsafe {
        (*meta).hint_valid = 0;

        (*meta).xdp_timestamp = bpf_ktime_get_tai_ns();

        let err = bpf_xdp_metadata_rx_timestamp(ctx, addr_of_mut!((*meta).rx_timestamp));
        if err != 0 {
            *(addr_of_mut!((*meta).rx_timestamp) as *mut i32) = err; /* rx_timestamp_err */
        } else {
            (*meta).hint_valid |= XDP_META_FIELD_TS;
        }

        let err = bpf_xdp_metadata_rx_hash(ctx, addr_of_mut!((*meta).rx_hash), addr_of_mut!((*meta).rx_hash_type));
        if err != 0 {
            *(addr_of_mut!((*meta).rx_hash_type) as *mut i32) = err; /* rx_hash_err */
        } else {
            (*meta).hint_valid |= XDP_META_FIELD_RSS;
        }

        let err = bpf_xdp_metadata_rx_vlan_tag(ctx, addr_of_mut!((*meta).rx_vlan_proto), addr_of_mut!((*meta).rx_vlan_tci));
        if err != 0 {
            *(addr_of_mut!((*meta).rx_vlan_proto) as *mut i32) = err; /* rx_vlan_tag_err */
        } else {
            (*meta).hint_valid |= XDP_META_FIELD_VLAN_TAG;
        }

        sync_fetch_and_add_u64(addr_of_mut!(pkts_redir), 1);
    }
    let rx_queue_index = vload!((*ctx).rx_queue_index) as u64;
    bpf_redirect_map(&xsk, rx_queue_index, XDP_PASS as u64) as i32
}

bpf_object!("GPL");
