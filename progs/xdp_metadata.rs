#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/xdp_metadata.c
// (bpf-rs-core idiom).
//
// `xsk`/`dev_map` use non-generic member sets (XSKMAP has no maps::XSKMAP
// const yet; dev_map uses key_size/value_size, not __type) so dev_map goes
// through the bpf_map! escape hatch; xsk fits BpfMap's generic shape with
// the raw enum bpf_map_type literal (17) as the const-generic TYPE param.
//
// struct xdp_meta (xdp_metadata.h) is field-for-field offset-identical to
// the C source's anonymous unions: this program only ever reads/writes the
// members listed here, and each C union's size equals its largest member,
// so a plain (non-packed) struct in declaration order reproduces every
// offset the userspace test relies on.

use bpf_rs_core::bpf_map;
use bpf_rs_core::helpers::{bpf_redirect_map, bpf_xdp_adjust_meta};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::{bpf_object, vload};

const XDP_DROP: i32 = 1;
const XDP_PASS: i32 = 2;

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const IPPROTO_UDP: u8 = 17;

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

/// struct xdp_meta (xdp_metadata.h) — see module comment for the layout
/// rationale.
#[repr(C)]
struct xdp_meta {
    rx_timestamp: u64,
    xdp_timestamp: u64,
    rx_hash: u32,
    rx_hash_type: u32,
    rx_vlan_proto: u16,
    rx_vlan_tci: u16,
    hint_valid: u32,
}

extern "C" {
    fn bpf_xdp_metadata_rx_timestamp(ctx: *const xdp_md, timestamp: *mut u64) -> i32;
    // enum xdp_rss_hash_type has underlying type int, same layout as u32.
    fn bpf_xdp_metadata_rx_hash(ctx: *const xdp_md, hash: *mut u32, rss_type: *mut u32) -> i32;
    fn bpf_xdp_metadata_rx_vlan_tag(
        ctx: *const xdp_md,
        vlan_proto: *mut u16,
        vlan_tci: *mut u16,
    ) -> i32;
}

#[link_section = ".maps"]
#[no_mangle]
static xsk: BpfMap<u32, u32, 17, 4> = BpfMap::new(); // BPF_MAP_TYPE_XSKMAP = 17

#[link_section = ".maps"]
#[no_mangle]
static prog_arr: BpfMap<u32, u32, { maps::PROG_ARRAY }, 1> = BpfMap::new();

bpf_map! {
    dev_map {
        r#type: *const [i32; 14],      // BPF_MAP_TYPE_DEVMAP
        key_size: *const [i32; 4],     // sizeof(__u32)
        value_size: *const [i32; 8],   // sizeof(struct bpf_devmap_val)
        max_entries: *const [i32; 1],
    }
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn rx(ctx: *const xdp_md) -> i32 {
    let data_end = vload!((*ctx).data_end) as usize;
    let data = vload!((*ctx).data) as usize;

    let eth = data as *const ethhdr;
    let mut udp: usize = 0;

    if data + core::mem::size_of::<ethhdr>() < data_end {
        let h_proto = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*eth).h_proto)) };

        if h_proto == htons(ETH_P_IP) {
            let iph_addr = data + core::mem::size_of::<ethhdr>();
            if iph_addr + core::mem::size_of::<iphdr>() < data_end {
                let iph = iph_addr as *const iphdr;
                let protocol =
                    unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*iph).protocol)) };
                if protocol == IPPROTO_UDP {
                    udp = iph_addr + core::mem::size_of::<iphdr>();
                }
            }
        }
        if h_proto == htons(ETH_P_IPV6) {
            let ip6h_addr = data + core::mem::size_of::<ethhdr>();
            if ip6h_addr + core::mem::size_of::<ipv6hdr>() < data_end {
                let ip6h = ip6h_addr as *const ipv6hdr;
                let nexthdr =
                    unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip6h).nexthdr)) };
                if nexthdr == IPPROTO_UDP {
                    udp = ip6h_addr + core::mem::size_of::<ipv6hdr>();
                }
            }
        }
        if udp != 0 && udp + core::mem::size_of::<udphdr>() > data_end {
            udp = 0;
        }
    }

    if udp == 0 {
        return XDP_PASS;
    }

    // Forwarding UDP:8080 to AF_XDP
    let udp_hdr = udp as *const udphdr;
    let dest = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*udp_hdr).dest)) };
    if dest != htons(8080) {
        return XDP_PASS;
    }

    // Reserve enough for all custom metadata.
    let ret = bpf_xdp_adjust_meta(ctx as *mut xdp_md, -(core::mem::size_of::<xdp_meta>() as i32));
    if ret != 0 {
        return XDP_DROP;
    }

    let data = vload!((*ctx).data) as usize;
    let data_meta = vload!((*ctx).data_meta) as usize;

    if data_meta + core::mem::size_of::<xdp_meta>() > data {
        return XDP_DROP;
    }

    let meta = data_meta as *mut xdp_meta;

    // Export metadata.

    // We expect veth bpf_xdp_metadata_rx_timestamp to return 0 HW
    // timestamp, so put some non-zero value into AF_XDP frame for
    // the userspace.
    let mut timestamp: u64 = u64::MAX;
    unsafe { bpf_xdp_metadata_rx_timestamp(ctx, &mut timestamp) };
    if timestamp == 0 {
        unsafe { (*meta).rx_timestamp = 1 };
    }

    unsafe {
        bpf_xdp_metadata_rx_hash(
            ctx,
            core::ptr::addr_of_mut!((*meta).rx_hash),
            core::ptr::addr_of_mut!((*meta).rx_hash_type),
        );
        bpf_xdp_metadata_rx_vlan_tag(
            ctx,
            core::ptr::addr_of_mut!((*meta).rx_vlan_proto),
            core::ptr::addr_of_mut!((*meta).rx_vlan_tci),
        );
    }

    let rx_queue_index = vload!((*ctx).rx_queue_index) as u64;
    bpf_redirect_map(&xsk, rx_queue_index, XDP_PASS as u64) as i32
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn redirect(ctx: *const xdp_md) -> i32 {
    let rx_queue_index = vload!((*ctx).rx_queue_index) as u64;
    bpf_redirect_map(&dev_map, rx_queue_index, XDP_PASS as u64) as i32
}

bpf_object!("GPL");
