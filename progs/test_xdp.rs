#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_xdp.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_map_lookup_elem, bpf_xdp_adjust_head};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::vload;

const XDP_DROP: i32 = 1;
const XDP_PASS: i32 = 2;
const XDP_TX: i32 = 3;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_IPIP: u8 = 4;
const IPPROTO_IPV6: u8 = 41;

const MAX_IPTNL_ENTRIES: usize = 256;

#[inline(always)]
fn htons(x: u16) -> u16 {
    x.to_be()
}

#[inline(always)]
fn ntohs(x: u16) -> u16 {
    u16::from_be(x)
}

// Small fixed-size copies get recognized by LLVM's MemCpyOpt as
// memcpy-shaped and rewritten into an unresolvable `bpf_arena_memcpy`
// kfunc call (only valid in arena programs); byte-at-a-time volatile
// access is the pattern the optimizer won't merge back into memcpy.
#[inline(always)]
unsafe fn vcopy(dst: *mut u8, src: *const u8, len: usize) {
    let mut i = 0usize;
    while i < len {
        core::ptr::write_volatile(dst.add(i), core::ptr::read_volatile(src.add(i)));
        i += 1;
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

// Packet-overlay headers: read/written directly on unaligned packet memory,
// so every field access must go through an unaligned (packed) load/store.
#[repr(C, packed)]
struct EthHdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

#[repr(C, packed)]
struct IpHdr {
    version_ihl: u8,
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
struct Ipv6Hdr {
    version_priority: u8,
    flow_lbl: [u8; 3],
    payload_len: u16,
    nexthdr: u8,
    hop_limit: u8,
    saddr: [u32; 4],
    daddr: [u32; 4],
}

#[repr(C, packed)]
struct TcpHdr {
    source: u16,
    dest: u16,
    _rest: [u8; 16],
}

#[repr(C, packed)]
struct UdpHdr {
    source: u16,
    dest: u16,
    _rest: [u8; 4],
}

// test_iptunnel_common.h's struct vip / struct iptnl_info. Stack-allocated
// (never overlaid on packet memory), so ordinary #[repr(C)] alignment/
// padding matches the C original exactly.
#[repr(C)]
union Addr {
    v6: [u32; 4],
    v4: u32,
}

#[repr(C)]
struct Vip {
    daddr: Addr,
    dport: u16,
    family: u16,
    protocol: u8,
}

#[repr(C)]
struct IptnlInfo {
    saddr: Addr,
    daddr: Addr,
    family: u16,
    dmac: [u8; 6],
}

#[link_section = ".maps"]
#[no_mangle]
static rxcnt: BpfMap<u32, u64, { maps::PERCPU_ARRAY }, 256> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static vip2tnl: BpfMap<Vip, IptnlInfo, { maps::HASH }, MAX_IPTNL_ENTRIES> = BpfMap::new();

#[inline(always)]
fn count_tx(protocol: u8) {
    let key: u32 = protocol as u32;
    let ptr = bpf_map_lookup_elem(&rxcnt, &key) as *mut u64;
    if !ptr.is_null() {
        unsafe { *ptr = (*ptr).wrapping_add(1) };
    }
}

#[inline(always)]
fn get_dport(trans_data: usize, data_end: usize, protocol: u8) -> i32 {
    match protocol {
        IPPROTO_TCP => {
            if trans_data + core::mem::size_of::<TcpHdr>() > data_end {
                return -1;
            }
            unsafe { (*(trans_data as *const TcpHdr)).dest as i32 }
        }
        IPPROTO_UDP => {
            if trans_data + core::mem::size_of::<UdpHdr>() > data_end {
                return -1;
            }
            unsafe { (*(trans_data as *const UdpHdr)).dest as i32 }
        }
        _ => 0,
    }
}

#[inline(always)]
fn set_ethhdr(new_eth: *mut EthHdr, old_eth: *const EthHdr, tnl: *const IptnlInfo, h_proto: u16) {
    unsafe {
        vcopy(
            core::ptr::addr_of_mut!((*new_eth).h_source) as *mut u8,
            core::ptr::addr_of!((*old_eth).h_dest) as *const u8,
            6,
        );
        vcopy(
            core::ptr::addr_of_mut!((*new_eth).h_dest) as *mut u8,
            core::ptr::addr_of!((*tnl).dmac) as *const u8,
            6,
        );
        (*new_eth).h_proto = h_proto;
    }
}

#[inline(never)]
fn handle_ipv4(xdp: *const xdp_md) -> i32 {
    let mut data_end = vload!((*xdp).data_end) as usize;
    let mut data = vload!((*xdp).data) as usize;

    let iph = (data + core::mem::size_of::<EthHdr>()) as *const IpHdr;
    if (iph as usize) + core::mem::size_of::<IpHdr>() > data_end {
        return XDP_DROP;
    }

    let protocol = unsafe { (*iph).protocol };
    let trans_data = iph as usize + core::mem::size_of::<IpHdr>();
    let dport = get_dport(trans_data, data_end, protocol);
    if dport == -1 {
        return XDP_DROP;
    }

    let mut vip = unsafe { core::mem::MaybeUninit::<Vip>::zeroed().assume_init() };
    vip.protocol = protocol;
    vip.family = AF_INET;
    unsafe { vip.daddr.v4 = (*iph).daddr };
    vip.dport = dport as u16;
    let payload_len = ntohs(unsafe { (*iph).tot_len });

    let tnl = bpf_map_lookup_elem(&vip2tnl, &vip) as *const IptnlInfo;
    if tnl.is_null() || unsafe { (*tnl).family } != AF_INET {
        return XDP_PASS;
    }

    if bpf_xdp_adjust_head(xdp as *mut xdp_md, -(core::mem::size_of::<IpHdr>() as i32)) != 0 {
        return XDP_DROP;
    }

    data = vload!((*xdp).data) as usize;
    data_end = vload!((*xdp).data_end) as usize;

    let new_eth = data as *mut EthHdr;
    let iph = (data + core::mem::size_of::<EthHdr>()) as *mut IpHdr;
    let old_eth = (data + core::mem::size_of::<IpHdr>()) as *const EthHdr;

    if (new_eth as usize) + core::mem::size_of::<EthHdr>() > data_end
        || (old_eth as usize) + core::mem::size_of::<EthHdr>() > data_end
        || (iph as usize) + core::mem::size_of::<IpHdr>() > data_end
    {
        return XDP_DROP;
    }

    set_ethhdr(new_eth, old_eth, tnl, htons(ETH_P_IP));

    unsafe {
        (*iph).version_ihl = 0x45;
        (*iph).frag_off = 0;
        (*iph).protocol = IPPROTO_IPIP;
        (*iph).check = 0;
        (*iph).tos = 0;
        (*iph).tot_len = htons(payload_len.wrapping_add(core::mem::size_of::<IpHdr>() as u16));
        (*iph).daddr = (*tnl).daddr.v4;
        (*iph).saddr = (*tnl).saddr.v4;
        (*iph).ttl = 8;
    }

    let mut csum: u32 = 0;
    let mut next_iph = iph as *mut u16;
    for _ in 0..(core::mem::size_of::<IpHdr>() >> 1) {
        csum = csum.wrapping_add(unsafe { core::ptr::read_unaligned(next_iph) } as u32);
        next_iph = unsafe { next_iph.add(1) };
    }
    let check = !((csum & 0xffff).wrapping_add(csum >> 16)) as u16;
    unsafe { (*iph).check = check };

    count_tx(protocol);

    XDP_TX
}

#[inline(never)]
fn handle_ipv6(xdp: *const xdp_md) -> i32 {
    let mut data_end = vload!((*xdp).data_end) as usize;
    let mut data = vload!((*xdp).data) as usize;

    let ip6h = (data + core::mem::size_of::<EthHdr>()) as *const Ipv6Hdr;
    if (ip6h as usize) + core::mem::size_of::<Ipv6Hdr>() > data_end {
        return XDP_DROP;
    }

    let nexthdr = unsafe { (*ip6h).nexthdr };
    let trans_data = ip6h as usize + core::mem::size_of::<Ipv6Hdr>();
    let dport = get_dport(trans_data, data_end, nexthdr);
    if dport == -1 {
        return XDP_DROP;
    }

    let mut vip = unsafe { core::mem::MaybeUninit::<Vip>::zeroed().assume_init() };
    vip.protocol = nexthdr;
    vip.family = AF_INET6;
    unsafe {
        vcopy(
            core::ptr::addr_of_mut!(vip.daddr.v6) as *mut u8,
            core::ptr::addr_of!((*ip6h).daddr) as *const u8,
            16,
        );
    }
    vip.dport = dport as u16;
    let payload_len = unsafe { (*ip6h).payload_len };

    let tnl = bpf_map_lookup_elem(&vip2tnl, &vip) as *const IptnlInfo;
    if tnl.is_null() || unsafe { (*tnl).family } != AF_INET6 {
        return XDP_PASS;
    }

    if bpf_xdp_adjust_head(xdp as *mut xdp_md, -(core::mem::size_of::<Ipv6Hdr>() as i32)) != 0 {
        return XDP_DROP;
    }

    data = vload!((*xdp).data) as usize;
    data_end = vload!((*xdp).data_end) as usize;

    let new_eth = data as *mut EthHdr;
    let ip6h = (data + core::mem::size_of::<EthHdr>()) as *mut Ipv6Hdr;
    let old_eth = (data + core::mem::size_of::<Ipv6Hdr>()) as *const EthHdr;

    if (new_eth as usize) + core::mem::size_of::<EthHdr>() > data_end
        || (old_eth as usize) + core::mem::size_of::<EthHdr>() > data_end
        || (ip6h as usize) + core::mem::size_of::<Ipv6Hdr>() > data_end
    {
        return XDP_DROP;
    }

    set_ethhdr(new_eth, old_eth, tnl, htons(ETH_P_IPV6));

    unsafe {
        (*ip6h).version_priority = 0x60;
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*ip6h).flow_lbl) as *mut u8, 0);
        core::ptr::write_volatile(
            (core::ptr::addr_of_mut!((*ip6h).flow_lbl) as *mut u8).add(1),
            0,
        );
        core::ptr::write_volatile(
            (core::ptr::addr_of_mut!((*ip6h).flow_lbl) as *mut u8).add(2),
            0,
        );
        (*ip6h).payload_len =
            htons(ntohs(payload_len).wrapping_add(core::mem::size_of::<Ipv6Hdr>() as u16));
        (*ip6h).nexthdr = IPPROTO_IPV6;
        (*ip6h).hop_limit = 8;
        vcopy(
            core::ptr::addr_of_mut!((*ip6h).saddr) as *mut u8,
            core::ptr::addr_of!((*tnl).saddr.v6) as *const u8,
            16,
        );
        vcopy(
            core::ptr::addr_of_mut!((*ip6h).daddr) as *mut u8,
            core::ptr::addr_of!((*tnl).daddr.v6) as *const u8,
            16,
        );
    }

    count_tx(nexthdr);

    XDP_TX
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn _xdp_tx_iptunnel(xdp: *const xdp_md) -> i32 {
    let data_end = vload!((*xdp).data_end) as usize;
    let data = vload!((*xdp).data) as usize;

    let eth = data as *const EthHdr;
    if (eth as usize) + core::mem::size_of::<EthHdr>() > data_end {
        return XDP_DROP;
    }

    let h_proto = unsafe { (*eth).h_proto };

    if h_proto == htons(ETH_P_IP) {
        handle_ipv4(xdp)
    } else if h_proto == htons(ETH_P_IPV6) {
        handle_ipv6(xdp)
    } else {
        XDP_DROP
    }
}

bpf_object!("GPL");
