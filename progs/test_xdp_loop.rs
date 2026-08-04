#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_xdp_loop.c
// (bpf-rs-core idiom). Despite the file name this is the xdp_tx_iptunnel
// program, reused by bpf_verif_scale.c as a verifier-scale XDP load test
// (test_verif_scale_xdp_loop -> scale_test("test_xdp_loop.bpf.o", ...)):
// the oracle only checks bpf_object__load() succeeds, no packets are sent.
// test_iptunnel_common.h's `struct vip`/`struct iptnl_info` are inlined
// here since only progs/test_xdp_loop.rs may be created.

use bpf_rs_core::helpers::{bpf_map_lookup_elem, bpf_xdp_adjust_head};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::{bpf_object, vload};

const XDP_DROP: i32 = 1;
const XDP_PASS: i32 = 2;
const XDP_TX: i32 = 3;

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_IPIP: u8 = 4;
const IPPROTO_IPV6: u8 = 41;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

const MAX_IPTNL_ENTRIES: usize = 256;

#[inline(always)]
fn htons(x: u16) -> u16 {
    x.to_be()
}

#[inline(always)]
fn ntohs(x: u16) -> u16 {
    u16::from_be(x)
}

/// Byte-at-a-time volatile copy: a plain slice/array copy of this size gets
/// recognized by LLVM's MemCpyOpt and rewritten into an extern
/// `bpf_arena_memcpy` kfunc call, which only resolves inside arena
/// programs and fails to load here ("not found in kernel or module BTFs").
#[inline(always)]
fn vcopy(dst_ptr: *mut u8, src_ptr: *const u8, len: usize) {
    let mut i = 0usize;
    while i < len {
        unsafe {
            core::ptr::write_volatile(dst_ptr.add(i), core::ptr::read_volatile(src_ptr.add(i)));
        }
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

// struct ethhdr (linux/if_ether.h) — packed.
#[repr(C, packed)]
struct ethhdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

// struct iphdr (linux/ip.h) — packed, no options.
#[repr(C, packed)]
struct iphdr {
    ihl_version: u8, // low nibble = ihl, high nibble = version
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

// struct ipv6hdr (linux/ipv6.h) — packed. saddr/daddr represented directly
// as [u32; 4] (matching in6_addr's s6_addr32 view; the union's other views
// are never used here).
#[repr(C, packed)]
struct ipv6hdr {
    version_priority: u8, // low nibble = priority, high nibble = version
    flow_lbl: [u8; 3],
    payload_len: u16,
    nexthdr: u8,
    hop_limit: u8,
    saddr: [u32; 4],
    daddr: [u32; 4],
}

// struct tcphdr (linux/tcp.h) — packed, only through `dest`; the rest keeps
// the size (20 bytes) correct for the `th + 1 > data_end` bounds check.
#[repr(C, packed)]
struct tcphdr {
    source: u16,
    dest: u16,
    seq: u32,
    ack_seq: u32,
    flags: u16,
    window: u16,
    check: u16,
    urg_ptr: u16,
}

// struct udphdr (linux/udp.h) — packed.
#[repr(C, packed)]
struct udphdr {
    source: u16,
    dest: u16,
    len: u16,
    check: u16,
}

// test_iptunnel_common.h's `union { __u32 v6[4]; __u32 v4; }`.
#[repr(C)]
#[derive(Clone, Copy)]
union AddrUnion {
    v6: [u32; 4],
    v4: u32,
}

// struct vip (test_iptunnel_common.h). Used only as this program's own
// map key, never matched against kernel BTF by name.
#[repr(C)]
struct Vip {
    daddr: AddrUnion,
    dport: u16,
    family: u16,
    protocol: u8,
}

// struct iptnl_info (test_iptunnel_common.h).
#[repr(C)]
struct IptnlInfo {
    saddr: AddrUnion,
    daddr: AddrUnion,
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
fn count_tx(protocol: u32) {
    let rxcnt_count = bpf_map_lookup_elem(&rxcnt, &protocol) as *mut u64;
    if !rxcnt_count.is_null() {
        unsafe { *rxcnt_count += 1 };
    }
}

#[inline(always)]
fn get_dport(trans_data: *const u8, data_end: usize, protocol: u8) -> i32 {
    match protocol {
        IPPROTO_TCP => {
            let th = trans_data as *const tcphdr;
            if (th as usize) + core::mem::size_of::<tcphdr>() > data_end {
                return -1;
            }
            unsafe { (*th).dest as i32 }
        }
        IPPROTO_UDP => {
            let uh = trans_data as *const udphdr;
            if (uh as usize) + core::mem::size_of::<udphdr>() > data_end {
                return -1;
            }
            unsafe { (*uh).dest as i32 }
        }
        _ => 0,
    }
}

#[inline(always)]
fn set_ethhdr(new_eth: *mut ethhdr, old_eth: *const ethhdr, tnl: *const IptnlInfo, h_proto: u16) {
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

#[inline(always)]
fn handle_ipv4(xdp: *mut xdp_md) -> i32 {
    unsafe {
        let data_end = vload!((*xdp).data_end) as usize;
        let mut data = vload!((*xdp).data) as usize;

        let iph = (data + core::mem::size_of::<ethhdr>()) as *const iphdr;

        if (iph as usize) + core::mem::size_of::<iphdr>() > data_end {
            return XDP_DROP;
        }

        let dport = get_dport(
            (iph as usize + core::mem::size_of::<iphdr>()) as *const u8,
            data_end,
            (*iph).protocol,
        );
        if dport == -1 {
            return XDP_DROP;
        }

        let mut vip: Vip = core::mem::zeroed();
        vip.protocol = (*iph).protocol;
        vip.family = AF_INET;
        vip.daddr.v4 = (*iph).daddr;
        vip.dport = dport as u16;
        let payload_len = ntohs((*iph).tot_len);

        let tnl = bpf_map_lookup_elem(&vip2tnl, &vip) as *const IptnlInfo;
        // It only does v4-in-v4
        if tnl.is_null() || (*tnl).family != AF_INET {
            return XDP_PASS;
        }

        if bpf_xdp_adjust_head(xdp, 0 - core::mem::size_of::<iphdr>() as i32) != 0 {
            return XDP_DROP;
        }

        data = vload!((*xdp).data) as usize;
        let data_end = vload!((*xdp).data_end) as usize;

        let new_eth = data as *mut ethhdr;
        let iph = (data + core::mem::size_of::<ethhdr>()) as *mut iphdr;
        let old_eth = (data + core::mem::size_of::<iphdr>()) as *const ethhdr;

        if (new_eth as usize) + core::mem::size_of::<ethhdr>() > data_end
            || (old_eth as usize) + core::mem::size_of::<ethhdr>() > data_end
            || (iph as usize) + core::mem::size_of::<iphdr>() > data_end
        {
            return XDP_DROP;
        }

        set_ethhdr(new_eth, old_eth, tnl, htons(ETH_P_IP));

        (*iph).ihl_version = (4u8 << 4) | 5u8;
        (*iph).frag_off = 0;
        (*iph).protocol = IPPROTO_IPIP;
        (*iph).check = 0;
        (*iph).tos = 0;
        (*iph).tot_len = htons(payload_len.wrapping_add(core::mem::size_of::<iphdr>() as u16));
        (*iph).daddr = (*tnl).daddr.v4;
        (*iph).saddr = (*tnl).saddr.v4;
        (*iph).ttl = 8;

        let mut csum: u32 = 0;
        let mut next_iph = iph as *const u16;
        let mut i = 0usize;
        while i < (core::mem::size_of::<iphdr>() >> 1) {
            csum = csum.wrapping_add(core::ptr::read_unaligned(next_iph) as u32);
            next_iph = next_iph.add(1);
            i += 1;
        }
        let sum = (csum & 0xffff).wrapping_add(csum >> 16);
        (*iph).check = !sum as u16;

        count_tx(vip.protocol as u32);

        XDP_TX
    }
}

#[inline(always)]
fn handle_ipv6(xdp: *mut xdp_md) -> i32 {
    unsafe {
        let data_end = vload!((*xdp).data_end) as usize;
        let mut data = vload!((*xdp).data) as usize;

        let ip6h = (data + core::mem::size_of::<ethhdr>()) as *const ipv6hdr;

        if (ip6h as usize) + core::mem::size_of::<ipv6hdr>() > data_end {
            return XDP_DROP;
        }

        let dport = get_dport(
            (ip6h as usize + core::mem::size_of::<ipv6hdr>()) as *const u8,
            data_end,
            (*ip6h).nexthdr,
        );
        if dport == -1 {
            return XDP_DROP;
        }

        let mut vip: Vip = core::mem::zeroed();
        vip.protocol = (*ip6h).nexthdr;
        vip.family = AF_INET6;
        vcopy(
            core::ptr::addr_of_mut!(vip.daddr.v6) as *mut u8,
            core::ptr::addr_of!((*ip6h).daddr) as *const u8,
            16,
        );
        vip.dport = dport as u16;
        let payload_len = (*ip6h).payload_len;

        let tnl = bpf_map_lookup_elem(&vip2tnl, &vip) as *const IptnlInfo;
        // It only does v6-in-v6
        if tnl.is_null() || (*tnl).family != AF_INET6 {
            return XDP_PASS;
        }

        if bpf_xdp_adjust_head(xdp, 0 - core::mem::size_of::<ipv6hdr>() as i32) != 0 {
            return XDP_DROP;
        }

        data = vload!((*xdp).data) as usize;
        let data_end = vload!((*xdp).data_end) as usize;

        let new_eth = data as *mut ethhdr;
        let ip6h = (data + core::mem::size_of::<ethhdr>()) as *mut ipv6hdr;
        let old_eth = (data + core::mem::size_of::<ipv6hdr>()) as *const ethhdr;

        if (new_eth as usize) + core::mem::size_of::<ethhdr>() > data_end
            || (old_eth as usize) + core::mem::size_of::<ethhdr>() > data_end
            || (ip6h as usize) + core::mem::size_of::<ipv6hdr>() > data_end
        {
            return XDP_DROP;
        }

        set_ethhdr(new_eth, old_eth, tnl, htons(ETH_P_IPV6));

        (*ip6h).version_priority = 6u8 << 4;
        (*ip6h).flow_lbl = [0, 0, 0];
        (*ip6h).payload_len =
            htons(ntohs(payload_len).wrapping_add(core::mem::size_of::<ipv6hdr>() as u16));
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

        count_tx(vip.protocol as u32);

        XDP_TX
    }
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn _xdp_tx_iptunnel(xdp: *mut xdp_md) -> i32 {
    let data_end = vload!((*xdp).data_end) as usize;
    let data = vload!((*xdp).data) as usize;
    let eth = data as *const ethhdr;

    if (eth as usize) + core::mem::size_of::<ethhdr>() > data_end {
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
