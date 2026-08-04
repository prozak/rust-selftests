#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/xdp_flowtable.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_map_lookup_elem, sync_fetch_and_add_u32};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::vload;

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
const IP_MF: u16 = 0x2000;
const IP_OFFSET: u16 = 0x1fff;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const IPPROTO_TCP: u8 = 6;

const XDP_DROP: i32 = 1;
const XDP_PASS: i32 = 2;

const ETHHDR_LEN: usize = 14; // sizeof(struct ethhdr)
const IPV6HDR_LEN: usize = 40; // sizeof(struct ipv6hdr)
const FLOW_PORTS_LEN: usize = 4; // sizeof(struct flow_ports___local)

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

// struct ethhdr (linux/if_ether.h) — packed.
#[repr(C, packed)]
struct ethhdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

// struct iphdr (linux/ip.h) — packed; ihl is the low nibble of the first
// byte on little-endian (x86) targets.
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

const _: () = assert!(core::mem::size_of::<iphdr>() == 20);

// struct ipv6hdr (linux/ipv6.h) — packed.
#[repr(C, packed)]
struct ipv6hdr {
    version_priority: u8,
    flow_lbl: [u8; 3],
    payload_len: u16,
    nexthdr: u8,
    hop_limit: u8,
    saddr: [u32; 4],
    daddr: [u32; 4],
}

const _: () = assert!(core::mem::size_of::<ipv6hdr>() == IPV6HDR_LEN);

// struct flow_ports___local (this file): __be16 source, dest.
#[repr(C, packed)]
struct flow_ports {
    source: u16,
    dest: u16,
}

const _: () = assert!(core::mem::size_of::<flow_ports>() == FLOW_PORTS_LEN);

// struct tcphdr (linux/tcp.h): only the bytes through the flags byte are
// read. On little-endian the byte at offset 12 holds res1:4|doff:4 and the
// byte at offset 13 holds fin,syn,rst,psh,ack,urg,ece,cwr (bit 0 = fin,
// bit 2 = rst), matching the real wire layout of the TCP flags byte.
#[repr(C, packed)]
struct tcphdr {
    source: u16,
    dest: u16,
    seq: u32,
    ack_seq: u32,
    doff_byte: u8,
    flags_byte: u8,
    window: u16,
    check: u16,
    urg_ptr: u16,
}

const _: () = assert!(core::mem::size_of::<tcphdr>() == 20);

// struct bpf_fib_lookup (linux/bpf.h): 64-byte layout, unions represented
// with matching Rust unions. Stack scratch buffer passed by pointer to the
// bpf_xdp_flow_lookup kfunc — not BTF-matched like a map value, so only the
// raw offsets need to agree with the kernel's struct.
#[repr(C)]
union TotLenOrMtu {
    tot_len: u16,
    #[allow(dead_code)]
    mtu_result: u16,
}

#[repr(C)]
union TosOrFlowinfo {
    tos: u8,
    flowinfo: u32,
    #[allow(dead_code)]
    rt_metric: u32,
}

#[repr(C)]
union AddrSrc {
    ipv4_src: u32,
    ipv6_src: [u32; 4],
}

#[repr(C)]
union AddrDst {
    ipv4_dst: u32,
    ipv6_dst: [u32; 4],
}

#[repr(C)]
union VlanOrTbid {
    #[allow(dead_code)]
    h_vlan: [u16; 2],
    #[allow(dead_code)]
    tbid: u32,
}

#[repr(C)]
union MarkOrMac {
    #[allow(dead_code)]
    mark: u32,
    #[allow(dead_code)]
    mac: [u8; 12],
}

#[repr(C)]
struct bpf_fib_lookup {
    family: u8,
    l4_protocol: u8,
    sport: u16,
    dport: u16,
    tot_len: TotLenOrMtu,
    ifindex: u32,
    tos_flowinfo: TosOrFlowinfo,
    addr_src: AddrSrc,
    addr_dst: AddrDst,
    vlan_tbid: VlanOrTbid,
    mark_mac: MarkOrMac,
}

const _: () = assert!(core::mem::size_of::<bpf_fib_lookup>() == 64);

// Word-at-a-time, not an aggregate assignment: a 16-byte in6_addr copy
// lowers to an llvm.memcpy that add_ksyms.py rewrites into an extern
// bpf_arena_memcpy kfunc call, which isn't in this kernel's BTF outside
// arena progs.
#[inline(always)]
unsafe fn copy_in6_addr(dst: *mut [u32; 4], src: *const [u32; 4]) {
    let dst = dst as *mut u32;
    let src = src as *const u32;
    let mut i = 0usize;
    while i < 4 {
        core::ptr::write_unaligned(dst.add(i), core::ptr::read_unaligned(src.add(i)));
        i += 1;
    }
}

#[repr(C)]
struct bpf_flowtable_opts___local {
    error: i32,
}

// struct flow_offload_tuple_rhash___local (this file): opaque, only ever
// null-checked — never dereferenced.
#[repr(C)]
struct flow_offload_tuple_rhash___local {
    _opaque: [u8; 0],
}

extern "C" {
    fn bpf_xdp_flow_lookup(
        ctx: *mut xdp_md,
        tuple: *mut bpf_fib_lookup,
        opts: *mut bpf_flowtable_opts___local,
        opts_len: u32,
    ) -> *mut flow_offload_tuple_rhash___local;
}

#[link_section = ".maps"]
#[no_mangle]
static stats: BpfMap<u32, u32, { maps::ARRAY }, 1> = BpfMap::new();

#[inline(never)]
fn check_iphdr(iph: *const iphdr) -> bool {
    unsafe {
        if (*iph).frag_off & (IP_MF | IP_OFFSET).to_be() != 0 {
            return false;
        }

        let ihl = (*iph).ihl_version & 0x0F;
        if (ihl as usize) * 4 != core::mem::size_of::<iphdr>() {
            return false;
        }

        if (*iph).ttl <= 1 {
            return false;
        }
    }

    true
}

#[inline(never)]
fn check_tcp_state(ports_addr: usize, data_end: usize, proto: u8) -> bool {
    if proto == IPPROTO_TCP {
        if ports_addr + core::mem::size_of::<tcphdr>() > data_end {
            return false;
        }

        let tcph = ports_addr as *const tcphdr;
        unsafe {
            if (*tcph).flags_byte & 0x01 != 0 || (*tcph).flags_byte & 0x04 != 0 {
                return false;
            }
        }
    }

    true
}

#[inline(never)]
fn handle_ipv4(data: usize, data_end: usize, tuple: &mut bpf_fib_lookup) -> i32 {
    let iph = (data + ETHHDR_LEN) as *const iphdr;
    let ports_addr = iph as usize + core::mem::size_of::<iphdr>();

    if ports_addr + FLOW_PORTS_LEN > data_end {
        return XDP_PASS;
    }

    if !check_iphdr(iph) {
        return XDP_PASS;
    }

    let protocol = unsafe { (*iph).protocol };
    if !check_tcp_state(ports_addr, data_end, protocol) {
        return XDP_PASS;
    }

    let ports = ports_addr as *const flow_ports;
    unsafe {
        tuple.family = AF_INET;
        tuple.tos_flowinfo.tos = (*iph).tos;
        tuple.l4_protocol = protocol;
        tuple.tot_len.tot_len = u16::from_be((*iph).tot_len);
        tuple.addr_src.ipv4_src = (*iph).saddr;
        tuple.addr_dst.ipv4_dst = (*iph).daddr;
        tuple.sport = (*ports).source;
        tuple.dport = (*ports).dest;
    }

    0
}

#[inline(never)]
fn handle_ipv6(data: usize, data_end: usize, tuple: &mut bpf_fib_lookup) -> i32 {
    let ip6h = (data + ETHHDR_LEN) as *const ipv6hdr;
    let ports_addr = ip6h as usize + IPV6HDR_LEN;

    if ports_addr + FLOW_PORTS_LEN > data_end {
        return XDP_PASS;
    }

    if unsafe { (*ip6h).hop_limit } <= 1 {
        return XDP_PASS;
    }

    let nexthdr = unsafe { (*ip6h).nexthdr };
    if !check_tcp_state(ports_addr, data_end, nexthdr) {
        return XDP_PASS;
    }

    let ports = ports_addr as *const flow_ports;
    unsafe {
        tuple.family = AF_INET6;
        tuple.l4_protocol = nexthdr;
        tuple.tot_len.tot_len = u16::from_be((*ip6h).payload_len);
        copy_in6_addr(
            core::ptr::addr_of_mut!(tuple.addr_src.ipv6_src),
            core::ptr::addr_of!((*ip6h).saddr),
        );
        copy_in6_addr(
            core::ptr::addr_of_mut!(tuple.addr_dst.ipv6_dst),
            core::ptr::addr_of!((*ip6h).daddr),
        );
        tuple.sport = (*ports).source;
        tuple.dport = (*ports).dest;
    }

    0
}

#[link_section = "xdp.frags"]
#[no_mangle]
extern "C" fn xdp_flowtable_do_lookup(ctx: *const xdp_md) -> i32 {
    let data_end = vload!((*ctx).data_end) as usize;
    let data = vload!((*ctx).data) as usize;

    if data + ETHHDR_LEN > data_end {
        return XDP_DROP;
    }

    let eth = data as *const ethhdr;
    let h_proto = unsafe { (*eth).h_proto };

    let mut tuple: bpf_fib_lookup = unsafe { core::mem::zeroed() };
    tuple.ifindex = vload!((*ctx).ingress_ifindex);

    if h_proto == htons(ETH_P_IP) {
        let ret = handle_ipv4(data, data_end, &mut tuple);
        if ret != 0 {
            return ret;
        }
    } else if h_proto == htons(ETH_P_IPV6) {
        let ret = handle_ipv6(data, data_end, &mut tuple);
        if ret != 0 {
            return ret;
        }
    } else {
        return XDP_PASS;
    }

    let mut opts = bpf_flowtable_opts___local { error: 0 };
    let tuplehash = unsafe {
        bpf_xdp_flow_lookup(
            ctx as *mut xdp_md,
            &mut tuple,
            &mut opts,
            core::mem::size_of::<bpf_flowtable_opts___local>() as u32,
        )
    };
    if tuplehash.is_null() {
        return XDP_PASS;
    }

    let key: u32 = 0;
    let val = bpf_map_lookup_elem(&stats, &key);
    if !val.is_null() {
        sync_fetch_and_add_u32(val as *mut u32, 1);
    }

    XDP_PASS
}

bpf_object!("GPL");
