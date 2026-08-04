#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/xdpwall.c
// (bpf-rs-core idiom).
//
// A read-only XDP firewall: parses eth+ipv6(+GUE tunnel)+tcp/udp, looks up
// several small maps to compute a `fw_match_info` verdict scratch struct,
// and drops everything except non-SYN TCP. No packet field is ever
// written, no CO-RE, no kfuncs — just bounds-checked linear-buffer parsing
// and `bpf_map_lookup_elem`. The only userspace test consuming this
// (prog_tests/xdpwall.c) just does `xdpwall__open_and_load` + destroy, so
// the load itself is the acceptance oracle.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_map_lookup_elem;
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::vload;

// ---- Unaligned packed-field read (see test_cls_redirect.rs) --------------

macro_rules! pget {
    ($place:expr) => {
        unsafe { core::ptr::read_unaligned(core::ptr::addr_of!($place)) }
    };
}

// ---- byte-order helpers ---------------------------------------------------

#[inline(always)]
fn htons(x: u16) -> u16 {
    x.to_be()
}
#[inline(always)]
fn ntohs(x: u16) -> u16 {
    u16::from_be(x)
}

// ---- constants --------------------------------------------------------

const XDP_DROP: i32 = 1;
const XDP_PASS: i32 = 2;

const ETH_P_IPV6: u16 = 0x86DD;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMPV6: u8 = 58;

// enum pkt_parse_err
const NO_ERR: u8 = 0;
const BAD_IP6_HDR: u8 = 1;
#[allow(dead_code)]
const BAD_IP4GUE_HDR: u8 = 2;
const BAD_IP6GUE_HDR: u8 = 3;

// enum pkt_flag
const TUNNEL: u8 = 0x1;
const TCP_SYN: u8 = 0x2;
#[allow(dead_code)]
const QUIC_INITIAL_FLAG: u8 = 0x4;
const TCP_ACK: u8 = 0x8;
const TCP_RST: u8 = 0x10;

// TCP flag byte bits (fin:1,syn:1,rst:1,psh:1,ack:1,urg:1,ece:1,cwr:1)
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_ACK: u8 = 0x10;
const TCP_FLAG_RST: u8 = 0x04;
const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_MASK: u8 = TCP_FLAG_ACK | TCP_FLAG_RST | TCP_FLAG_SYN | TCP_FLAG_FIN;

// enum ip_type
const IP_V4: u32 = 1;
const IP_V6: u32 = 2;

// ---- wire header layouts (see test_cls_redirect.rs for the idiom) --------

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct EthHdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct IpHdr {
    ihl_version: u8, // ihl:4, version:4 (LE bit order)
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
#[derive(Clone, Copy)]
struct Ipv6Hdr {
    priority_version: u8, // priority:4, version:4 (LE bit order)
    flow_lbl: [u8; 3],
    payload_len: u16,
    nexthdr: u8,
    hop_limit: u8,
    saddr: [u8; 16],
    daddr: [u8; 16],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct UdpHdr {
    source: u16,
    dest: u16,
    len: u16,
    check: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct TcpHdr {
    source: u16,
    dest: u16,
    seq: u32,
    ack_seq: u32,
    res1_doff: u8,
    flags: u8,
    window: u16,
    check: u16,
    urg_ptr: u16,
}

// ---- .maps ---------------------------------------------------------------

#[link_section = ".maps"]
#[no_mangle]
static v6_addr_map: BpfMap<[u8; 16], bool, { maps::HASH }, 16> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static v4_addr_map: BpfMap<u32, bool, { maps::HASH }, 16> = BpfMap::new();

#[repr(C)]
struct V4LpmKey {
    prefixlen: u32,
    src: u32,
}

// BPF_MAP_TYPE_LPM_TRIE with key_size/value_size given directly (no
// __type(key,...)/__type(value,...) in the C source) -- escape hatch,
// members in source order: type, max_entries, key_size, value_size,
// map_flags. sizeof(struct v4_lpm_key) == 8, sizeof(struct v4_lpm_val)
// (key + __u8 val, u32-aligned) == 12.
bpf_rs_core::bpf_map! {
    v4_lpm_val_map {
        r#type: *const [i32; 11],       // BPF_MAP_TYPE_LPM_TRIE
        max_entries: *const [i32; 16],
        key_size: *const [i32; 8],
        value_size: *const [i32; 12],
        map_flags: *const [i32; 1],     // BPF_F_NO_PREALLOC
    }
}

#[repr(C)]
struct V4LpmVal {
    key: V4LpmKey,
    val: u8,
}

#[link_section = ".maps"]
#[no_mangle]
static tcp_port_map: BpfMap<i32, u8, { maps::ARRAY }, 16> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static udp_port_map: BpfMap<i32, u16, { maps::ARRAY }, 16> = BpfMap::new();

// ---- fw_match_info / pkt_info ---------------------------------------------

struct FwMatchInfo {
    v4_src_ip_match: u8,
    v6_src_ip_match: u8,
    v4_src_prefix_match: u8,
    v4_dst_prefix_match: u8,
    tcp_dp_match: u8,
    udp_sp_match: u16,
    udp_dp_match: u16,
    is_tcp: bool,
    is_tcp_syn: bool,
}

struct PktInfo {
    kind: u32,     // enum ip_type
    ip: *const u8, // union { iphdr*, ipv6hdr* }, cast per `kind`
    sport: i32,
    dport: i32,
    trans_hdr_offset: u16,
    proto: u8,
    flags: u8,
}

// ---- map filters ------------------------------------------------------

#[inline(always)]
fn filter_ipv6_addr(ipv6addr: *const [u8; 16]) -> u8 {
    let leaf = bpf_map_lookup_elem(&v6_addr_map, unsafe { &*ipv6addr }) as *const bool;
    if leaf.is_null() {
        0
    } else {
        unsafe { *leaf as u8 }
    }
}

#[inline(always)]
fn filter_ipv4_addr(ipaddr: u32) -> u8 {
    let leaf = bpf_map_lookup_elem(&v4_addr_map, &ipaddr) as *const bool;
    if leaf.is_null() {
        0
    } else {
        unsafe { *leaf as u8 }
    }
}

#[inline(always)]
fn filter_ipv4_lpm(ipaddr: u32) -> u8 {
    let v4_key = V4LpmKey {
        src: ipaddr,
        prefixlen: 32,
    };
    let lpm_val = bpf_map_lookup_elem(&v4_lpm_val_map, &v4_key) as *const V4LpmVal;
    if lpm_val.is_null() {
        0
    } else {
        unsafe { (*lpm_val).val }
    }
}

#[inline(always)]
fn filter_src_dst_ip(info: *const PktInfo, match_info: *mut FwMatchInfo) {
    let kind = unsafe { (*info).kind };
    if kind == IP_V6 {
        let ipv6 = unsafe { (*info).ip } as *const Ipv6Hdr;
        let saddr = unsafe { core::ptr::addr_of!((*ipv6).saddr) };
        unsafe {
            (*match_info).v6_src_ip_match = filter_ipv6_addr(saddr);
        }
    } else if kind == IP_V4 {
        let ipv4 = unsafe { (*info).ip } as *const IpHdr;
        let saddr = pget!((*ipv4).saddr);
        let daddr = pget!((*ipv4).daddr);
        unsafe {
            (*match_info).v4_src_ip_match = filter_ipv4_addr(saddr);
            (*match_info).v4_src_prefix_match = filter_ipv4_lpm(saddr);
            (*match_info).v4_dst_prefix_match = filter_ipv4_lpm(daddr);
        }
    }
}

// ---- header parsing --------------------------------------------------

#[inline(always)]
fn parse_ethhdr(data: usize, data_end: usize) -> *const EthHdr {
    if data + core::mem::size_of::<EthHdr>() > data_end {
        core::ptr::null()
    } else {
        data as *const EthHdr
    }
}

#[inline(always)]
fn get_transport_hdr(offset: u16, data: usize, data_end: usize) -> *const u8 {
    if offset > 255 || data + offset as usize > data_end {
        core::ptr::null()
    } else {
        (data + offset as usize) as *const u8
    }
}

#[inline(always)]
fn tcphdr_only_contains_flag(flags_byte: u8, flag: u8) -> bool {
    (flags_byte & TCP_FLAG_MASK) == flag
}

#[inline(always)]
fn set_tcp_flags(info: *mut PktInfo, tcp: *const TcpHdr) {
    let flags_byte = pget!((*tcp).flags);
    if tcphdr_only_contains_flag(flags_byte, TCP_FLAG_SYN) {
        unsafe {
            (*info).flags |= TCP_SYN;
        }
    } else if tcphdr_only_contains_flag(flags_byte, TCP_FLAG_ACK) {
        unsafe {
            (*info).flags |= TCP_ACK;
        }
    } else if tcphdr_only_contains_flag(flags_byte, TCP_FLAG_RST) {
        unsafe {
            (*info).flags |= TCP_RST;
        }
    }
}

#[inline(always)]
fn parse_tcp(info: *mut PktInfo, transport_hdr: usize, data_end: usize) -> bool {
    if transport_hdr + core::mem::size_of::<TcpHdr>() > data_end {
        return false;
    }
    let tcp = transport_hdr as *const TcpHdr;

    unsafe {
        (*info).sport = ntohs(pget!((*tcp).source)) as i32;
        (*info).dport = ntohs(pget!((*tcp).dest)) as i32;
    }
    set_tcp_flags(info, tcp);

    true
}

#[inline(always)]
fn parse_udp(info: *mut PktInfo, transport_hdr: usize, data_end: usize) -> bool {
    if transport_hdr + core::mem::size_of::<UdpHdr>() > data_end {
        return false;
    }
    let udp = transport_hdr as *const UdpHdr;

    unsafe {
        (*info).sport = ntohs(pget!((*udp).source)) as i32;
        (*info).dport = ntohs(pget!((*udp).dest)) as i32;
    }

    true
}

#[inline(always)]
fn filter_tcp_port(port: i32) -> u8 {
    let leaf = bpf_map_lookup_elem(&tcp_port_map, &port) as *const u8;
    if leaf.is_null() {
        0
    } else {
        unsafe { *leaf }
    }
}

#[inline(always)]
fn filter_udp_port(port: i32) -> u16 {
    let leaf = bpf_map_lookup_elem(&udp_port_map, &port) as *const u16;
    if leaf.is_null() {
        0
    } else {
        unsafe { *leaf }
    }
}

#[inline(always)]
fn filter_transport_hdr(
    transport_hdr: usize,
    data_end: usize,
    info: *mut PktInfo,
    match_info: *mut FwMatchInfo,
) -> bool {
    let proto = unsafe { (*info).proto };
    if proto == IPPROTO_TCP {
        if !parse_tcp(info, transport_hdr, data_end) {
            return false;
        }
        unsafe {
            (*match_info).is_tcp = true;
            (*match_info).is_tcp_syn = ((*info).flags & TCP_SYN) > 0;
            (*match_info).tcp_dp_match = filter_tcp_port((*info).dport);
        }
    } else if proto == IPPROTO_UDP {
        if !parse_udp(info, transport_hdr, data_end) {
            return false;
        }
        unsafe {
            (*match_info).udp_dp_match = filter_udp_port((*info).dport);
            (*match_info).udp_sp_match = filter_udp_port((*info).sport);
        }
    }

    true
}

#[inline(always)]
fn parse_gue_v6(info: *mut PktInfo, ip6h: *const Ipv6Hdr, data_end: usize) -> u8 {
    let udp_addr = ip6h as usize + core::mem::size_of::<Ipv6Hdr>();
    let encap_data_addr = udp_addr + core::mem::size_of::<UdpHdr>();

    if udp_addr + core::mem::size_of::<UdpHdr>() > data_end {
        return BAD_IP6_HDR;
    }
    let udp = udp_addr as *const UdpHdr;

    if pget!((*udp).dest) != htons(6666) {
        return NO_ERR;
    }

    unsafe {
        (*info).flags |= TUNNEL;
    }

    if encap_data_addr + 1 > data_end {
        return BAD_IP6GUE_HDR;
    }

    let first_byte = unsafe { core::ptr::read_unaligned(encap_data_addr as *const u8) };
    if first_byte & 0x30 != 0 {
        if encap_data_addr + core::mem::size_of::<Ipv6Hdr>() > data_end {
            return BAD_IP6GUE_HDR;
        }
        let inner_ip6h = encap_data_addr as *const Ipv6Hdr;

        unsafe {
            (*info).kind = IP_V6;
            (*info).proto = pget!((*inner_ip6h).nexthdr);
            (*info).ip = inner_ip6h as *const u8;
            (*info).trans_hdr_offset = (*info).trans_hdr_offset.wrapping_add(
                (core::mem::size_of::<Ipv6Hdr>() + core::mem::size_of::<UdpHdr>()) as u16,
            );
        }
    } else {
        if encap_data_addr + core::mem::size_of::<IpHdr>() > data_end {
            return BAD_IP6GUE_HDR;
        }
        let inner_ip4h = encap_data_addr as *const IpHdr;

        unsafe {
            (*info).kind = IP_V4;
            (*info).proto = pget!((*inner_ip4h).protocol);
            (*info).ip = inner_ip4h as *const u8;
            (*info).trans_hdr_offset = (*info).trans_hdr_offset.wrapping_add(
                (core::mem::size_of::<IpHdr>() + core::mem::size_of::<UdpHdr>()) as u16,
            );
        }
    }

    NO_ERR
}

#[inline(always)]
fn parse_ipv6_gue(info: *mut PktInfo, data: usize, data_end: usize) -> u8 {
    let ip6h_addr = data + core::mem::size_of::<EthHdr>();
    if ip6h_addr + core::mem::size_of::<Ipv6Hdr>() > data_end {
        return BAD_IP6_HDR;
    }
    let ip6h = ip6h_addr as *const Ipv6Hdr;

    unsafe {
        (*info).proto = pget!((*ip6h).nexthdr);
        (*info).ip = ip6h as *const u8;
        (*info).kind = IP_V6;
        (*info).trans_hdr_offset =
            (core::mem::size_of::<EthHdr>() + core::mem::size_of::<Ipv6Hdr>()) as u16;
    }

    if unsafe { (*info).proto } == IPPROTO_UDP {
        return parse_gue_v6(info, ip6h, data_end);
    }

    NO_ERR
}

// ---- UAPI struct xdp_md (linux/bpf.h) -------------------------------------

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

// ---- entry point ------------------------------------------------------

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn edgewall(ctx: *const xdp_md) -> i32 {
    let data_end = vload!((*ctx).data_end) as usize;
    let data = vload!((*ctx).data) as usize;

    let mut match_info = FwMatchInfo {
        v4_src_ip_match: 0,
        v6_src_ip_match: 0,
        v4_src_prefix_match: 0,
        v4_dst_prefix_match: 0,
        tcp_dp_match: 0,
        udp_sp_match: 0,
        udp_dp_match: 0,
        is_tcp: false,
        is_tcp_syn: false,
    };
    let mut info = PktInfo {
        kind: 0,
        ip: core::ptr::null(),
        sport: 0,
        dport: 0,
        trans_hdr_offset: 0,
        proto: 0,
        flags: 0,
    };

    let eth = parse_ethhdr(data, data_end);
    if eth.is_null() {
        return XDP_DROP;
    }

    let proto = pget!((*eth).h_proto);
    if proto != htons(ETH_P_IPV6) {
        return XDP_DROP;
    }

    if parse_ipv6_gue(&mut info as *mut PktInfo, data, data_end) != NO_ERR {
        return XDP_DROP;
    }

    if info.proto == IPPROTO_ICMPV6 {
        return XDP_PASS;
    }

    if info.proto != IPPROTO_TCP && info.proto != IPPROTO_UDP {
        return XDP_DROP;
    }

    filter_src_dst_ip(&info as *const PktInfo, &mut match_info as *mut FwMatchInfo);

    let transport_hdr = get_transport_hdr(info.trans_hdr_offset, data, data_end);
    if transport_hdr.is_null() {
        return XDP_DROP;
    }

    let filter_res = filter_transport_hdr(
        transport_hdr as usize,
        data_end,
        &mut info as *mut PktInfo,
        &mut match_info as *mut FwMatchInfo,
    );
    if !filter_res {
        return XDP_DROP;
    }

    if match_info.is_tcp && !match_info.is_tcp_syn {
        return XDP_PASS;
    }

    XDP_DROP
}

bpf_object!("GPL");
