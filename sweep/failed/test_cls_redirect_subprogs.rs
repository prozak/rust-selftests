#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_cls_redirect.c
// compiled with -DSUBPROGS (test_cls_redirect_subprogs.c is `#define
// SUBPROGS` + `#include "test_cls_redirect.c"`), bpf-rs-core idiom.
//
// A TC GLB/UDP decapsulator: parses an outer eth+ip+udp+gue+unigue
// ("encap_headers_t") header stack, walks a variable-length next-hop list,
// classifies the inner packet (TCP/UDP/ICMP, syn/established/syncookie via
// socket lookups) and either strips the encapsulation and redirects locally
// or re-encapsulates (GUE or GRE) towards the next hop.
//
// Two structural choices carry the whole file:
//
// - Every header struct that lives inside the packet (encap_headers_t,
//   encap_gre_t and their members) is `#[repr(C, packed)]`, and is only ever
//   touched through raw pointers via the `pget!`/`pset!` macros
//   (`read_unaligned`/`write_unaligned` over `addr_of!`/`addr_of_mut!`) —
//   mirroring the "never take a reference to a static mut" rule for globals,
//   applied to packed/unaligned packet memory instead. C's bitfields
//   (guehdr's hlen/control/variant, unigue's version/forward_syn/
//   last_hop_gre) become a single raw byte field plus free accessor
//   functions doing the shift/mask by hand.
//
// - Every function the C source marks `INLINING` (== `__noinline` under
//   SUBPROGS) is `#[inline(never)] #[no_mangle] extern "C" fn` here, so the
//   Rust object exercises the same bpf2bpf subprogram call graph the C
//   SUBPROGS variant is built to test. `#[no_mangle]` keeps rustc from
//   dead-arg-eliminating a parameter across the real call boundary (as in
//   test_global_func1.rs); the build's internalize pass demotes these back
//   to local symbols since none of them are in the C object's keep-list.
//   Functions the C marks `__always_inline` (buf_* and the two pkt_parse_*
//   that return pointers into the caller's own stack scratch) stay
//   `#[inline(always)]` plain functions — pkt_parse_ipv6 in particular must
//   actually inline, since a real subprogram cannot return a pointer into
//   its own stack frame.

use core::ffi::c_void;

use bpf_rs_core::ctx::{__sk_buff, TC_ACT_OK, TC_ACT_SHOT};
use bpf_rs_core::helpers::{
    bpf_check_mtu, bpf_csum_level, bpf_l3_csum_replace, bpf_map_lookup_elem, bpf_redirect,
    bpf_sk_lookup_udp, bpf_sk_release, bpf_skb_adjust_room, bpf_skb_load_bytes,
    bpf_skb_pull_data, bpf_skb_store_bytes, bpf_skc_lookup_tcp, bpf_tcp_check_syncookie,
};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::{bpf_object, vload};

// ---- Unaligned packed-field access -----------------------------------

macro_rules! pget {
    ($place:expr) => {
        unsafe { core::ptr::read_unaligned(core::ptr::addr_of!($place)) }
    };
}

macro_rules! pset {
    ($place:expr, $val:expr) => {
        unsafe { core::ptr::write_unaligned(core::ptr::addr_of_mut!($place), $val) }
    };
}

macro_rules! bump {
    ($place:expr) => {
        unsafe {
            $place = $place.wrapping_add(1);
        }
    };
}

const CONTINUE_PROCESSING: i32 = -1;

macro_rules! maybe_return {
    ($e:expr) => {{
        let __ret: i32 = $e;
        if __ret != CONTINUE_PROCESSING {
            return __ret;
        }
    }};
}

#[inline(always)]
fn htons(x: u16) -> u16 {
    x.to_be()
}

#[inline(always)]
fn ntohs(x: u16) -> u16 {
    u16::from_be(x)
}

// ---- Protocol / flag constants ----------------------------------------

const ETH_ALEN: usize = 6;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;

const IPPROTO_HOPOPTS: u8 = 0;
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_IPIP: u8 = 4;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_IPV6: u8 = 41;
const IPPROTO_GRE: u8 = 47;
const IPPROTO_ROUTING: u8 = 43;
const IPPROTO_FRAGMENT: u8 = 44;
const IPPROTO_ICMPV6: u8 = 58;
const IPPROTO_DSTOPTS: u8 = 60;
const IPPROTO_MH: u8 = 135;

const ICMP_ECHOREPLY: u8 = 0;
const ICMP_DEST_UNREACH: u8 = 3;
const ICMP_FRAG_NEEDED: u8 = 4;
const ICMP_ECHO: u8 = 8;

const ICMPV6_PKT_TOOBIG: u8 = 2;
const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY: u8 = 129;

const IP_OFFSET_MASK: u16 = 0x1FFF;
const IP_MF: u16 = 0x2000;

const BPF_F_CURRENT_NETNS: u64 = -1i64 as u64;
const BPF_TCP_ESTABLISHED: u32 = 1;
const BPF_TCP_LISTEN: u32 = 10;
const BPF_F_INGRESS: u64 = 1 << 0;
const BPF_ADJ_ROOM_NET: u32 = 0;
const BPF_ADJ_ROOM_MAC: u32 = 1;
const BPF_F_ADJ_ROOM_FIXED_GSO: u64 = 1 << 0;
const BPF_F_ADJ_ROOM_NO_CSUM_RESET: u64 = 1 << 5;
const BPF_CSUM_LEVEL_INC: u64 = 1;
const BPF_CSUM_LEVEL_DEC: u64 = 2;

// verdict_t
const INVALID: i32 = 0;
const UNKNOWN: i32 = 1;
const ECHO_REQUEST: i32 = 2;
const SYN: i32 = 3;
const SYN_COOKIE: i32 = 4;
const ESTABLISHED: i32 = 5;

// byte offsets within the header structs below, used where the C source
// uses offsetof() on packed/embedded fields.
const IPV4_TTL_OFFSET: u32 = 8;
const IPV4_CHECK_OFFSET: u32 = 10;
const IPV6_HOP_LIMIT_OFFSET: u32 = 7;

// ---- Wire header layouts ------------------------------------------------

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
    res1_doff: u8, // res1:4, doff:4 (LE bit order)
    flags: u8,     // fin:1,syn:1,rst:1,psh:1,ack:1,urg:1,ece:1,cwr:1 (LE bit order)
    window: u16,
    check: u16,
    urg_ptr: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct IcmpHdr {
    type_: u8,
    code: u8,
    checksum: u16,
    un: [u8; 4],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct Icmp6Hdr {
    icmp6_type: u8,
    icmp6_code: u8,
    icmp6_cksum: u16,
    dataun: [u8; 4],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct InAddr {
    s_addr: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct GreBaseHdr {
    flags: u16,
    protocol: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct GueHdr {
    b0: u8, // hlen:5, control:1, variant:2 (LE bit order)
    proto_ctype: u8,
    flags: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Unigue {
    b0: u8, // _r:2, last_hop_gre:1, forward_syn:1, version:4 (LE bit order)
    reserved: u8,
    next_hop: u8,
    hop_count: u8,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct EncapHeaders {
    eth: EthHdr,
    ip: IpHdr,
    udp: UdpHdr,
    gue: GueHdr,
    unigue: Unigue,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct EncapGre {
    eth: EthHdr,
    ip: IpHdr,
    gre: GreBaseHdr,
}

#[repr(C)]
struct ExtHdr {
    next: u8,
    len: u8,
}

#[inline(always)]
fn ip_ihl(b: u8) -> u8 {
    b & 0xF
}
#[inline(always)]
fn ip_version(b: u8) -> u8 {
    (b >> 4) & 0xF
}
#[inline(always)]
fn ipv6_version(b: u8) -> u8 {
    (b >> 4) & 0xF
}
#[inline(always)]
fn gue_control(b: u8) -> u8 {
    (b >> 5) & 0x1
}
#[inline(always)]
fn gue_variant(b: u8) -> u8 {
    (b >> 6) & 0x3
}
#[inline(always)]
fn gue_hlen(b: u8) -> u8 {
    b & 0x1F
}
#[inline(always)]
fn unigue_last_hop_gre(b: u8) -> u8 {
    (b >> 2) & 0x1
}
#[inline(always)]
fn unigue_forward_syn(b: u8) -> u8 {
    (b >> 3) & 0x1
}
#[inline(always)]
fn unigue_version(b: u8) -> u8 {
    (b >> 4) & 0xF
}
#[inline(always)]
fn tcp_syn(b: u8) -> bool {
    (b >> 1) & 0x1 != 0
}

// ---- struct bpf_sock_tuple / struct bpf_sock (UAPI) --------------------

#[repr(C)]
#[derive(Clone, Copy)]
struct TupleIpv4 {
    saddr: u32,
    daddr: u32,
    sport: u16,
    dport: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TupleIpv6 {
    saddr: [u32; 4],
    daddr: [u32; 4],
    sport: u16,
    dport: u16,
}

#[repr(C)]
union SockTuple {
    ipv4: TupleIpv4,
    ipv6: TupleIpv6,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct FlowPorts {
    src: u16,
    dst: u16,
}

// Only the fields up to and including `state` are used; the rest exist so
// this matches the real struct bpf_sock byte layout (the verifier checks
// sock-typed field access by offset, independent of our own BTF).
#[repr(C)]
#[allow(dead_code)]
struct BpfSock {
    bound_dev_if: u32,
    family: u32,
    type_: u32,
    protocol: u32,
    mark: u32,
    priority: u32,
    src_ip4: u32,
    src_ip6: [u32; 4],
    src_port: u32,
    dst_port: u16,
    _pad: u16,
    dst_ip4: u32,
    dst_ip6: [u32; 4],
    state: u32,
    rx_queue_mapping: i32,
}

// ---- metrics_t / metrics_map --------------------------------------------

#[repr(C)]
struct Metrics {
    processed_packets_total: u64,
    l3_protocol_packets_total_ipv4: u64,
    l3_protocol_packets_total_ipv6: u64,
    l4_protocol_packets_total_tcp: u64,
    l4_protocol_packets_total_udp: u64,
    accepted_packets_total_syn: u64,
    accepted_packets_total_syn_cookies: u64,
    accepted_packets_total_last_hop: u64,
    accepted_packets_total_icmp_echo_request: u64,
    accepted_packets_total_established: u64,
    forwarded_packets_total_gue: u64,
    forwarded_packets_total_gre: u64,

    errors_total_unknown_l3_proto: u64,
    errors_total_unknown_l4_proto: u64,
    errors_total_malformed_ip: u64,
    errors_total_fragmented_ip: u64,
    errors_total_malformed_icmp: u64,
    errors_total_unwanted_icmp: u64,
    errors_total_malformed_icmp_pkt_too_big: u64,
    errors_total_malformed_tcp: u64,
    errors_total_malformed_udp: u64,
    errors_total_icmp_echo_replies: u64,
    errors_total_malformed_encapsulation: u64,
    errors_total_encap_adjust_failed: u64,
    errors_total_encap_buffer_too_small: u64,
    errors_total_redirect_loop: u64,
    errors_total_encap_mtu_violate: u64,
}

#[link_section = ".maps"]
#[no_mangle]
static metrics_map: BpfMap<u32, Metrics, { maps::PERCPU_ARRAY }, 1> = BpfMap::new();

#[no_mangle]
#[inline(never)]
extern "C" fn get_global_metrics() -> *mut Metrics {
    let key: u32 = 0;
    bpf_map_lookup_elem(&metrics_map, &key) as *mut Metrics
}

// ---- .rodata config ------------------------------------------------------

#[link_section = ".rodata"]
#[no_mangle]
static ENCAPSULATION_PORT: u16 = 0;

#[link_section = ".rodata"]
#[no_mangle]
static ENCAPSULATION_IP: u32 = 0;

#[inline(always)]
fn encapsulation_port() -> u16 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(ENCAPSULATION_PORT)) }
}

#[inline(always)]
fn encapsulation_ip() -> u32 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(ENCAPSULATION_IP)) }
}

// ---- buf_t equivalent -----------------------------------------------------

#[repr(C)]
struct Buf {
    skb: *mut __sk_buff,
    head: *mut u8,
    tail: *mut u8,
}

#[inline(always)]
fn buf_off(buf: *mut Buf) -> usize {
    let skb = unsafe { (*buf).skb };
    let head = unsafe { (*buf).head };
    (head as usize).wrapping_sub(vload!((*skb).data) as usize)
}

#[inline(always)]
fn buf_copy(buf: *mut Buf, dst: *mut c_void, len: usize) -> bool {
    let skb = unsafe { (*buf).skb };
    if bpf_skb_load_bytes(skb as *const c_void, buf_off(buf) as u32, dst, len as u32) != 0 {
        return false;
    }
    unsafe {
        (*buf).head = (*buf).head.add(len);
    }
    true
}

#[inline(always)]
fn buf_skip(buf: *mut Buf, len: usize) -> bool {
    let skb = unsafe { (*buf).skb };
    if buf_off(buf).wrapping_add(len) > vload!((*skb).len) as usize {
        return false;
    }
    unsafe {
        (*buf).head = (*buf).head.add(len);
    }
    true
}

#[inline(always)]
fn buf_assign(buf: *mut Buf, len: usize, scratch: *mut c_void) -> *mut u8 {
    let head = unsafe { (*buf).head };
    let tail = unsafe { (*buf).tail };
    let want = unsafe { head.add(len) };
    if want > tail {
        if scratch.is_null() {
            return core::ptr::null_mut();
        }
        return if buf_copy(buf, scratch, len) {
            scratch as *mut u8
        } else {
            core::ptr::null_mut()
        };
    }
    unsafe {
        (*buf).head = want;
    }
    head
}

// ---- Packet parsing helpers ------------------------------------------------

#[no_mangle]
#[inline(never)]
extern "C" fn pkt_skip_ipv4_options(buf: *mut Buf, ipv4: *const IpHdr) -> bool {
    let ihl = ip_ihl(pget!((*ipv4).ihl_version));
    if ihl <= 5 {
        return true;
    }
    buf_skip(buf, (ihl.wrapping_sub(5)) as usize * 4)
}

#[no_mangle]
#[inline(never)]
extern "C" fn ipv4_is_fragment(ip: *const IpHdr) -> bool {
    let frag_off_raw = pget!((*ip).frag_off);
    let frag_off = frag_off_raw & htons(IP_OFFSET_MASK);
    (frag_off_raw & htons(IP_MF)) != 0 || frag_off > 0
}

#[inline(always)]
fn pkt_parse_ipv4(pkt: *mut Buf, scratch: *mut IpHdr) -> *mut IpHdr {
    let ipv4 = buf_assign(pkt, core::mem::size_of::<IpHdr>(), scratch as *mut c_void) as *mut IpHdr;
    if ipv4.is_null() {
        return core::ptr::null_mut();
    }
    if ip_ihl(pget!((*ipv4).ihl_version)) < 5 {
        return core::ptr::null_mut();
    }
    if !pkt_skip_ipv4_options(pkt, ipv4) {
        return core::ptr::null_mut();
    }
    ipv4
}

#[no_mangle]
#[inline(never)]
extern "C" fn pkt_parse_icmp_l4_ports(pkt: *mut Buf, ports: *mut FlowPorts) -> bool {
    if !buf_copy(pkt, ports as *mut c_void, core::mem::size_of::<FlowPorts>()) {
        return false;
    }
    let dst = pget!((*ports).src);
    pset!((*ports).src, pget!((*ports).dst));
    pset!((*ports).dst, dst);
    true
}

#[no_mangle]
#[inline(never)]
extern "C" fn pkt_checksum_fold(csum_in: u32) -> u16 {
    let mut csum = csum_in;
    csum = (csum & 0xffff).wrapping_add(csum >> 16);
    csum = (csum & 0xffff).wrapping_add(csum >> 16);
    !(csum as u16)
}

#[no_mangle]
#[inline(never)]
extern "C" fn pkt_ipv4_checksum(iph: *mut IpHdr) {
    pset!((*iph).check, 0u16);

    let mut acc: u32 = 0;
    let words = iph as *const u16;
    let mut i = 0usize;
    while i < core::mem::size_of::<IpHdr>() / 2 {
        let w = unsafe { core::ptr::read_unaligned(words.add(i)) };
        acc = acc.wrapping_add(w as u32);
        i += 1;
    }

    pset!((*iph).check, pkt_checksum_fold(acc));
}

#[no_mangle]
#[inline(never)]
extern "C" fn pkt_skip_ipv6_extension_headers(
    pkt: *mut Buf,
    ipv6: *const Ipv6Hdr,
    upper_proto: *mut u8,
    is_fragment: *mut bool,
) -> bool {
    let mut exthdr = ExtHdr {
        next: pget!((*ipv6).nexthdr),
        len: 0,
    };
    unsafe {
        *is_fragment = false;
    }

    let mut i = 0;
    while i < 6 {
        match exthdr.next {
            IPPROTO_FRAGMENT => {
                unsafe {
                    *is_fragment = true;
                }
                if !buf_copy(
                    pkt,
                    &mut exthdr as *mut ExtHdr as *mut c_void,
                    core::mem::size_of::<ExtHdr>(),
                ) {
                    return false;
                }
                if !buf_skip(
                    pkt,
                    (exthdr.len as usize + 1) * 8 - core::mem::size_of::<ExtHdr>(),
                ) {
                    return false;
                }
            }

            IPPROTO_HOPOPTS | IPPROTO_ROUTING | IPPROTO_DSTOPTS | IPPROTO_MH => {
                if !buf_copy(
                    pkt,
                    &mut exthdr as *mut ExtHdr as *mut c_void,
                    core::mem::size_of::<ExtHdr>(),
                ) {
                    return false;
                }
                if !buf_skip(
                    pkt,
                    (exthdr.len as usize + 1) * 8 - core::mem::size_of::<ExtHdr>(),
                ) {
                    return false;
                }
            }

            _ => {
                unsafe {
                    *upper_proto = exthdr.next;
                }
                return true;
            }
        }
        i += 1;
    }

    false
}

#[inline(always)]
fn pkt_parse_ipv6(
    pkt: *mut Buf,
    scratch: *mut Ipv6Hdr,
    proto: *mut u8,
    is_fragment: *mut bool,
) -> *mut Ipv6Hdr {
    let ipv6 =
        buf_assign(pkt, core::mem::size_of::<Ipv6Hdr>(), scratch as *mut c_void) as *mut Ipv6Hdr;
    if ipv6.is_null() {
        return core::ptr::null_mut();
    }
    if !pkt_skip_ipv6_extension_headers(pkt, ipv6, proto, is_fragment) {
        return core::ptr::null_mut();
    }
    ipv6
}

// ---- Redirect / forwarding ------------------------------------------------

#[no_mangle]
#[inline(never)]
extern "C" fn accept_locally(skb: *mut __sk_buff, encap: *mut EncapHeaders) -> i32 {
    let hop_count = pget!((*encap).unigue.hop_count);
    let payload_off =
        core::mem::size_of::<EncapHeaders>() + core::mem::size_of::<InAddr>() * hop_count as usize;
    let encap_overhead = payload_off as i32 - core::mem::size_of::<EthHdr>() as i32;

    if pget!((*encap).gue.proto_ctype) == IPPROTO_IPV6 {
        pset!((*encap).eth.h_proto, htons(ETH_P_IPV6));
    }

    if bpf_skb_adjust_room(
        skb as *const c_void,
        -encap_overhead,
        BPF_ADJ_ROOM_MAC,
        BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_NO_CSUM_RESET,
    ) != 0
        || bpf_csum_level(skb as *const c_void, BPF_CSUM_LEVEL_DEC) != 0
    {
        return TC_ACT_SHOT;
    }

    bpf_redirect(vload!((*skb).ifindex), BPF_F_INGRESS) as i32
}

#[no_mangle]
#[inline(never)]
extern "C" fn forward_with_gre(
    skb: *mut __sk_buff,
    encap: *mut EncapHeaders,
    next_hop: *const InAddr,
    metrics: *mut Metrics,
) -> i32 {
    bump!((*metrics).forwarded_packets_total_gre);

    let hop_count = pget!((*encap).unigue.hop_count);
    let payload_off =
        core::mem::size_of::<EncapHeaders>() + core::mem::size_of::<InAddr>() * hop_count as usize;
    let encap_overhead = payload_off as i32
        - core::mem::size_of::<EthHdr>() as i32
        - core::mem::size_of::<IpHdr>() as i32;
    let delta = core::mem::size_of::<GreBaseHdr>() as i32 - encap_overhead;
    let mut proto: u16 = ETH_P_IP;
    let mut mtu_len: u32 = 0;

    if pget!((*encap).gue.proto_ctype) == IPPROTO_IPV6 {
        proto = ETH_P_IPV6;
        let mut ttl: u8 = 0;
        let off = payload_off as u32 + IPV6_HOP_LIMIT_OFFSET;

        if bpf_skb_load_bytes(skb as *const c_void, off, &mut ttl as *mut u8 as *mut c_void, 1) != 0 {
            bump!((*metrics).errors_total_malformed_encapsulation);
            return TC_ACT_SHOT;
        }
        if ttl == 0 {
            bump!((*metrics).errors_total_redirect_loop);
            return TC_ACT_SHOT;
        }
        ttl = ttl.wrapping_sub(1);
        if bpf_skb_store_bytes(skb as *const c_void, off, &ttl as *const u8 as *const c_void, 1, 0) != 0 {
            bump!((*metrics).errors_total_malformed_encapsulation);
            return TC_ACT_SHOT;
        }
    } else {
        let mut ttl: u8 = 0;
        let off = payload_off as u32 + IPV4_TTL_OFFSET;

        if bpf_skb_load_bytes(skb as *const c_void, off, &mut ttl as *mut u8 as *mut c_void, 1) != 0 {
            bump!((*metrics).errors_total_malformed_encapsulation);
            return TC_ACT_SHOT;
        }
        if ttl == 0 {
            bump!((*metrics).errors_total_redirect_loop);
            return TC_ACT_SHOT;
        }

        let check_off = payload_off as u32 + IPV4_CHECK_OFFSET;
        if bpf_l3_csum_replace(
            skb as *const c_void,
            check_off,
            ttl as u64,
            ttl.wrapping_sub(1) as u64,
            2,
        ) != 0
        {
            bump!((*metrics).errors_total_malformed_encapsulation);
            return TC_ACT_SHOT;
        }

        ttl = ttl.wrapping_sub(1);
        if bpf_skb_store_bytes(skb as *const c_void, off, &ttl as *const u8 as *const c_void, 1, 0) != 0 {
            bump!((*metrics).errors_total_malformed_encapsulation);
            return TC_ACT_SHOT;
        }
    }

    if bpf_check_mtu(skb as *const c_void, vload!((*skb).ifindex), &mut mtu_len as *mut u32, delta, 0) != 0 {
        bump!((*metrics).errors_total_encap_mtu_violate);
        return TC_ACT_SHOT;
    }

    if bpf_skb_adjust_room(
        skb as *const c_void,
        delta,
        BPF_ADJ_ROOM_NET,
        BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_NO_CSUM_RESET,
    ) != 0
        || bpf_csum_level(skb as *const c_void, BPF_CSUM_LEVEL_INC) != 0
    {
        bump!((*metrics).errors_total_encap_adjust_failed);
        return TC_ACT_SHOT;
    }

    if bpf_skb_pull_data(skb as *const c_void, core::mem::size_of::<EncapGre>() as u32) != 0 {
        bump!((*metrics).errors_total_encap_buffer_too_small);
        return TC_ACT_SHOT;
    }

    let mut pkt = Buf {
        skb,
        head: vload!((*skb).data) as *mut u8,
        tail: vload!((*skb).data_end) as *mut u8,
    };

    let encap_gre = buf_assign(&mut pkt, core::mem::size_of::<EncapGre>(), core::ptr::null_mut())
        as *mut EncapGre;
    if encap_gre.is_null() {
        bump!((*metrics).errors_total_encap_buffer_too_small);
        return TC_ACT_SHOT;
    }

    pset!((*encap_gre).ip.protocol, IPPROTO_GRE);
    pset!((*encap_gre).ip.daddr, pget!((*next_hop).s_addr));
    pset!((*encap_gre).ip.saddr, encapsulation_ip());
    let tot_len = pget!((*encap_gre).ip.tot_len);
    pset!(
        (*encap_gre).ip.tot_len,
        htons((ntohs(tot_len) as i32).wrapping_add(delta) as u16)
    );
    pset!((*encap_gre).gre.flags, 0u16);
    pset!((*encap_gre).gre.protocol, htons(proto));
    pkt_ipv4_checksum(unsafe { core::ptr::addr_of_mut!((*encap_gre).ip) });

    bpf_redirect(vload!((*skb).ifindex), 0) as i32
}

#[no_mangle]
#[inline(never)]
extern "C" fn forward_to_next_hop(
    skb: *mut __sk_buff,
    encap: *mut EncapHeaders,
    next_hop: *const InAddr,
    metrics: *mut Metrics,
) -> i32 {
    let mut temp = [0u8; ETH_ALEN];
    let dest = unsafe { core::ptr::addr_of_mut!((*encap).eth.h_dest) } as *mut u8;
    let source = unsafe { core::ptr::addr_of_mut!((*encap).eth.h_source) } as *mut u8;
    unsafe {
        core::ptr::copy_nonoverlapping(dest, temp.as_mut_ptr(), ETH_ALEN);
        core::ptr::copy_nonoverlapping(source, dest, ETH_ALEN);
        core::ptr::copy_nonoverlapping(temp.as_ptr(), source, ETH_ALEN);
    }

    let hop_count = pget!((*encap).unigue.hop_count);
    let next_hop_idx = pget!((*encap).unigue.next_hop);
    let b0 = pget!((*encap).unigue.b0);

    if next_hop_idx == hop_count.wrapping_sub(1) && unigue_last_hop_gre(b0) != 0 {
        return forward_with_gre(skb, encap, next_hop, metrics);
    }

    bump!((*metrics).forwarded_packets_total_gue);
    let old_saddr = pget!((*encap).ip.saddr);
    pset!((*encap).ip.saddr, pget!((*encap).ip.daddr));
    pset!((*encap).ip.daddr, pget!((*next_hop).s_addr));
    if next_hop_idx < hop_count {
        pset!((*encap).unigue.next_hop, next_hop_idx.wrapping_add(1));
    }

    let off = core::mem::size_of::<EthHdr>() as u32 + IPV4_CHECK_OFFSET;
    let ret = bpf_l3_csum_replace(
        skb as *const c_void,
        off,
        old_saddr as u64,
        pget!((*next_hop).s_addr) as u64,
        4,
    );
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    bpf_redirect(vload!((*skb).ifindex), 0) as i32
}

#[no_mangle]
#[inline(never)]
extern "C" fn skip_next_hops(pkt: *mut Buf, n: u8) -> i32 {
    match n {
        1 => {
            if !buf_skip(pkt, core::mem::size_of::<InAddr>()) {
                return TC_ACT_SHOT;
            }
            CONTINUE_PROCESSING
        }
        0 => CONTINUE_PROCESSING,
        _ => TC_ACT_SHOT,
    }
}

#[no_mangle]
#[inline(never)]
extern "C" fn get_next_hop(pkt: *mut Buf, encap: *const EncapHeaders, next_hop: *mut InAddr) -> i32 {
    let next_hop_idx = pget!((*encap).unigue.next_hop);
    let hop_count = pget!((*encap).unigue.hop_count);

    if next_hop_idx > hop_count {
        return TC_ACT_SHOT;
    }

    maybe_return!(skip_next_hops(pkt, next_hop_idx));

    if next_hop_idx == hop_count {
        pset!((*next_hop).s_addr, 0u32);
        return CONTINUE_PROCESSING;
    }

    if !buf_copy(pkt, next_hop as *mut c_void, core::mem::size_of::<InAddr>()) {
        return TC_ACT_SHOT;
    }

    skip_next_hops(pkt, hop_count.wrapping_sub(next_hop_idx).wrapping_sub(1))
}

// ---- Socket-lookup based classification -----------------------------------

#[no_mangle]
#[inline(never)]
extern "C" fn fill_tuple(
    tuple: *mut SockTuple,
    iph: *const c_void,
    iphlen: u64,
    sport: u16,
    dport: u16,
) -> u64 {
    if iphlen == core::mem::size_of::<IpHdr>() as u64 {
        let ipv4 = iph as *const IpHdr;
        pset!((*tuple).ipv4.daddr, pget!((*ipv4).daddr));
        pset!((*tuple).ipv4.saddr, pget!((*ipv4).saddr));
        pset!((*tuple).ipv4.sport, sport);
        pset!((*tuple).ipv4.dport, dport);
        core::mem::size_of::<TupleIpv4>() as u64
    } else if iphlen == core::mem::size_of::<Ipv6Hdr>() as u64 {
        let ipv6 = iph as *const Ipv6Hdr;
        unsafe {
            core::ptr::copy_nonoverlapping(
                core::ptr::addr_of!((*ipv6).daddr) as *const u8,
                core::ptr::addr_of_mut!((*tuple).ipv6.daddr) as *mut u8,
                16,
            );
            core::ptr::copy_nonoverlapping(
                core::ptr::addr_of!((*ipv6).saddr) as *const u8,
                core::ptr::addr_of_mut!((*tuple).ipv6.saddr) as *mut u8,
                16,
            );
        }
        pset!((*tuple).ipv6.sport, sport);
        pset!((*tuple).ipv6.dport, dport);
        core::mem::size_of::<TupleIpv6>() as u64
    } else {
        0
    }
}

#[no_mangle]
#[inline(never)]
extern "C" fn classify_tcp(
    skb: *mut __sk_buff,
    tuple: *mut SockTuple,
    tuplen: u64,
    iph: *const c_void,
    tcp: *const TcpHdr,
) -> i32 {
    let sk = bpf_skc_lookup_tcp(skb as *const c_void, tuple, tuplen as u32, BPF_F_CURRENT_NETNS, 0)
        as *mut BpfSock;
    if sk.is_null() {
        return UNKNOWN;
    }

    if unsafe { (*sk).state } != BPF_TCP_LISTEN {
        bpf_sk_release(sk as *mut c_void);
        return ESTABLISHED;
    }

    if !iph.is_null() && !tcp.is_null() {
        let mut iphlen = core::mem::size_of::<IpHdr>() as u32;
        if tuplen == core::mem::size_of::<TupleIpv6>() as u64 {
            iphlen = core::mem::size_of::<Ipv6Hdr>() as u32;
        }

        if bpf_tcp_check_syncookie(sk, iph, iphlen, tcp, core::mem::size_of::<TcpHdr>() as u32) == 0 {
            bpf_sk_release(sk as *mut c_void);
            return SYN_COOKIE;
        }
    }

    bpf_sk_release(sk as *mut c_void);
    UNKNOWN
}

#[no_mangle]
#[inline(never)]
extern "C" fn classify_udp(skb: *mut __sk_buff, tuple: *mut SockTuple, tuplen: u64) -> i32 {
    let sk = bpf_sk_lookup_udp(skb as *const c_void, tuple, tuplen as u32, BPF_F_CURRENT_NETNS, 0)
        as *mut BpfSock;
    if sk.is_null() {
        return UNKNOWN;
    }

    if unsafe { (*sk).state } == BPF_TCP_ESTABLISHED {
        bpf_sk_release(sk as *mut c_void);
        return ESTABLISHED;
    }

    bpf_sk_release(sk as *mut c_void);
    UNKNOWN
}

#[no_mangle]
#[inline(never)]
extern "C" fn classify_icmp(
    skb: *mut __sk_buff,
    proto: u8,
    tuple: *mut SockTuple,
    tuplen: u64,
    metrics: *mut Metrics,
) -> i32 {
    match proto {
        IPPROTO_TCP => classify_tcp(skb, tuple, tuplen, core::ptr::null(), core::ptr::null()),
        IPPROTO_UDP => classify_udp(skb, tuple, tuplen),
        _ => {
            bump!((*metrics).errors_total_malformed_icmp);
            INVALID
        }
    }
}

// ---- Per-protocol packet processing ----------------------------------------

#[no_mangle]
#[inline(never)]
extern "C" fn process_icmpv4(pkt: *mut Buf, metrics: *mut Metrics) -> i32 {
    let mut icmp = IcmpHdr {
        type_: 0,
        code: 0,
        checksum: 0,
        un: [0; 4],
    };
    if !buf_copy(
        pkt,
        &mut icmp as *mut IcmpHdr as *mut c_void,
        core::mem::size_of::<IcmpHdr>(),
    ) {
        bump!((*metrics).errors_total_malformed_icmp);
        return INVALID;
    }

    if pget!(icmp.type_) == ICMP_ECHOREPLY {
        bump!((*metrics).errors_total_icmp_echo_replies);
        return INVALID;
    }

    if pget!(icmp.type_) == ICMP_ECHO {
        return ECHO_REQUEST;
    }

    if pget!(icmp.type_) != ICMP_DEST_UNREACH || pget!(icmp.code) != ICMP_FRAG_NEEDED {
        bump!((*metrics).errors_total_unwanted_icmp);
        return INVALID;
    }

    let mut scratch = IpHdr {
        ihl_version: 0,
        tos: 0,
        tot_len: 0,
        id: 0,
        frag_off: 0,
        ttl: 0,
        protocol: 0,
        check: 0,
        saddr: 0,
        daddr: 0,
    };
    let ipv4 = pkt_parse_ipv4(pkt, &mut scratch as *mut IpHdr);
    if ipv4.is_null() {
        bump!((*metrics).errors_total_malformed_icmp_pkt_too_big);
        return INVALID;
    }

    let mut tuple = SockTuple {
        ipv4: TupleIpv4 {
            saddr: 0,
            daddr: 0,
            sport: 0,
            dport: 0,
        },
    };
    let tuple_ptr = core::ptr::addr_of_mut!(tuple);
    pset!((*tuple_ptr).ipv4.saddr, pget!((*ipv4).daddr));
    pset!((*tuple_ptr).ipv4.daddr, pget!((*ipv4).saddr));

    let ports = unsafe { core::ptr::addr_of_mut!((*tuple_ptr).ipv4.sport) } as *mut FlowPorts;
    if !pkt_parse_icmp_l4_ports(pkt, ports) {
        bump!((*metrics).errors_total_malformed_icmp_pkt_too_big);
        return INVALID;
    }

    let protocol = pget!((*ipv4).protocol);
    let skb = unsafe { (*pkt).skb };
    classify_icmp(
        skb,
        protocol,
        tuple_ptr,
        core::mem::size_of::<TupleIpv4>() as u64,
        metrics,
    )
}

#[no_mangle]
#[inline(never)]
extern "C" fn process_icmpv6(pkt: *mut Buf, metrics: *mut Metrics) -> i32 {
    let mut icmp6 = Icmp6Hdr {
        icmp6_type: 0,
        icmp6_code: 0,
        icmp6_cksum: 0,
        dataun: [0; 4],
    };
    if !buf_copy(
        pkt,
        &mut icmp6 as *mut Icmp6Hdr as *mut c_void,
        core::mem::size_of::<Icmp6Hdr>(),
    ) {
        bump!((*metrics).errors_total_malformed_icmp);
        return INVALID;
    }

    if pget!(icmp6.icmp6_type) == ICMPV6_ECHO_REPLY {
        bump!((*metrics).errors_total_icmp_echo_replies);
        return INVALID;
    }

    if pget!(icmp6.icmp6_type) == ICMPV6_ECHO_REQUEST {
        return ECHO_REQUEST;
    }

    if pget!(icmp6.icmp6_type) != ICMPV6_PKT_TOOBIG {
        bump!((*metrics).errors_total_unwanted_icmp);
        return INVALID;
    }

    let mut is_fragment = false;
    let mut l4_proto: u8 = 0;
    let mut scratch = Ipv6Hdr {
        priority_version: 0,
        flow_lbl: [0; 3],
        payload_len: 0,
        nexthdr: 0,
        hop_limit: 0,
        saddr: [0; 16],
        daddr: [0; 16],
    };
    let ipv6 = pkt_parse_ipv6(
        pkt,
        &mut scratch as *mut Ipv6Hdr,
        &mut l4_proto as *mut u8,
        &mut is_fragment as *mut bool,
    );
    if ipv6.is_null() {
        bump!((*metrics).errors_total_malformed_icmp_pkt_too_big);
        return INVALID;
    }

    if is_fragment {
        bump!((*metrics).errors_total_fragmented_ip);
        return INVALID;
    }

    let mut tuple = SockTuple {
        ipv6: TupleIpv6 {
            saddr: [0; 4],
            daddr: [0; 4],
            sport: 0,
            dport: 0,
        },
    };
    let tuple_ptr = core::ptr::addr_of_mut!(tuple);
    unsafe {
        core::ptr::copy_nonoverlapping(
            core::ptr::addr_of!((*ipv6).daddr) as *const u8,
            core::ptr::addr_of_mut!((*tuple_ptr).ipv6.saddr) as *mut u8,
            16,
        );
        core::ptr::copy_nonoverlapping(
            core::ptr::addr_of!((*ipv6).saddr) as *const u8,
            core::ptr::addr_of_mut!((*tuple_ptr).ipv6.daddr) as *mut u8,
            16,
        );
    }

    let ports = unsafe { core::ptr::addr_of_mut!((*tuple_ptr).ipv6.sport) } as *mut FlowPorts;
    if !pkt_parse_icmp_l4_ports(pkt, ports) {
        bump!((*metrics).errors_total_malformed_icmp_pkt_too_big);
        return INVALID;
    }

    let skb = unsafe { (*pkt).skb };
    classify_icmp(
        skb,
        l4_proto,
        tuple_ptr,
        core::mem::size_of::<TupleIpv6>() as u64,
        metrics,
    )
}

#[no_mangle]
#[inline(never)]
extern "C" fn process_tcp(pkt: *mut Buf, iph: *const c_void, iphlen: u64, metrics: *mut Metrics) -> i32 {
    bump!((*metrics).l4_protocol_packets_total_tcp);

    let mut scratch = TcpHdr {
        source: 0,
        dest: 0,
        seq: 0,
        ack_seq: 0,
        res1_doff: 0,
        flags: 0,
        window: 0,
        check: 0,
        urg_ptr: 0,
    };
    let tcp = buf_assign(pkt, core::mem::size_of::<TcpHdr>(), &mut scratch as *mut TcpHdr as *mut c_void)
        as *mut TcpHdr;
    if tcp.is_null() {
        bump!((*metrics).errors_total_malformed_tcp);
        return INVALID;
    }

    if tcp_syn(pget!((*tcp).flags)) {
        return SYN;
    }

    let mut tuple = SockTuple {
        ipv4: TupleIpv4 {
            saddr: 0,
            daddr: 0,
            sport: 0,
            dport: 0,
        },
    };
    let tuple_ptr = core::ptr::addr_of_mut!(tuple);
    let tuplen = fill_tuple(tuple_ptr, iph, iphlen, pget!((*tcp).source), pget!((*tcp).dest));
    let skb = unsafe { (*pkt).skb };
    classify_tcp(skb, tuple_ptr, tuplen, iph, tcp)
}

#[no_mangle]
#[inline(never)]
extern "C" fn process_udp(pkt: *mut Buf, iph: *const c_void, iphlen: u64, metrics: *mut Metrics) -> i32 {
    bump!((*metrics).l4_protocol_packets_total_udp);

    let mut scratch = UdpHdr {
        source: 0,
        dest: 0,
        len: 0,
        check: 0,
    };
    let udph =
        buf_assign(pkt, core::mem::size_of::<UdpHdr>(), &mut scratch as *mut UdpHdr as *mut c_void)
            as *mut UdpHdr;
    if udph.is_null() {
        bump!((*metrics).errors_total_malformed_udp);
        return INVALID;
    }

    let mut tuple = SockTuple {
        ipv4: TupleIpv4 {
            saddr: 0,
            daddr: 0,
            sport: 0,
            dport: 0,
        },
    };
    let tuple_ptr = core::ptr::addr_of_mut!(tuple);
    let tuplen = fill_tuple(tuple_ptr, iph, iphlen, pget!((*udph).source), pget!((*udph).dest));
    let skb = unsafe { (*pkt).skb };
    classify_udp(skb, tuple_ptr, tuplen)
}

#[no_mangle]
#[inline(never)]
extern "C" fn process_ipv4(pkt: *mut Buf, metrics: *mut Metrics) -> i32 {
    bump!((*metrics).l3_protocol_packets_total_ipv4);

    let mut scratch = IpHdr {
        ihl_version: 0,
        tos: 0,
        tot_len: 0,
        id: 0,
        frag_off: 0,
        ttl: 0,
        protocol: 0,
        check: 0,
        saddr: 0,
        daddr: 0,
    };
    let ipv4 = pkt_parse_ipv4(pkt, &mut scratch as *mut IpHdr);
    if ipv4.is_null() {
        bump!((*metrics).errors_total_malformed_ip);
        return INVALID;
    }

    if ip_version(pget!((*ipv4).ihl_version)) != 4 {
        bump!((*metrics).errors_total_malformed_ip);
        return INVALID;
    }

    if ipv4_is_fragment(ipv4) {
        bump!((*metrics).errors_total_fragmented_ip);
        return INVALID;
    }

    match pget!((*ipv4).protocol) {
        IPPROTO_ICMP => process_icmpv4(pkt, metrics),
        IPPROTO_TCP => process_tcp(pkt, ipv4 as *const c_void, core::mem::size_of::<IpHdr>() as u64, metrics),
        IPPROTO_UDP => process_udp(pkt, ipv4 as *const c_void, core::mem::size_of::<IpHdr>() as u64, metrics),
        _ => {
            bump!((*metrics).errors_total_unknown_l4_proto);
            INVALID
        }
    }
}

#[no_mangle]
#[inline(never)]
extern "C" fn process_ipv6(pkt: *mut Buf, metrics: *mut Metrics) -> i32 {
    bump!((*metrics).l3_protocol_packets_total_ipv6);

    let mut l4_proto: u8 = 0;
    let mut is_fragment = false;
    let mut scratch = Ipv6Hdr {
        priority_version: 0,
        flow_lbl: [0; 3],
        payload_len: 0,
        nexthdr: 0,
        hop_limit: 0,
        saddr: [0; 16],
        daddr: [0; 16],
    };
    let ipv6 = pkt_parse_ipv6(
        pkt,
        &mut scratch as *mut Ipv6Hdr,
        &mut l4_proto as *mut u8,
        &mut is_fragment as *mut bool,
    );
    if ipv6.is_null() {
        bump!((*metrics).errors_total_malformed_ip);
        return INVALID;
    }

    if ipv6_version(pget!((*ipv6).priority_version)) != 6 {
        bump!((*metrics).errors_total_malformed_ip);
        return INVALID;
    }

    if is_fragment {
        bump!((*metrics).errors_total_fragmented_ip);
        return INVALID;
    }

    match l4_proto {
        IPPROTO_ICMPV6 => process_icmpv6(pkt, metrics),
        IPPROTO_TCP => process_tcp(pkt, ipv6 as *const c_void, core::mem::size_of::<Ipv6Hdr>() as u64, metrics),
        IPPROTO_UDP => process_udp(pkt, ipv6 as *const c_void, core::mem::size_of::<Ipv6Hdr>() as u64, metrics),
        _ => {
            bump!((*metrics).errors_total_unknown_l4_proto);
            INVALID
        }
    }
}

// ---- Entry point ------------------------------------------------------------

#[link_section = "tc"]
#[no_mangle]
extern "C" fn cls_redirect(skb: *mut __sk_buff) -> i32 {
    let metrics = get_global_metrics();
    if metrics.is_null() {
        return TC_ACT_SHOT;
    }

    bump!((*metrics).processed_packets_total);

    if vload!((*skb).protocol) != htons(ETH_P_IP) as u32 {
        return TC_ACT_OK;
    }

    if bpf_skb_pull_data(skb as *const c_void, core::mem::size_of::<EncapHeaders>() as u32) != 0 {
        return TC_ACT_OK;
    }

    let mut pkt = Buf {
        skb,
        head: vload!((*skb).data) as *mut u8,
        tail: vload!((*skb).data_end) as *mut u8,
    };

    let encap = buf_assign(&mut pkt, core::mem::size_of::<EncapHeaders>(), core::ptr::null_mut())
        as *mut EncapHeaders;
    if encap.is_null() {
        return TC_ACT_OK;
    }

    if ip_ihl(pget!((*encap).ip.ihl_version)) != 5 {
        return TC_ACT_OK;
    }

    if pget!((*encap).ip.daddr) != encapsulation_ip() || pget!((*encap).ip.protocol) != IPPROTO_UDP {
        return TC_ACT_OK;
    }

    if pget!((*encap).udp.dest) != encapsulation_port() {
        return TC_ACT_OK;
    }

    if ipv4_is_fragment(unsafe { core::ptr::addr_of!((*encap).ip) }) {
        bump!((*metrics).errors_total_fragmented_ip);
        return TC_ACT_SHOT;
    }

    let gue_b0 = pget!((*encap).gue.b0);
    if gue_variant(gue_b0) != 0 {
        bump!((*metrics).errors_total_malformed_encapsulation);
        return TC_ACT_SHOT;
    }

    if gue_control(gue_b0) != 0 {
        bump!((*metrics).errors_total_malformed_encapsulation);
        return TC_ACT_SHOT;
    }

    if pget!((*encap).gue.flags) != 0 {
        bump!((*metrics).errors_total_malformed_encapsulation);
        return TC_ACT_SHOT;
    }

    let hop_count = pget!((*encap).unigue.hop_count);
    if gue_hlen(gue_b0) != (core::mem::size_of::<Unigue>() / 4) as u8 + hop_count {
        bump!((*metrics).errors_total_malformed_encapsulation);
        return TC_ACT_SHOT;
    }

    let unigue_b0 = pget!((*encap).unigue.b0);
    if unigue_version(unigue_b0) != 0 {
        bump!((*metrics).errors_total_malformed_encapsulation);
        return TC_ACT_SHOT;
    }

    if pget!((*encap).unigue.reserved) != 0 {
        return TC_ACT_SHOT;
    }

    let mut next_hop = InAddr { s_addr: 0 };
    maybe_return!(get_next_hop(&mut pkt, encap, &mut next_hop as *mut InAddr));

    if pget!(next_hop.s_addr) == 0 {
        bump!((*metrics).accepted_packets_total_last_hop);
        return accept_locally(skb, encap);
    }

    let verdict = match pget!((*encap).gue.proto_ctype) {
        IPPROTO_IPIP => process_ipv4(&mut pkt, metrics),
        IPPROTO_IPV6 => process_ipv6(&mut pkt, metrics),
        _ => {
            bump!((*metrics).errors_total_unknown_l3_proto);
            return TC_ACT_SHOT;
        }
    };

    match verdict {
        INVALID => TC_ACT_SHOT,

        UNKNOWN => forward_to_next_hop(skb, encap, &next_hop as *const InAddr, metrics),

        ECHO_REQUEST => {
            bump!((*metrics).accepted_packets_total_icmp_echo_request);
            accept_locally(skb, encap)
        }

        SYN => {
            if unigue_forward_syn(pget!((*encap).unigue.b0)) != 0 {
                forward_to_next_hop(skb, encap, &next_hop as *const InAddr, metrics)
            } else {
                bump!((*metrics).accepted_packets_total_syn);
                accept_locally(skb, encap)
            }
        }

        SYN_COOKIE => {
            bump!((*metrics).accepted_packets_total_syn_cookies);
            accept_locally(skb, encap)
        }

        ESTABLISHED => {
            bump!((*metrics).accepted_packets_total_established);
            accept_locally(skb, encap)
        }

        _ => TC_ACT_SHOT,
    }
}

bpf_object!("Dual BSD/GPL");
