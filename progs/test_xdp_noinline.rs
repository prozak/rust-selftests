#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_xdp_noinline.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_ktime_get_ns, bpf_map_lookup_elem, bpf_map_update_elem, bpf_xdp_adjust_head,
};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::{bpf_map, vload};

const XDP_DROP: i32 = 1;
const XDP_PASS: i32 = 2;
const XDP_TX: i32 = 3;

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;

const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_IPIP: u8 = 4;
const IPPROTO_IPV6: u8 = 41;

const PCKT_FRAGMENTED: u16 = 65343;

const F_ICMP: u8 = 1 << 0;
const F_SYN_SET: u8 = 1 << 1;

const CH_RINGS_SIZE: usize = 12 * 655;

const JHASH_INITVAL: u32 = 0xdeadbeef;

#[inline(always)]
fn rol32(word: u32, shift: u32) -> u32 {
    word.rotate_left(shift)
}

#[inline(always)]
fn jhash_mix(a: &mut u32, b: &mut u32, c: &mut u32) {
    *a = a.wrapping_sub(*c);
    *a ^= rol32(*c, 4);
    *c = c.wrapping_add(*b);
    *b = b.wrapping_sub(*a);
    *b ^= rol32(*a, 6);
    *a = a.wrapping_add(*c);
    *c = c.wrapping_sub(*b);
    *c ^= rol32(*b, 8);
    *b = b.wrapping_add(*a);
    *a = a.wrapping_sub(*c);
    *a ^= rol32(*c, 16);
    *c = c.wrapping_add(*b);
    *b = b.wrapping_sub(*a);
    *b ^= rol32(*a, 19);
    *a = a.wrapping_add(*c);
    *c = c.wrapping_sub(*b);
    *c ^= rol32(*b, 4);
    *b = b.wrapping_add(*a);
}

#[inline(always)]
fn jhash_final(a: &mut u32, b: &mut u32, c: &mut u32) {
    *c ^= *b;
    *c = c.wrapping_sub(rol32(*b, 14));
    *a ^= *c;
    *a = a.wrapping_sub(rol32(*c, 11));
    *b ^= *a;
    *b = b.wrapping_sub(rol32(*a, 25));
    *c ^= *b;
    *c = c.wrapping_sub(rol32(*b, 16));
    *a ^= *c;
    *a = a.wrapping_sub(rol32(*c, 4));
    *b ^= *a;
    *b = b.wrapping_sub(rol32(*a, 14));
    *c ^= *b;
    *c = c.wrapping_sub(rol32(*b, 24));
}

/// jhash() specialized to a fixed 16-byte key (the only length this file
/// ever calls it with — `jhash(pckt->flow.srcv6, 16, 12)`). See
/// [[test_l4lb]] project memory: the general C algorithm's one 12-byte mix
/// round plus a length==4 tail (`a += k[3]`, a raw word add) collapses to
/// exactly this for length 16.
#[inline(always)]
fn jhash_16(k: &[u32; 4], initval: u32) -> u32 {
    let mut a = JHASH_INITVAL.wrapping_add(16).wrapping_add(initval);
    let mut b = a;
    let mut c = a;
    a = a.wrapping_add(k[0]);
    b = b.wrapping_add(k[1]);
    c = c.wrapping_add(k[2]);
    jhash_mix(&mut a, &mut b, &mut c);
    a = a.wrapping_add(k[3]);
    jhash_final(&mut a, &mut b, &mut c);
    c
}

#[inline(always)]
fn jhash_2words(a_in: u32, b_in: u32, initval: u32) -> u32 {
    let iv = initval.wrapping_add(JHASH_INITVAL).wrapping_add(2 << 2);
    let mut a = a_in.wrapping_add(iv);
    let mut b = b_in.wrapping_add(iv);
    let mut c = iv;
    jhash_final(&mut a, &mut b, &mut c);
    c
}

// Word-at-a-time, not an aggregate assignment: an aggregate copy lowers to
// an llvm.memcpy that add_ksyms.py rewrites into an extern bpf_arena_memcpy
// kfunc call, unavailable outside arena programs.
#[inline(always)]
unsafe fn copy_words(dst: *mut u32, src: *const u32, n: usize) {
    let mut i = 0usize;
    while i < n {
        core::ptr::write_unaligned(dst.add(i), core::ptr::read_unaligned(src.add(i)));
        i += 1;
    }
}

// Byte-at-a-time volatile copy for the (unaligned, non-4-byte-multiple) mac
// address fields — same memcpy-merge hazard as copy_words, but at byte
// granularity.
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
// so every field access must go through a packed (unaligned) load/store.
#[repr(C, packed)]
struct EthHdr {
    eth_dest: [u8; 6],
    eth_source: [u8; 6],
    eth_proto: u16,
}

#[repr(C, packed)]
struct IpHdr {
    version_ihl: u8,
    tos: u8,
    tot_len: u16,
    #[allow(dead_code)]
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
    #[allow(dead_code)]
    flow_lbl: [u8; 3],
    payload_len: u16,
    nexthdr: u8,
    hop_limit: u8,
    saddr: [u32; 4],
    daddr: [u32; 4],
}

#[repr(C, packed)]
struct IcmpHdr {
    itype: u8,
    icode: u8,
    checksum: u16,
    #[allow(dead_code)]
    un: u32,
}

#[repr(C, packed)]
struct Icmp6Hdr {
    icmp6_type: u8,
    #[allow(dead_code)]
    icmp6_code: u8,
    icmp6_cksum: u16,
    #[allow(dead_code)]
    dataun: u32,
}

#[repr(C, packed)]
struct UdpHdr {
    source: u16,
    dest: u16,
    #[allow(dead_code)]
    len: u16,
    #[allow(dead_code)]
    check: u16,
}

#[repr(C, packed)]
struct TcpHdr {
    source: u16,
    dest: u16,
    #[allow(dead_code)]
    seq: u32,
    #[allow(dead_code)]
    ack_seq: u32,
    flags: u16,
    #[allow(dead_code)]
    window: u16,
    #[allow(dead_code)]
    check: u16,
    #[allow(dead_code)]
    urg_ptr: u16,
}

// -------- stack-only structs: struct flow_key / packet_description --------

#[repr(C)]
union SrcAddr {
    src: u32,
    srcv6: [u32; 4],
}

#[repr(C)]
union DstAddr {
    dst: u32,
    dstv6: [u32; 4],
}

#[repr(C)]
union PortsU {
    ports: u32,
    port16: [u16; 2],
}

#[repr(C)]
struct FlowKey {
    src: SrcAddr,
    dst: DstAddr,
    ports: PortsU,
    proto: u8,
    _pad: [u8; 3],
}

#[repr(C)]
struct PacketDescription {
    flow: FlowKey,
    flags: u8,
}

// struct vip_definition (this file): the vip_map key. Layout matches
// test_iptunnel_common.h's struct vip (used by the userspace test to build
// the same key) field-for-field: union, port, family, proto. HASH-map keys
// are matched by raw memcmp — see map-key-struct-padding-zeroed-not-reliable
// project memory — but since it's built once as a full struct literal below
// (never mem::zeroed()-then-mutate), the named pad is enough.
#[repr(C)]
union VipAddr {
    vip: u32,
    vipv6: [u32; 4],
}

#[repr(C)]
struct VipDefinition {
    vip: VipAddr,
    port: u16,
    family: u16,
    proto: u8,
    _pad: [u8; 3],
}

#[repr(C)]
struct VipMeta {
    flags: u32,
    vip_num: u32,
}

#[repr(C)]
struct RealPosLru {
    pos: u32,
    atime: u64,
}

#[repr(C)]
union RealAddr {
    dst: u32,
    dstv6: [u32; 4],
}

#[repr(C)]
struct RealDefinition {
    addr: RealAddr,
    flags: u8,
}

// struct lb_stats (this file): __u64 v2, then __u64 v1 — this odd order is
// load-bearing, it's what makes the vip_num-keyed slot line up byte-for-byte
// with the userspace test's `struct vip_stats { __u64 bytes; __u64 pkts; }`
// (v2 <-> bytes, v1 <-> pkts).
#[repr(C)]
struct LbStats {
    v2: u64,
    v1: u64,
}

#[repr(C)]
union CtlValue {
    #[allow(dead_code)]
    value: u64,
    #[allow(dead_code)]
    ifindex: u32,
    mac: [u8; 6],
}

#[link_section = ".maps"]
#[no_mangle]
static vip_map: BpfMap<VipDefinition, VipMeta, { maps::HASH }, 512> = BpfMap::new();

bpf_map! {
    lru_cache {
        r#type: *const [i32; maps::LRU_HASH],
        max_entries: *const [i32; 300],
        map_flags: *const [i32; 2],   // 1U << 1
        key: *const FlowKey,
        value: *const RealPosLru,
    }
}

#[link_section = ".maps"]
#[no_mangle]
static ch_rings: BpfMap<u32, u32, { maps::ARRAY }, CH_RINGS_SIZE> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static reals: BpfMap<u32, RealDefinition, { maps::ARRAY }, 40> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static stats: BpfMap<u32, LbStats, { maps::PERCPU_ARRAY }, 515> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static ctl_array: BpfMap<u32, CtlValue, { maps::ARRAY }, 16> = BpfMap::new();

#[inline(always)]
fn calc_offset(is_ipv6: bool, is_icmp: bool) -> u64 {
    let mut off = core::mem::size_of::<EthHdr>() as u64;
    if is_ipv6 {
        off += core::mem::size_of::<Ipv6Hdr>() as u64;
        if is_icmp {
            off +=
                core::mem::size_of::<Icmp6Hdr>() as u64 + core::mem::size_of::<Ipv6Hdr>() as u64;
        }
    } else {
        off += core::mem::size_of::<IpHdr>() as u64;
        if is_icmp {
            off += core::mem::size_of::<IcmpHdr>() as u64 + core::mem::size_of::<IpHdr>() as u64;
        }
    }
    off
}

#[inline(always)]
fn parse_udp(data: usize, data_end: usize, is_ipv6: bool, pckt: &mut PacketDescription) -> bool {
    let is_icmp = pckt.flags & F_ICMP != 0;
    let off = calc_offset(is_ipv6, is_icmp);
    let udp = (data + off as usize) as *const UdpHdr;
    if udp as usize + core::mem::size_of::<UdpHdr>() > data_end {
        return false;
    }
    unsafe {
        if !is_icmp {
            pckt.flow.ports.port16[0] = (*udp).source;
            pckt.flow.ports.port16[1] = (*udp).dest;
        } else {
            pckt.flow.ports.port16[0] = (*udp).dest;
            pckt.flow.ports.port16[1] = (*udp).source;
        }
    }
    true
}

#[inline(always)]
fn parse_tcp(data: usize, data_end: usize, is_ipv6: bool, pckt: &mut PacketDescription) -> bool {
    let is_icmp = pckt.flags & F_ICMP != 0;
    let off = calc_offset(is_ipv6, is_icmp);
    let tcp = (data + off as usize) as *const TcpHdr;
    if tcp as usize + core::mem::size_of::<TcpHdr>() > data_end {
        return false;
    }
    // struct tcphdr's little-endian bitfield: byte13 bit1 is `syn` (byte12
    // holds res1:4|doff:4, byte13 holds fin,syn,rst,psh,ack,urg,ece,cwr as
    // bits 0..7) — reading the 2 bytes as a native (LE) u16 puts `syn` at
    // bit 9. Same trick as [[test_l4lb]].
    let flags = unsafe { (*tcp).flags };
    if (flags >> 9) & 1 != 0 {
        pckt.flags |= F_SYN_SET;
    }
    unsafe {
        if !is_icmp {
            pckt.flow.ports.port16[0] = (*tcp).source;
            pckt.flow.ports.port16[1] = (*tcp).dest;
        } else {
            pckt.flow.ports.port16[0] = (*tcp).dest;
            pckt.flow.ports.port16[1] = (*tcp).source;
        }
    }
    true
}

#[inline(always)]
fn swap_mac_and_send(data: usize, _data_end: usize) -> i32 {
    let eth = data as *mut EthHdr;
    let mut tmp_mac = [0u8; 6];
    unsafe {
        vcopy(
            tmp_mac.as_mut_ptr(),
            core::ptr::addr_of!((*eth).eth_source) as *const u8,
            6,
        );
        vcopy(
            core::ptr::addr_of_mut!((*eth).eth_source) as *mut u8,
            core::ptr::addr_of!((*eth).eth_dest) as *const u8,
            6,
        );
        vcopy(
            core::ptr::addr_of_mut!((*eth).eth_dest) as *mut u8,
            tmp_mac.as_ptr(),
            6,
        );
    }
    XDP_TX
}

#[inline(always)]
fn send_icmp_reply(data: usize, data_end: usize) -> i32 {
    if data
        + core::mem::size_of::<EthHdr>()
        + core::mem::size_of::<IpHdr>()
        + core::mem::size_of::<IcmpHdr>()
        > data_end
    {
        return XDP_DROP;
    }
    let mut off = core::mem::size_of::<EthHdr>();
    let iph = (data + off) as *mut IpHdr;
    off += core::mem::size_of::<IpHdr>();
    let icmp_hdr = (data + off) as *mut IcmpHdr;
    unsafe {
        (*icmp_hdr).itype = 0;
        (*icmp_hdr).checksum = (*icmp_hdr).checksum.wrapping_add(0x0007);
        (*iph).ttl = 4;
        let tmp_addr = (*iph).daddr;
        (*iph).daddr = (*iph).saddr;
        (*iph).saddr = tmp_addr;
        (*iph).check = 0;
    }
    let mut csum: u32 = 0;
    let mut next_iph = iph as *mut u16;
    for _ in 0..(core::mem::size_of::<IpHdr>() >> 1) {
        csum = csum.wrapping_add(unsafe { core::ptr::read_unaligned(next_iph) } as u32);
        next_iph = unsafe { next_iph.add(1) };
    }
    let check = !((csum & 0xffff).wrapping_add(csum >> 16)) as u16;
    unsafe { (*iph).check = check };
    swap_mac_and_send(data, data_end)
}

#[inline(always)]
fn send_icmp6_reply(data: usize, data_end: usize) -> i32 {
    if data
        + core::mem::size_of::<EthHdr>()
        + core::mem::size_of::<Ipv6Hdr>()
        + core::mem::size_of::<Icmp6Hdr>()
        > data_end
    {
        return XDP_DROP;
    }
    let mut off = core::mem::size_of::<EthHdr>();
    let ip6h = (data + off) as *mut Ipv6Hdr;
    off += core::mem::size_of::<Ipv6Hdr>();
    let icmp_hdr = (data + off) as *mut Icmp6Hdr;
    let mut tmp_addr = [0u32; 4];
    unsafe {
        (*icmp_hdr).icmp6_type = 129;
        (*icmp_hdr).icmp6_cksum = (*icmp_hdr).icmp6_cksum.wrapping_sub(0x0001);
        (*ip6h).hop_limit = 4;
        copy_words(
            tmp_addr.as_mut_ptr(),
            core::ptr::addr_of!((*ip6h).saddr) as *const u32,
            4,
        );
        copy_words(
            core::ptr::addr_of_mut!((*ip6h).saddr) as *mut u32,
            core::ptr::addr_of!((*ip6h).daddr) as *const u32,
            4,
        );
        copy_words(
            core::ptr::addr_of_mut!((*ip6h).daddr) as *mut u32,
            tmp_addr.as_ptr(),
            4,
        );
    }
    swap_mac_and_send(data, data_end)
}

#[inline(always)]
fn parse_icmpv6(data: usize, data_end: usize, off: u64, pckt: &mut PacketDescription) -> i32 {
    let icmp_hdr = (data + off as usize) as *const Icmp6Hdr;
    if icmp_hdr as usize + core::mem::size_of::<Icmp6Hdr>() > data_end {
        return XDP_DROP;
    }
    if unsafe { (*icmp_hdr).icmp6_type } == 128 {
        return send_icmp6_reply(data, data_end);
    }
    if unsafe { (*icmp_hdr).icmp6_type } != 3 {
        return XDP_PASS;
    }
    let off2 = off + core::mem::size_of::<Icmp6Hdr>() as u64;
    let ip6h = (data + off2 as usize) as *const Ipv6Hdr;
    if ip6h as usize + core::mem::size_of::<Ipv6Hdr>() > data_end {
        return XDP_DROP;
    }
    unsafe {
        pckt.flow.proto = (*ip6h).nexthdr;
        pckt.flags |= F_ICMP;
        copy_words(
            pckt.flow.src.srcv6.as_mut_ptr(),
            core::ptr::addr_of!((*ip6h).daddr) as *const u32,
            4,
        );
        copy_words(
            pckt.flow.dst.dstv6.as_mut_ptr(),
            core::ptr::addr_of!((*ip6h).saddr) as *const u32,
            4,
        );
    }
    -1
}

#[inline(always)]
fn parse_icmp(data: usize, data_end: usize, off: u64, pckt: &mut PacketDescription) -> i32 {
    let icmp_hdr = (data + off as usize) as *const IcmpHdr;
    if icmp_hdr as usize + core::mem::size_of::<IcmpHdr>() > data_end {
        return XDP_DROP;
    }
    if unsafe { (*icmp_hdr).itype } == 8 {
        return send_icmp_reply(data, data_end);
    }
    let (itype, icode) = unsafe { ((*icmp_hdr).itype, (*icmp_hdr).icode) };
    if itype != 3 || icode != 4 {
        return XDP_PASS;
    }
    let off2 = off + core::mem::size_of::<IcmpHdr>() as u64;
    let iph = (data + off2 as usize) as *const IpHdr;
    if iph as usize + core::mem::size_of::<IpHdr>() > data_end {
        return XDP_DROP;
    }
    if unsafe { (*iph).version_ihl } & 0x0f != 5 {
        return XDP_DROP;
    }
    unsafe {
        pckt.flow.proto = (*iph).protocol;
        pckt.flags |= F_ICMP;
        pckt.flow.src.src = (*iph).daddr;
        pckt.flow.dst.dst = (*iph).saddr;
    }
    -1
}

#[inline(always)]
fn get_packet_hash(pckt: &PacketDescription, hash_16bytes: bool) -> u32 {
    if hash_16bytes {
        let inner = jhash_16(unsafe { &pckt.flow.src.srcv6 }, 12);
        jhash_2words(inner, unsafe { pckt.flow.ports.ports }, 24)
    } else {
        jhash_2words(
            unsafe { pckt.flow.src.src },
            unsafe { pckt.flow.ports.ports },
            24,
        )
    }
}

#[inline(always)]
fn get_packet_dst(
    pckt: &mut PacketDescription,
    vip_info: &VipMeta,
    is_ipv6: bool,
) -> *const RealDefinition {
    let mut hash_16bytes = is_ipv6;
    if vip_info.flags & (1 << 2) != 0 {
        hash_16bytes = true;
    }
    if vip_info.flags & (1 << 3) != 0 {
        unsafe {
            pckt.flow.ports.port16[0] = pckt.flow.ports.port16[1];
            pckt.flow.src.srcv6 = [0; 4];
        }
    }
    let hash = get_packet_hash(pckt, hash_16bytes);
    if hash != 0x358459b7 && hash != 0x2f4bc6bb {
        return core::ptr::null();
    }
    let mut key = 2u32.wrapping_mul(vip_info.vip_num).wrapping_add(hash % 2);
    let real_pos = bpf_map_lookup_elem(&ch_rings, &key) as *const u32;
    if real_pos.is_null() {
        return core::ptr::null();
    }
    key = unsafe { *real_pos };
    let real = bpf_map_lookup_elem(&reals, &key) as *const RealDefinition;
    if real.is_null() {
        return real;
    }
    if vip_info.flags & (1 << 1) == 0 {
        let conn_rate_key: u32 = 512 + 2;
        let conn_rate_stats = bpf_map_lookup_elem(&stats, &conn_rate_key) as *mut LbStats;
        if conn_rate_stats.is_null() {
            return real;
        }
        let cur_time = bpf_ktime_get_ns();
        unsafe {
            if (cur_time.wrapping_sub((*conn_rate_stats).v2)) >> 32 > 0xffFFFF {
                (*conn_rate_stats).v1 = 1;
                (*conn_rate_stats).v2 = cur_time;
            } else {
                (*conn_rate_stats).v1 = (*conn_rate_stats).v1.wrapping_add(1);
                if (*conn_rate_stats).v1 >= 1 {
                    return real;
                }
            }
        }
        let mut new_dst_lru = RealPosLru { pos: 0, atime: 0 };
        if pckt.flow.proto == IPPROTO_UDP {
            new_dst_lru.atime = cur_time;
        }
        new_dst_lru.pos = key;
        bpf_map_update_elem(&lru_cache, &pckt.flow, &new_dst_lru, 0);
    }
    real
}

#[inline(always)]
fn connection_table_lookup(pckt: &mut PacketDescription) -> *const RealDefinition {
    let dst_lru = bpf_map_lookup_elem(&lru_cache, &pckt.flow) as *mut RealPosLru;
    if dst_lru.is_null() {
        return core::ptr::null();
    }
    if pckt.flow.proto == IPPROTO_UDP {
        let cur_time = bpf_ktime_get_ns();
        if cur_time.wrapping_sub(unsafe { (*dst_lru).atime }) > 300000 {
            return core::ptr::null();
        }
        unsafe { (*dst_lru).atime = cur_time };
    }
    let key = unsafe { (*dst_lru).pos };
    bpf_map_lookup_elem(&reals, &key) as *const RealDefinition
}

// don't believe your eyes! process_l3_headers_v6 in the C original has 6
// arguments — bpf/llvm allow at most 5 for a real (non-inlined) BPF-to-BPF
// call, and the comment notes only `static` + optimizer arg-elision makes
// it work. Our translation lets rustc freely inline everything (as
// [[test_l4lb]] does for the same katran-derived code), so no such call
// ever reaches the verifier — data/data_end are passed directly instead of
// through the C's `void *extra_args[2]` indirection.
#[inline(always)]
fn process_l3_headers_v6(
    pckt: &mut PacketDescription,
    off_in: u64,
    pkt_bytes: &mut u16,
    data: usize,
    data_end: usize,
) -> i32 {
    let ip6h = (data + off_in as usize) as *const Ipv6Hdr;
    if ip6h as usize + core::mem::size_of::<Ipv6Hdr>() > data_end {
        return XDP_DROP;
    }
    let off = off_in + core::mem::size_of::<Ipv6Hdr>() as u64;
    let protocol = unsafe { (*ip6h).nexthdr };
    pckt.flow.proto = protocol;
    *pkt_bytes = u16::from_be(unsafe { (*ip6h).payload_len });
    if protocol == 45 {
        return XDP_DROP;
    } else if protocol == 59 {
        let action = parse_icmpv6(data, data_end, off, pckt);
        if action >= 0 {
            return action;
        }
    } else {
        unsafe {
            copy_words(
                pckt.flow.src.srcv6.as_mut_ptr(),
                core::ptr::addr_of!((*ip6h).saddr) as *const u32,
                4,
            );
            copy_words(
                pckt.flow.dst.dstv6.as_mut_ptr(),
                core::ptr::addr_of!((*ip6h).daddr) as *const u32,
                4,
            );
        }
    }
    -1
}

#[inline(always)]
fn process_l3_headers_v4(
    pckt: &mut PacketDescription,
    off_in: u64,
    pkt_bytes: &mut u16,
    data: usize,
    data_end: usize,
) -> i32 {
    let iph = (data + off_in as usize) as *const IpHdr;
    if iph as usize + core::mem::size_of::<IpHdr>() > data_end {
        return XDP_DROP;
    }
    if unsafe { (*iph).version_ihl } & 0x0f != 5 {
        return XDP_DROP;
    }
    let protocol = unsafe { (*iph).protocol };
    pckt.flow.proto = protocol;
    *pkt_bytes = u16::from_be(unsafe { (*iph).tot_len });
    let off = off_in + 20;
    if unsafe { (*iph).frag_off } & PCKT_FRAGMENTED != 0 {
        return XDP_DROP;
    }
    if protocol == IPPROTO_ICMP {
        let action = parse_icmp(data, data_end, off, pckt);
        if action >= 0 {
            return action;
        }
    } else {
        unsafe {
            pckt.flow.src.src = (*iph).saddr;
            pckt.flow.dst.dst = (*iph).daddr;
        }
    }
    -1
}

#[inline(never)]
fn encap_v6(
    xdp: *const xdp_md,
    cval: &CtlValue,
    pckt: &PacketDescription,
    dst: &RealDefinition,
    pkt_bytes: u16,
) -> bool {
    if bpf_xdp_adjust_head(xdp as *mut xdp_md, -(core::mem::size_of::<Ipv6Hdr>() as i32)) != 0 {
        return false;
    }
    let data = vload!((*xdp).data) as usize;
    let data_end = vload!((*xdp).data_end) as usize;
    let new_eth = data as *mut EthHdr;
    let ip6h = (data + core::mem::size_of::<EthHdr>()) as *mut Ipv6Hdr;
    let old_eth = (data + core::mem::size_of::<Ipv6Hdr>()) as *const EthHdr;

    if (new_eth as usize) + core::mem::size_of::<EthHdr>() > data_end
        || (old_eth as usize) + core::mem::size_of::<EthHdr>() > data_end
        || (ip6h as usize) + core::mem::size_of::<Ipv6Hdr>() > data_end
    {
        return false;
    }

    unsafe {
        vcopy(
            core::ptr::addr_of_mut!((*new_eth).eth_dest) as *mut u8,
            cval.mac.as_ptr(),
            6,
        );
        vcopy(
            core::ptr::addr_of_mut!((*new_eth).eth_source) as *mut u8,
            core::ptr::addr_of!((*old_eth).eth_dest) as *const u8,
            6,
        );
        (*new_eth).eth_proto = 56710;
        (*ip6h).version_priority = 0x60;
        let flow_lbl_ptr = core::ptr::addr_of_mut!((*ip6h).flow_lbl) as *mut u8;
        core::ptr::write_volatile(flow_lbl_ptr, 0);
        core::ptr::write_volatile(flow_lbl_ptr.add(1), 0);
        core::ptr::write_volatile(flow_lbl_ptr.add(2), 0);
        (*ip6h).nexthdr = IPPROTO_IPV6;
    }

    let ip_suffix = unsafe { pckt.flow.src.srcv6[3] ^ (pckt.flow.ports.port16[0] as u32) };

    unsafe {
        (*ip6h).payload_len = pkt_bytes
            .wrapping_add(core::mem::size_of::<Ipv6Hdr>() as u16)
            .to_be();
        (*ip6h).hop_limit = 4;
        let saddr_ptr = core::ptr::addr_of_mut!((*ip6h).saddr) as *mut u32;
        core::ptr::write_unaligned(saddr_ptr, 1);
        core::ptr::write_unaligned(saddr_ptr.add(1), 2);
        core::ptr::write_unaligned(saddr_ptr.add(2), 3);
        core::ptr::write_unaligned(saddr_ptr.add(3), ip_suffix);
        copy_words(
            core::ptr::addr_of_mut!((*ip6h).daddr) as *mut u32,
            dst.addr.dstv6.as_ptr(),
            4,
        );
    }
    true
}

#[inline(never)]
fn encap_v4(
    xdp: *const xdp_md,
    cval: &CtlValue,
    pckt: &PacketDescription,
    dst: &RealDefinition,
    pkt_bytes: u16,
) -> bool {
    let mut ip_suffix = u16::from_be(unsafe { pckt.flow.ports.port16[0] }) as u32;
    ip_suffix <<= 15;
    ip_suffix ^= unsafe { pckt.flow.src.src };

    if bpf_xdp_adjust_head(xdp as *mut xdp_md, -(core::mem::size_of::<IpHdr>() as i32)) != 0 {
        return false;
    }
    let data = vload!((*xdp).data) as usize;
    let data_end = vload!((*xdp).data_end) as usize;
    let new_eth = data as *mut EthHdr;
    let iph = (data + core::mem::size_of::<EthHdr>()) as *mut IpHdr;
    let old_eth = (data + core::mem::size_of::<IpHdr>()) as *const EthHdr;

    if (new_eth as usize) + core::mem::size_of::<EthHdr>() > data_end
        || (old_eth as usize) + core::mem::size_of::<EthHdr>() > data_end
        || (iph as usize) + core::mem::size_of::<IpHdr>() > data_end
    {
        return false;
    }

    unsafe {
        vcopy(
            core::ptr::addr_of_mut!((*new_eth).eth_dest) as *mut u8,
            cval.mac.as_ptr(),
            6,
        );
        vcopy(
            core::ptr::addr_of_mut!((*new_eth).eth_source) as *mut u8,
            core::ptr::addr_of!((*old_eth).eth_dest) as *const u8,
            6,
        );
        (*new_eth).eth_proto = 8;
        (*iph).version_ihl = 0x45;
        (*iph).frag_off = 0;
        (*iph).protocol = IPPROTO_IPIP;
        (*iph).check = 0;
        (*iph).tos = 1;
        (*iph).tot_len = pkt_bytes
            .wrapping_add(core::mem::size_of::<IpHdr>() as u16)
            .to_be();
        (*iph).saddr = ((0xFFFF_0000u32 & ip_suffix) | 4268) ^ dst.addr.dst;
        (*iph).ttl = 4;
    }

    let mut csum: u32 = 0;
    let mut next_iph = iph as *mut u16;
    for _ in 0..(core::mem::size_of::<IpHdr>() >> 1) {
        csum = csum.wrapping_add(unsafe { core::ptr::read_unaligned(next_iph) } as u32);
        next_iph = unsafe { next_iph.add(1) };
    }
    let check = !((csum & 0xffff).wrapping_add(csum >> 16)) as u16;
    unsafe { (*iph).check = check };

    if bpf_xdp_adjust_head(xdp as *mut xdp_md, core::mem::size_of::<IpHdr>() as i32) != 0 {
        return false;
    }
    true
}

#[inline(always)]
fn process_packet(data: usize, off_in: u64, data_end: usize, is_ipv6: bool, xdp: *const xdp_md) -> i32 {
    let mut pckt: PacketDescription = unsafe { core::mem::zeroed() };
    let mut pkt_bytes: u16 = 0;

    let action = if is_ipv6 {
        process_l3_headers_v6(&mut pckt, off_in, &mut pkt_bytes, data, data_end)
    } else {
        process_l3_headers_v4(&mut pckt, off_in, &mut pkt_bytes, data, data_end)
    };
    if action >= 0 {
        return action;
    }

    let protocol = pckt.flow.proto;
    if protocol == IPPROTO_TCP {
        if !parse_tcp(data, data_end, is_ipv6, &mut pckt) {
            return XDP_DROP;
        }
    } else if protocol == IPPROTO_UDP {
        if !parse_udp(data, data_end, is_ipv6, &mut pckt) {
            return XDP_DROP;
        }
    } else {
        return XDP_TX;
    }

    let mut vip = VipDefinition {
        vip: VipAddr { vipv6: [0; 4] },
        port: 0,
        family: 0,
        proto: 0,
        _pad: [0; 3],
    };
    if is_ipv6 {
        unsafe { copy_words(vip.vip.vipv6.as_mut_ptr(), pckt.flow.dst.dstv6.as_ptr(), 4) };
    } else {
        vip.vip.vip = unsafe { pckt.flow.dst.dst };
    }
    vip.port = unsafe { pckt.flow.ports.port16[1] };
    vip.proto = pckt.flow.proto;

    let mut vip_info_ptr = bpf_map_lookup_elem(&vip_map, &vip) as *const VipMeta;
    if vip_info_ptr.is_null() {
        vip.port = 0;
        vip_info_ptr = bpf_map_lookup_elem(&vip_map, &vip) as *const VipMeta;
        if vip_info_ptr.is_null() {
            return XDP_PASS;
        }
        if unsafe { (*vip_info_ptr).flags } & (1 << 4) == 0 {
            unsafe { pckt.flow.ports.port16[1] = 0 };
        }
    }
    let vip_info = unsafe { &*vip_info_ptr };

    if data_end.wrapping_sub(data) > 1400 {
        return XDP_DROP;
    }

    let stats_key: u32 = 512;
    let data_stats_ptr = bpf_map_lookup_elem(&stats, &stats_key) as *mut LbStats;
    if data_stats_ptr.is_null() {
        return XDP_DROP;
    }
    unsafe { (*data_stats_ptr).v1 = (*data_stats_ptr).v1.wrapping_add(1) };

    let mut dst_ptr: *const RealDefinition = core::ptr::null();
    if vip_info.flags & (1 << 0) != 0 {
        unsafe { pckt.flow.ports.port16[0] = 0 };
    }
    if pckt.flags & F_SYN_SET == 0 && vip_info.flags & (1 << 1) == 0 {
        dst_ptr = connection_table_lookup(&mut pckt);
    }
    if dst_ptr.is_null() {
        if pckt.flow.proto == IPPROTO_TCP {
            let lru_stats_key: u32 = 513;
            let lru_stats = bpf_map_lookup_elem(&stats, &lru_stats_key) as *mut LbStats;
            if lru_stats.is_null() {
                return XDP_DROP;
            }
            if pckt.flags & F_SYN_SET != 0 {
                unsafe { (*lru_stats).v1 = (*lru_stats).v1.wrapping_add(1) };
            } else {
                unsafe { (*lru_stats).v2 = (*lru_stats).v2.wrapping_add(1) };
            }
        }
        dst_ptr = get_packet_dst(&mut pckt, vip_info, is_ipv6);
        if dst_ptr.is_null() {
            return XDP_DROP;
        }
        unsafe { (*data_stats_ptr).v2 = (*data_stats_ptr).v2.wrapping_add(1) };
    }

    let mac_addr_pos: u32 = 0;
    let cval_ptr = bpf_map_lookup_elem(&ctl_array, &mac_addr_pos) as *const CtlValue;
    if cval_ptr.is_null() {
        return XDP_DROP;
    }
    let dst = unsafe { &*dst_ptr };
    let cval = unsafe { &*cval_ptr };

    if dst.flags & (1 << 0) != 0 {
        if !encap_v6(xdp, cval, &pckt, dst, pkt_bytes) {
            return XDP_DROP;
        }
    } else if !encap_v4(xdp, cval, &pckt, dst, pkt_bytes) {
        return XDP_DROP;
    }

    let vip_num = vip_info.vip_num;
    let data_stats_ptr2 = bpf_map_lookup_elem(&stats, &vip_num) as *mut LbStats;
    if data_stats_ptr2.is_null() {
        return XDP_DROP;
    }
    unsafe {
        (*data_stats_ptr2).v1 = (*data_stats_ptr2).v1.wrapping_add(1);
        (*data_stats_ptr2).v2 = (*data_stats_ptr2).v2.wrapping_add(pkt_bytes as u64);
    }

    let data2 = vload!((*xdp).data) as usize;
    let data_end2 = vload!((*xdp).data_end) as usize;
    if data2 + 4 > data_end2 {
        return XDP_DROP;
    }
    unsafe { core::ptr::write_unaligned(data2 as *mut u32, dst.addr.dst) };
    XDP_DROP
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn balancer_ingress_v4(ctx: *const xdp_md) -> i32 {
    let data = vload!((*ctx).data) as usize;
    let data_end = vload!((*ctx).data_end) as usize;

    let nh_off = core::mem::size_of::<EthHdr>();
    if data + nh_off > data_end {
        return XDP_DROP;
    }
    let eth = data as *const EthHdr;
    let eth_proto = u16::from_be(unsafe { (*eth).eth_proto });
    if eth_proto == ETH_P_IP {
        process_packet(data, nh_off as u64, data_end, false, ctx)
    } else {
        XDP_DROP
    }
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn balancer_ingress_v6(ctx: *const xdp_md) -> i32 {
    let data = vload!((*ctx).data) as usize;
    let data_end = vload!((*ctx).data_end) as usize;

    let nh_off = core::mem::size_of::<EthHdr>();
    if data + nh_off > data_end {
        return XDP_DROP;
    }
    let eth = data as *const EthHdr;
    let eth_proto = u16::from_be(unsafe { (*eth).eth_proto });
    if eth_proto == ETH_P_IPV6 {
        process_packet(data, nh_off as u64, data_end, true, ctx)
    } else {
        XDP_DROP
    }
}

bpf_object!("GPL");
