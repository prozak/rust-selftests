#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_l4lb_noinline_dynptr.c
// (bpf-rs-core idiom). Same katran-derived load balancer as test_l4lb.c, but
// every packet-header access goes through bpf_dynptr_slice(_rdwr)/
// bpf_dynptr_write instead of raw ctx->data/data_end pointer arithmetic.

use core::ffi::c_void;

use bpf_rs_core::ctx::{__sk_buff, TC_ACT_OK, TC_ACT_SHOT};
use bpf_rs_core::helpers::{
    bpf_dynptr_write, bpf_map_lookup_elem, bpf_redirect, bpf_skb_set_tunnel_key,
};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::bpf_object;

const TC_ACT_UNSPEC: i32 = -1;

const PCKT_FRAGMENTED: u16 = 65343;
const IPV4_HDR_LEN_NO_OPT: u64 = 20;
const IPV4_PLUS_ICMP_HDR: u64 = 28;
const IPV6_PLUS_ICMP_HDR: u64 = 48;
const RING_SIZE: u32 = 2;
const MAX_VIPS: usize = 12;
const MAX_REALS: usize = 5;
const CTL_MAP_SIZE: usize = 16;
const CH_RINGS_SIZE: usize = MAX_VIPS * RING_SIZE as usize;
const F_IPV6: u8 = 1 << 0;
const F_HASH_NO_SRC_PORT: u32 = 1 << 0;
const F_ICMP: u8 = 1 << 0;
const F_SYN_SET: u8 = 1 << 1;

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;

const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_FRAGMENT: u8 = 44;
const IPPROTO_ICMPV6: u8 = 58;

const ICMP_DEST_UNREACH: u8 = 3;
const ICMP_FRAG_NEEDED: u8 = 4;
const ICMPV6_PKT_TOOBIG: u8 = 2;

const BPF_F_TUNINFO_IPV6: u64 = 1 << 0;

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

const JHASH_INITVAL: u32 = 0xdeadbeef;

/// jhash() specialized to a fixed 16-byte key (the only length this file
/// ever calls it with — `jhash(pckt->srcv6, 16, ...)`). The general C
/// algorithm's one 12-byte mix round plus a length==4 tail (`a += k[3]`, a
/// raw little-endian word add) collapses to exactly this for length 16.
#[inline(always)]
fn jhash_srcv6(k: &[u32; 4], initval: u32) -> u32 {
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

// Word-at-a-time, not an aggregate assignment: a 16-byte in6_addr copy
// lowers to an llvm.memcpy that add_ksyms.py rewrites into an extern
// bpf_arena_memcpy kfunc call, which isn't in this kernel's BTF outside
// arena progs.
#[inline(always)]
unsafe fn copy_words(dst: *mut u32, src: *const u32, n: usize) {
    let mut i = 0usize;
    while i < n {
        core::ptr::write_unaligned(dst.add(i), core::ptr::read_unaligned(src.add(i)));
        i += 1;
    }
}

// UAPI struct bpf_dynptr (linux/bpf.h): opaque, two anonymous __u64
// bitfields, aligned(8).
#[repr(C, align(8))]
struct bpf_dynptr {
    __opaque: [u64; 2],
}

extern "C" {
    fn bpf_dynptr_from_skb(skb: *const __sk_buff, flags: u64, ptr: *mut bpf_dynptr) -> i32;
    fn bpf_dynptr_slice(
        ptr: *const bpf_dynptr,
        offset: u64,
        buffer: *mut c_void,
        buffer_sz: u64,
    ) -> *mut c_void;
    fn bpf_dynptr_slice_rdwr(
        ptr: *const bpf_dynptr,
        offset: u64,
        buffer: *mut c_void,
        buffer_sz: u64,
    ) -> *mut c_void;
}

#[repr(C)]
union AddrUnion {
    v4: u32,
    v6: [u32; 4],
}

#[repr(C)]
union PortsUnion {
    ports: u32,
    port16: [u16; 2],
}

#[repr(C)]
struct PacketDescription {
    src: AddrUnion,
    dst: AddrUnion,
    ports: PortsUnion,
    proto: u8,
    flags: u8,
}

// struct ctl_value (test_l4lb_noinline_dynptr.c): stack/map-value scratch,
// only ever read via `.ifindex`.
#[repr(C)]
union CtlValue {
    #[allow(dead_code)]
    value: u64,
    ifindex: u32,
    #[allow(dead_code)]
    mac: [u8; 6],
}

#[repr(C)]
struct VipMeta {
    flags: u32,
    vip_num: u32,
}

#[repr(C)]
union RealAddr {
    dst: u32,
    dstv6: [u32; 4],
}

#[repr(C)]
struct RealDefinition {
    daddr: RealAddr,
    flags: u8,
    _pad: [u8; 3],
}

#[repr(C)]
struct VipStats {
    bytes: u64,
    pkts: u64,
}

// struct vip (test_iptunnel_common.h): the vip_map key. HASH-map keys are
// matched by raw memcmp, so the 3-byte tail pad must be an explicitly
// zeroed named field, not left to a `mem::zeroed()`-then-mutate pattern
// LLVM can partially elide — see map-key-struct-padding-zeroed-not-reliable
// in project memory.
#[repr(C)]
struct Vip {
    daddr: AddrUnion,
    dport: u16,
    family: u16,
    protocol: u8,
    _pad: [u8; 3],
}

#[repr(C)]
union RemoteAddr {
    remote_ipv4: u32,
    remote_ipv6: [u32; 4],
}

#[repr(C)]
union TunnelExtOrFlags {
    #[allow(dead_code)]
    tunnel_ext: u16,
    #[allow(dead_code)]
    tunnel_flags: u16,
}

#[repr(C)]
union LocalAddr {
    #[allow(dead_code)]
    local_ipv4: u32,
    #[allow(dead_code)]
    local_ipv6: [u32; 4],
}

// struct bpf_tunnel_key (linux/bpf.h), full 44-byte layout: a stack
// scratch buffer passed by pointer to bpf_skb_set_tunnel_key(), not
// BTF-matched like a map value or global — only the raw offsets need to
// agree with the kernel's struct.
#[repr(C)]
struct BpfTunnelKey {
    tunnel_id: u32,
    remote: RemoteAddr,
    tunnel_tos: u8,
    tunnel_ttl: u8,
    ext_flags: TunnelExtOrFlags,
    tunnel_label: u32,
    local: LocalAddr,
}

const _: () = assert!(core::mem::size_of::<BpfTunnelKey>() == 44);

#[repr(C)]
struct EthHdr {
    #[allow(dead_code)]
    eth_dest: [u8; 6],
    #[allow(dead_code)]
    eth_source: [u8; 6],
    eth_proto: u16,
}

#[repr(C, packed)]
struct IpHdr {
    version_ihl: u8,
    #[allow(dead_code)]
    tos: u8,
    tot_len: u16,
    #[allow(dead_code)]
    id: u16,
    frag_off: u16,
    #[allow(dead_code)]
    ttl: u8,
    protocol: u8,
    #[allow(dead_code)]
    check: u16,
    saddr: u32,
    daddr: u32,
}

#[repr(C, packed)]
struct Ipv6Hdr {
    #[allow(dead_code)]
    version_priority: u8,
    #[allow(dead_code)]
    flow_lbl: [u8; 3],
    payload_len: u16,
    nexthdr: u8,
    #[allow(dead_code)]
    hop_limit: u8,
    saddr: [u32; 4],
    daddr: [u32; 4],
}

#[repr(C, packed)]
struct IcmpHdr {
    itype: u8,
    icode: u8,
    #[allow(dead_code)]
    checksum: u16,
    #[allow(dead_code)]
    un: u32,
}

#[repr(C, packed)]
struct Icmp6Hdr {
    icmp6_type: u8,
    #[allow(dead_code)]
    icmp6_code: u8,
    #[allow(dead_code)]
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

#[link_section = ".maps"]
#[no_mangle]
static vip_map: BpfMap<Vip, VipMeta, { maps::HASH }, MAX_VIPS> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static ch_rings: BpfMap<u32, u32, { maps::ARRAY }, CH_RINGS_SIZE> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static reals: BpfMap<u32, RealDefinition, { maps::ARRAY }, MAX_REALS> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static stats: BpfMap<u32, VipStats, { maps::PERCPU_ARRAY }, MAX_VIPS> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static ctl_array: BpfMap<u32, CtlValue, { maps::ARRAY }, CTL_MAP_SIZE> = BpfMap::new();

#[inline(always)]
fn get_packet_hash(pckt: &PacketDescription, ipv6: bool) -> u32 {
    if ipv6 {
        let inner = jhash_srcv6(unsafe { &pckt.src.v6 }, MAX_VIPS as u32);
        jhash_2words(inner, unsafe { pckt.ports.ports }, CH_RINGS_SIZE as u32)
    } else {
        jhash_2words(
            unsafe { pckt.src.v4 },
            unsafe { pckt.ports.ports },
            CH_RINGS_SIZE as u32,
        )
    }
}

#[inline(always)]
fn get_packet_dst(
    pckt: &PacketDescription,
    vip_info: &VipMeta,
    is_ipv6: bool,
) -> *const RealDefinition {
    let hash = get_packet_hash(pckt, is_ipv6) % RING_SIZE;
    let key = RING_SIZE.wrapping_mul(vip_info.vip_num).wrapping_add(hash);

    let real_pos_ptr = bpf_map_lookup_elem(&ch_rings, &key) as *const u32;
    if real_pos_ptr.is_null() {
        return core::ptr::null();
    }
    let key2 = unsafe { *real_pos_ptr };
    bpf_map_lookup_elem(&reals, &key2) as *const RealDefinition
}

#[inline(always)]
fn parse_icmpv6(skb_ptr: *const bpf_dynptr, off: u64, pckt: &mut PacketDescription) -> i32 {
    let mut buffer = [0u8; core::mem::size_of::<Ipv6Hdr>()];
    let icmp_hdr = unsafe {
        bpf_dynptr_slice(
            skb_ptr,
            off,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len() as u64,
        ) as *const Icmp6Hdr
    };
    if icmp_hdr.is_null() {
        return TC_ACT_SHOT;
    }
    if unsafe { (*icmp_hdr).icmp6_type } != ICMPV6_PKT_TOOBIG {
        return TC_ACT_OK;
    }
    let off2 = off + core::mem::size_of::<Icmp6Hdr>() as u64;
    let ip6h = unsafe {
        bpf_dynptr_slice(
            skb_ptr,
            off2,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len() as u64,
        ) as *const Ipv6Hdr
    };
    if ip6h.is_null() {
        return TC_ACT_SHOT;
    }
    unsafe {
        pckt.proto = (*ip6h).nexthdr;
        pckt.flags |= F_ICMP;
        copy_words(
            pckt.src.v6.as_mut_ptr(),
            core::ptr::addr_of!((*ip6h).daddr) as *const u32,
            4,
        );
        copy_words(
            pckt.dst.v6.as_mut_ptr(),
            core::ptr::addr_of!((*ip6h).saddr) as *const u32,
            4,
        );
    }
    TC_ACT_UNSPEC
}

#[inline(always)]
fn parse_icmp(skb_ptr: *const bpf_dynptr, off: u64, pckt: &mut PacketDescription) -> i32 {
    let mut buffer_icmp = [0u8; core::mem::size_of::<IpHdr>()];
    let mut buffer_ip = [0u8; core::mem::size_of::<IpHdr>()];
    let icmp_hdr = unsafe {
        bpf_dynptr_slice(
            skb_ptr,
            off,
            buffer_icmp.as_mut_ptr() as *mut c_void,
            buffer_icmp.len() as u64,
        ) as *const IcmpHdr
    };
    if icmp_hdr.is_null() {
        return TC_ACT_SHOT;
    }
    let (itype, icode) = unsafe { ((*icmp_hdr).itype, (*icmp_hdr).icode) };
    if itype != ICMP_DEST_UNREACH || icode != ICMP_FRAG_NEEDED {
        return TC_ACT_OK;
    }
    let off2 = off + core::mem::size_of::<IcmpHdr>() as u64;
    let iph = unsafe {
        bpf_dynptr_slice(
            skb_ptr,
            off2,
            buffer_ip.as_mut_ptr() as *mut c_void,
            buffer_ip.len() as u64,
        ) as *const IpHdr
    };
    if iph.is_null() {
        return TC_ACT_SHOT;
    }
    if unsafe { (*iph).version_ihl } & 0x0f != 5 {
        return TC_ACT_SHOT;
    }
    unsafe {
        pckt.proto = (*iph).protocol;
        pckt.flags |= F_ICMP;
        pckt.src.v4 = (*iph).daddr;
        pckt.dst.v4 = (*iph).saddr;
    }
    TC_ACT_UNSPEC
}

#[inline(always)]
fn parse_udp(skb_ptr: *const bpf_dynptr, off: u64, pckt: &mut PacketDescription) -> bool {
    let mut buffer = [0u8; core::mem::size_of::<UdpHdr>()];
    let udp = unsafe {
        bpf_dynptr_slice(
            skb_ptr,
            off,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len() as u64,
        ) as *const UdpHdr
    };
    if udp.is_null() {
        return false;
    }
    unsafe {
        if pckt.flags & F_ICMP == 0 {
            pckt.ports.port16[0] = (*udp).source;
            pckt.ports.port16[1] = (*udp).dest;
        } else {
            pckt.ports.port16[0] = (*udp).dest;
            pckt.ports.port16[1] = (*udp).source;
        }
    }
    true
}

#[inline(always)]
fn parse_tcp(skb_ptr: *const bpf_dynptr, off: u64, pckt: &mut PacketDescription) -> bool {
    let mut buffer = [0u8; core::mem::size_of::<TcpHdr>()];
    let tcp = unsafe {
        bpf_dynptr_slice(
            skb_ptr,
            off,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len() as u64,
        ) as *const TcpHdr
    };
    if tcp.is_null() {
        return false;
    }
    let flags = unsafe { (*tcp).flags };
    // struct tcphdr's little-endian bitfield: byte13 bit1 is `syn` (byte12
    // holds res1:4|doff:4, byte13 holds fin,syn,rst,psh,ack,urg,ece,cwr as
    // bits 0..7) — reading the 2 bytes as a native (LE) u16 puts `syn` at
    // bit 9.
    if (flags >> 9) & 1 != 0 {
        pckt.flags |= F_SYN_SET;
    }
    unsafe {
        if pckt.flags & F_ICMP == 0 {
            pckt.ports.port16[0] = (*tcp).source;
            pckt.ports.port16[1] = (*tcp).dest;
        } else {
            pckt.ports.port16[0] = (*tcp).dest;
            pckt.ports.port16[1] = (*tcp).source;
        }
    }
    true
}

#[inline(always)]
fn process_packet(
    skb_ptr: *const bpf_dynptr,
    eth: *mut EthHdr,
    off_in: u64,
    is_ipv6: bool,
    skb: *const __sk_buff,
) -> i32 {
    let mut pckt: PacketDescription = unsafe { core::mem::zeroed() };
    let mut tkey: BpfTunnelKey = unsafe { core::mem::zeroed() };
    tkey.tunnel_ttl = 64;

    let v4_intf_pos: u32 = 1;
    let v6_intf_pos: u32 = 2;
    let mut off = off_in;
    let pkt_bytes: u16;

    if is_ipv6 {
        let mut buffer = [0u8; core::mem::size_of::<Ipv6Hdr>()];
        let ip6h = unsafe {
            bpf_dynptr_slice(
                skb_ptr,
                off,
                buffer.as_mut_ptr() as *mut c_void,
                buffer.len() as u64,
            ) as *const Ipv6Hdr
        };
        if ip6h.is_null() {
            return TC_ACT_SHOT;
        }
        let iph_len = core::mem::size_of::<Ipv6Hdr>() as u64;
        let nexthdr = unsafe { (*ip6h).nexthdr };
        pckt.proto = nexthdr;
        pkt_bytes = u16::from_be(unsafe { (*ip6h).payload_len });
        off += iph_len;
        if nexthdr == IPPROTO_FRAGMENT {
            return TC_ACT_SHOT;
        } else if nexthdr == IPPROTO_ICMPV6 {
            let action = parse_icmpv6(skb_ptr, off, &mut pckt);
            if action >= 0 {
                return action;
            }
            off += IPV6_PLUS_ICMP_HDR;
        } else {
            unsafe {
                copy_words(
                    pckt.src.v6.as_mut_ptr(),
                    core::ptr::addr_of!((*ip6h).saddr) as *const u32,
                    4,
                );
                copy_words(
                    pckt.dst.v6.as_mut_ptr(),
                    core::ptr::addr_of!((*ip6h).daddr) as *const u32,
                    4,
                );
            }
        }
    } else {
        let mut buffer = [0u8; core::mem::size_of::<IpHdr>()];
        let iph = unsafe {
            bpf_dynptr_slice(
                skb_ptr,
                off,
                buffer.as_mut_ptr() as *mut c_void,
                buffer.len() as u64,
            ) as *const IpHdr
        };
        if iph.is_null() {
            return TC_ACT_SHOT;
        }
        if unsafe { (*iph).version_ihl } & 0x0f != 5 {
            return TC_ACT_SHOT;
        }

        let protocol = unsafe { (*iph).protocol };
        pckt.proto = protocol;
        pkt_bytes = u16::from_be(unsafe { (*iph).tot_len });
        off += IPV4_HDR_LEN_NO_OPT;

        if unsafe { (*iph).frag_off } & PCKT_FRAGMENTED != 0 {
            return TC_ACT_SHOT;
        }
        if protocol == IPPROTO_ICMP {
            let action = parse_icmp(skb_ptr, off, &mut pckt);
            if action >= 0 {
                return action;
            }
            off += IPV4_PLUS_ICMP_HDR;
        } else {
            unsafe {
                pckt.src.v4 = (*iph).saddr;
                pckt.dst.v4 = (*iph).daddr;
            }
        }
    }
    let protocol = pckt.proto;

    if protocol == IPPROTO_TCP {
        if !parse_tcp(skb_ptr, off, &mut pckt) {
            return TC_ACT_SHOT;
        }
    } else if protocol == IPPROTO_UDP {
        if !parse_udp(skb_ptr, off, &mut pckt) {
            return TC_ACT_SHOT;
        }
    } else {
        return TC_ACT_SHOT;
    }

    let mut vip = Vip {
        daddr: AddrUnion { v6: [0; 4] },
        dport: 0,
        family: 0,
        protocol: 0,
        _pad: [0; 3],
    };
    if is_ipv6 {
        unsafe { copy_words(vip.daddr.v6.as_mut_ptr(), pckt.dst.v6.as_ptr(), 4) };
    } else {
        unsafe { vip.daddr.v4 = pckt.dst.v4 };
    }
    vip.dport = unsafe { pckt.ports.port16[1] };
    vip.protocol = pckt.proto;

    let mut vip_info_ptr = bpf_map_lookup_elem(&vip_map, &vip) as *const VipMeta;
    if vip_info_ptr.is_null() {
        vip.dport = 0;
        vip_info_ptr = bpf_map_lookup_elem(&vip_map, &vip) as *const VipMeta;
        if vip_info_ptr.is_null() {
            return TC_ACT_SHOT;
        }
        unsafe { pckt.ports.port16[1] = 0 };
    }
    let vip_info = unsafe { &*vip_info_ptr };

    if vip_info.flags & F_HASH_NO_SRC_PORT != 0 {
        unsafe { pckt.ports.port16[0] = 0 };
    }

    let dst_ptr = get_packet_dst(&pckt, vip_info, is_ipv6);
    if dst_ptr.is_null() {
        return TC_ACT_SHOT;
    }
    let dst = unsafe { &*dst_ptr };

    let mut tun_flag: u64 = 0;
    let ifindex: u32;
    if dst.flags & F_IPV6 != 0 {
        let cval_ptr = bpf_map_lookup_elem(&ctl_array, &v6_intf_pos) as *const CtlValue;
        if cval_ptr.is_null() {
            return TC_ACT_SHOT;
        }
        ifindex = unsafe { (*cval_ptr).ifindex };
        unsafe {
            copy_words(
                tkey.remote.remote_ipv6.as_mut_ptr(),
                dst.daddr.dstv6.as_ptr(),
                4,
            )
        };
        tun_flag = BPF_F_TUNINFO_IPV6;
    } else {
        let cval_ptr = bpf_map_lookup_elem(&ctl_array, &v4_intf_pos) as *const CtlValue;
        if cval_ptr.is_null() {
            return TC_ACT_SHOT;
        }
        ifindex = unsafe { (*cval_ptr).ifindex };
        tkey.remote.remote_ipv4 = unsafe { dst.daddr.dst };
    }

    let vip_num = vip_info.vip_num;
    let data_stats_ptr = bpf_map_lookup_elem(&stats, &vip_num) as *mut VipStats;
    if data_stats_ptr.is_null() {
        return TC_ACT_SHOT;
    }
    unsafe {
        (*data_stats_ptr).pkts = (*data_stats_ptr).pkts.wrapping_add(1);
        (*data_stats_ptr).bytes = (*data_stats_ptr).bytes.wrapping_add(pkt_bytes as u64);
    }

    bpf_skb_set_tunnel_key(
        skb as *const c_void,
        &tkey as *const BpfTunnelKey,
        core::mem::size_of::<BpfTunnelKey>() as u32,
        tun_flag,
    );

    let remote_ipv4 = unsafe { tkey.remote.remote_ipv4 };
    unsafe { core::ptr::write_unaligned(eth as *mut u32, remote_ipv4) };

    bpf_redirect(ifindex, 0) as i32
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn balancer_ingress(ctx: *const __sk_buff) -> i32 {
    let mut buffer = [0u8; core::mem::size_of::<EthHdr>()];
    let mut ptr = bpf_dynptr { __opaque: [0, 0] };
    let nh_off = core::mem::size_of::<EthHdr>() as u64;

    unsafe {
        bpf_dynptr_from_skb(ctx, 0, &mut ptr as *mut bpf_dynptr);
    }

    let eth = unsafe {
        bpf_dynptr_slice_rdwr(
            &ptr as *const bpf_dynptr,
            0,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len() as u64,
        ) as *mut EthHdr
    };
    if eth.is_null() {
        return TC_ACT_SHOT;
    }
    let eth_proto = unsafe { (*eth).eth_proto };

    let err;
    if eth_proto == ETH_P_IP.to_be() {
        err = process_packet(&ptr as *const bpf_dynptr, eth, nh_off, false, ctx);
    } else if eth_proto == ETH_P_IPV6.to_be() {
        err = process_packet(&ptr as *const bpf_dynptr, eth, nh_off, true, ctx);
    } else {
        return TC_ACT_SHOT;
    }

    if (eth as *mut u8) == buffer.as_mut_ptr() {
        bpf_dynptr_write(
            &ptr as *const bpf_dynptr,
            0,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len() as u64,
            0,
        );
    }

    err
}

bpf_object!("GPL");
