#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_tc_tunnel.c: 18 TC in-place-tunnel
// encapsulators (ipip/gre/udp(fou)/vxlan/sit/ip6tnl/ip6gre/ip6udp/ip6vxlan,
// each optionally wrapping an L2 header) plus one shared decapsulator. Every
// helper the C source marks `static`/`static __always_inline` becomes a
// private `#[inline(always)] fn` here (none of them are referenced by name
// from userspace, only the 18 SEC("tc") entry points are).
//
// Wire header structs are `#[repr(C, packed)]`, touched only through
// `pget!`/`pset!` (read_unaligned/write_unaligned over addr_of!/addr_of_mut!)
// — same idiom as test_cls_redirect.rs. The scratch "outer header" buffers
// (v4hdr/v6hdr in the C source, each a `struct ip + union { udp; gre; } +
// L2-pad` blob) are represented as a single zeroed `[u8; N]` stack array
// with `*mut IpHdr`/`*mut Ipv6Hdr`/`*mut UdpHdr`/`*mut GreHdr` views computed
// by pointer arithmetic, instead of a Rust struct wrapping a union: the
// pad/L2 payload's real offset is only ever produced at runtime via
// `&h_outer + olen` (exactly mirroring the C pointer arithmetic), so no
// named field ever needs to describe it, and a plain byte buffer sidesteps
// packed-union-field-init entirely (also proactively avoids the
// copy-nonoverlapping/struct-assign -> arena-memcpy-kfunc landmine: the
// inner-to-outer header copy uses the same volatile per-byte `vcopy` loop
// as test_cls_redirect.rs instead of a whole-struct assignment).

use core::ffi::c_void;

use bpf_rs_core::ctx::{__sk_buff, TC_ACT_OK, TC_ACT_SHOT};
use bpf_rs_core::helpers::{bpf_skb_adjust_room, bpf_skb_load_bytes, bpf_skb_store_bytes};
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

#[inline(always)]
unsafe fn vcopy(dst: *mut u8, src: *const u8, len: usize) {
    let mut i = 0usize;
    while i < len {
        core::ptr::write_volatile(dst.add(i), core::ptr::read_volatile(src.add(i)));
        i += 1;
    }
}

#[inline(always)]
fn htons(x: u16) -> u16 {
    x.to_be()
}

#[inline(always)]
fn ntohs(x: u16) -> u16 {
    u16::from_be(x)
}

#[inline(always)]
fn htonl(x: u32) -> u32 {
    x.to_be()
}

#[inline(always)]
fn ip_ihl(b: u8) -> u8 {
    b & 0xF
}

// ---- Constants ------------------------------------------------------------

const ETH_HLEN: u32 = 14;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const ETH_P_MPLS_UC: u16 = 0x8847;
const ETH_P_TEB: u16 = 0x6558;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_IPIP: u8 = 4;
const IPPROTO_IPV6: u8 = 41;
const IPPROTO_GRE: u8 = 47;
const NEXTHDR_DEST: u8 = 60;

const UDP_PORT: u16 = 5555;
const MPLS_OVER_UDP_PORT: u16 = 6635;
const ETH_OVER_UDP_PORT: u16 = 7777;
const VXLAN_UDP_PORT: u16 = 8472;

const EXTPROTO_VXLAN: u16 = 0x1;
const VNI_ID: u32 = 1;

const CFG_PORT: u16 = 8000;
const CFG_UDP_SRC: u16 = 20000;

const BPF_ADJ_ROOM_MAC: u32 = 1;
const BPF_F_ADJ_ROOM_FIXED_GSO: u64 = 1 << 0;
const BPF_F_ADJ_ROOM_ENCAP_L3_IPV4: u64 = 1 << 1;
const BPF_F_ADJ_ROOM_ENCAP_L3_IPV6: u64 = 1 << 2;
const BPF_F_ADJ_ROOM_ENCAP_L4_GRE: u64 = 1 << 3;
const BPF_F_ADJ_ROOM_ENCAP_L4_UDP: u64 = 1 << 4;
const BPF_F_ADJ_ROOM_ENCAP_L2_ETH: u64 = 1 << 6;
const BPF_F_ADJ_ROOM_DECAP_L3_IPV4: u64 = 1 << 7;
const BPF_F_ADJ_ROOM_DECAP_L3_IPV6: u64 = 1 << 8;
const BPF_F_INVALIDATE_HASH: u64 = 1 << 1;

#[inline(always)]
fn adj_room_encap_l2(len: i32) -> u64 {
    ((len as u64) & 0xff) << 56
}

#[inline(always)]
fn mpls_label() -> u32 {
    // MPLS label 1000 with S bit (last label) set and ttl of 255.
    htonl((1000u32 << 12) | 0x0000_0100 | 0xff)
}

// ---- Wire header layouts ------------------------------------------------

#[repr(C, packed)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
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
#[allow(dead_code)]
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

#[repr(C, packed)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct UdpHdr {
    source: u16,
    dest: u16,
    len: u16,
    check: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct GreHdr {
    flags: u16,
    protocol: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct VxlanHdr {
    vx_flags: u32,
    vx_vni: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct EthHdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct Ipv6OptHdr {
    nexthdr: u8,
    hdrlen: u8,
}

const L2_PAD_SZ: usize = core::mem::size_of::<VxlanHdr>() + ETH_HLEN as usize;
// scratch outer-header buffer capacity: ip + max(udp, gre) l4 header + L2 pad
const V4HDR_CAP: usize =
    core::mem::size_of::<IpHdr>() + core::mem::size_of::<UdpHdr>() + L2_PAD_SZ;
const V6HDR_CAP: usize =
    core::mem::size_of::<Ipv6Hdr>() + core::mem::size_of::<UdpHdr>() + L2_PAD_SZ;

// ---- IPv4 checksum ----------------------------------------------------

#[inline(always)]
fn set_ipv4_csum(iph: *mut IpHdr) {
    pset!((*iph).check, 0u16);

    let mut csum: u32 = 0;
    let words = iph as *const u16;
    let n = core::mem::size_of::<IpHdr>() / 2;
    let mut i = 0usize;
    while i < n {
        let w = unsafe { core::ptr::read_unaligned(words.add(i)) };
        csum = csum.wrapping_add(w as u32);
        i += 1;
    }

    let sum: u32 = (csum & 0xffff).wrapping_add(csum >> 16);
    pset!((*iph).check, (!sum) as u16);
}

// ---- IPv4 outer encapsulation -------------------------------------------

#[inline(always)]
fn __encap_ipv4(skb: *mut __sk_buff, encap_proto: u8, l2_proto: u16, ext_proto: u16) -> i32 {
    let mut iph_inner = IpHdr {
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
    let mut udp_dst: u16 = UDP_PORT;
    let tcp_off: u32;

    // Most tests encapsulate a packet into a tunnel with the same network
    // protocol, and derive the outer header fields from the inner header.
    //
    // The 6in4 case tests different inner and outer protocols. As the inner
    // is ipv6, but the outer expects an ipv4 header as input, manually build
    // an IpHdr based on the Ipv6Hdr.
    if encap_proto == IPPROTO_IPV6 {
        let saddr: u32 = (192u32 << 24) | (168u32 << 16) | (1u32 << 8) | 1;
        let daddr: u32 = (192u32 << 24) | (168u32 << 16) | (1u32 << 8) | 2;
        let mut iph6_inner = Ipv6Hdr {
            priority_version: 0,
            flow_lbl: [0; 3],
            payload_len: 0,
            nexthdr: 0,
            hop_limit: 0,
            saddr: [0; 16],
            daddr: [0; 16],
        };

        if bpf_skb_load_bytes(
            skb as *const c_void,
            ETH_HLEN,
            &mut iph6_inner as *mut Ipv6Hdr as *mut c_void,
            core::mem::size_of::<Ipv6Hdr>() as u32,
        ) < 0
        {
            return TC_ACT_OK;
        }

        pset!(iph_inner.ihl_version, (4u8 << 4) | 5u8);
        let payload_len = ntohs(pget!(iph6_inner.payload_len));
        let tot_len = (core::mem::size_of::<Ipv6Hdr>() as u32).wrapping_add(payload_len as u32) as u16;
        pset!(iph_inner.tot_len, htons(tot_len));
        pset!(iph_inner.ttl, pget!(iph6_inner.hop_limit).wrapping_sub(1));
        pset!(iph_inner.protocol, pget!(iph6_inner.nexthdr));
        pset!(iph_inner.saddr, htonl(saddr));
        pset!(iph_inner.daddr, htonl(daddr));

        tcp_off = core::mem::size_of::<Ipv6Hdr>() as u32;
    } else {
        if bpf_skb_load_bytes(
            skb as *const c_void,
            ETH_HLEN,
            &mut iph_inner as *mut IpHdr as *mut c_void,
            core::mem::size_of::<IpHdr>() as u32,
        ) < 0
        {
            return TC_ACT_OK;
        }

        tcp_off = core::mem::size_of::<IpHdr>() as u32;
    }

    // filter only packets we want
    if ip_ihl(pget!(iph_inner.ihl_version)) != 5 || pget!(iph_inner.protocol) != IPPROTO_TCP {
        return TC_ACT_OK;
    }

    let mut tcph = TcpHdr {
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
    if bpf_skb_load_bytes(
        skb as *const c_void,
        ETH_HLEN + tcp_off,
        &mut tcph as *mut TcpHdr as *mut c_void,
        core::mem::size_of::<TcpHdr>() as u32,
    ) < 0
    {
        return TC_ACT_OK;
    }

    if pget!(tcph.dest) != htons(CFG_PORT) {
        return TC_ACT_OK;
    }

    let mut olen: i32 = core::mem::size_of::<IpHdr>() as i32;
    let mut l2_len: i32 = 0;

    let mut flags: u64 = BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_ENCAP_L3_IPV4;

    match l2_proto {
        ETH_P_MPLS_UC => {
            l2_len = core::mem::size_of::<u32>() as i32;
            udp_dst = MPLS_OVER_UDP_PORT;
        }
        ETH_P_TEB => {
            l2_len = ETH_HLEN as i32;
            if ext_proto & EXTPROTO_VXLAN != 0 {
                udp_dst = VXLAN_UDP_PORT;
                l2_len += core::mem::size_of::<VxlanHdr>() as i32;
            } else {
                udp_dst = ETH_OVER_UDP_PORT;
            }
        }
        _ => {}
    }
    flags |= adj_room_encap_l2(l2_len);

    let mut h_outer_buf = [0u8; V4HDR_CAP];
    let h_outer = h_outer_buf.as_mut_ptr();
    let h_outer_ip = h_outer as *mut IpHdr;
    let h_outer_gre = unsafe { h_outer.add(core::mem::size_of::<IpHdr>()) } as *mut GreHdr;
    let h_outer_udp = unsafe { h_outer.add(core::mem::size_of::<IpHdr>()) } as *mut UdpHdr;

    match encap_proto {
        IPPROTO_GRE => {
            flags |= BPF_F_ADJ_ROOM_ENCAP_L4_GRE;
            olen += core::mem::size_of::<GreHdr>() as i32;
            pset!((*h_outer_gre).protocol, htons(l2_proto));
            pset!((*h_outer_gre).flags, 0u16);
        }
        IPPROTO_UDP => {
            flags |= BPF_F_ADJ_ROOM_ENCAP_L4_UDP;
            olen += core::mem::size_of::<UdpHdr>() as i32;
            pset!((*h_outer_udp).source, htons(CFG_UDP_SRC));
            pset!((*h_outer_udp).dest, htons(udp_dst));
            pset!((*h_outer_udp).check, 0u16);
            let sum = (ntohs(pget!(iph_inner.tot_len)) as u32)
                .wrapping_add(core::mem::size_of::<UdpHdr>() as u32)
                .wrapping_add(l2_len as u32);
            pset!((*h_outer_udp).len, htons(sum as u16));
        }
        IPPROTO_IPIP | IPPROTO_IPV6 => {}
        _ => return TC_ACT_OK,
    }

    // add L2 encap (if specified)
    let mut l2_hdr = unsafe { h_outer.add(olen as usize) };
    match l2_proto {
        ETH_P_MPLS_UC => {
            unsafe { core::ptr::write_unaligned(l2_hdr as *mut u32, mpls_label()) };
        }
        ETH_P_TEB => {
            flags |= BPF_F_ADJ_ROOM_ENCAP_L2_ETH;

            if ext_proto & EXTPROTO_VXLAN != 0 {
                let vxlan_hdr = l2_hdr as *mut VxlanHdr;
                pset!((*vxlan_hdr).vx_flags, htonl(1u32 << 27));
                pset!((*vxlan_hdr).vx_vni, htonl(VNI_ID << 8));
                l2_hdr = unsafe { l2_hdr.add(core::mem::size_of::<VxlanHdr>()) };
            }

            if bpf_skb_load_bytes(skb as *const c_void, 0, l2_hdr as *mut c_void, ETH_HLEN) != 0 {
                return TC_ACT_SHOT;
            }
        }
        _ => {}
    }
    olen += l2_len;

    // add room between mac and network header
    if bpf_skb_adjust_room(skb as *const c_void, olen, BPF_ADJ_ROOM_MAC, flags) != 0 {
        return TC_ACT_SHOT;
    }

    // prepare new outer network header
    unsafe {
        vcopy(
            h_outer_ip as *mut u8,
            &iph_inner as *const IpHdr as *const u8,
            core::mem::size_of::<IpHdr>(),
        )
    };
    let cur_tot_len = ntohs(pget!((*h_outer_ip).tot_len));
    let sum = (olen as u32).wrapping_add(cur_tot_len as u32) as u16;
    pset!((*h_outer_ip).tot_len, htons(sum));
    pset!((*h_outer_ip).protocol, encap_proto);

    set_ipv4_csum(h_outer_ip);

    // store new outer network header
    if bpf_skb_store_bytes(
        skb as *const c_void,
        ETH_HLEN,
        h_outer as *const c_void,
        olen as u32,
        BPF_F_INVALIDATE_HASH,
    ) < 0
    {
        return TC_ACT_SHOT;
    }

    // if changing outer proto type, update eth->h_proto
    if encap_proto == IPPROTO_IPV6 {
        let mut eth = EthHdr {
            h_dest: [0; 6],
            h_source: [0; 6],
            h_proto: 0,
        };

        if bpf_skb_load_bytes(
            skb as *const c_void,
            0,
            &mut eth as *mut EthHdr as *mut c_void,
            core::mem::size_of::<EthHdr>() as u32,
        ) < 0
        {
            return TC_ACT_SHOT;
        }
        pset!(eth.h_proto, htons(ETH_P_IP));
        if bpf_skb_store_bytes(
            skb as *const c_void,
            0,
            &eth as *const EthHdr as *const c_void,
            core::mem::size_of::<EthHdr>() as u32,
            0,
        ) < 0
        {
            return TC_ACT_SHOT;
        }
    }

    TC_ACT_OK
}

#[inline(always)]
fn encap_ipv4(skb: *mut __sk_buff, encap_proto: u8, l2_proto: u16) -> i32 {
    __encap_ipv4(skb, encap_proto, l2_proto, 0)
}

// ---- IPv6 outer encapsulation -------------------------------------------

#[inline(always)]
fn __encap_ipv6(skb: *mut __sk_buff, encap_proto: u8, l2_proto: u16, ext_proto: u16) -> i32 {
    let mut udp_dst: u16 = UDP_PORT;
    let mut iph_inner = Ipv6Hdr {
        priority_version: 0,
        flow_lbl: [0; 3],
        payload_len: 0,
        nexthdr: 0,
        hop_limit: 0,
        saddr: [0; 16],
        daddr: [0; 16],
    };

    if bpf_skb_load_bytes(
        skb as *const c_void,
        ETH_HLEN,
        &mut iph_inner as *mut Ipv6Hdr as *mut c_void,
        core::mem::size_of::<Ipv6Hdr>() as u32,
    ) < 0
    {
        return TC_ACT_OK;
    }

    // filter only packets we want
    let mut tcph = TcpHdr {
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
    if bpf_skb_load_bytes(
        skb as *const c_void,
        ETH_HLEN + core::mem::size_of::<Ipv6Hdr>() as u32,
        &mut tcph as *mut TcpHdr as *mut c_void,
        core::mem::size_of::<TcpHdr>() as u32,
    ) < 0
    {
        return TC_ACT_OK;
    }

    if pget!(tcph.dest) != htons(CFG_PORT) {
        return TC_ACT_OK;
    }

    let mut olen: i32 = core::mem::size_of::<Ipv6Hdr>() as i32;
    let mut l2_len: i32 = 0;

    let mut flags: u64 = BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_ENCAP_L3_IPV6;

    match l2_proto {
        ETH_P_MPLS_UC => {
            l2_len = core::mem::size_of::<u32>() as i32;
            udp_dst = MPLS_OVER_UDP_PORT;
        }
        ETH_P_TEB => {
            l2_len = ETH_HLEN as i32;
            if ext_proto & EXTPROTO_VXLAN != 0 {
                udp_dst = VXLAN_UDP_PORT;
                l2_len += core::mem::size_of::<VxlanHdr>() as i32;
            } else {
                udp_dst = ETH_OVER_UDP_PORT;
            }
        }
        _ => {}
    }
    flags |= adj_room_encap_l2(l2_len);

    let mut h_outer_buf = [0u8; V6HDR_CAP];
    let h_outer = h_outer_buf.as_mut_ptr();
    let h_outer_ip = h_outer as *mut Ipv6Hdr;
    let h_outer_gre = unsafe { h_outer.add(core::mem::size_of::<Ipv6Hdr>()) } as *mut GreHdr;
    let h_outer_udp = unsafe { h_outer.add(core::mem::size_of::<Ipv6Hdr>()) } as *mut UdpHdr;

    match encap_proto {
        IPPROTO_GRE => {
            flags |= BPF_F_ADJ_ROOM_ENCAP_L4_GRE;
            olen += core::mem::size_of::<GreHdr>() as i32;
            pset!((*h_outer_gre).protocol, htons(l2_proto));
            pset!((*h_outer_gre).flags, 0u16);
        }
        IPPROTO_UDP => {
            flags |= BPF_F_ADJ_ROOM_ENCAP_L4_UDP;
            olen += core::mem::size_of::<UdpHdr>() as i32;
            pset!((*h_outer_udp).source, htons(CFG_UDP_SRC));
            pset!((*h_outer_udp).dest, htons(udp_dst));
            let tot_len = ((ntohs(pget!(iph_inner.payload_len)) as u32)
                .wrapping_add(core::mem::size_of::<Ipv6Hdr>() as u32)
                .wrapping_add(core::mem::size_of::<UdpHdr>() as u32)
                .wrapping_add(l2_len as u32)) as u16;
            pset!((*h_outer_udp).check, 0u16);
            pset!((*h_outer_udp).len, htons(tot_len));
        }
        IPPROTO_IPV6 => {}
        _ => return TC_ACT_OK,
    }

    // add L2 encap (if specified)
    let mut l2_hdr = unsafe { h_outer.add(olen as usize) };
    match l2_proto {
        ETH_P_MPLS_UC => {
            unsafe { core::ptr::write_unaligned(l2_hdr as *mut u32, mpls_label()) };
        }
        ETH_P_TEB => {
            flags |= BPF_F_ADJ_ROOM_ENCAP_L2_ETH;

            if ext_proto & EXTPROTO_VXLAN != 0 {
                let vxlan_hdr = l2_hdr as *mut VxlanHdr;
                pset!((*vxlan_hdr).vx_flags, htonl(1u32 << 27));
                pset!((*vxlan_hdr).vx_vni, htonl(VNI_ID << 8));
                l2_hdr = unsafe { l2_hdr.add(core::mem::size_of::<VxlanHdr>()) };
            }

            if bpf_skb_load_bytes(skb as *const c_void, 0, l2_hdr as *mut c_void, ETH_HLEN) != 0 {
                return TC_ACT_SHOT;
            }
        }
        _ => {}
    }
    olen += l2_len;

    // add room between mac and network header
    if bpf_skb_adjust_room(skb as *const c_void, olen, BPF_ADJ_ROOM_MAC, flags) != 0 {
        return TC_ACT_SHOT;
    }

    // prepare new outer network header
    unsafe {
        vcopy(
            h_outer_ip as *mut u8,
            &iph_inner as *const Ipv6Hdr as *const u8,
            core::mem::size_of::<Ipv6Hdr>(),
        )
    };
    let cur_payload_len = ntohs(pget!((*h_outer_ip).payload_len));
    let sum = (olen as u32).wrapping_add(cur_payload_len as u32) as u16;
    pset!((*h_outer_ip).payload_len, htons(sum));
    pset!((*h_outer_ip).nexthdr, encap_proto);

    // store new outer network header
    if bpf_skb_store_bytes(
        skb as *const c_void,
        ETH_HLEN,
        h_outer as *const c_void,
        olen as u32,
        BPF_F_INVALIDATE_HASH,
    ) < 0
    {
        return TC_ACT_SHOT;
    }

    TC_ACT_OK
}

#[inline(always)]
fn encap_ipv6(skb: *mut __sk_buff, encap_proto: u8, l2_proto: u16) -> i32 {
    __encap_ipv6(skb, encap_proto, l2_proto, 0)
}

// ---- ipv6-in-ipv4-in-ipv6 (sit-style 6in4-in-6) special case ------------

fn encap_ipv6_ipip6(skb: *mut __sk_buff) -> i32 {
    let mut h_outer = Ipv6Hdr {
        priority_version: 0,
        flow_lbl: [0; 3],
        payload_len: 0,
        nexthdr: 0,
        hop_limit: 0,
        saddr: [0; 16],
        daddr: [0; 16],
    };
    let mut iph_inner = IpHdr {
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
    let mut tcph = TcpHdr {
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

    if bpf_skb_load_bytes(
        skb as *const c_void,
        ETH_HLEN,
        &mut iph_inner as *mut IpHdr as *mut c_void,
        core::mem::size_of::<IpHdr>() as u32,
    ) < 0
    {
        return TC_ACT_OK;
    }

    // filter only packets we want
    let ihl = ip_ihl(pget!(iph_inner.ihl_version));
    let tcp_off = ETH_HLEN + (ihl as u32) * 4;
    if bpf_skb_load_bytes(
        skb as *const c_void,
        tcp_off,
        &mut tcph as *mut TcpHdr as *mut c_void,
        core::mem::size_of::<TcpHdr>() as u32,
    ) < 0
    {
        return TC_ACT_OK;
    }

    if pget!(tcph.dest) != htons(CFG_PORT) {
        return TC_ACT_OK;
    }

    let olen: i32 = core::mem::size_of::<Ipv6Hdr>() as i32;
    let flags: u64 = BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_ENCAP_L3_IPV6;

    // add room between mac and network header
    if bpf_skb_adjust_room(skb as *const c_void, olen, BPF_ADJ_ROOM_MAC, flags) != 0 {
        return TC_ACT_SHOT;
    }

    // prepare new outer network header
    pset!(h_outer.priority_version, 6u8 << 4);
    pset!(h_outer.hop_limit, pget!(iph_inner.ttl));
    h_outer.saddr[1] = 0xfd;
    h_outer.saddr[15] = 1;
    h_outer.daddr[1] = 0xfd;
    h_outer.daddr[15] = 2;
    pset!(h_outer.payload_len, pget!(iph_inner.tot_len));
    pset!(h_outer.nexthdr, IPPROTO_IPIP);

    // store new outer network header
    if bpf_skb_store_bytes(
        skb as *const c_void,
        ETH_HLEN,
        &h_outer as *const Ipv6Hdr as *const c_void,
        olen as u32,
        BPF_F_INVALIDATE_HASH,
    ) < 0
    {
        return TC_ACT_SHOT;
    }

    // update eth->h_proto
    let mut eth = EthHdr {
        h_dest: [0; 6],
        h_source: [0; 6],
        h_proto: 0,
    };
    if bpf_skb_load_bytes(
        skb as *const c_void,
        0,
        &mut eth as *mut EthHdr as *mut c_void,
        core::mem::size_of::<EthHdr>() as u32,
    ) < 0
    {
        return TC_ACT_SHOT;
    }
    pset!(eth.h_proto, htons(ETH_P_IPV6));
    if bpf_skb_store_bytes(
        skb as *const c_void,
        0,
        &eth as *const EthHdr as *const c_void,
        core::mem::size_of::<EthHdr>() as u32,
        0,
    ) < 0
    {
        return TC_ACT_SHOT;
    }

    TC_ACT_OK
}

// ---- Decapsulation --------------------------------------------------------

fn decap_internal(skb: *mut __sk_buff, off: i32, len: i32, proto: u8) -> i32 {
    let mut flags: u64 = BPF_F_ADJ_ROOM_FIXED_GSO;
    let mut olen = len;

    match proto {
        IPPROTO_IPIP => {
            flags |= BPF_F_ADJ_ROOM_DECAP_L3_IPV4;
        }
        IPPROTO_IPV6 => {
            flags |= BPF_F_ADJ_ROOM_DECAP_L3_IPV6;
        }
        NEXTHDR_DEST => {
            let mut ip6_opt_hdr = Ipv6OptHdr { nexthdr: 0, hdrlen: 0 };
            if bpf_skb_load_bytes(
                skb as *const c_void,
                (off + len) as u32,
                &mut ip6_opt_hdr as *mut Ipv6OptHdr as *mut c_void,
                core::mem::size_of::<Ipv6OptHdr>() as u32,
            ) < 0
            {
                return TC_ACT_OK;
            }
            match pget!(ip6_opt_hdr.nexthdr) {
                IPPROTO_IPIP => flags |= BPF_F_ADJ_ROOM_DECAP_L3_IPV4,
                IPPROTO_IPV6 => flags |= BPF_F_ADJ_ROOM_DECAP_L3_IPV6,
                _ => return TC_ACT_OK,
            }
        }
        IPPROTO_GRE => {
            olen += core::mem::size_of::<GreHdr>() as i32;
            let mut greh = GreHdr { flags: 0, protocol: 0 };
            if bpf_skb_load_bytes(
                skb as *const c_void,
                (off + len) as u32,
                &mut greh as *mut GreHdr as *mut c_void,
                core::mem::size_of::<GreHdr>() as u32,
            ) < 0
            {
                return TC_ACT_OK;
            }
            match ntohs(pget!(greh.protocol)) {
                ETH_P_MPLS_UC => olen += core::mem::size_of::<u32>() as i32,
                ETH_P_TEB => olen += ETH_HLEN as i32,
                _ => {}
            }
        }
        IPPROTO_UDP => {
            olen += core::mem::size_of::<UdpHdr>() as i32;
            let mut udph = UdpHdr {
                source: 0,
                dest: 0,
                len: 0,
                check: 0,
            };
            if bpf_skb_load_bytes(
                skb as *const c_void,
                (off + len) as u32,
                &mut udph as *mut UdpHdr as *mut c_void,
                core::mem::size_of::<UdpHdr>() as u32,
            ) < 0
            {
                return TC_ACT_OK;
            }
            match ntohs(pget!(udph.dest)) {
                MPLS_OVER_UDP_PORT => olen += core::mem::size_of::<u32>() as i32,
                ETH_OVER_UDP_PORT => olen += ETH_HLEN as i32,
                VXLAN_UDP_PORT => olen += ETH_HLEN as i32 + core::mem::size_of::<VxlanHdr>() as i32,
                _ => {}
            }
        }
        _ => return TC_ACT_OK,
    }

    if bpf_skb_adjust_room(skb as *const c_void, -olen, BPF_ADJ_ROOM_MAC, flags) != 0 {
        return TC_ACT_SHOT;
    }

    TC_ACT_OK
}

fn decap_ipv4(skb: *mut __sk_buff) -> i32 {
    let mut iph_outer = IpHdr {
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
    if bpf_skb_load_bytes(
        skb as *const c_void,
        ETH_HLEN,
        &mut iph_outer as *mut IpHdr as *mut c_void,
        core::mem::size_of::<IpHdr>() as u32,
    ) < 0
    {
        return TC_ACT_OK;
    }

    if ip_ihl(pget!(iph_outer.ihl_version)) != 5 {
        return TC_ACT_OK;
    }

    decap_internal(
        skb,
        ETH_HLEN as i32,
        core::mem::size_of::<IpHdr>() as i32,
        pget!(iph_outer.protocol),
    )
}

fn decap_ipv6(skb: *mut __sk_buff) -> i32 {
    let mut iph_outer = Ipv6Hdr {
        priority_version: 0,
        flow_lbl: [0; 3],
        payload_len: 0,
        nexthdr: 0,
        hop_limit: 0,
        saddr: [0; 16],
        daddr: [0; 16],
    };
    if bpf_skb_load_bytes(
        skb as *const c_void,
        ETH_HLEN,
        &mut iph_outer as *mut Ipv6Hdr as *mut c_void,
        core::mem::size_of::<Ipv6Hdr>() as u32,
    ) < 0
    {
        return TC_ACT_OK;
    }

    decap_internal(
        skb,
        ETH_HLEN as i32,
        core::mem::size_of::<Ipv6Hdr>() as i32,
        pget!(iph_outer.nexthdr),
    )
}

// ---- Entry points ------------------------------------------------------

#[link_section = "tc"]
#[no_mangle]
extern "C" fn __encap_ipip_none(skb: *mut __sk_buff) -> i32 {
    if vload!((*skb).protocol) == htons(ETH_P_IP) as u32 {
        encap_ipv4(skb, IPPROTO_IPIP, ETH_P_IP)
    } else {
        TC_ACT_OK
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn __encap_gre_none(skb: *mut __sk_buff) -> i32 {
    if vload!((*skb).protocol) == htons(ETH_P_IP) as u32 {
        encap_ipv4(skb, IPPROTO_GRE, ETH_P_IP)
    } else {
        TC_ACT_OK
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn __encap_gre_mpls(skb: *mut __sk_buff) -> i32 {
    if vload!((*skb).protocol) == htons(ETH_P_IP) as u32 {
        encap_ipv4(skb, IPPROTO_GRE, ETH_P_MPLS_UC)
    } else {
        TC_ACT_OK
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn __encap_gre_eth(skb: *mut __sk_buff) -> i32 {
    if vload!((*skb).protocol) == htons(ETH_P_IP) as u32 {
        encap_ipv4(skb, IPPROTO_GRE, ETH_P_TEB)
    } else {
        TC_ACT_OK
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn __encap_udp_none(skb: *mut __sk_buff) -> i32 {
    if vload!((*skb).protocol) == htons(ETH_P_IP) as u32 {
        encap_ipv4(skb, IPPROTO_UDP, ETH_P_IP)
    } else {
        TC_ACT_OK
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn __encap_udp_mpls(skb: *mut __sk_buff) -> i32 {
    if vload!((*skb).protocol) == htons(ETH_P_IP) as u32 {
        encap_ipv4(skb, IPPROTO_UDP, ETH_P_MPLS_UC)
    } else {
        TC_ACT_OK
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn __encap_udp_eth(skb: *mut __sk_buff) -> i32 {
    if vload!((*skb).protocol) == htons(ETH_P_IP) as u32 {
        encap_ipv4(skb, IPPROTO_UDP, ETH_P_TEB)
    } else {
        TC_ACT_OK
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn __encap_vxlan_eth(skb: *mut __sk_buff) -> i32 {
    if vload!((*skb).protocol) == htons(ETH_P_IP) as u32 {
        __encap_ipv4(skb, IPPROTO_UDP, ETH_P_TEB, EXTPROTO_VXLAN)
    } else {
        TC_ACT_OK
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn __encap_sit_none(skb: *mut __sk_buff) -> i32 {
    if vload!((*skb).protocol) == htons(ETH_P_IPV6) as u32 {
        encap_ipv4(skb, IPPROTO_IPV6, ETH_P_IP)
    } else {
        TC_ACT_OK
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn __encap_ip6tnl_none(skb: *mut __sk_buff) -> i32 {
    if vload!((*skb).protocol) == htons(ETH_P_IPV6) as u32 {
        encap_ipv6(skb, IPPROTO_IPV6, ETH_P_IPV6)
    } else {
        TC_ACT_OK
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn __encap_ipip6_none(skb: *mut __sk_buff) -> i32 {
    if vload!((*skb).protocol) == htons(ETH_P_IP) as u32 {
        encap_ipv6_ipip6(skb)
    } else {
        TC_ACT_OK
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn __encap_ip6gre_none(skb: *mut __sk_buff) -> i32 {
    if vload!((*skb).protocol) == htons(ETH_P_IPV6) as u32 {
        encap_ipv6(skb, IPPROTO_GRE, ETH_P_IPV6)
    } else {
        TC_ACT_OK
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn __encap_ip6gre_mpls(skb: *mut __sk_buff) -> i32 {
    if vload!((*skb).protocol) == htons(ETH_P_IPV6) as u32 {
        encap_ipv6(skb, IPPROTO_GRE, ETH_P_MPLS_UC)
    } else {
        TC_ACT_OK
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn __encap_ip6gre_eth(skb: *mut __sk_buff) -> i32 {
    if vload!((*skb).protocol) == htons(ETH_P_IPV6) as u32 {
        encap_ipv6(skb, IPPROTO_GRE, ETH_P_TEB)
    } else {
        TC_ACT_OK
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn __encap_ip6udp_none(skb: *mut __sk_buff) -> i32 {
    if vload!((*skb).protocol) == htons(ETH_P_IPV6) as u32 {
        encap_ipv6(skb, IPPROTO_UDP, ETH_P_IPV6)
    } else {
        TC_ACT_OK
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn __encap_ip6udp_mpls(skb: *mut __sk_buff) -> i32 {
    if vload!((*skb).protocol) == htons(ETH_P_IPV6) as u32 {
        encap_ipv6(skb, IPPROTO_UDP, ETH_P_MPLS_UC)
    } else {
        TC_ACT_OK
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn __encap_ip6udp_eth(skb: *mut __sk_buff) -> i32 {
    if vload!((*skb).protocol) == htons(ETH_P_IPV6) as u32 {
        encap_ipv6(skb, IPPROTO_UDP, ETH_P_TEB)
    } else {
        TC_ACT_OK
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn __encap_ip6vxlan_eth(skb: *mut __sk_buff) -> i32 {
    if vload!((*skb).protocol) == htons(ETH_P_IPV6) as u32 {
        __encap_ipv6(skb, IPPROTO_UDP, ETH_P_TEB, EXTPROTO_VXLAN)
    } else {
        TC_ACT_OK
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn decap_f(skb: *mut __sk_buff) -> i32 {
    let proto = vload!((*skb).protocol);
    if proto == htons(ETH_P_IP) as u32 {
        decap_ipv4(skb)
    } else if proto == htons(ETH_P_IPV6) as u32 {
        decap_ipv6(skb)
    } else {
        TC_ACT_OK
    }
}

bpf_object!("GPL");
