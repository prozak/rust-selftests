#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_sk_assign_libbpf.c, which is just
// `#include "test_sk_assign.c"` under IPROUTE2_HAVE_LIBBPF (the new-style
// libbpf map definition, vs. the iproute2-style struct bpf_elf_map under the
// #else branch). bpf-rs-core idiom.
//
// TC ingress program: parses the L3 header far enough to build a pointer to
// a `struct bpf_sock_tuple` directly inside the packet — the L3 address
// fields are immediately followed in memory by the L4 header's source/dest
// ports, so `&iph->saddr` (resp. `&ip6h->saddr`) already has the exact
// layout of `tuple->ipv4` (resp. `tuple->ipv6`), no copy needed. It then
// looks the tuple up as an existing socket, and on miss falls back to
// `server_map` (a `BPF_MAP_TYPE_SOCKMAP` holding exactly one socket at key
// 0, pinned so the userspace test can update it) keyed off a fixed
// destination port (4321). `bpf_sk_assign` redirects the skb to whichever
// socket was found.

use core::ffi::c_void;

use bpf_rs_core::ctx::{__sk_buff, TC_ACT_OK, TC_ACT_SHOT};
use bpf_rs_core::helpers::{
    bpf_map_lookup_elem, bpf_sk_assign, bpf_sk_lookup_udp, bpf_sk_release, bpf_skc_lookup_tcp,
};
use bpf_rs_core::{bpf_map, bpf_object, vload};

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const BPF_F_CURRENT_NETNS: u64 = -1i64 as u64;
const BPF_TCP_LISTEN: u32 = 10;
const CONNECT_PORT: u16 = 4321;

#[inline(always)]
fn htons(x: u16) -> u16 {
    x.to_be()
}

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

// struct bpf_sock_tuple's two union members (UAPI linux/bpf.h). Only used to
// size/read the in-packet tuple built by get_tuple(), never constructed.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct TupleIpv4 {
    saddr: u32,
    daddr: u32,
    sport: u16,
    dport: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct TupleIpv6 {
    saddr: [u8; 16],
    daddr: [u8; 16],
    sport: u16,
    dport: u16,
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
}

bpf_map! {
    server_map {
        r#type: *const [i32; 15], // BPF_MAP_TYPE_SOCKMAP
        key: *const i32,
        value: *const u64,
        pinning: *const [i32; 1], // LIBBPF_PIN_BY_NAME
        max_entries: *const [i32; 1],
    }
}

/// Mirrors the C original's `get_tuple`: on success, returns a pointer that
/// aliases packet memory at the L3 address fields (which is a valid
/// `struct bpf_sock_tuple` in place, see the file header), plus whether the
/// packet is IPv4 and whether the L4 protocol is TCP.
#[inline(always)]
fn get_tuple(skb: *const __sk_buff) -> Option<(*mut u8, bool, bool)> {
    let data_end = vload!((*skb).data_end) as usize;
    let data = vload!((*skb).data) as usize;

    if data + core::mem::size_of::<EthHdr>() > data_end {
        return None;
    }
    let eth = data as *const EthHdr;
    let h_proto = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*eth).h_proto)) };

    let ipv4;
    let result: *mut u8;
    let proto: u8;

    if h_proto == htons(ETH_P_IP) {
        let iph_off = data + core::mem::size_of::<EthHdr>();
        if iph_off + core::mem::size_of::<IpHdr>() > data_end {
            return None;
        }
        let iph = iph_off as *const IpHdr;
        let ihl_version =
            unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*iph).ihl_version)) };
        if (ihl_version & 0xf) != 5 {
            // Options are not supported.
            return None;
        }
        proto = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*iph).protocol)) };
        ipv4 = true;
        result = unsafe { core::ptr::addr_of!((*iph).saddr) } as *mut u8;
    } else if h_proto == htons(ETH_P_IPV6) {
        let ip6h_off = data + core::mem::size_of::<EthHdr>();
        if ip6h_off + core::mem::size_of::<Ipv6Hdr>() > data_end {
            return None;
        }
        let ip6h = ip6h_off as *const Ipv6Hdr;
        proto = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip6h).nexthdr)) };
        ipv4 = false;
        result = unsafe { core::ptr::addr_of!((*ip6h).saddr) } as *mut u8;
    } else {
        return Some((data as *mut u8, false, false));
    }

    if proto != IPPROTO_TCP && proto != IPPROTO_UDP {
        return None;
    }

    Some((result, ipv4, proto == IPPROTO_TCP))
}

#[inline(always)]
fn tuple_len(ipv4: bool) -> usize {
    if ipv4 {
        core::mem::size_of::<TupleIpv4>()
    } else {
        core::mem::size_of::<TupleIpv6>()
    }
}

#[inline(always)]
fn tuple_dport(tuple: *const u8, ipv4: bool) -> u16 {
    if ipv4 {
        unsafe {
            core::ptr::read_unaligned(core::ptr::addr_of!(
                (*(tuple as *const TupleIpv4)).dport
            ))
        }
    } else {
        unsafe {
            core::ptr::read_unaligned(core::ptr::addr_of!(
                (*(tuple as *const TupleIpv6)).dport
            ))
        }
    }
}

#[inline(always)]
fn assign_and_release(skb: *const __sk_buff, sk: *mut c_void) -> i32 {
    let ret = bpf_sk_assign(skb as *const c_void, sk, 0);
    bpf_sk_release(sk);
    ret as i32
}

#[inline(always)]
fn handle_udp(skb: *const __sk_buff, tuple: *mut u8, ipv4: bool) -> i32 {
    let data_end = vload!((*skb).data_end) as usize;
    let tlen = tuple_len(ipv4);
    if (tuple as usize) + tlen > data_end {
        return TC_ACT_SHOT;
    }

    let mut sk = bpf_sk_lookup_udp(
        skb as *const c_void,
        tuple as *const c_void,
        tlen as u32,
        BPF_F_CURRENT_NETNS,
        0,
    );
    if sk.is_null() {
        let dport = tuple_dport(tuple, ipv4);
        if dport != htons(CONNECT_PORT) {
            return TC_ACT_OK;
        }

        let zero: i32 = 0;
        sk = bpf_map_lookup_elem(&server_map, &zero);
        if sk.is_null() {
            return TC_ACT_SHOT;
        }
    }

    assign_and_release(skb, sk)
}

#[inline(always)]
fn handle_tcp(skb: *const __sk_buff, tuple: *mut u8, ipv4: bool) -> i32 {
    let data_end = vload!((*skb).data_end) as usize;
    let tlen = tuple_len(ipv4);
    if (tuple as usize) + tlen > data_end {
        return TC_ACT_SHOT;
    }

    let mut sk = bpf_skc_lookup_tcp(
        skb as *const c_void,
        tuple as *const c_void,
        tlen as u32,
        BPF_F_CURRENT_NETNS,
        0,
    );
    if !sk.is_null() {
        if unsafe { (*(sk as *const BpfSock)).state } != BPF_TCP_LISTEN {
            return assign_and_release(skb, sk);
        }
        bpf_sk_release(sk);
    }

    let dport = tuple_dport(tuple, ipv4);
    if dport != htons(CONNECT_PORT) {
        return TC_ACT_OK;
    }

    let zero: i32 = 0;
    sk = bpf_map_lookup_elem(&server_map, &zero);
    if sk.is_null() {
        return TC_ACT_SHOT;
    }

    if unsafe { (*(sk as *const BpfSock)).state } != BPF_TCP_LISTEN {
        bpf_sk_release(sk);
        return TC_ACT_SHOT;
    }

    assign_and_release(skb, sk)
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn bpf_sk_assign_test(skb: *const __sk_buff) -> i32 {
    let (tuple, ipv4, tcp) = match get_tuple(skb) {
        Some(t) => t,
        None => return TC_ACT_SHOT,
    };

    // Note that the verifier socket return type for bpf_skc_lookup_tcp()
    // differs from bpf_sk_lookup_udp(), so even though the C-level type is
    // the same here, if we try to share the implementations they will fail
    // to verify because we're crossing pointer types.
    let ret = if tcp {
        handle_tcp(skb, tuple, ipv4)
    } else {
        handle_udp(skb, tuple, ipv4)
    };

    if ret == 0 {
        TC_ACT_OK
    } else {
        TC_ACT_SHOT
    }
}

bpf_object!("GPL");
