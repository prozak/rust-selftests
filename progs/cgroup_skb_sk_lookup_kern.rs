#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/cgroup_skb_sk_lookup_kern.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{
    bpf_sk_ancestor_cgroup_id, bpf_sk_cgroup_id, bpf_sk_lookup_tcp, bpf_sk_release,
    bpf_skb_ancestor_cgroup_id, bpf_skb_cgroup_id, bpf_skb_load_bytes,
};
use bpf_rs_core::vload;
use core::ffi::c_void;

const ETH_P_IPV6: u16 = 0x86DD;
const IPPROTO_TCP: u8 = 6;
const BPF_F_CURRENT_NETNS: u64 = -1i64 as u64;

#[inline(always)]
fn htons(x: u16) -> u16 {
    x.to_be()
}

// struct ipv6hdr (linux/ipv6.h): only nexthdr/saddr/daddr are read; the
// leading bitfield byte and payload_len/hop_limit are kept as raw bytes so
// the struct's size (and thus the following field offsets) matches the
// real header exactly.
#[repr(C)]
struct Ipv6Hdr {
    ver_priority: u8,
    flow_lbl: [u8; 3],
    payload_len: u16,
    nexthdr: u8,
    hop_limit: u8,
    saddr: [u32; 4],
    daddr: [u32; 4],
}

// struct tcphdr (linux/tcp.h): only source/dest are read; the rest is kept
// as raw bytes for the correct struct size.
#[repr(C)]
struct TcpHdr {
    source: u16,
    dest: u16,
    seq: u32,
    ack_seq: u32,
    flags: u16,
    window: u16,
    check: u16,
    urg_ptr: u16,
}

// struct bpf_sock_tuple's `.ipv6` member (UAPI linux/bpf.h). The union's
// other member (`.ipv4`) is never used by this program, so only the ipv6
// shape is declared, at the union's (zero) offset.
#[repr(C)]
struct SockTupleIpv6 {
    saddr: [u32; 4],
    daddr: [u32; 4],
    sport: u16,
    dport: u16,
}

#[no_mangle]
static mut g_serv_port: u16 = 0;

#[inline(always)]
fn is_allowed_peer_cg(skb: *const c_void, ip6h: &Ipv6Hdr, tcph: &TcpHdr) -> i32 {
    // Element-wise (not whole-array) copies: an array-valued struct-literal
    // copy gets lowered by LLVM to a `memcpy` libcall, which the BPF backend
    // resolves to the arena-only `bpf_arena_memcpy` kfunc — unavailable
    // (and meaningless) outside an arena-backed program, so the load fails.
    let mut tuple = SockTupleIpv6 {
        saddr: [0; 4],
        daddr: [0; 4],
        sport: tcph.dest,
        dport: tcph.source,
    };
    tuple.saddr[0] = ip6h.daddr[0];
    tuple.saddr[1] = ip6h.daddr[1];
    tuple.saddr[2] = ip6h.daddr[2];
    tuple.saddr[3] = ip6h.daddr[3];
    tuple.daddr[0] = ip6h.saddr[0];
    tuple.daddr[1] = ip6h.saddr[1];
    tuple.daddr[2] = ip6h.saddr[2];
    tuple.daddr[3] = ip6h.saddr[3];
    let tuple_len = core::mem::size_of::<SockTupleIpv6>() as u32;

    let peer_sk = bpf_sk_lookup_tcp(skb, &tuple as *const SockTupleIpv6, tuple_len, BPF_F_CURRENT_NETNS, 0);
    if peer_sk.is_null() {
        return 0;
    }

    let cgid = bpf_skb_cgroup_id(skb);
    let peer_cgid = bpf_sk_cgroup_id(peer_sk);

    let acgid = bpf_skb_ancestor_cgroup_id(skb, 2);
    let peer_acgid = bpf_sk_ancestor_cgroup_id(peer_sk, 2);

    bpf_sk_release(peer_sk);

    (cgid != 0 && cgid == peer_cgid && acgid != 0 && acgid == peer_acgid) as i32
}

#[link_section = "cgroup_skb/ingress"]
#[no_mangle]
extern "C" fn ingress_lookup(skb: *const __sk_buff) -> i32 {
    if vload!((*skb).protocol) != htons(ETH_P_IPV6) as u32 {
        return 1;
    }

    // For SYN packets coming to listening socket skb->remote_port will be
    // zero, so IPv6/TCP headers are loaded to identify remote peer
    // instead.
    let mut ip6h: Ipv6Hdr = unsafe { core::mem::zeroed() };
    if bpf_skb_load_bytes(
        skb as *const c_void,
        0,
        &mut ip6h as *mut Ipv6Hdr as *mut c_void,
        core::mem::size_of::<Ipv6Hdr>() as u32,
    ) != 0
    {
        return 1;
    }

    if ip6h.nexthdr != IPPROTO_TCP {
        return 1;
    }

    let mut tcph: TcpHdr = unsafe { core::mem::zeroed() };
    if bpf_skb_load_bytes(
        skb as *const c_void,
        core::mem::size_of::<Ipv6Hdr>() as u32,
        &mut tcph as *mut TcpHdr as *mut c_void,
        core::mem::size_of::<TcpHdr>() as u32,
    ) != 0
    {
        return 1;
    }

    if unsafe { g_serv_port } == 0 {
        return 0;
    }

    if tcph.dest != unsafe { g_serv_port } {
        return 1;
    }

    is_allowed_peer_cg(skb as *const c_void, &ip6h, &tcph)
}

bpf_object!("GPL");
