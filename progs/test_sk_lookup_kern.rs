#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_sk_lookup_kern.c
// (bpf-rs-core idiom).
//
// prog_tests/reference_tracking.c's test_reference_tracking() loads each
// program here individually (autoload toggled per-program) and asserts:
// programs named "err_*" MUST fail verification, everything else MUST load
// successfully. It never runs the programs, so only load-time (verifier)
// behavior matters, not packet-parsing correctness.

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_sk_lookup_tcp, bpf_sk_release, bpf_trace_printk};
use bpf_rs_core::vload;

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
const IPPROTO_TCP: u8 = 6;
const BPF_F_CURRENT_NETNS: u64 = -1i64 as u64;
const TC_ACT_OK: i32 = 0;
const TC_ACT_SHOT: i32 = 2;
const TC_ACT_UNSPEC: i32 = -1;

#[inline(always)]
fn htons(x: u16) -> u16 {
    x.to_be()
}

// struct ethhdr (linux/if_ether.h) — packed, size 14.
#[repr(C, packed)]
struct EthHdr {
    #[allow(dead_code)]
    h_dest: [u8; 6],
    #[allow(dead_code)]
    h_source: [u8; 6],
    h_proto: u16,
}

// struct iphdr (linux/ip.h) — packed, no options, size 20.
#[repr(C, packed)]
struct IpHdr {
    version_ihl: u8,
    #[allow(dead_code)]
    tos: u8,
    #[allow(dead_code)]
    tot_len: u16,
    #[allow(dead_code)]
    id: u16,
    #[allow(dead_code)]
    frag_off: u16,
    #[allow(dead_code)]
    ttl: u8,
    protocol: u8,
    #[allow(dead_code)]
    check: u16,
    saddr: u32,
    #[allow(dead_code)]
    daddr: u32,
}

// struct ipv6hdr (linux/ipv6.h) — packed, size 40.
#[repr(C, packed)]
struct Ipv6Hdr {
    #[allow(dead_code)]
    version_priority: u8,
    #[allow(dead_code)]
    flow_lbl: [u8; 3],
    #[allow(dead_code)]
    payload_len: u16,
    nexthdr: u8,
    #[allow(dead_code)]
    hop_limit: u8,
    saddr: [u8; 16],
    #[allow(dead_code)]
    daddr: [u8; 16],
}

// struct bpf_sock_tuple's largest (.ipv6) member (UAPI linux/bpf.h); the
// union's other member (.ipv4) is a prefix of this shape at the same (zero)
// offset, so this one struct covers `sizeof(struct bpf_sock_tuple)` for
// zero-init and for casting a packet offset into a tuple pointer.
#[repr(C)]
struct SockTupleIpv6 {
    #[allow(dead_code)]
    saddr: [u32; 4],
    #[allow(dead_code)]
    daddr: [u32; 4],
    #[allow(dead_code)]
    sport: u16,
    #[allow(dead_code)]
    dport: u16,
}

const SOCK_TUPLE_IPV4_LEN: u32 = 12;

/// Fill 'tuple' with L3 info, and attempt to find L4. On fail, return null.
#[inline(always)]
fn get_tuple(
    data: usize,
    nh_off: usize,
    data_end: usize,
    eth_proto: u16,
    ipv4: &mut bool,
) -> *const SockTupleIpv6 {
    let mut ihl_len: usize = 0;
    let mut proto: u8 = 0;
    let mut result: *const SockTupleIpv6 = core::ptr::null();

    if eth_proto == htons(ETH_P_IP) {
        let iph = (data + nh_off) as *const IpHdr;
        if iph as usize + core::mem::size_of::<IpHdr>() > data_end {
            return core::ptr::null();
        }
        let ihl = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*iph).version_ihl)) } & 0x0f;
        ihl_len = (ihl as usize) * 4;
        proto = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*iph).protocol)) };
        *ipv4 = true;
        result = unsafe { core::ptr::addr_of!((*iph).saddr) as *const SockTupleIpv6 };
    } else if eth_proto == htons(ETH_P_IPV6) {
        let ip6h = (data + nh_off) as *const Ipv6Hdr;
        if ip6h as usize + core::mem::size_of::<Ipv6Hdr>() > data_end {
            return core::ptr::null();
        }
        ihl_len = core::mem::size_of::<Ipv6Hdr>();
        proto = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip6h).nexthdr)) };
        // Matches the upstream C source: it sets *ipv4 = true in the ipv6
        // branch too (this is a pre-existing quirk of the original test).
        *ipv4 = true;
        result = unsafe { core::ptr::addr_of!((*ip6h).saddr) as *const SockTupleIpv6 };
    }

    if data + nh_off + ihl_len > data_end || proto != IPPROTO_TCP {
        return core::ptr::null();
    }

    result
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn sk_lookup_success(skb: *const __sk_buff) -> i32 {
    let data_end = vload!((*skb).data_end) as usize;
    let data = vload!((*skb).data) as usize;

    if data + core::mem::size_of::<EthHdr>() > data_end {
        return TC_ACT_SHOT;
    }
    let eth = data as *const EthHdr;
    let eth_proto = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*eth).h_proto)) };

    let mut ipv4 = false;
    let tuple = get_tuple(data, core::mem::size_of::<EthHdr>(), data_end, eth_proto, &mut ipv4);
    // C: `tuple + sizeof *tuple > data_end` — POINTER arithmetic, so the
    // sizeof scales by the element size: the compiled object adds
    // 36 * 36 = 1296 bytes, not 36 (upstream's quirk, kept faithfully).
    if tuple.is_null()
        || tuple as usize
            + core::mem::size_of::<SockTupleIpv6>() * core::mem::size_of::<SockTupleIpv6>()
            > data_end
    {
        return TC_ACT_SHOT;
    }

    let tuple_len: u32 = if ipv4 {
        SOCK_TUPLE_IPV4_LEN
    } else {
        core::mem::size_of::<SockTupleIpv6>() as u32
    };

    let sk = bpf_sk_lookup_tcp(skb as *const c_void, tuple, tuple_len, BPF_F_CURRENT_NETNS, 0);

    let fmt = b"sk=%d\n\0";
    bpf_trace_printk(fmt.as_ptr() as *const c_void, fmt.len() as u32, if sk.is_null() { 0 } else { 1 }, 0, 0);

    if !sk.is_null() {
        bpf_sk_release(sk as *mut c_void);
    }
    if sk.is_null() { TC_ACT_UNSPEC } else { TC_ACT_OK }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn sk_lookup_success_simple(skb: *const __sk_buff) -> i32 {
    let tuple: SockTupleIpv6 = unsafe { core::mem::zeroed() };
    let sk = bpf_sk_lookup_tcp(
        skb as *const c_void,
        &tuple as *const SockTupleIpv6,
        core::mem::size_of::<SockTupleIpv6>() as u32,
        BPF_F_CURRENT_NETNS,
        0,
    );
    if !sk.is_null() {
        bpf_sk_release(sk as *mut c_void);
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn err_use_after_free(skb: *const __sk_buff) -> i32 {
    let tuple: SockTupleIpv6 = unsafe { core::mem::zeroed() };
    let sk = bpf_sk_lookup_tcp(
        skb as *const c_void,
        &tuple as *const SockTupleIpv6,
        core::mem::size_of::<SockTupleIpv6>() as u32,
        BPF_F_CURRENT_NETNS,
        0,
    );
    let mut family: u32 = 0;
    if !sk.is_null() {
        bpf_sk_release(sk as *mut c_void);
        // Use-after-free: `sk`'s reference was just released, so this read
        // must be rejected by the verifier.
        family = unsafe { core::ptr::read_unaligned((sk as *const u8).add(4) as *const u32) };
    }
    family as i32
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn err_modify_sk_pointer(skb: *const __sk_buff) -> i32 {
    let tuple: SockTupleIpv6 = unsafe { core::mem::zeroed() };
    let sk = bpf_sk_lookup_tcp(
        skb as *const c_void,
        &tuple as *const SockTupleIpv6,
        core::mem::size_of::<SockTupleIpv6>() as u32,
        BPF_F_CURRENT_NETNS,
        0,
    );
    if !sk.is_null() {
        // Pointer arithmetic on a reference-tracked socket pointer: rejected.
        // C: `sk += 1` is POINTER arithmetic — the object advances by
        // sizeof(struct bpf_sock) = 80 bytes, not 1; mirror it.
        let sk = unsafe { (sk as *const u8).add(80) } as *mut c_void;
        bpf_sk_release(sk);
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn err_modify_sk_or_null_pointer(skb: *const __sk_buff) -> i32 {
    let tuple: SockTupleIpv6 = unsafe { core::mem::zeroed() };
    let sk = bpf_sk_lookup_tcp(
        skb as *const c_void,
        &tuple as *const SockTupleIpv6,
        core::mem::size_of::<SockTupleIpv6>() as u32,
        BPF_F_CURRENT_NETNS,
        0,
    );
    // Pointer arithmetic on a possibly-null, reference-tracked socket
    // pointer, done *before* the null check: rejected.
    // C: `sk += 1` is POINTER arithmetic — the object advances by
        // sizeof(struct bpf_sock) = 80 bytes, not 1; mirror it.
        let sk = unsafe { (sk as *const u8).add(80) } as *mut c_void;
    if !sk.is_null() {
        bpf_sk_release(sk);
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn err_no_release(skb: *const __sk_buff) -> i32 {
    let tuple: SockTupleIpv6 = unsafe { core::mem::zeroed() };
    // Leaked reference: never released before the program exits.
    bpf_sk_lookup_tcp(
        skb as *const c_void,
        &tuple as *const SockTupleIpv6,
        core::mem::size_of::<SockTupleIpv6>() as u32,
        BPF_F_CURRENT_NETNS,
        0,
    );
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn err_release_twice(skb: *const __sk_buff) -> i32 {
    let tuple: SockTupleIpv6 = unsafe { core::mem::zeroed() };
    let sk = bpf_sk_lookup_tcp(
        skb as *const c_void,
        &tuple as *const SockTupleIpv6,
        core::mem::size_of::<SockTupleIpv6>() as u32,
        BPF_F_CURRENT_NETNS,
        0,
    );
    bpf_sk_release(sk as *mut c_void);
    bpf_sk_release(sk as *mut c_void);
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn err_release_unchecked(skb: *const __sk_buff) -> i32 {
    let tuple: SockTupleIpv6 = unsafe { core::mem::zeroed() };
    let sk = bpf_sk_lookup_tcp(
        skb as *const c_void,
        &tuple as *const SockTupleIpv6,
        core::mem::size_of::<SockTupleIpv6>() as u32,
        BPF_F_CURRENT_NETNS,
        0,
    );
    // Released without a preceding null check: rejected (PTR_TO_SOCKET_OR_NULL
    // passed to a release function that requires a checked, non-null ptr).
    bpf_sk_release(sk as *mut c_void);
    0
}

// Not a BPF program: no SEC(), plain global function (matches the C
// source's non-static `void lookup_no_release(struct __sk_buff *skb)`,
// which stays its own global symbol/subprogram in the clang-built object —
// the internalize keep-list is derived from those global symbol names, so
// this must keep the same name and external linkage here too).
#[no_mangle]
extern "C" fn lookup_no_release(skb: *const __sk_buff) {
    let tuple: SockTupleIpv6 = unsafe { core::mem::zeroed() };
    bpf_sk_lookup_tcp(
        skb as *const c_void,
        &tuple as *const SockTupleIpv6,
        core::mem::size_of::<SockTupleIpv6>() as u32,
        BPF_F_CURRENT_NETNS,
        0,
    );
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn err_no_release_subcall(skb: *const __sk_buff) -> i32 {
    lookup_no_release(skb);
    0
}

bpf_object!("GPL");
