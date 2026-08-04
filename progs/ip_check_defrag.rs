#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/ip_check_defrag.c
// (bpf-rs-core idiom).

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use btf_macros::btf;

const NF_DROP: i32 = 0;
const NF_ACCEPT: i32 = 1;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const IP_MF: i32 = 0x2000;
const IP_OFFSET: i32 = 0x1FFF;
const NEXTHDR_FRAGMENT: u8 = 44;

#[no_mangle]
static mut shootdowns: i32 = 0;

// struct iphdr (linux/ip.h) — packed.
#[repr(C, packed)]
struct iphdr {
    version_ihl: u8,
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

// struct ipv6hdr (linux/ipv6.h) — packed.
#[repr(C, packed)]
struct ipv6hdr {
    version_priority: u8,
    flow_lbl: [u8; 3],
    payload_len: u16,
    nexthdr: u8,
    hop_limit: u8,
    saddr: [u8; 16],
    daddr: [u8; 16],
}

#[allow(non_camel_case_types)]
#[repr(C, align(8))]
struct bpf_dynptr {
    opaque: [u64; 2],
}

// Minimal local CO-RE view of the kernel's real `struct sk_buff`, matching
// the C source's read of ctx->skb->protocol.
#[btf]
struct sk_buff {
    protocol: u16,
}

// struct bpf_nf_ctx (net/netfilter/nf_bpf_link.h): two trusted BTF-ID
// pointers, state (unused here) then skb (real kernel struct sk_buff *).
#[repr(C)]
struct bpf_nf_ctx {
    state: *const c_void,
    skb: *mut sk_buff,
}

extern "C" {
    fn bpf_dynptr_from_skb(skb: *mut __sk_buff, flags: u64, ptr: *mut bpf_dynptr) -> i32;
    fn bpf_dynptr_slice(
        ptr: *const bpf_dynptr,
        offset: u64,
        buffer: *mut c_void,
        buffer_sz: u64,
    ) -> *mut c_void;
}

fn is_frag_v4(iph: *const iphdr) -> bool {
    let frag_off = unsafe { (*iph).frag_off };
    let mut offset = u16::from_be(frag_off) as i32;
    let flags = offset & !IP_OFFSET;
    offset &= IP_OFFSET;
    offset <<= 3;
    (flags & IP_MF) != 0 || offset != 0
}

fn is_frag_v6(ip6h: *const ipv6hdr) -> bool {
    unsafe { (*ip6h).nexthdr == NEXTHDR_FRAGMENT }
}

fn handle_v4(skb: *mut __sk_buff) -> i32 {
    let mut ptr = bpf_dynptr { opaque: [0u64; 2] };
    let mut iph_buf = [0u8; 20];

    if unsafe { bpf_dynptr_from_skb(skb, 0, &mut ptr as *mut bpf_dynptr) } != 0 {
        return NF_DROP;
    }

    let iph = unsafe {
        bpf_dynptr_slice(
            &ptr as *const bpf_dynptr,
            0,
            iph_buf.as_mut_ptr() as *mut c_void,
            iph_buf.len() as u64,
        )
    } as *const iphdr;
    if iph.is_null() {
        return NF_DROP;
    }

    if is_frag_v4(iph) {
        unsafe { shootdowns += 1 };
        return NF_DROP;
    }

    NF_ACCEPT
}

fn handle_v6(skb: *mut __sk_buff) -> i32 {
    let mut ptr = bpf_dynptr { opaque: [0u64; 2] };
    let mut ip6h_buf = [0u8; 40];

    if unsafe { bpf_dynptr_from_skb(skb, 0, &mut ptr as *mut bpf_dynptr) } != 0 {
        return NF_DROP;
    }

    let ip6h = unsafe {
        bpf_dynptr_slice(
            &ptr as *const bpf_dynptr,
            0,
            ip6h_buf.as_mut_ptr() as *mut c_void,
            ip6h_buf.len() as u64,
        )
    } as *const ipv6hdr;
    if ip6h.is_null() {
        return NF_DROP;
    }

    if is_frag_v6(ip6h) {
        unsafe { shootdowns += 1 };
        return NF_DROP;
    }

    NF_ACCEPT
}

#[link_section = "netfilter"]
#[no_mangle]
extern "C" fn defrag(ctx: *const bpf_nf_ctx) -> i32 {
    let skb_kern = unsafe { (*ctx).skb };
    let protocol = *unsafe { &*skb_kern }.protocol().get().unwrap();
    let skb = skb_kern as *mut __sk_buff;

    match u16::from_be(protocol) {
        p if p == ETH_P_IP => handle_v4(skb),
        p if p == ETH_P_IPV6 => handle_v6(skb),
        _ => NF_ACCEPT,
    }
}

bpf_object!("GPL");
