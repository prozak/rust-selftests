#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_tc_change_tail.c
// (bpf-rs-core idiom).

use core::ffi::c_void;

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_skb_change_tail, bpf_skb_pull_data};
use bpf_rs_core::{bpf_object, vload};

const TCX_PASS: i32 = 0;
const TCX_DROP: i32 = 2;

const IPPROTO_UDP: i32 = 17;

// PAGE_SIZE << 2, matching BPF_SKB_MAX_LEN in the C source.
const BPF_SKB_MAX_LEN: u32 = 4096 << 2;

// struct ethhdr (linux/if_ether.h) — packed; only its size is needed here.
#[repr(C, packed)]
struct ethhdr {
    _h_dest: [u8; 6],
    _h_source: [u8; 6],
    _h_proto: u16,
}

// struct iphdr (linux/ip.h) — packed. ihl:version share byte 0 as
// LE-ordered 4-bit fields (ihl in the low nibble, version in the high).
#[repr(C, packed)]
struct iphdr {
    ihl_version: u8,
    _tos: u8,
    _tot_len: u16,
    _id: u16,
    _frag_off: u16,
    _ttl: u8,
    protocol: u8,
    _check: u16,
    _saddr: u32,
    _daddr: u32,
}

// struct udphdr (linux/udp.h) — packed; only its size is needed here.
#[repr(C, packed)]
struct udphdr {
    _source: u16,
    _dest: u16,
    _len: u16,
    _check: u16,
}

#[inline(always)]
fn parse_ip_header(skb: *const __sk_buff, ip_proto: &mut i32) -> Option<*const iphdr> {
    let data_end = vload!((*skb).data_end) as usize;
    let data = vload!((*skb).data) as usize;

    // Verify Ethernet header.
    if data + core::mem::size_of::<ethhdr>() > data_end {
        return None;
    }

    // Skip Ethernet header to get to IP header.
    let iph = (data + core::mem::size_of::<ethhdr>()) as *const iphdr;

    // Verify IP header.
    if iph as usize + core::mem::size_of::<iphdr>() > data_end {
        return None;
    }

    let ihl_version = unsafe { (*iph).ihl_version };
    let version = ihl_version >> 4;
    let ihl = ihl_version & 0xF;

    // Only support IPv4.
    if version != 4 {
        return None;
    }

    // Minimum IP header length.
    if ihl < 5 {
        return None;
    }

    *ip_proto = unsafe { (*iph).protocol } as i32;
    Some(iph)
}

#[inline(always)]
fn parse_udp_header(skb: *const __sk_buff, iph: *const iphdr) -> Option<*const udphdr> {
    let data_end = vload!((*skb).data_end) as usize;

    // Calculate UDP header position.
    let ihl = unsafe { (*iph).ihl_version } & 0xF;
    let udp = iph as usize + (ihl as usize) * 4;

    // Verify UDP header bounds.
    if udp + core::mem::size_of::<udphdr>() > data_end {
        return None;
    }

    Some(udp as *const udphdr)
}

#[no_mangle]
static mut change_tail_ret: i64 = 1;

#[link_section = "tc/ingress"]
#[no_mangle]
extern "C" fn change_tail(skb: *const __sk_buff) -> i32 {
    let len = vload!((*skb).len) as i32;

    bpf_skb_pull_data(skb as *const c_void, len as u32);

    let mut ip_proto: i32 = 0;
    let iph = match parse_ip_header(skb, &mut ip_proto) {
        Some(p) => p,
        None => return TCX_PASS,
    };

    if ip_proto != IPPROTO_UDP {
        return TCX_PASS;
    }

    let udp = match parse_udp_header(skb, iph) {
        Some(p) => p,
        None => return TCX_PASS,
    };

    let data_end = vload!((*skb).data_end) as usize;
    let payload = udp as usize + core::mem::size_of::<udphdr>();
    if payload + 1 > data_end {
        return TCX_PASS;
    }

    let byte0 = unsafe { *(payload as *const u8) };

    if byte0 == b'T' {
        // Trim the packet.
        let ret = bpf_skb_change_tail(skb as *const c_void, (len - 1) as u32, 0);
        unsafe { change_tail_ret = ret };
        if ret == 0 {
            bpf_skb_change_tail(skb as *const c_void, len as u32, 0);
        }
        TCX_PASS
    } else if byte0 == b'G' {
        // Grow the packet.
        let ret = bpf_skb_change_tail(skb as *const c_void, (len + 1) as u32, 0);
        unsafe { change_tail_ret = ret };
        if ret == 0 {
            bpf_skb_change_tail(skb as *const c_void, len as u32, 0);
        }
        TCX_PASS
    } else if byte0 == b'E' {
        // Error.
        let ret = bpf_skb_change_tail(skb as *const c_void, BPF_SKB_MAX_LEN, 0);
        unsafe { change_tail_ret = ret };
        TCX_PASS
    } else if byte0 == b'Z' {
        // Zero.
        let ret = bpf_skb_change_tail(skb as *const c_void, 0, 0);
        unsafe { change_tail_ret = ret };
        TCX_PASS
    } else {
        TCX_DROP
    }
}

bpf_object!("GPL");
