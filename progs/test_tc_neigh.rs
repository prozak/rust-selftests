#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_tc_neigh.c
// (bpf-rs-core idiom).

use core::ffi::c_void;

use bpf_rs_core::ctx::{__sk_buff, TC_ACT_OK, TC_ACT_SHOT};
use bpf_rs_core::helpers::{bpf_redirect_neigh, bpf_skb_store_bytes};
use bpf_rs_core::{bpf_object, vload};

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;

const ETH_ALEN: usize = 6;

const IP4_SRC: u32 = 0xac10_0164; // 172.16.1.100
const IP4_DST: u32 = 0xac10_0264; // 172.16.2.100

// Raw bytes, matching the C array literal exactly (avoids any
// endianness conversion — compared byte-for-byte against the packet's
// network-order address bytes below).
const IP6_SRC: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe,
];
const IP6_DST: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe,
];

#[inline(always)]
fn htons(x: u16) -> u16 {
    x.to_be()
}

#[inline(always)]
fn htonl(x: u32) -> u32 {
    x.to_be()
}

// struct ethhdr (linux/if_ether.h) — packed.
#[repr(C, packed)]
struct ethhdr {
    #[allow(dead_code)]
    h_dest: [u8; 6],
    #[allow(dead_code)]
    h_source: [u8; 6],
    #[allow(dead_code)]
    h_proto: u16,
}

// struct iphdr (linux/ip.h) — packed (follows a 14-byte ethhdr, so never
// 4-byte aligned); only through daddr, no options.
#[repr(C, packed)]
struct iphdr {
    #[allow(dead_code)]
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
    #[allow(dead_code)]
    protocol: u8,
    #[allow(dead_code)]
    check: u16,
    #[allow(dead_code)]
    saddr: u32,
    daddr: u32,
}

// struct ipv6hdr (linux/ipv6.h) — packed.
#[repr(C, packed)]
struct ipv6hdr {
    #[allow(dead_code)]
    version_priority: u8,
    #[allow(dead_code)]
    flow_lbl: [u8; 3],
    #[allow(dead_code)]
    payload_len: u16,
    #[allow(dead_code)]
    nexthdr: u8,
    #[allow(dead_code)]
    hop_limit: u8,
    #[allow(dead_code)]
    saddr: [u8; 16],
    daddr: [u8; 16],
}

#[inline(always)]
fn v6_daddr_equal(daddr: *const [u8; 16], addr: &[u8; 16]) -> bool {
    unsafe {
        let d = daddr as *const u8;
        let mut i = 0usize;
        while i < 16 {
            if core::ptr::read_unaligned(d.add(i)) != addr[i] {
                return false;
            }
            i += 1;
        }
    }
    true
}

#[inline(always)]
fn is_remote_ep_v4(skb: *const __sk_buff, addr: u32) -> bool {
    let data_end = vload!((*skb).data_end) as usize;
    let data = vload!((*skb).data) as usize;

    if data + core::mem::size_of::<ethhdr>() > data_end {
        return false;
    }

    let ip4h = (data + core::mem::size_of::<ethhdr>()) as *const iphdr;
    if ip4h as usize + core::mem::size_of::<iphdr>() > data_end {
        return false;
    }

    let daddr = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip4h).daddr)) };
    daddr == addr
}

#[inline(always)]
fn is_remote_ep_v6(skb: *const __sk_buff, addr: &[u8; 16]) -> bool {
    let data_end = vload!((*skb).data_end) as usize;
    let data = vload!((*skb).data) as usize;

    if data + core::mem::size_of::<ethhdr>() > data_end {
        return false;
    }

    let ip6h = (data + core::mem::size_of::<ethhdr>()) as *const ipv6hdr;
    if ip6h as usize + core::mem::size_of::<ipv6hdr>() > data_end {
        return false;
    }

    v6_daddr_equal(unsafe { core::ptr::addr_of!((*ip6h).daddr) }, addr)
}

#[inline(always)]
fn tc_redir(skb: *const __sk_buff, v4_addr: u32, v6_addr: &[u8; 16], ifindex: u32) -> i32 {
    // C switches on the full `__u32 skb->protocol`; narrowing to u16 here
    // would match on the low half alone.
    let protocol = vload!((*skb).protocol);

    let redirect = if protocol == htons(ETH_P_IP) as u32 {
        is_remote_ep_v4(skb, htonl(v4_addr))
    } else if protocol == htons(ETH_P_IPV6) as u32 {
        is_remote_ep_v6(skb, v6_addr)
    } else {
        false
    };

    if !redirect {
        return TC_ACT_OK;
    }

    let zero = [0u8; ETH_ALEN * 2];
    if bpf_skb_store_bytes(
        skb as *const c_void,
        0,
        zero.as_ptr() as *const c_void,
        (ETH_ALEN * 2) as u32,
        0,
    ) < 0
    {
        return TC_ACT_SHOT;
    }

    bpf_redirect_neigh(ifindex, core::ptr::null_mut::<c_void>(), 0, 0) as i32
}

#[link_section = ".rodata"]
#[no_mangle]
static IFINDEX_SRC: u32 = 0;

#[link_section = ".rodata"]
#[no_mangle]
static IFINDEX_DST: u32 = 0;

#[link_section = "tc"]
#[no_mangle]
extern "C" fn tc_chk(skb: *const __sk_buff) -> i32 {
    let data_end = vload!((*skb).data_end) as usize;
    let data = vload!((*skb).data) as usize;

    if data + core::mem::size_of::<ethhdr>() > data_end {
        return TC_ACT_SHOT;
    }

    let raw = data as *const u32;
    let r0 = unsafe { core::ptr::read_unaligned(raw) };
    let r1 = unsafe { core::ptr::read_unaligned(raw.add(1)) };
    let r2 = unsafe { core::ptr::read_unaligned(raw.add(2)) };

    if r0 == 0 && r1 == 0 && r2 == 0 {
        TC_ACT_SHOT
    } else {
        TC_ACT_OK
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn tc_dst(skb: *const __sk_buff) -> i32 {
    let ifindex = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(IFINDEX_SRC)) };
    tc_redir(skb, IP4_SRC, &IP6_SRC, ifindex)
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn tc_src(skb: *const __sk_buff) -> i32 {
    let ifindex = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(IFINDEX_DST)) };
    tc_redir(skb, IP4_DST, &IP6_DST, ifindex)
}

// The C source names its license global `__license` (not the crate macro's
// default `_license`); the internalize keep-list is derived from the C
// object's global symbol names, so without a matching symbol here the
// license section is silently DCE'd away and the GPL-only bpf_redirect_neigh
// helper call is rejected as non-GPL.
#[link_section = "license"]
#[no_mangle]
static __license: [u8; 4] = bpf_rs_core::__lic_bytes::<4>("GPL");

bpf_object!("GPL");
