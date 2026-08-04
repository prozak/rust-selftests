#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_dst_clear.c
// (bpf-rs-core idiom).

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::{__sk_buff, TC_ACT_OK, TC_ACT_SHOT};
use bpf_rs_core::helpers::{bpf_skb_adjust_room, bpf_skb_load_bytes};
use bpf_rs_core::vload;
use btf_macros::btf;

const ETH_HLEN: u32 = 14;
const ETH_P_IP: u16 = 0x0800;
const IPPROTO_UDP: u8 = 17;
const UDP_TEST_PORT: u16 = 7777;

// Mode/flags for bpf_skb_adjust_room (linux/bpf.h).
const BPF_ADJ_ROOM_MAC: u32 = 1;
const BPF_F_ADJ_ROOM_FIXED_GSO: u64 = 1 << 0;
const BPF_F_ADJ_ROOM_ENCAP_L3_IPV4: u64 = 1 << 1;

#[inline(always)]
fn htons(x: u16) -> u16 {
    x.to_be()
}

// struct iphdr (linux/ip.h) — packed, follows a 14-byte ethhdr.
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

// struct udphdr (linux/udp.h) — packed.
#[repr(C, packed)]
struct udphdr {
    source: u16,
    dest: u16,
    len: u16,
    check: u16,
}

// Minimal local CO-RE view of the kernel's real `struct sk_buff`, matching
// the C source's own local re-declaration (only the field dst_clear needs).
#[btf]
struct sk_buff {
    _skb_refdst: u64,
}

extern "C" {
    fn bpf_cast_to_kern_ctx(ctx: *mut c_void) -> *mut c_void;
}

#[no_mangle]
static mut had_dst: bool = false;
#[no_mangle]
static mut dst_cleared: bool = false;

#[link_section = "tc/egress"]
#[no_mangle]
extern "C" fn dst_clear(skb: *const __sk_buff) -> i32 {
    let mut iph: iphdr = unsafe { core::mem::zeroed() };
    let mut udph: udphdr = unsafe { core::mem::zeroed() };

    if vload!((*skb).protocol) != htons(ETH_P_IP) as u32 {
        return TC_ACT_OK;
    }

    if bpf_skb_load_bytes(
        skb as *const c_void,
        ETH_HLEN,
        &mut iph as *mut iphdr as *mut c_void,
        core::mem::size_of::<iphdr>() as u32,
    ) != 0
    {
        return TC_ACT_OK;
    }

    if iph.protocol != IPPROTO_UDP {
        return TC_ACT_OK;
    }

    if bpf_skb_load_bytes(
        skb as *const c_void,
        ETH_HLEN + core::mem::size_of::<iphdr>() as u32,
        &mut udph as *mut udphdr as *mut c_void,
        core::mem::size_of::<udphdr>() as u32,
    ) != 0
    {
        return TC_ACT_OK;
    }

    if udph.dest != htons(UDP_TEST_PORT) {
        return TC_ACT_OK;
    }

    let kskb = unsafe { bpf_cast_to_kern_ctx(skb as *mut c_void) } as *const sk_buff;
    unsafe {
        had_dst = *(&*kskb)._skb_refdst().get().unwrap() != 0;
    }

    // Same-protocol encap (IPIP): protocol stays IPv4, but the dst from the
    // original routing is no longer valid for the outer hdr.
    let err = bpf_skb_adjust_room(
        skb as *const c_void,
        core::mem::size_of::<iphdr>() as i32,
        BPF_ADJ_ROOM_MAC,
        BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_ENCAP_L3_IPV4,
    );
    if err != 0 {
        return TC_ACT_SHOT;
    }

    unsafe {
        dst_cleared = *(&*kskb)._skb_refdst().get().unwrap() == 0;
    }

    TC_ACT_SHOT
}

// The C source names its license global `__license` (not the crate macro's
// default `_license`); the internalize keep-list is derived from the C
// object's global symbol names, so without a matching symbol here the
// license section is silently DCE'd away and the GPL-only bpf_skb_load_bytes
// / bpf_skb_adjust_room calls are rejected as non-GPL.
#[link_section = "license"]
#[no_mangle]
static __license: [u8; 4] = bpf_rs_core::__lic_bytes::<4>("GPL");

bpf_object!("GPL");
