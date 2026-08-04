#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_assign_reuse.c
// (bpf-rs-core idiom).

use core::ffi::c_void;
use core::mem::size_of;

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_get_socket_cookie, bpf_map_lookup_elem, bpf_sk_assign, bpf_sk_release};
use bpf_rs_core::maps::BpfMap;
use bpf_rs_core::vload;

const ETH_P_IP: u16 = 0x0800;
const IPPROTO_TCP: u32 = 6;
const IPPROTO_UDP: u32 = 17;

const TC_ACT_OK: i32 = 0;
const TC_ACT_SHOT: i32 = 2;

const SK_DROP: i32 = 0;
const SK_PASS: i32 = 1;

#[inline(always)]
fn htons(x: u16) -> u16 {
    x.to_be()
}

// C's __builtin_memcpy of small fixed headers lowers to an llvm.memcpy that
// add_ksyms.py rewrites into an unresolvable extern bpf_arena_memcpy kfunc
// call; a volatile byte loop is the one pattern the optimizer can't fold
// into that shape.
#[inline(always)]
unsafe fn vcopy(dst: *mut u8, src: *const u8, len: usize) {
    let mut i = 0usize;
    while i < len {
        core::ptr::write_volatile(dst.add(i), core::ptr::read_volatile(src.add(i)));
        i += 1;
    }
}

#[inline(always)]
unsafe fn vmemeq(a: *const u8, b: *const u8, len: usize) -> bool {
    let mut i = 0usize;
    while i < len {
        if core::ptr::read_volatile(a.add(i)) != core::ptr::read_volatile(b.add(i)) {
            return false;
        }
        i += 1;
    }
    true
}

// struct ethhdr (linux/if_ether.h).
#[repr(C)]
struct EthHdr {
    #[allow(dead_code)]
    h_dest: [u8; 6],
    #[allow(dead_code)]
    h_source: [u8; 6],
    h_proto: u16,
}

const _: () = assert!(size_of::<EthHdr>() == 14);

// struct iphdr (linux/ip.h), through protocol/daddr, no options — packed:
// it follows a 14-byte ethhdr, so it is never 4-byte aligned in the packet.
#[repr(C, packed)]
struct IpHdr {
    #[allow(dead_code)]
    ihl_version: u8,
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
    #[allow(dead_code)]
    saddr: u32,
    #[allow(dead_code)]
    daddr: u32,
}

const _: () = assert!(size_of::<IpHdr>() == 20);

// struct ipv6hdr (linux/ipv6.h) — packed, same alignment reasoning as IpHdr.
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
    #[allow(dead_code)]
    saddr: [u32; 4],
    #[allow(dead_code)]
    daddr: [u32; 4],
}

const _: () = assert!(size_of::<Ipv6Hdr>() == 40);

// struct tcphdr (linux/tcp.h) — packed, same alignment reasoning as IpHdr.
// `flags` packs the little-endian bitfield res1:4,doff:4,fin:1,syn:1,
// rst:1,psh:1,ack:1,urg:1,ece:1,cwr:1 (fin is bit 8, syn is bit 9, ack is
// bit 12 counting from the LSB, matching __LITTLE_ENDIAN_BITFIELD layout).
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct TcpHdr {
    #[allow(dead_code)]
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

const _: () = assert!(size_of::<TcpHdr>() == 20);

// struct udphdr (linux/udp.h) — packed, same alignment reasoning as IpHdr.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct UdpHdr {
    #[allow(dead_code)]
    source: u16,
    dest: u16,
    #[allow(dead_code)]
    len: u16,
    #[allow(dead_code)]
    check: u16,
}

const _: () = assert!(size_of::<UdpHdr>() == 8);

/// UAPI struct sk_reuseport_md (linux/bpf.h). data/data_end/sk/migrating_sk
/// are __bpf_md_ptr unions (pointer overlaid with u64), represented as u64.
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct sk_reuseport_md {
    pub data: u64,
    pub data_end: u64,
    pub len: u32,
    #[allow(dead_code)]
    pub eth_protocol: u32,
    pub ip_protocol: u32,
    #[allow(dead_code)]
    pub bind_inany: u32,
    #[allow(dead_code)]
    pub hash: u32,
    pub sk: u64,
    #[allow(dead_code)]
    pub migrating_sk: u64,
}

#[no_mangle]
static mut sk_cookie_seen: u64 = 0;
#[no_mangle]
static mut reuseport_executed: u64 = 0;

// union { struct tcphdr tcp; struct udphdr udp; } headers; sized to the
// larger member (tcphdr, 20 bytes); never read by the userspace harness, so
// only its size (used by the memcpy/memcmp below) needs to match the C
// original.
#[no_mangle]
static mut headers: [u8; 20] = [0u8; 20];

#[link_section = ".rodata"]
#[no_mangle]
static dest_port: u16 = 0;

const SOCKMAP: usize = 15;

#[link_section = ".maps"]
#[no_mangle]
static sk_map: BpfMap<u32, u64, { SOCKMAP }, 1> = BpfMap::new();

#[link_section = "sk_reuseport"]
#[no_mangle]
extern "C" fn reuse_accept(ctx: *const sk_reuseport_md) -> i32 {
    unsafe { reuseport_executed += 1 };

    let ip_protocol = vload!((*ctx).ip_protocol);
    let data = vload!((*ctx).data) as usize;
    let data_end = vload!((*ctx).data_end) as usize;

    if ip_protocol == IPPROTO_TCP {
        if data + size_of::<TcpHdr>() > data_end {
            return SK_DROP;
        }
        let eq = unsafe {
            vmemeq(
                core::ptr::addr_of!(headers) as *const u8,
                data as *const u8,
                size_of::<TcpHdr>(),
            )
        };
        if !eq {
            return SK_DROP;
        }
    } else if ip_protocol == IPPROTO_UDP {
        if data + size_of::<UdpHdr>() > data_end {
            return SK_DROP;
        }
        let eq = unsafe {
            vmemeq(
                core::ptr::addr_of!(headers) as *const u8,
                data as *const u8,
                size_of::<UdpHdr>(),
            )
        };
        if !eq {
            return SK_DROP;
        }
    } else {
        return SK_DROP;
    }

    let sk = vload!((*ctx).sk) as *mut c_void;
    unsafe { sk_cookie_seen = bpf_get_socket_cookie(sk as *const c_void) };
    SK_PASS
}

#[link_section = "sk_reuseport"]
#[no_mangle]
extern "C" fn reuse_drop(_ctx: *const sk_reuseport_md) -> i32 {
    unsafe { reuseport_executed += 1 };
    unsafe { sk_cookie_seen = 0 };
    SK_DROP
}

#[inline(always)]
fn assign_sk(skb: *const __sk_buff) -> i32 {
    let zero: u32 = 0;
    let sk = bpf_map_lookup_elem(&sk_map, &zero);
    if sk.is_null() {
        return TC_ACT_SHOT;
    }
    let ret = bpf_sk_assign(skb as *const core::ffi::c_void, sk, 0);
    bpf_sk_release(sk);
    if ret != 0 {
        TC_ACT_SHOT
    } else {
        TC_ACT_OK
    }
}

// C declares this `static bool`, so every `return <int>;` inside it is
// implicitly truncated to 0/1 by the C _Bool conversion before tc_main
// forwards it as its own int return — reproduced here explicitly rather
// than returning the raw TC_ACT_* / assign_sk() values.
#[inline(always)]
fn maybe_assign_tcp(skb: *const __sk_buff, th: *const TcpHdr) -> i32 {
    let data_end = vload!((*skb).data_end) as usize;
    if th as usize + size_of::<TcpHdr>() > data_end {
        return 1; // (bool)TC_ACT_SHOT
    }

    let flags = unsafe { (*th).flags };
    let syn = (flags >> 9) & 1;
    let ack = (flags >> 12) & 1;
    let dest = unsafe { (*th).dest };

    if syn == 0 || ack != 0 || dest != htons(unsafe { core::ptr::read_volatile(&dest_port) }) {
        return 0; // (bool)TC_ACT_OK
    }

    unsafe {
        vcopy(
            core::ptr::addr_of_mut!(headers) as *mut u8,
            th as *const u8,
            size_of::<TcpHdr>(),
        );
    }

    if assign_sk(skb) != 0 {
        1
    } else {
        0
    }
}

#[inline(always)]
fn maybe_assign_udp(skb: *const __sk_buff, uh: *const UdpHdr) -> i32 {
    let data_end = vload!((*skb).data_end) as usize;
    if uh as usize + size_of::<UdpHdr>() > data_end {
        return 1; // (bool)TC_ACT_SHOT
    }

    let dest = unsafe { (*uh).dest };
    if dest != htons(unsafe { core::ptr::read_volatile(&dest_port) }) {
        return 0; // (bool)TC_ACT_OK
    }

    unsafe {
        vcopy(
            core::ptr::addr_of_mut!(headers) as *mut u8,
            uh as *const u8,
            size_of::<UdpHdr>(),
        );
    }

    if assign_sk(skb) != 0 {
        1
    } else {
        0
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn tc_main(skb: *const __sk_buff) -> i32 {
    let data_end = vload!((*skb).data_end) as usize;
    let data = vload!((*skb).data) as usize;

    if data + size_of::<EthHdr>() > data_end {
        return TC_ACT_SHOT;
    }
    let eth = data as *const EthHdr;

    if unsafe { (*eth).h_proto } == htons(ETH_P_IP) {
        let iph_off = data + size_of::<EthHdr>();
        if iph_off + size_of::<IpHdr>() > data_end {
            return TC_ACT_SHOT;
        }
        let iph = iph_off as *const IpHdr;
        let protocol = unsafe { (*iph).protocol } as u32;
        let th_off = iph_off + size_of::<IpHdr>();

        if protocol == IPPROTO_TCP {
            maybe_assign_tcp(skb, th_off as *const TcpHdr)
        } else if protocol == IPPROTO_UDP {
            maybe_assign_udp(skb, th_off as *const UdpHdr)
        } else {
            TC_ACT_SHOT
        }
    } else {
        let ip6h_off = data + size_of::<EthHdr>();
        if ip6h_off + size_of::<Ipv6Hdr>() > data_end {
            return TC_ACT_SHOT;
        }
        let ip6h = ip6h_off as *const Ipv6Hdr;
        let nexthdr = unsafe { (*ip6h).nexthdr } as u32;
        let th_off = ip6h_off + size_of::<Ipv6Hdr>();

        if nexthdr == IPPROTO_TCP {
            maybe_assign_tcp(skb, th_off as *const TcpHdr)
        } else if nexthdr == IPPROTO_UDP {
            maybe_assign_udp(skb, th_off as *const UdpHdr)
        } else {
            TC_ACT_SHOT
        }
    }
}

// The C source names its license global `LICENSE` (not the crate macro's
// default `_license`); the internalize keep-list is derived from the C
// object's global symbol names, so without a matching symbol here the
// license section is silently DCE'd away and every GPL-only helper call is
// rejected as non-GPL.
#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 4] = bpf_rs_core::__lic_bytes::<4>("GPL");

bpf_object!("GPL");
