// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/xdp_features.c
// (bpf-rs-core idiom). The xdp_features user program (test_xdp_features.sh:
// two veths in two netns, a tester and a DUT) sets `tester_addr`/`dut_addr`
// in .rodata, attaches one of the DUT programs and the tester ones, sends
// echo packets (UDP port 12346, a CMD_ECHO TLV) and reads the `stats`/
// `dut_stats` counters; the tp_btf programs count exceptions and cpumap
// deliveries. NO-ORACLE: the shell test is not a prog_tests consumer.
//
// `struct in6_addr` is the C's: a union member `in6_u` (named, as the
// kernel's) of the three address views, anonymous in BTF (`// BTF_ANON:`);
// `tester_addr`/`dut_addr` are `const volatile`, read word by word. The
// `__always_inline` helpers are inlined into every program as in the C;
// the packet walk keeps the C's pointer comparisons as usize arithmetic
// (xdp_metadata.rs); the 6-byte MAC copies are unaligned [u8; 6] moves.
// BTF_ANON: in6_u

#![allow(non_upper_case_globals)]

use core::ptr::{addr_of, addr_of_mut, read_unaligned, read_volatile, write_unaligned};

use bpf_rs_core::helpers::{bpf_map_lookup_elem, bpf_redirect_map, sync_fetch_and_add_u32};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::{bpf_map, bpf_object, vload};

const XDP_ABORTED: i32 = 0;
const XDP_DROP: i32 = 1;
const XDP_PASS: i32 = 2;
const XDP_TX: i32 = 3;

const EINVAL: i32 = 22;

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const IPPROTO_UDP: u8 = 17;
const ETH_ALEN: usize = 6;

/* xdp_features.h */
const CMD_ECHO: u16 = 2;
const DUT_ECHO_PORT: u16 = 12346;

#[inline(always)]
fn htons(x: u16) -> u16 {
    x.to_be()
}

/// UAPI struct xdp_md (linux/bpf.h).
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct xdp_md {
    pub data: u32,
    pub data_end: u32,
    pub data_meta: u32,
    pub ingress_ifindex: u32,
    pub rx_queue_index: u32,
    pub egress_ifindex: u32,
}

#[repr(C, packed)]
struct ethhdr {
    h_dest: [u8; ETH_ALEN],
    h_source: [u8; ETH_ALEN],
    h_proto: u16,
}

#[repr(C, packed)]
struct iphdr {
    ihl_version: u8,
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
struct ipv6hdr {
    version_priority: u8,
    flow_lbl: [u8; 3],
    payload_len: u16,
    nexthdr: u8,
    hop_limit: u8,
    saddr: [u32; 4],
    daddr: [u32; 4],
}

#[repr(C, packed)]
struct udphdr {
    source: u16,
    dest: u16,
    len: u16,
    check: u16,
}

#[repr(C, packed)]
struct tlv_hdr {
    r#type: u16,
    len: u16,
}

#[allow(non_camel_case_types)]
#[repr(C)]
union in6_u {
    u6_addr8: [u8; 16],
    u6_addr16: [u16; 8],
    u6_addr32: [u32; 4],
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct in6_addr {
    in6_u: in6_u,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct xdp_cpumap_stats {
    redirect: u32,
    pass: u32,
    drop: u32,
}

#[link_section = ".maps"]
#[no_mangle]
static stats: BpfMap<u32, u32, { maps::ARRAY }, 1> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static dut_stats: BpfMap<u32, u32, { maps::ARRAY }, 1> = BpfMap::new();

bpf_map! {
    cpu_map {
        r#type: *const [i32; 16],      // BPF_MAP_TYPE_CPUMAP
        key_size: *const [i32; 4],     // sizeof(__u32)
        value_size: *const [i32; 8],   // sizeof(struct bpf_cpumap_val)
        max_entries: *const [i32; 1],
    }
}

bpf_map! {
    dev_map {
        r#type: *const [i32; 14],      // BPF_MAP_TYPE_DEVMAP
        key_size: *const [i32; 4],     // sizeof(__u32)
        value_size: *const [i32; 8],   // sizeof(struct bpf_devmap_val)
        max_entries: *const [i32; 1],
    }
}

#[link_section = ".rodata"]
#[no_mangle]
static tester_addr: in6_addr = in6_addr { in6_u: in6_u { u6_addr32: [0; 4] } };
#[link_section = ".rodata"]
#[no_mangle]
static dut_addr: in6_addr = in6_addr { in6_u: in6_u { u6_addr32: [0; 4] } };

/// `addr.s6_addr32[i]` of one of the two `const volatile` addresses
#[inline(always)]
fn addr_word(addr: *const in6_addr, i: usize) -> u32 {
    unsafe { read_volatile((addr as *const u32).add(i)) }
}

#[inline(always)]
fn xdp_process_echo_packet(xdp: *const xdp_md, dut: bool) -> i32 {
    let data_end = vload!((*xdp).data_end) as usize;
    let data = vload!((*xdp).data) as usize;
    let eh = data as *const ethhdr;
    let uh: usize;

    if data + core::mem::size_of::<ethhdr>() > data_end {
        return -EINVAL;
    }

    let h_proto = unsafe { read_unaligned(addr_of!((*eh).h_proto)) };
    if h_proto == htons(ETH_P_IP) {
        let ih_addr = data + core::mem::size_of::<ethhdr>();
        let ih = ih_addr as *const iphdr;
        let saddr = if dut { addr_word(addr_of!(tester_addr), 3) } else { addr_word(addr_of!(dut_addr), 3) };
        let daddr = if dut { addr_word(addr_of!(dut_addr), 3) } else { addr_word(addr_of!(tester_addr), 3) };

        if ih_addr + core::mem::size_of::<iphdr>() > data_end {
            return -EINVAL;
        }

        if saddr != unsafe { read_unaligned(addr_of!((*ih).saddr)) } {
            return -EINVAL;
        }
        if daddr != unsafe { read_unaligned(addr_of!((*ih).daddr)) } {
            return -EINVAL;
        }
        if unsafe { read_unaligned(addr_of!((*ih).protocol)) } != IPPROTO_UDP {
            return -EINVAL;
        }

        uh = ih_addr + core::mem::size_of::<iphdr>();
    } else if h_proto == htons(ETH_P_IPV6) {
        let (saddr_p, daddr_p) = if dut {
            (addr_of!(tester_addr), addr_of!(dut_addr))
        } else {
            (addr_of!(dut_addr), addr_of!(tester_addr))
        };
        let saddr = [addr_word(saddr_p, 0), addr_word(saddr_p, 1), addr_word(saddr_p, 2), addr_word(saddr_p, 3)];
        let daddr = [addr_word(daddr_p, 0), addr_word(daddr_p, 1), addr_word(daddr_p, 2), addr_word(daddr_p, 3)];
        let ih6_addr = data + core::mem::size_of::<ethhdr>();
        let ih6 = ih6_addr as *const ipv6hdr;

        if ih6_addr + core::mem::size_of::<ipv6hdr>() > data_end {
            return -EINVAL;
        }

        /* ipv6_addr_equal(saddr, ih6->saddr) */
        let pkt_saddr = unsafe { addr_of!((*ih6).saddr) } as *const u32;
        if !(saddr[0] == unsafe { read_unaligned(pkt_saddr) }
            && saddr[1] == unsafe { read_unaligned(pkt_saddr.add(1)) }
            && saddr[2] == unsafe { read_unaligned(pkt_saddr.add(2)) }
            && saddr[3] == unsafe { read_unaligned(pkt_saddr.add(3)) })
        {
            return -EINVAL;
        }
        let pkt_daddr = unsafe { addr_of!((*ih6).daddr) } as *const u32;
        if !(daddr[0] == unsafe { read_unaligned(pkt_daddr) }
            && daddr[1] == unsafe { read_unaligned(pkt_daddr.add(1)) }
            && daddr[2] == unsafe { read_unaligned(pkt_daddr.add(2)) }
            && daddr[3] == unsafe { read_unaligned(pkt_daddr.add(3)) })
        {
            return -EINVAL;
        }
        if unsafe { read_unaligned(addr_of!((*ih6).nexthdr)) } != IPPROTO_UDP {
            return -EINVAL;
        }

        uh = ih6_addr + core::mem::size_of::<ipv6hdr>();
    } else {
        return -EINVAL;
    }

    if uh + core::mem::size_of::<udphdr>() > data_end {
        return -EINVAL;
    }

    let udp = uh as *const udphdr;
    let port = if dut {
        unsafe { read_unaligned(addr_of!((*udp).dest)) }
    } else {
        unsafe { read_unaligned(addr_of!((*udp).source)) }
    };
    if port != htons(DUT_ECHO_PORT) {
        return -EINVAL;
    }

    let tlv_addr = uh + core::mem::size_of::<udphdr>();
    if tlv_addr + core::mem::size_of::<tlv_hdr>() > data_end {
        return -EINVAL;
    }

    let tlv = tlv_addr as *const tlv_hdr;
    if htons(unsafe { read_unaligned(addr_of!((*tlv).r#type)) }) == CMD_ECHO {
        0
    } else {
        -EINVAL
    }
}

#[inline(always)]
fn xdp_update_stats(xdp: *const xdp_md, tx: bool, dut: bool) -> i32 {
    let key: u32 = 0;

    if xdp_process_echo_packet(xdp, tx) != 0 {
        return -EINVAL;
    }

    let val = if dut {
        bpf_map_lookup_elem(&dut_stats, &key)
    } else {
        bpf_map_lookup_elem(&stats, &key)
    } as *mut u32;

    if !val.is_null() {
        sync_fetch_and_add_u32(val, 1);
    }

    0
}

/* Tester */
#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_tester_check_tx(xdp: *const xdp_md) -> i32 {
    xdp_update_stats(xdp, true, false);

    XDP_PASS
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_tester_check_rx(xdp: *const xdp_md) -> i32 {
    xdp_update_stats(xdp, false, false);

    XDP_PASS
}

/* DUT */
#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_do_pass(xdp: *const xdp_md) -> i32 {
    xdp_update_stats(xdp, true, true);

    XDP_PASS
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_do_drop(xdp: *const xdp_md) -> i32 {
    if xdp_update_stats(xdp, true, true) != 0 {
        return XDP_PASS;
    }

    XDP_DROP
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_do_aborted(xdp: *const xdp_md) -> i32 {
    if xdp_process_echo_packet(xdp, true) != 0 {
        return XDP_PASS;
    }

    XDP_ABORTED
}

/// swap the ethernet addresses: the C's three __builtin_memcpy of ETH_ALEN
#[inline(always)]
fn swap_mac(eh: *mut ethhdr) {
    unsafe {
        let tmp_mac: [u8; ETH_ALEN] = read_unaligned(addr_of!((*eh).h_source));
        write_unaligned(addr_of_mut!((*eh).h_source), read_unaligned(addr_of!((*eh).h_dest)));
        write_unaligned(addr_of_mut!((*eh).h_dest), tmp_mac);
    }
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_do_tx(xdp: *const xdp_md) -> i32 {
    let data = vload!((*xdp).data) as usize;
    let eh = data as *mut ethhdr;

    if xdp_update_stats(xdp, true, true) != 0 {
        return XDP_PASS;
    }

    swap_mac(eh);

    XDP_TX
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_do_redirect(xdp: *const xdp_md) -> i32 {
    if xdp_process_echo_packet(xdp, true) != 0 {
        return XDP_PASS;
    }

    bpf_redirect_map(&cpu_map, 0, 0) as i32
}

#[link_section = "tp_btf/xdp_exception"]
#[no_mangle]
extern "C" fn xdp_exception(_ctx: *const u64) -> i32 {
    let key: u32 = 0;

    let val = bpf_map_lookup_elem(&dut_stats, &key) as *mut u32;
    if !val.is_null() {
        sync_fetch_and_add_u32(val, 1);
    }

    0
}

#[link_section = "tp_btf/xdp_cpumap_kthread"]
#[no_mangle]
extern "C" fn tp_xdp_cpumap_kthread(_ctx: *const u64) -> i32 {
    let key: u32 = 0;

    let val = bpf_map_lookup_elem(&dut_stats, &key) as *mut u32;
    if !val.is_null() {
        sync_fetch_and_add_u32(val, 1);
    }

    0
}

#[link_section = "xdp/cpumap"]
#[no_mangle]
extern "C" fn xdp_do_redirect_cpumap(xdp: *const xdp_md) -> i32 {
    let data = vload!((*xdp).data) as usize;
    let eh = data as *mut ethhdr;

    if xdp_process_echo_packet(xdp, true) != 0 {
        return XDP_PASS;
    }

    swap_mac(eh);

    bpf_redirect_map(&dev_map, 0, 0) as i32
}

bpf_object!("GPL");
