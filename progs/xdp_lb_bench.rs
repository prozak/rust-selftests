// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

// Direct translation of tools/testing/selftests/bpf/progs/xdp_lb_bench.c
// (bpf-rs-core idiom): the XDP load balancer that benchs/bench_xdp_lb.c
// drives with bpf_prog_test_run (`bench -a xdp-lb --scenario ...`). The
// driver validates the output packet byte for byte and the per-CPU
// counters, so the encapsulation and the stats updates are the oracle.
//
// BENCH_BPF_LOOP (bench_bpf_timing.bpf.h) is written out: `batch_iters`
// timed iterations of a may_goto-guarded loop, each undone by the reset
// block (strip the encapsulation, randomize the source), one sample
// recorded, then one untimed iteration whose result is the return value.
// The volatile globals (`flow_mask`, `cold_lru`, `batch_iters`,
// `timing_enabled`) are read through read_volatile at every C read site;
// the .bss order is the C's (`// C_LAYOUT:`). `timing_samples` stays
// `u64`: the driver's bench.h types it unsigned long long.
//
// Like clang, `process_packet` (the C's __noinline) and the two jhash
// helpers are out-of-line .text subprograms; clang dropped the constant
// `initval` argument of both hashes, so they take the folded value here.
// Every fixed-size copy (MAC addresses, in6_addr words, the saved ethhdr)
// is a volatile element loop and every zero-init an explicit store: an
// aggregate copy or memset becomes a `bpf_arena_memcpy`/`memset` kfunc
// call, which a plain XDP program cannot use.
// C_LAYOUT: .bss

use core::ffi::c_void;
use core::ptr::{addr_of, addr_of_mut, null_mut, read_volatile, write_volatile};

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_get_prandom_u32, bpf_get_smp_processor_id, bpf_ktime_get_ns, bpf_map_lookup_elem,
    bpf_map_update_elem, bpf_xdp_adjust_head,
};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::vload;

const XDP_DROP: i32 = 1;
const XDP_PASS: i32 = 2;
const XDP_TX: i32 = 3;

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;

const IPPROTO_IPIP: u8 = 4;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_IPV6: u8 = 41;
const IPPROTO_FRAGMENT: u8 = 44;

// xdp_lb_bench_common.h
const F_IPV6: u8 = 1 << 0;
const F_LRU_BYPASS: u32 = 1 << 1;

const CH_RING_SIZE: u32 = 65537;
const MAX_VIPS: u32 = 16;
const CH_RINGS_SIZE: usize = (MAX_VIPS * CH_RING_SIZE) as usize;
const MAX_REALS: usize = 512;
const DEFAULT_LRU_SIZE: usize = 100000;
const ONE_SEC: u64 = 1000000000;
const MAX_CONN_RATE: u64 = 100000000;
const LRU_UDP_TIMEOUT: u64 = 30000000000;
const PCKT_FRAGMENTED: u16 = 0x3FFF;
const KNUTH_HASH_MULT: u32 = 2654435761;
const IPIP_V4_PREFIX: u32 = 4268;
const IPIP_V6_PREFIX1: u32 = 1;
const IPIP_V6_PREFIX2: u32 = 0;
const IPIP_V6_PREFIX3: u32 = 0;

const STATS_LRU: u32 = MAX_VIPS + 0;
const STATS_XDP_TX: u32 = MAX_VIPS + 1;
const STATS_XDP_PASS: u32 = MAX_VIPS + 2;
const STATS_XDP_DROP: u32 = MAX_VIPS + 3;
const STATS_NEW_CONN: u32 = MAX_VIPS + 4;
const STATS_LRU_MISS: u32 = MAX_VIPS + 5;
const STATS_SIZE: usize = (MAX_VIPS + 6) as usize;

// bench_bpf_timing.bpf.h
const BENCH_NR_SAMPLES: usize = 4096;
const BENCH_NR_CPUS: usize = 256;
const BENCH_CPU_MASK: u32 = (BENCH_NR_CPUS - 1) as u32;

const JHASH_INITVAL: u32 = 0xdeadbeef;

// ---- UAPI header views ------------------------------------------------

/// UAPI struct xdp_md (linux/bpf.h).
#[repr(C)]
pub struct xdp_md {
    pub data: u32,
    pub data_end: u32,
    pub data_meta: u32,
    pub ingress_ifindex: u32,
    pub rx_queue_index: u32,
    pub egress_ifindex: u32,
}

// struct ethhdr (linux/if_ether.h).
#[repr(C)]
struct ethhdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

// struct iphdr (linux/ip.h); ihl low nibble, version high nibble.
#[repr(C)]
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

// struct ipv6hdr (linux/ipv6.h); priority low nibble, version high nibble.
#[repr(C)]
struct ipv6hdr {
    priority_version: u8,
    flow_lbl: [u8; 3],
    payload_len: u16,
    nexthdr: u8,
    hop_limit: u8,
    saddr: [u32; 4],
    daddr: [u32; 4],
}

// struct udphdr (linux/udp.h).
#[repr(C)]
struct udphdr {
    source: u16,
    dest: u16,
    len: u16,
    check: u16,
}

// struct tcphdr (linux/tcp.h); byte 13 is cwr,ece,urg,ack,psh,rst,syn,fin
// from MSB to LSB.
#[repr(C)]
struct tcphdr {
    source: u16,
    dest: u16,
    seq: u32,
    ack_seq: u32,
    doff_res1: u8,
    flags: u8,
    window: u16,
    check: u16,
    urg_ptr: u16,
}

const TCPF_SYN: u8 = 1 << 1;
const TCPF_RST: u8 = 1 << 2;

// ---- xdp_lb_bench_common.h types ---------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
union flow_key_src {
    src: u32,
    srcv6: [u32; 4],
}

#[repr(C)]
#[derive(Clone, Copy)]
union flow_key_dst {
    dst: u32,
    dstv6: [u32; 4],
}

#[repr(C)]
#[derive(Clone, Copy)]
union flow_key_ports {
    ports: u32,
    port16: [u16; 2],
}

#[repr(C)]
struct flow_key {
    src: flow_key_src,
    dst: flow_key_dst,
    ports: flow_key_ports,
    proto: u8,
    pad: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy)]
union vip_definition_addr {
    vip: u32,
    vipv6: [u32; 4],
}

#[repr(C)]
struct vip_definition {
    addr: vip_definition_addr,
    port: u16,
    proto: u8,
    pad: u8,
}

#[repr(C)]
struct vip_meta {
    flags: u32,
    vip_num: u32,
}

// The C struct has a 4-byte hole after `pos`; explicit here so the
// `= { .pos = real_pos }` zeroing covers it.
#[repr(C)]
struct real_pos_lru {
    pos: u32,
    _pad: u32,
    atime: u64,
}

#[repr(C)]
struct real_definition {
    dst: u32,
    dstv6: [u32; 4],
    flags: u8,
    _pad: [u8; 3],
}

#[repr(C)]
struct lb_stats {
    v1: u64,
    v2: u64,
}

#[repr(C)]
struct ctl_value {
    mac: [u8; 6],
    pad: [u8; 2],
}

// ---- maps --------------------------------------------------------------

#[link_section = ".maps"]
#[no_mangle]
static vip_map: BpfMap<vip_definition, vip_meta, { maps::HASH }, 64> = BpfMap::new();

// The C declares the inner map's type with a name, `struct lru_inner_map`,
// used both for the standalone `lru_inner` map and as the element type of
// `lru_mapping`; member order type, key, value, max_entries.
#[repr(C)]
struct lru_inner_map {
    r#type: *const [i32; maps::LRU_HASH],
    key: *const flow_key,
    value: *const real_pos_lru,
    max_entries: *const [i32; DEFAULT_LRU_SIZE],
}
unsafe impl Sync for lru_inner_map {}

#[link_section = ".maps"]
#[no_mangle]
static lru_inner: lru_inner_map = lru_inner_map {
    r#type: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
    max_entries: core::ptr::null(),
};

#[repr(C)]
struct lru_mapping_def {
    r#type: *const [i32; 12], // BPF_MAP_TYPE_ARRAY_OF_MAPS
    key: *const u32,
    value: *const u32,
    max_entries: *const [i32; BENCH_NR_CPUS],
    values: [*const lru_inner_map; 0],
}
unsafe impl Sync for lru_mapping_def {}

#[link_section = ".maps"]
#[no_mangle]
static lru_mapping: lru_mapping_def = lru_mapping_def {
    r#type: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
    max_entries: core::ptr::null(),
    values: [],
};

#[link_section = ".maps"]
#[no_mangle]
static ch_rings: BpfMap<u32, u32, { maps::ARRAY }, CH_RINGS_SIZE> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static reals: BpfMap<u32, real_definition, { maps::ARRAY }, MAX_REALS> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static stats: BpfMap<u32, lb_stats, { maps::PERCPU_ARRAY }, STATS_SIZE> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static reals_stats: BpfMap<u32, lb_stats, { maps::PERCPU_ARRAY }, MAX_REALS> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static ctl_array: BpfMap<u32, ctl_value, { maps::ARRAY }, 1> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static vip_miss_stats: BpfMap<u32, vip_definition, { maps::ARRAY }, 1> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static lru_miss_stats: BpfMap<u32, u32, { maps::PERCPU_ARRAY }, MAX_REALS> = BpfMap::new();

// ---- globals (.bss, the C's order) --------------------------------------

#[no_mangle]
static mut flow_mask: u32 = 0; // volatile
#[no_mangle]
static mut cold_lru: u32 = 0; // volatile
#[no_mangle]
static mut batch_gen: u32 = 0;
#[no_mangle]
static mut batch_iters: u32 = 0; // volatile
#[no_mangle]
static mut timing_samples: [[u64; BENCH_NR_SAMPLES]; BENCH_NR_CPUS] =
    [[0; BENCH_NR_SAMPLES]; BENCH_NR_CPUS];
#[no_mangle]
static mut timing_idx: [u32; BENCH_NR_CPUS] = [0; BENCH_NR_CPUS];
#[no_mangle]
static mut timing_enabled: u32 = 0; // volatile

// ---- bench_bpf_timing.bpf.h ---------------------------------------------

// bpf_may_goto.h's `can_loop`: the may_goto instruction, which the verifier
// lets the loop take only while it still has budget.
#[inline(always)]
unsafe fn can_loop() -> bool {
    let mut ret = true;
    core::arch::asm!(
        "1:",
        ".byte 0xe5",
        ".byte 0",
        ".long (({0} - 1b - 8) / 8) & 0xffff",
        ".short 0",
        label { ret = false; },
    );
    ret
}

#[inline(always)]
fn bench_record_sample(elapsed_ns: u64) {
    unsafe {
        if read_volatile(addr_of!(timing_enabled)) == 0 {
            return;
        }
        let cpu = bpf_get_smp_processor_id() & BENCH_CPU_MASK;
        let idx = *addr_of!(timing_idx).cast::<u32>().add(cpu as usize);
        if idx >= BENCH_NR_SAMPLES as u32 {
            return;
        }
        *addr_of_mut!(timing_samples)
            .cast::<u64>()
            .add(cpu as usize * BENCH_NR_SAMPLES + idx as usize) = elapsed_ns;
        *addr_of_mut!(timing_idx).cast::<u32>().add(cpu as usize) = idx + 1;
    }
}

// ---- byte helpers --------------------------------------------------------

#[inline(always)]
fn byte_add(p: *mut u8, n: usize) -> *mut u8 {
    unsafe { p.add(n) }
}

#[inline(always)]
unsafe fn vcopy8(dst: *mut u8, src: *const u8, len: usize) {
    let mut i = 0usize;
    while i < len {
        write_volatile(dst.add(i), read_volatile(src.add(i)));
        i += 1;
    }
}

#[inline(always)]
unsafe fn vcopy32(dst: *mut u32, src: *const u32, words: usize) {
    let mut i = 0usize;
    while i < words {
        write_volatile(dst.add(i), read_volatile(src.add(i)));
        i += 1;
    }
}

// 4-byte stores: the key structs are 4-aligned on the stack, and the
// verifier rejects a misaligned 8-byte stack store.
#[inline(always)]
unsafe fn vzero32(dst: *mut u32, words: usize) {
    let mut i = 0usize;
    while i < words {
        write_volatile(dst.add(i), 0);
        i += 1;
    }
}

// ---- jhash ---------------------------------------------------------------

#[inline(always)]
fn rol32(word: u32, shift: u32) -> u32 {
    word.rotate_left(shift)
}

#[inline(always)]
fn jhash_mix(a: &mut u32, b: &mut u32, c: &mut u32) {
    *a = a.wrapping_sub(*c);
    *a ^= rol32(*c, 4);
    *c = c.wrapping_add(*b);
    *b = b.wrapping_sub(*a);
    *b ^= rol32(*a, 6);
    *a = a.wrapping_add(*c);
    *c = c.wrapping_sub(*b);
    *c ^= rol32(*b, 8);
    *b = b.wrapping_add(*a);
    *a = a.wrapping_sub(*c);
    *a ^= rol32(*c, 16);
    *c = c.wrapping_add(*b);
    *b = b.wrapping_sub(*a);
    *b ^= rol32(*a, 19);
    *a = a.wrapping_add(*c);
    *c = c.wrapping_sub(*b);
    *c ^= rol32(*b, 4);
    *b = b.wrapping_add(*a);
}

#[inline(always)]
fn jhash_final(a: &mut u32, b: &mut u32, c: &mut u32) {
    *c ^= *b;
    *c = c.wrapping_sub(rol32(*b, 14));
    *a ^= *c;
    *a = a.wrapping_sub(rol32(*c, 11));
    *b ^= *a;
    *b = b.wrapping_sub(rol32(*a, 25));
    *c ^= *b;
    *c = c.wrapping_sub(rol32(*b, 16));
    *a ^= *c;
    *a = a.wrapping_sub(rol32(*c, 4));
    *b ^= *a;
    *b = b.wrapping_sub(rol32(*a, 14));
    *c ^= *b;
    *c = c.wrapping_sub(rol32(*b, 24));
}

/// jhash_2words(a, b, CH_RING_SIZE): clang kept it out of line and folded
/// the constant initval, as here.
#[inline(never)]
#[export_name = "jhash_2words"]
extern "C" fn jhash_2words(a: u32, b: u32) -> u32 {
    let initval = CH_RING_SIZE.wrapping_add(JHASH_INITVAL).wrapping_add(2 << 2);
    let mut a = a.wrapping_add(initval);
    let mut b = b.wrapping_add(initval);
    let mut c = initval;
    jhash_final(&mut a, &mut b, &mut c);
    c
}

/// jhash2_4words(k, MAX_VIPS): clang kept it out of line and folded the
/// constant initval, as here.
#[inline(never)]
#[export_name = "jhash2_4words"]
extern "C" fn jhash2_4words(k: *const u32) -> u32 {
    let mut a = JHASH_INITVAL.wrapping_add(4 << 2).wrapping_add(MAX_VIPS);
    let mut b = a;
    let mut c = a;

    unsafe {
        a = a.wrapping_add(*k);
        b = b.wrapping_add(*k.add(1));
        c = c.wrapping_add(*k.add(2));
    }
    jhash_mix(&mut a, &mut b, &mut c);

    a = a.wrapping_add(unsafe { *k.add(3) });
    jhash_final(&mut a, &mut b, &mut c);

    c
}

// ---- encapsulation ------------------------------------------------------

#[inline(always)]
fn ipv4_csum(iph: *mut iphdr) {
    let next_iph = iph as *const u16;
    let mut csum: u32 = 0;

    let mut i = 0usize;
    while i < core::mem::size_of::<iphdr>() >> 1 {
        csum = csum.wrapping_add(unsafe { *next_iph.add(i) } as u32);
        i += 1;
    }

    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    unsafe { (*iph).check = !csum as u16 };
}

#[inline(always)]
fn create_encap_ipv4_src(port: u16, src: u32) -> u32 {
    let mut ip_suffix: u32 = port.to_be() as u32;

    ip_suffix <<= 16;
    ip_suffix ^= src;
    (0xFFFF0000 & ip_suffix) | IPIP_V4_PREFIX
}

#[inline(always)]
fn create_encap_ipv6_src(port: u16, src: u32, saddr: &mut [u32; 4]) {
    saddr[0] = IPIP_V6_PREFIX1;
    saddr[1] = IPIP_V6_PREFIX2;
    saddr[2] = IPIP_V6_PREFIX3;
    saddr[3] = src ^ port as u32;
}

/*
 * old_eth MUST be read BEFORE writing the outer header because
 * bpf_xdp_adjust_head makes them overlap.
 */
#[inline(always)]
fn encap_v4(xdp: *mut xdp_md, saddr: u32, daddr: u32, payload_len: u16, dst_mac: *const u8) -> i32 {
    if bpf_xdp_adjust_head(xdp, -(core::mem::size_of::<iphdr>() as i32)) != 0 {
        return -1;
    }

    let data = vload!((*xdp).data) as usize as *mut u8;
    let data_end = vload!((*xdp).data_end) as usize as *mut u8;

    let new_eth = data as *mut ethhdr;
    let iph = byte_add(data, core::mem::size_of::<ethhdr>()) as *mut iphdr;
    let old_eth = byte_add(data, core::mem::size_of::<iphdr>()) as *mut ethhdr;

    if byte_add(new_eth as *mut u8, core::mem::size_of::<ethhdr>()) > data_end
        || byte_add(old_eth as *mut u8, core::mem::size_of::<ethhdr>()) > data_end
        || byte_add(iph as *mut u8, core::mem::size_of::<iphdr>()) > data_end
    {
        return -1;
    }

    unsafe {
        vcopy8((*new_eth).h_source.as_mut_ptr(), (*old_eth).h_dest.as_ptr(), 6);
        vcopy8((*new_eth).h_dest.as_mut_ptr(), dst_mac, 6);
        (*new_eth).h_proto = ETH_P_IP.to_be();

        // __builtin_memset(iph, 0, sizeof(*iph)) followed by the field
        // stores: every byte of the header is written below.
        (*iph).ihl_version = (4 << 4) | (core::mem::size_of::<iphdr>() >> 2) as u8;
        (*iph).tos = 0;
        (*iph).tot_len = (payload_len.wrapping_add(core::mem::size_of::<iphdr>() as u16)).to_be();
        (*iph).id = 0;
        (*iph).frag_off = 0;
        (*iph).ttl = 64;
        (*iph).protocol = IPPROTO_IPIP;
        (*iph).check = 0;
        (*iph).saddr = saddr;
        (*iph).daddr = daddr;
    }
    ipv4_csum(iph);

    0
}

#[inline(always)]
fn encap_v6(
    xdp: *mut xdp_md,
    saddr: *const u32,
    daddr: *const u32,
    nexthdr: u8,
    payload_len: u16,
    dst_mac: *const u8,
) -> i32 {
    if bpf_xdp_adjust_head(xdp, -(core::mem::size_of::<ipv6hdr>() as i32)) != 0 {
        return -1;
    }

    let data = vload!((*xdp).data) as usize as *mut u8;
    let data_end = vload!((*xdp).data_end) as usize as *mut u8;

    let new_eth = data as *mut ethhdr;
    let ip6h = byte_add(data, core::mem::size_of::<ethhdr>()) as *mut ipv6hdr;
    let old_eth = byte_add(data, core::mem::size_of::<ipv6hdr>()) as *mut ethhdr;

    if byte_add(new_eth as *mut u8, core::mem::size_of::<ethhdr>()) > data_end
        || byte_add(old_eth as *mut u8, core::mem::size_of::<ethhdr>()) > data_end
        || byte_add(ip6h as *mut u8, core::mem::size_of::<ipv6hdr>()) > data_end
    {
        return -1;
    }

    unsafe {
        vcopy8((*new_eth).h_source.as_mut_ptr(), (*old_eth).h_dest.as_ptr(), 6);
        vcopy8((*new_eth).h_dest.as_mut_ptr(), dst_mac, 6);
        (*new_eth).h_proto = ETH_P_IPV6.to_be();

        // __builtin_memset(ip6h, 0, sizeof(*ip6h)) followed by the field
        // stores: every byte of the header is written below.
        (*ip6h).priority_version = 6 << 4;
        (*ip6h).flow_lbl = [0; 3];
        (*ip6h).nexthdr = nexthdr;
        (*ip6h).payload_len = payload_len.to_be();
        (*ip6h).hop_limit = 64;
        vcopy32((*ip6h).saddr.as_mut_ptr(), saddr, 4);
        vcopy32((*ip6h).daddr.as_mut_ptr(), daddr, 4);
    }

    0
}

// ---- stats and lookups ----------------------------------------------------

#[inline(always)]
fn update_stats<M>(map: *const M, key: u32, bytes: u16) {
    let st = bpf_map_lookup_elem(map, &key) as *mut lb_stats;

    if !st.is_null() {
        unsafe {
            (*st).v1 = (*st).v1.wrapping_add(1);
            (*st).v2 = (*st).v2.wrapping_add(bytes as u64);
        }
    }
}

#[inline(always)]
fn count_action(action: i32) {
    let key: u32 = if action == XDP_TX {
        STATS_XDP_TX
    } else if action == XDP_PASS {
        STATS_XDP_PASS
    } else {
        STATS_XDP_DROP
    };

    let st = bpf_map_lookup_elem(&stats, &key) as *mut lb_stats;
    if !st.is_null() {
        unsafe { (*st).v1 = (*st).v1.wrapping_add(1) };
    }
}

#[inline(always)]
fn is_under_flood() -> bool {
    let key: u32 = STATS_NEW_CONN;
    let conn_st = bpf_map_lookup_elem(&stats, &key) as *mut lb_stats;

    if conn_st.is_null() {
        return true;
    }

    let cur_time = bpf_ktime_get_ns();
    unsafe {
        if cur_time.wrapping_sub((*conn_st).v2) > ONE_SEC {
            (*conn_st).v1 = 1;
            (*conn_st).v2 = cur_time;
        } else {
            (*conn_st).v1 = (*conn_st).v1.wrapping_add(1);
            if (*conn_st).v1 > MAX_CONN_RATE {
                return true;
            }
        }
    }
    false
}

#[inline(always)]
fn connection_table_lookup(
    lru_map: *mut c_void,
    flow: &mut flow_key,
    out_pos: &mut u32,
) -> *mut real_definition {
    let dst_lru = bpf_map_lookup_elem(lru_map as *const c_void, flow) as *mut real_pos_lru;
    if dst_lru.is_null() {
        return null_mut();
    }

    /* UDP connections use atime-based timeout instead of FIN/RST */
    if flow.proto == IPPROTO_UDP {
        let cur_time = bpf_ktime_get_ns();

        if cur_time.wrapping_sub(unsafe { (*dst_lru).atime }) > LRU_UDP_TIMEOUT {
            return null_mut();
        }
        unsafe { (*dst_lru).atime = cur_time };
    }

    let key: u32 = unsafe { (*dst_lru).pos };
    *out_pos = key;
    bpf_map_lookup_elem(&reals, &key) as *mut real_definition
}

#[inline(always)]
fn get_packet_dst(
    real: &mut *mut real_definition,
    flow: &mut flow_key,
    vip_info: *mut vip_meta,
    is_v6: bool,
    lru_map: *mut c_void,
    is_rst: bool,
    out_pos: &mut u32,
) -> bool {
    let under_flood = is_under_flood();

    let hash: u32 = if is_v6 {
        let src_hash = jhash2_4words(unsafe { flow.src.srcv6.as_ptr() });

        jhash_2words(src_hash, unsafe { flow.ports.ports })
    } else {
        jhash_2words(unsafe { flow.src.src }, unsafe { flow.ports.ports })
    };

    let ch_key: u32 = CH_RING_SIZE
        .wrapping_mul(unsafe { (*vip_info).vip_num })
        .wrapping_add(hash % CH_RING_SIZE);
    let ch_val = bpf_map_lookup_elem(&ch_rings, &ch_key) as *mut u32;
    if ch_val.is_null() {
        return false;
    }
    let real_pos: u32 = unsafe { *ch_val };

    *real = bpf_map_lookup_elem(&reals, &real_pos) as *mut real_definition;
    if real.is_null() {
        return false;
    }

    if unsafe { (*vip_info).flags } & F_LRU_BYPASS == 0 && !under_flood && !is_rst {
        let mut new_lru = real_pos_lru { pos: real_pos, _pad: 0, atime: 0 };

        if flow.proto == IPPROTO_UDP {
            new_lru.atime = bpf_ktime_get_ns();
        }
        bpf_map_update_elem(lru_map as *const c_void, flow, &new_lru, 0);
    }

    *out_pos = real_pos;
    true
}

#[inline(always)]
fn update_vip_lru_miss_stats(vip: &vip_definition, is_v6: bool, real_idx: u32) {
    let key: u32 = 0;

    let miss_vip = bpf_map_lookup_elem(&vip_miss_stats, &key) as *mut vip_definition;
    if miss_vip.is_null() {
        return;
    }

    unsafe {
        if is_v6 {
            if (*miss_vip).addr.vipv6[0] != vip.addr.vipv6[0]
                || (*miss_vip).addr.vipv6[1] != vip.addr.vipv6[1]
                || (*miss_vip).addr.vipv6[2] != vip.addr.vipv6[2]
                || (*miss_vip).addr.vipv6[3] != vip.addr.vipv6[3]
            {
                return;
            }
        } else {
            if (*miss_vip).addr.vip != vip.addr.vip {
                return;
            }
        }

        if (*miss_vip).port != vip.port || (*miss_vip).proto != vip.proto {
            return;
        }
    }

    let cnt = bpf_map_lookup_elem(&lru_miss_stats, &real_idx) as *mut u32;
    if !cnt.is_null() {
        unsafe { *cnt = (*cnt).wrapping_add(1) };
    }
}

// ---- the load balancer ----------------------------------------------------

#[inline(never)]
#[export_name = "process_packet"]
extern "C" fn process_packet(xdp: *mut xdp_md) -> i32 {
    let data = vload!((*xdp).data) as usize as *mut u8;
    let data_end = vload!((*xdp).data_end) as usize as *mut u8;
    let eth = data as *mut ethhdr;
    let mut dst: *mut real_definition = null_mut();
    // struct vip_definition vip_def = {}; struct flow_key flow = {};
    let mut vip_def: vip_definition = unsafe { core::mem::zeroed() };
    let mut flow: flow_key = unsafe { core::mem::zeroed() };
    unsafe {
        vzero32(&mut flow as *mut flow_key as *mut u32, 10);
        vzero32(&mut vip_def as *mut vip_definition as *mut u32, 5);
    }
    let mut tnl_src: [u32; 4] = [0; 4];
    let l4: *mut u8;
    let payload_len: u16;
    let mut real_pos: u32 = 0;
    let proto: u8;
    let mut action: i32 = XDP_DROP;
    let is_v6: bool;
    let mut is_syn = false;
    let mut is_rst = false;

    'out: {
        if byte_add(eth as *mut u8, core::mem::size_of::<ethhdr>()) > data_end {
            break 'out;
        }

        let h_proto = unsafe { (*eth).h_proto };
        if h_proto == ETH_P_IPV6.to_be() {
            is_v6 = true;
        } else if h_proto == ETH_P_IP.to_be() {
            is_v6 = false;
        } else {
            action = XDP_PASS;
            break 'out;
        }

        if is_v6 {
            let ip6h = byte_add(eth as *mut u8, core::mem::size_of::<ethhdr>()) as *mut ipv6hdr;

            if byte_add(ip6h as *mut u8, core::mem::size_of::<ipv6hdr>()) > data_end {
                break 'out;
            }
            if unsafe { (*ip6h).nexthdr } == IPPROTO_FRAGMENT {
                break 'out;
            }

            payload_len = (core::mem::size_of::<ipv6hdr>() as u16)
                .wrapping_add(u16::from_be(unsafe { (*ip6h).payload_len }));
            proto = unsafe { (*ip6h).nexthdr };

            unsafe {
                vcopy32(flow.src.srcv6.as_mut_ptr(), (*ip6h).saddr.as_ptr(), 4);
                vcopy32(flow.dst.dstv6.as_mut_ptr(), (*ip6h).daddr.as_ptr(), 4);
                vcopy32(vip_def.addr.vipv6.as_mut_ptr(), (*ip6h).daddr.as_ptr(), 4);
            }
            l4 = byte_add(ip6h as *mut u8, core::mem::size_of::<ipv6hdr>());
        } else {
            let iph = byte_add(eth as *mut u8, core::mem::size_of::<ethhdr>()) as *mut iphdr;

            if byte_add(iph as *mut u8, core::mem::size_of::<iphdr>()) > data_end {
                break 'out;
            }
            if unsafe { (*iph).ihl_version } & 0x0f != 5 {
                break 'out;
            }
            if unsafe { (*iph).frag_off } & PCKT_FRAGMENTED.to_be() != 0 {
                break 'out;
            }

            payload_len = u16::from_be(unsafe { (*iph).tot_len });
            proto = unsafe { (*iph).protocol };

            unsafe {
                flow.src.src = (*iph).saddr;
                flow.dst.dst = (*iph).daddr;
                vip_def.addr.vip = (*iph).daddr;
            }
            l4 = byte_add(iph as *mut u8, core::mem::size_of::<iphdr>());
        }

        /* TCP and UDP share the same port layout at offset 0 */
        if proto != IPPROTO_TCP && proto != IPPROTO_UDP {
            action = XDP_PASS;
            break 'out;
        }

        let uh = l4 as *mut udphdr;
        if byte_add(uh as *mut u8, core::mem::size_of::<udphdr>()) > data_end {
            break 'out;
        }
        unsafe {
            flow.ports.port16[0] = (*uh).source;
            flow.ports.port16[1] = (*uh).dest;
        }

        if proto == IPPROTO_TCP {
            let th = l4 as *mut tcphdr;

            if byte_add(th as *mut u8, core::mem::size_of::<tcphdr>()) > data_end {
                break 'out;
            }
            let flags = unsafe { (*th).flags };
            is_syn = flags & TCPF_SYN != 0;
            is_rst = flags & TCPF_RST != 0;
        }

        flow.proto = proto;
        vip_def.port = unsafe { flow.ports.port16[1] };
        vip_def.proto = proto;

        let vip_info = bpf_map_lookup_elem(&vip_map, &vip_def) as *mut vip_meta;
        if vip_info.is_null() {
            action = XDP_PASS;
            break 'out;
        }

        let key: u32 = STATS_LRU;
        let data_stats = bpf_map_lookup_elem(&stats, &key) as *mut lb_stats;
        if data_stats.is_null() {
            break 'out;
        }
        unsafe { (*data_stats).v1 = (*data_stats).v1.wrapping_add(1) };

        let cpu_num: u32 = bpf_get_smp_processor_id();
        let lru_map = bpf_map_lookup_elem(&lru_mapping, &cpu_num);
        if lru_map.is_null() {
            break 'out;
        }

        if unsafe { (*vip_info).flags } & F_LRU_BYPASS == 0 && !is_syn {
            dst = connection_table_lookup(lru_map, &mut flow, &mut real_pos);
        }

        if dst.is_null() {
            if flow.proto == IPPROTO_TCP {
                let key: u32 = STATS_LRU_MISS;
                let miss_st = bpf_map_lookup_elem(&stats, &key) as *mut lb_stats;
                if !miss_st.is_null() {
                    unsafe { (*miss_st).v1 = (*miss_st).v1.wrapping_add(1) };
                }
            }

            if !get_packet_dst(&mut dst, &mut flow, vip_info, is_v6, lru_map, is_rst, &mut real_pos) {
                break 'out;
            }

            update_vip_lru_miss_stats(&vip_def, is_v6, real_pos);
            unsafe { (*data_stats).v2 = (*data_stats).v2.wrapping_add(1) };
        }

        let key: u32 = 0;
        let cval = bpf_map_lookup_elem(&ctl_array, &key) as *mut ctl_value;
        if cval.is_null() {
            break 'out;
        }

        update_stats(&stats, unsafe { (*vip_info).vip_num }, payload_len);
        update_stats(&reals_stats, real_pos, payload_len);

        let mac = unsafe { (*cval).mac.as_ptr() };
        if is_v6 {
            create_encap_ipv6_src(unsafe { flow.ports.port16[0] }, unsafe { flow.src.srcv6[0] }, &mut tnl_src);
            if encap_v6(
                xdp,
                tnl_src.as_ptr(),
                unsafe { (*dst).dstv6.as_ptr() },
                IPPROTO_IPV6,
                payload_len,
                mac,
            ) != 0
            {
                break 'out;
            }
        } else if unsafe { (*dst).flags } & F_IPV6 != 0 {
            create_encap_ipv6_src(unsafe { flow.ports.port16[0] }, unsafe { flow.src.src }, &mut tnl_src);
            if encap_v6(
                xdp,
                tnl_src.as_ptr(),
                unsafe { (*dst).dstv6.as_ptr() },
                IPPROTO_IPIP,
                payload_len,
                mac,
            ) != 0
            {
                break 'out;
            }
        } else {
            if encap_v4(
                xdp,
                create_encap_ipv4_src(unsafe { flow.ports.port16[0] }, unsafe { flow.src.src }),
                unsafe { (*dst).dst },
                payload_len,
                mac,
            ) != 0
            {
                break 'out;
            }
        }

        action = XDP_TX;
    }

    count_action(action);
    action
}

#[inline(always)]
fn strip_encap(xdp: *mut xdp_md, saved_eth: *const u8) -> i32 {
    let data = vload!((*xdp).data) as usize as *mut u8;
    let data_end = vload!((*xdp).data_end) as usize as *mut u8;
    let eth = data as *mut ethhdr;

    if byte_add(eth as *mut u8, core::mem::size_of::<ethhdr>()) > data_end {
        return -1;
    }

    let hdr_sz: i32 = if unsafe { (*eth).h_proto } == ETH_P_IPV6.to_be() {
        core::mem::size_of::<ipv6hdr>() as i32
    } else {
        core::mem::size_of::<iphdr>() as i32
    };

    if bpf_xdp_adjust_head(xdp, hdr_sz) != 0 {
        return -1;
    }

    let data = vload!((*xdp).data) as usize as *mut u8;
    let data_end = vload!((*xdp).data_end) as usize as *mut u8;
    let eth = data as *mut ethhdr;

    if byte_add(eth as *mut u8, core::mem::size_of::<ethhdr>()) > data_end {
        return -1;
    }

    unsafe { vcopy8(eth as *mut u8, saved_eth, core::mem::size_of::<ethhdr>()) };
    0
}

#[inline(always)]
fn randomize_src(xdp: *mut xdp_md, saddr_off: i32, rand_state: &mut u32) {
    let data = vload!((*xdp).data) as usize as *mut u8;
    let data_end = vload!((*xdp).data_end) as usize as *mut u8;
    let saddr = byte_add(data, saddr_off as usize) as *mut u32;

    *rand_state ^= *rand_state << 13;
    *rand_state ^= *rand_state >> 17;
    *rand_state ^= *rand_state << 5;

    if byte_add(saddr as *mut u8, 4) <= data_end {
        unsafe { *saddr = *rand_state & read_volatile(addr_of!(flow_mask)) };
    }
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_lb_bench(xdp: *mut xdp_md) -> i32 {
    let data = vload!((*xdp).data) as usize as *mut u8;
    let data_end = vload!((*xdp).data_end) as usize as *mut u8;
    let eth = data as *mut ethhdr;
    let mut saved_eth: [u8; 14] = [0; 14];
    let mut rand_state: u32 = 0;
    let mut batch_hash: u32 = 0;
    let saddr_off: i32;
    let is_v6: bool;

    if byte_add(eth as *mut u8, core::mem::size_of::<ethhdr>()) > data_end {
        return XDP_DROP;
    }

    unsafe { vcopy8(saved_eth.as_mut_ptr(), eth as *const u8, core::mem::size_of::<ethhdr>()) };

    is_v6 = unsafe { (*eth).h_proto } == ETH_P_IPV6.to_be();

    saddr_off = (core::mem::size_of::<ethhdr>()
        + if is_v6 { core::mem::offset_of!(ipv6hdr, saddr) } else { core::mem::offset_of!(iphdr, saddr) })
        as i32;

    if unsafe { read_volatile(addr_of!(flow_mask)) } != 0 {
        rand_state = bpf_get_prandom_u32() | 1;
    }

    if unsafe { read_volatile(addr_of!(cold_lru)) } != 0 {
        let saddr = byte_add(data, saddr_off as usize) as *mut u32;

        unsafe {
            batch_gen = batch_gen.wrapping_add(1);
            batch_hash = batch_gen.wrapping_add(bpf_get_smp_processor_id()).wrapping_mul(KNUTH_HASH_MULT);
        }
        if byte_add(saddr as *mut u8, 4) <= data_end {
            unsafe { *saddr ^= batch_hash };
        }
    }

    /* BENCH_BPF_LOOP(process_packet(xdp), ({ ... })) */
    let bench_start = bpf_ktime_get_ns();
    let mut bench_i: u32 = 0;

    while bench_i < unsafe { read_volatile(addr_of!(batch_iters)) } && unsafe { can_loop() } {
        let bench_result = process_packet(xdp);

        if bench_result == XDP_TX {
            if strip_encap(xdp, saved_eth.as_ptr()) != 0 {
                return XDP_DROP;
            }
            if rand_state != 0 {
                randomize_src(xdp, saddr_off, &mut rand_state);
            }
        }
        if unsafe { read_volatile(addr_of!(cold_lru)) } != 0 {
            let d = vload!((*xdp).data) as usize as *mut u8;
            let de = vload!((*xdp).data_end) as usize as *mut u8;
            let sa = byte_add(d, saddr_off as usize) as *mut u32;

            if byte_add(sa as *mut u8, 4) <= de {
                unsafe { *sa ^= batch_hash };
            }
        }
        bench_i += 1;
    }

    bench_record_sample(bpf_ktime_get_ns().wrapping_sub(bench_start));

    process_packet(xdp)
}

bpf_object!("GPL");
