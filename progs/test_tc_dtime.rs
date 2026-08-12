#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_tc_dtime.c
// (bpf-rs-core idiom).

use core::ffi::c_void;

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_redirect_neigh, bpf_skb_set_tstamp};
use bpf_rs_core::{bpf_object, vload, vstore};

const TC_ACT_OK: i32 = 0;
const TC_ACT_SHOT: i32 = 2;
const TC_ACT_UNSPEC: i32 = -1;

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

const ETH_HDR_LEN: usize = 14;

const IP4_SRC: u32 = 0xac100164u32.to_be(); // 172.16.1.100
const IP4_DST: u32 = 0xac100264u32.to_be(); // 172.16.2.100

const IP6_SRC_BYTES: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef, 0xca,
    0xfe,
];
const IP6_DST_BYTES: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xde, 0xad, 0xbe, 0xef, 0xca,
    0xfe,
];

const fn u32_from_le(b: &[u8; 16], off: usize) -> u32 {
    (b[off] as u32) | ((b[off + 1] as u32) << 8) | ((b[off + 2] as u32) << 16) | ((b[off + 3] as u32) << 24)
}

// s6_addr32[i], reconstructed from the wire bytes the same way the packed
// ipv6hdr.saddr field below does (raw bytes reinterpreted as native u32s,
// no byteswap).
const IP6_SRC_ADDR32: [u32; 4] = [
    u32_from_le(&IP6_SRC_BYTES, 0),
    u32_from_le(&IP6_SRC_BYTES, 4),
    u32_from_le(&IP6_SRC_BYTES, 8),
    u32_from_le(&IP6_SRC_BYTES, 12),
];
const IP6_DST_ADDR32: [u32; 4] = [
    u32_from_le(&IP6_DST_BYTES, 0),
    u32_from_le(&IP6_DST_BYTES, 4),
    u32_from_le(&IP6_DST_BYTES, 8),
    u32_from_le(&IP6_DST_BYTES, 12),
];

#[inline(always)]
fn v6_equal(a: [u32; 4], b: [u32; 4]) -> bool {
    a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3]
}

#[link_section = ".rodata"]
#[no_mangle]
static IFINDEX_SRC: u32 = 0;

#[link_section = ".rodata"]
#[no_mangle]
static IFINDEX_DST: u32 = 0;

#[inline(always)]
fn ifindex_src() -> u32 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(IFINDEX_SRC)) }
}

#[inline(always)]
fn ifindex_dst() -> u32 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(IFINDEX_DST)) }
}

const EGRESS_ENDHOST_MAGIC: u64 = 0x0b9fbeef;
const INGRESS_FWDNS_MAGIC: u64 = 0x1b9fbeef;
const EGRESS_FWDNS_MAGIC: u64 = 0x2b9fbeef;

// dtimes/errs column indices.
const INGRESS_FWDNS_P100: u32 = 0;
const INGRESS_FWDNS_P101: u32 = 1;
const EGRESS_FWDNS_P100: u32 = 2;
const EGRESS_FWDNS_P101: u32 = 3;
const INGRESS_ENDHOST: u32 = 4;
const EGRESS_ENDHOST: u32 = 5;
const SET_DTIME: u32 = 6;
const MAX_CNT: usize = 7;

// `test` row indices.
const TCP_IP6_CLEAR_DTIME: u32 = 0;
const TCP_IP4: u32 = 1;
const TCP_IP6: u32 = 2;
const UDP_IP4: u32 = 3;
const UDP_IP6: u32 = 4;
const TCP_IP4_RT_FWD: u32 = 5;
#[allow(dead_code)]
const TCP_IP6_RT_FWD: u32 = 6;
const UDP_IP4_RT_FWD: u32 = 7;
#[allow(dead_code)]
const UDP_IP6_RT_FWD: u32 = 8;
const UKN_TEST: u32 = 9;
const NR_TESTS: usize = 10;

const SRC_NS: u8 = 1;
const DST_NS: u8 = 2;

const BPF_SKB_CLOCK_REALTIME: u8 = 0;
const BPF_SKB_CLOCK_MONOTONIC: u8 = 1;
const BPF_SKB_CLOCK_TAI: u8 = 2;

#[no_mangle]
static mut dtimes: [[u32; MAX_CNT]; NR_TESTS] = [[0; MAX_CNT]; NR_TESTS];
#[no_mangle]
static mut errs: [[u32; MAX_CNT]; NR_TESTS] = [[0; MAX_CNT]; NR_TESTS];
#[no_mangle]
static mut test: u32 = 0;

#[inline(always)]
unsafe fn row_for_test() -> usize {
    let t = test;
    if (t as usize) < NR_TESTS {
        t as usize
    } else {
        UKN_TEST as usize
    }
}

#[inline(always)]
fn inc_dtimes(idx: u32) {
    unsafe {
        let row = row_for_test();
        let p = (core::ptr::addr_of_mut!(dtimes) as *mut u32).add(row * MAX_CNT + idx as usize);
        *p += 1;
    }
}

#[inline(always)]
fn inc_errs(idx: u32) {
    unsafe {
        let row = row_for_test();
        let p = (core::ptr::addr_of_mut!(errs) as *mut u32).add(row * MAX_CNT + idx as usize);
        *p += 1;
    }
}

#[inline(always)]
fn skb_proto(t: i32) -> i32 {
    t & 0xff
}

#[inline(always)]
fn skb_ns(t: i32) -> i32 {
    (t >> 8) & 0xff
}

#[inline(always)]
fn fwdns_clear_dtime() -> bool {
    unsafe { test == TCP_IP6_CLEAR_DTIME }
}

#[inline(always)]
fn bpf_fwd() -> bool {
    unsafe { test < TCP_IP4_RT_FWD }
}

#[inline(always)]
fn get_proto() -> u8 {
    match unsafe { test } {
        UDP_IP4 | UDP_IP6 | UDP_IP4_RT_FWD | UDP_IP6_RT_FWD => IPPROTO_UDP,
        _ => IPPROTO_TCP,
    }
}

#[inline(always)]
fn htons(x: u16) -> u16 {
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

// struct iphdr (linux/ip.h) — packed (follows a 14-byte ethhdr, never
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
    protocol: u8,
    #[allow(dead_code)]
    check: u16,
    saddr: u32,
    #[allow(dead_code)]
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
    nexthdr: u8,
    #[allow(dead_code)]
    hop_limit: u8,
    saddr: [u32; 4],
    #[allow(dead_code)]
    daddr: [u32; 4],
}

// struct tcphdr (linux/tcp.h) — only source/dest are read, but the type is
// full size so the `th + 1 > data_end` bounds check matches C.
#[repr(C, packed)]
struct tcphdr {
    source: u16,
    dest: u16,
    #[allow(dead_code)]
    seq: u32,
    #[allow(dead_code)]
    ack_seq: u32,
    #[allow(dead_code)]
    flags0: u8,
    #[allow(dead_code)]
    flags1: u8,
    #[allow(dead_code)]
    window: u16,
    #[allow(dead_code)]
    check: u16,
    #[allow(dead_code)]
    urg_ptr: u16,
}

// struct udphdr (linux/udp.h) — packed.
#[repr(C, packed)]
struct udphdr {
    source: u16,
    dest: u16,
    #[allow(dead_code)]
    len: u16,
    #[allow(dead_code)]
    check: u16,
}

/// -1: parse error: TC_ACT_SHOT
///  0: not testing traffic: TC_ACT_OK
/// >0: first byte is the inet_proto, second byte has the netns of the sender
#[inline(always)]
fn skb_get_type(skb: *const __sk_buff) -> i32 {
    let t = unsafe { test };
    let dst_ns_port = htons(50000u32.wrapping_add(t) as u16);

    let data_end = vload!((*skb).data_end) as usize;
    let data = vload!((*skb).data) as usize;

    let mut inet_proto: u8 = 0;
    let mut ns: u8 = 0;
    let trans: usize;

    // C's `switch (skb->protocol)` compares the FULL 32-bit ctx word; a
    // 16-bit mask here diverges for words whose upper bits are set.
    let protocol = vload!((*skb).protocol) as u32;
    if protocol == htons(ETH_P_IP) as u32 {
        let iph = (data + ETH_HDR_LEN) as *const iphdr;
        if iph as usize + core::mem::size_of::<iphdr>() > data_end {
            return -1;
        }
        let saddr = unsafe { (*iph).saddr };
        if saddr == IP4_SRC {
            ns = SRC_NS;
        } else if saddr == IP4_DST {
            ns = DST_NS;
        }
        inet_proto = unsafe { (*iph).protocol };
        trans = iph as usize + core::mem::size_of::<iphdr>();
    } else if protocol == htons(ETH_P_IPV6) as u32 {
        let ip6h = (data + ETH_HDR_LEN) as *const ipv6hdr;
        if ip6h as usize + core::mem::size_of::<ipv6hdr>() > data_end {
            return -1;
        }
        let saddr = unsafe { (*ip6h).saddr };
        if v6_equal(saddr, IP6_SRC_ADDR32) {
            ns = SRC_NS;
        } else if v6_equal(saddr, IP6_DST_ADDR32) {
            ns = DST_NS;
        }
        inet_proto = unsafe { (*ip6h).nexthdr };
        trans = ip6h as usize + core::mem::size_of::<ipv6hdr>();
    } else {
        return 0;
    }

    // skb is not from src_ns or dst_ns, or skb is not the testing IPPROTO.
    if ns == 0 || inet_proto != get_proto() {
        return 0;
    }

    let sport: u16;
    let dport: u16;
    if inet_proto == IPPROTO_TCP {
        let th = trans as *const tcphdr;
        if th as usize + core::mem::size_of::<tcphdr>() > data_end {
            return -1;
        }
        sport = unsafe { (*th).source };
        dport = unsafe { (*th).dest };
    } else if inet_proto == IPPROTO_UDP {
        let uh = trans as *const udphdr;
        if uh as usize + core::mem::size_of::<udphdr>() > data_end {
            return -1;
        }
        sport = unsafe { (*uh).source };
        dport = unsafe { (*uh).dest };
    } else {
        return 0;
    }

    // The skb is the testing traffic.
    if (ns == SRC_NS && dport == dst_ns_port) || (ns == DST_NS && sport == dst_ns_port) {
        return ((ns as i32) << 8) | inet_proto as i32;
    }

    0
}

/// format: direction@iface@netns
/// egress@veth_(src|dst)@ns_(src|dst)
#[link_section = "tc"]
#[no_mangle]
extern "C" fn egress_host(skb: *mut __sk_buff) -> i32 {
    let skb_type = skb_get_type(skb as *const __sk_buff);
    if skb_type == -1 {
        return TC_ACT_SHOT;
    }
    if skb_type == 0 {
        return TC_ACT_OK;
    }

    let proto = skb_proto(skb_type);
    if proto == IPPROTO_TCP as i32 {
        if vload!((*skb).tstamp_type) == BPF_SKB_CLOCK_MONOTONIC && vload!((*skb).tstamp) != 0 {
            inc_dtimes(EGRESS_ENDHOST);
        } else {
            inc_errs(EGRESS_ENDHOST);
        }
    } else if proto == IPPROTO_UDP as i32 {
        if vload!((*skb).tstamp_type) == BPF_SKB_CLOCK_TAI && vload!((*skb).tstamp) != 0 {
            inc_dtimes(EGRESS_ENDHOST);
        } else {
            inc_errs(EGRESS_ENDHOST);
        }
    } else if vload!((*skb).tstamp_type) == BPF_SKB_CLOCK_REALTIME && vload!((*skb).tstamp) != 0 {
        inc_errs(EGRESS_ENDHOST);
    }

    vstore!((*skb).tstamp, EGRESS_ENDHOST_MAGIC);

    TC_ACT_OK
}

/// ingress@veth_(src|dst)@ns_(src|dst)
#[link_section = "tc"]
#[no_mangle]
extern "C" fn ingress_host(skb: *const __sk_buff) -> i32 {
    let skb_type = skb_get_type(skb);
    if skb_type == -1 {
        return TC_ACT_SHOT;
    }
    if skb_type == 0 {
        return TC_ACT_OK;
    }

    if vload!((*skb).tstamp_type) == BPF_SKB_CLOCK_MONOTONIC
        && vload!((*skb).tstamp) == EGRESS_FWDNS_MAGIC
    {
        inc_dtimes(INGRESS_ENDHOST);
    } else {
        inc_errs(INGRESS_ENDHOST);
    }

    TC_ACT_OK
}

/// ingress@veth_(src|dst)_fwd@ns_fwd priority 100
#[link_section = "tc"]
#[no_mangle]
extern "C" fn ingress_fwdns_prio100(skb: *mut __sk_buff) -> i32 {
    let skb_type = skb_get_type(skb as *const __sk_buff);
    if skb_type == -1 {
        return TC_ACT_SHOT;
    }
    if skb_type == 0 {
        return TC_ACT_OK;
    }

    // delivery_time is only available to the ingress if the tc-bpf checks
    // the skb->tstamp_type.
    if vload!((*skb).tstamp) == EGRESS_ENDHOST_MAGIC {
        inc_errs(INGRESS_FWDNS_P100);
    }

    if fwdns_clear_dtime() {
        vstore!((*skb).tstamp, 0u64);
    }

    TC_ACT_UNSPEC
}

/// egress@veth_(src|dst)_fwd@ns_fwd priority 100
#[link_section = "tc"]
#[no_mangle]
extern "C" fn egress_fwdns_prio100(skb: *mut __sk_buff) -> i32 {
    let skb_type = skb_get_type(skb as *const __sk_buff);
    if skb_type == -1 {
        return TC_ACT_SHOT;
    }
    if skb_type == 0 {
        return TC_ACT_OK;
    }

    // delivery_time is always available to egress even if the tc-bpf did
    // not use the tstamp_type.
    if vload!((*skb).tstamp) == INGRESS_FWDNS_MAGIC {
        inc_dtimes(EGRESS_FWDNS_P100);
    } else {
        inc_errs(EGRESS_FWDNS_P100);
    }

    if fwdns_clear_dtime() {
        vstore!((*skb).tstamp, 0u64);
    }

    TC_ACT_UNSPEC
}

/// ingress@veth_(src|dst)_fwd@ns_fwd priority 101
#[link_section = "tc"]
#[no_mangle]
extern "C" fn ingress_fwdns_prio101(skb: *mut __sk_buff) -> i32 {
    let skb_type = skb_get_type(skb as *const __sk_buff);
    if skb_type == -1 || skb_type == 0 {
        // Should have handled in prio100.
        return TC_ACT_SHOT;
    }

    let tstamp_type = vload!((*skb).tstamp_type);
    if tstamp_type != 0 {
        if fwdns_clear_dtime()
            || (tstamp_type != BPF_SKB_CLOCK_MONOTONIC && tstamp_type != BPF_SKB_CLOCK_TAI)
            || vload!((*skb).tstamp) != EGRESS_ENDHOST_MAGIC
        {
            inc_errs(INGRESS_FWDNS_P101);
        } else {
            inc_dtimes(INGRESS_FWDNS_P101);
        }
    } else if !fwdns_clear_dtime() {
        inc_errs(INGRESS_FWDNS_P101);
    }

    if tstamp_type == BPF_SKB_CLOCK_MONOTONIC {
        vstore!((*skb).tstamp, INGRESS_FWDNS_MAGIC);
    } else if bpf_skb_set_tstamp(
        skb as *const c_void,
        INGRESS_FWDNS_MAGIC,
        BPF_SKB_CLOCK_MONOTONIC as u32,
    ) != 0
    {
        inc_errs(SET_DTIME);
    }

    if skb_ns(skb_type) == SRC_NS as i32 {
        if bpf_fwd() {
            bpf_redirect_neigh(ifindex_dst(), core::ptr::null_mut::<c_void>(), 0, 0) as i32
        } else {
            TC_ACT_OK
        }
    } else if bpf_fwd() {
        bpf_redirect_neigh(ifindex_src(), core::ptr::null_mut::<c_void>(), 0, 0) as i32
    } else {
        TC_ACT_OK
    }
}

/// egress@veth_(src|dst)_fwd@ns_fwd priority 101
#[link_section = "tc"]
#[no_mangle]
extern "C" fn egress_fwdns_prio101(skb: *mut __sk_buff) -> i32 {
    let skb_type = skb_get_type(skb as *const __sk_buff);
    if skb_type == -1 || skb_type == 0 {
        // Should have handled in prio100.
        return TC_ACT_SHOT;
    }

    let tstamp_type = vload!((*skb).tstamp_type);
    if tstamp_type != 0 {
        if fwdns_clear_dtime()
            || tstamp_type != BPF_SKB_CLOCK_MONOTONIC
            || vload!((*skb).tstamp) != INGRESS_FWDNS_MAGIC
        {
            inc_errs(EGRESS_FWDNS_P101);
        } else {
            inc_dtimes(EGRESS_FWDNS_P101);
        }
    } else if !fwdns_clear_dtime() {
        inc_errs(EGRESS_FWDNS_P101);
    }

    if tstamp_type == BPF_SKB_CLOCK_MONOTONIC {
        vstore!((*skb).tstamp, EGRESS_FWDNS_MAGIC);
    } else if bpf_skb_set_tstamp(
        skb as *const c_void,
        EGRESS_FWDNS_MAGIC,
        BPF_SKB_CLOCK_MONOTONIC as u32,
    ) != 0
    {
        inc_errs(SET_DTIME);
    }

    TC_ACT_OK
}

#[link_section = "license"]
#[no_mangle]
static __license: [u8; 4] = bpf_rs_core::__lic_bytes::<4>("GPL");

bpf_object!("GPL");
