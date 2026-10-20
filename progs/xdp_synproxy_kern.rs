// SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause
#![no_std]
#![no_main]
#![allow(non_camel_case_types)]

// Direct translation of tools/testing/selftests/bpf/progs/xdp_synproxy_kern.c
// (bpf-rs-core idiom): a SYN proxy in two flavours, `syncookie_xdp` and
// `syncookie_tc`, sharing every helper through a `const XDP: bool`
// parameter the way the C passes `bool xdp`. The userspace driver
// (xdp_synproxy.c) finds the programs and the two maps BY NAME, so
// `syncookie_xdp`, `syncookie_tc`, `values` and `allowed_ports` are
// load-bearing.
//
// Packet headers are plain `#[repr(C)]` views (no CO-RE: the C's
// vmlinux.h relocations against UAPI headers resolve to the same offsets);
// the only real kernel object read is `nf_conn.status`, through a `#[btf]`
// view like test_bpf_nf.rs. The conntrack kfuncs take their opts/tuple as
// size-checked memory, so the local `bpf_ct_opts___local` and
// `bpf_sock_tuple` layouts are all that matters.
//
// Fixed-size copies (MAC swap, in6_addr swap/copy, the 20-byte TCP header
// move that strips IPv4 options) are volatile word/byte loops: a value copy
// becomes a `bpf_arena_memcpy` kfunc call. `tsopt` is a volatile stack
// slot as in the C (the comment there explains the dead-NULL-branch
// miscompile), and the TC tail grow goes through a volatile `old_len`
// (otherwise "32-bit pointer arithmetic prohibited").

use core::ffi::c_void;
use core::mem::size_of;
use core::ptr::{null_mut, read_volatile, write_volatile};

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::{__sk_buff, TC_ACT_OK, TC_ACT_SHOT};
use bpf_rs_core::helpers::{
    self, bpf_csum_diff, bpf_ktime_get_ns, bpf_loop, bpf_map_lookup_elem, bpf_redirect,
    bpf_skb_change_tail, bpf_tcp_raw_check_syncookie_ipv4, bpf_tcp_raw_check_syncookie_ipv6,
    bpf_tcp_raw_gen_syncookie_ipv4, bpf_tcp_raw_gen_syncookie_ipv6, bpf_xdp_adjust_tail,
    sync_fetch_and_add_u64,
};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::vload;
use btf_macros::btf;

const XDP_ABORTED: i32 = 0;
const XDP_DROP: i32 = 1;
const XDP_PASS: i32 = 2;
const XDP_TX: i32 = 3;

const NSEC_PER_SEC: u64 = 1000000000;

const ETH_ALEN: usize = 6;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;

const IP_MF: u16 = 0x2000;
const IP_OFFSET: u16 = 0x1fff;

const IPPROTO_TCP: u8 = 6;
const NEXTHDR_TCP: u8 = 6;

const TCPOPT_NOP: u8 = 1;
const TCPOPT_EOL: u8 = 0;
const TCPOPT_MSS: u32 = 2;
const TCPOPT_WINDOW: u8 = 3;
const TCPOPT_SACK_PERM: u8 = 4;
const TCPOPT_TIMESTAMP: u8 = 8;

const TCPOLEN_MSS: u32 = 4;
const TCPOLEN_WINDOW: u8 = 3;
const TCPOLEN_SACK_PERM: u8 = 2;
const TCPOLEN_TIMESTAMP: u8 = 10;

const TCP_TS_HZ: u64 = 1000;
const TS_OPT_WSCALE_MASK: u32 = 0xf;
const TS_OPT_SACK: u32 = 1 << 4;
const TS_OPT_ECN: u32 = 1 << 5;
const TSBITS: u32 = 6;
const TSMASK: u32 = (1u32 << TSBITS) - 1;
const TCP_MAX_WSCALE: u8 = 14;

const IPV4_MAXLEN: usize = 60;
const TCP_MAXLEN: usize = 60;

const DEFAULT_MSS4: u16 = 1460;
const DEFAULT_MSS6: u16 = 1440;
const DEFAULT_WSCALE: u8 = 7;
const DEFAULT_TTL: u8 = 64;
const MAX_ALLOWED_PORTS: u32 = 8;

const MAX_PACKET_OFF: u64 = 0xffff;

// vmlinux.h: the TCP flag words are host-order views of the big-endian
// bytes 12-15 of the header (byte 13 holds the flags).
const TCP_FLAG_SYN: u32 = 0x00000200;
const TCP_FLAG_ACK: u32 = 0x00001000;
const TCP_FLAG_ECE: u32 = 0x00004000;

// byte 13 of struct tcphdr, from the LSB: fin syn rst psh ack urg ece cwr
const TCPF_FIN: u8 = 1 << 0;
const TCPF_SYN: u8 = 1 << 1;
const TCPF_RST: u8 = 1 << 2;
const TCPF_ACK: u8 = 1 << 4;
const TCPF_ECE: u8 = 1 << 6;
const TCPF_CWR: u8 = 1 << 7;

const BPF_F_CURRENT_NETNS: i32 = -1;
const ENOENT: i32 = 2;
const IPS_CONFIRMED: u64 = 1 << 3;

#[link_section = ".maps"]
#[no_mangle]
static values: BpfMap<u32, u64, { maps::ARRAY }, 2> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static allowed_ports: BpfMap<u32, u16, { maps::ARRAY }, { MAX_ALLOWED_PORTS as usize }> =
    BpfMap::new();

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
    h_dest: [u8; ETH_ALEN],
    h_source: [u8; ETH_ALEN],
    h_proto: u16,
}

// struct iphdr (linux/ip.h); ihl/version packed into the first byte on
// little-endian (ihl low nibble, version high nibble).
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

// struct ipv6hdr (linux/ipv6.h); priority/version packed into the first
// byte (priority low nibble, version high nibble); the addresses as the
// in6_u.u6_addr32 view.
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

// struct tcphdr (linux/tcp.h); the res1/doff/flags __u16 bitfield (bytes
// 12-13) split into two plain bytes: byte 12 is doff(hi nibble)|res1(lo
// nibble), byte 13 is cwr,ece,urg,ack,psh,rst,syn,fin from MSB to LSB.
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

// The C's `struct bpf_ct_opts___local` (12-byte opts ABI), a
// KF_ARG_PTR_TO_MEM_SIZE argument: the layout is all the kfunc checks.
#[repr(C)]
struct bpf_ct_opts___local {
    netns_id: i32,
    error: i32,
    l4proto: u8,
    dir: u8,
    reserved: [u8; 2],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct bpf_sock_tuple_v4 {
    saddr: u32,
    daddr: u32,
    sport: u16,
    dport: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct bpf_sock_tuple_v6 {
    saddr: [u32; 4],
    daddr: [u32; 4],
    sport: u16,
    dport: u16,
}

// UAPI struct bpf_sock_tuple (linux/bpf.h).
#[repr(C)]
union bpf_sock_tuple {
    ipv4: bpf_sock_tuple_v4,
    ipv6: bpf_sock_tuple_v6,
}

// Only `status` is read, through CO-RE.
#[btf]
struct nf_conn {
    status: u64,
}

extern "C" {
    fn bpf_xdp_ct_lookup(
        xdp_ctx: *mut c_void,
        bpf_tuple: *mut c_void,
        len_tuple: u32,
        opts: *mut c_void,
        len_opts: u32,
    ) -> *mut c_void;
    fn bpf_skb_ct_lookup(
        skb_ctx: *mut c_void,
        bpf_tuple: *mut c_void,
        len_tuple: u32,
        opts: *mut c_void,
        len_opts: u32,
    ) -> *mut c_void;
    fn bpf_ct_release(ct: *mut c_void);
}

#[inline(never)]
fn ct_status_get(ct: *const nf_conn) -> u64 {
    *unsafe { &*ct }.status().get().unwrap()
}

// ---- byte helpers ------------------------------------------------------

#[inline(always)]
fn byte_add(p: *mut u8, n: usize) -> *mut u8 {
    unsafe { p.add(n) }
}

// Volatile per-element swap/copy: a whole-array value copy is rewritten
// by LLVM into a `bpf_arena_memcpy` kfunc call, which this program cannot
// use. The C's __builtin_memcpy on 6 bytes becomes byte moves; on the
// 16-byte in6_addr it becomes word moves.
#[inline(always)]
unsafe fn vswap8(a: *mut u8, b: *mut u8, len: usize) {
    let mut i = 0usize;
    while i < len {
        let ta = read_volatile(a.add(i));
        let tb = read_volatile(b.add(i));
        write_volatile(a.add(i), tb);
        write_volatile(b.add(i), ta);
        i += 1;
    }
}

#[inline(always)]
unsafe fn vswap32(a: *mut u32, b: *mut u32, words: usize) {
    let mut i = 0usize;
    while i < words {
        let ta = read_volatile(a.add(i));
        let tb = read_volatile(b.add(i));
        write_volatile(a.add(i), tb);
        write_volatile(b.add(i), ta);
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

#[inline(always)]
fn swap_eth_addr(a: *mut u8, b: *mut u8) {
    unsafe { vswap8(a, b, ETH_ALEN) }
}

// struct { __be32 x; } __attribute__((packed)): an unaligned 32-bit load.
#[repr(C, packed)]
struct unaligned_be32(u32);

#[inline(always)]
fn get_unaligned_be32(p: *const u8) -> u32 {
    unsafe { (*(p as *const unaligned_be32)).0 }
}

// ---- tcphdr accessors --------------------------------------------------

#[inline(always)]
fn tcp_doff(tcp: *const tcphdr) -> u8 {
    unsafe { (*tcp).doff_res1 >> 4 }
}

#[inline(always)]
fn tcp_set_doff(tcp: *mut tcphdr, doff: u8) {
    unsafe { (*tcp).doff_res1 = ((*tcp).doff_res1 & 0x0f) | (doff << 4) }
}

#[inline(always)]
fn tcp_flags(tcp: *const tcphdr) -> u8 {
    unsafe { (*tcp).flags }
}

/// `tcp_flag_word(tp)`: `((union tcp_word_hdr *)tp)->words[3]`.
#[inline(always)]
fn tcp_flag_word(tcp: *mut tcphdr) -> *mut u32 {
    byte_add(tcp as *mut u8, 12) as *mut u32
}

#[inline(always)]
fn ipv4_ihl(ip: *const iphdr) -> u8 {
    unsafe { (*ip).ihl_version & 0x0f }
}

// ---- checksums ---------------------------------------------------------

#[inline(always)]
fn csum_fold(csum: u32) -> u16 {
    let csum = (csum & 0xffff) + (csum >> 16);
    let csum = (csum & 0xffff) + (csum >> 16);
    !csum as u16
}

#[inline(always)]
fn csum_tcpudp_magic(saddr: u32, daddr: u32, len: u32, proto: u8, csum: u32) -> u16 {
    let mut s: u64 = csum as u64;

    s += saddr as u64;
    s += daddr as u64;
    s += ((proto as u32).wrapping_add(len) << 8) as u64;
    s = (s & 0xffffffff) + (s >> 32);
    s = (s & 0xffffffff) + (s >> 32);

    csum_fold(s as u32)
}

#[inline(always)]
fn csum_ipv6_magic(saddr: *const [u32; 4], daddr: *const [u32; 4], len: u32, proto: u8, csum: u32) -> u16 {
    let mut sum: u64 = csum as u64;

    let mut i = 0usize;
    while i < 4 {
        sum += unsafe { (*saddr)[i] } as u64;
        i += 1;
    }

    let mut i = 0usize;
    while i < 4 {
        sum += unsafe { (*daddr)[i] } as u64;
        i += 1;
    }

    /* Don't combine additions to avoid 32-bit overflow. */
    sum += len.to_be() as u64;
    sum += (proto as u32).to_be() as u64;

    sum = (sum & 0xffffffff) + (sum >> 32);
    sum = (sum & 0xffffffff) + (sum >> 32);

    csum_fold(sum as u32)
}

#[inline(always)]
fn tcp_clock_ns() -> u64 {
    bpf_ktime_get_ns()
}

#[inline(always)]
fn tcp_ns_to_ts(ns: u64) -> u32 {
    (ns / (NSEC_PER_SEC / TCP_TS_HZ)) as u32
}

#[inline(always)]
fn tcp_clock_ms() -> u32 {
    tcp_ns_to_ts(tcp_clock_ns())
}

// ---- TCP option parsing (bpf_loop callback) ----------------------------

#[repr(C)]
struct tcpopt_context {
    data: *mut u8,
    data_end: *mut u8,
    tsecr: *mut u32,
    wscale: u8,
    option_timestamp: bool,
    option_sack: bool,
    _pad: u8,
    off: u32,
}

#[inline(always)]
fn next(ctx: &mut tcpopt_context, sz: u32) -> *mut u8 {
    let off = ctx.off as u64;

    /* Verifier forbids access to packet when offset exceeds MAX_PACKET_OFF */
    if off > MAX_PACKET_OFF - sz as u64 {
        return null_mut();
    }

    let mut data = byte_add(ctx.data, off as usize);
    helpers::sink(&mut data);
    if byte_add(data, sz as usize) >= ctx.data_end {
        return null_mut();
    }

    ctx.off += sz;
    data
}

#[inline(always)]
fn tscookie_tcpopt_parse(ctx: &mut tcpopt_context) -> i32 {
    let off = ctx.off;

    let opcode = next(ctx, 1);
    if opcode.is_null() {
        return 1;
    }
    let opcode = unsafe { *opcode };

    if opcode == TCPOPT_EOL {
        return 1;
    }
    if opcode == TCPOPT_NOP {
        return 0;
    }

    let opsize = next(ctx, 1);
    if opsize.is_null() {
        return 1;
    }
    let opsize = unsafe { *opsize };
    if opsize < 2 {
        return 1;
    }

    if opcode == TCPOPT_WINDOW {
        let wscale = next(ctx, 1);
        if wscale.is_null() {
            return 1;
        }
        if opsize == TCPOLEN_WINDOW {
            let w = unsafe { *wscale };
            ctx.wscale = if w < TCP_MAX_WSCALE { w } else { TCP_MAX_WSCALE };
        }
    } else if opcode == TCPOPT_TIMESTAMP {
        let tsecr = next(ctx, 4);
        if tsecr.is_null() {
            return 1;
        }
        if opsize == TCPOLEN_TIMESTAMP {
            ctx.option_timestamp = true;
            /* Client's tsval becomes our tsecr. */
            unsafe { *ctx.tsecr = get_unaligned_be32(tsecr) };
        }
    } else if opcode == TCPOPT_SACK_PERM {
        if opsize == TCPOLEN_SACK_PERM {
            ctx.option_sack = true;
        }
    }

    ctx.off = off + opsize as u32;

    0
}

#[inline(never)]
#[export_name = "tscookie_tcpopt_parse_batch"]
extern "C" fn tscookie_tcpopt_parse_batch(_index: u64, context: *mut tcpopt_context) -> i64 {
    let ctx = unsafe { &mut *context };
    let mut i = 0i32;

    while i < 7 {
        if tscookie_tcpopt_parse(ctx) != 0 {
            return 1;
        }
        i += 1;
    }
    0
}

#[inline(always)]
fn tscookie_init(
    tcp_header: *mut tcphdr,
    _tcp_len: u16,
    tsval: *mut u32,
    tsecr: *mut u32,
    data: *mut u8,
    data_end: *mut u8,
) -> bool {
    let mut loop_ctx = tcpopt_context {
        data,
        data_end,
        tsecr,
        wscale: TS_OPT_WSCALE_MASK as u8,
        option_timestamp: false,
        option_sack: false,
        _pad: 0,
        /* Note: currently verifier would track .off as unbound scalar.
         *       In case if verifier would at some point get smarter and
         *       compute bounded value for this var, beware that it might
         *       hinder bpf_loop() convergence validation.
         */
        off: (byte_add(tcp_header as *mut u8, size_of::<tcphdr>()) as usize - data as usize) as u32,
    };

    bpf_loop(6, tscookie_tcpopt_parse_batch, &mut loop_ctx as *mut tcpopt_context, 0);

    if !loop_ctx.option_timestamp {
        return false;
    }

    let mut cookie: u32 = tcp_clock_ms() & !TSMASK;
    cookie |= loop_ctx.wscale as u32 & TS_OPT_WSCALE_MASK;
    if loop_ctx.option_sack {
        cookie |= TS_OPT_SACK;
    }
    let flags = tcp_flags(tcp_header);
    if flags & TCPF_ECE != 0 && flags & TCPF_CWR != 0 {
        cookie |= TS_OPT_ECN;
    }
    unsafe { *tsval = cookie.to_be() };

    true
}

// ---- the `values` and `allowed_ports` maps -----------------------------

/// (mss, wscale, ttl)
#[inline(always)]
fn values_get_tcpipopts(ipv6: bool) -> (u16, u8, u8) {
    let key: u32 = 0;

    let value = bpf_map_lookup_elem(&values, &key) as *mut u64;
    if !value.is_null() && unsafe { *value } != 0 {
        let v = unsafe { *value };
        let mss = if ipv6 { (v >> 32) as u16 } else { v as u16 };
        let wscale = ((v >> 16) & 0xf) as u8;
        let ttl = (v >> 24) as u8;
        return (mss, wscale, ttl);
    }

    (if ipv6 { DEFAULT_MSS6 } else { DEFAULT_MSS4 }, DEFAULT_WSCALE, DEFAULT_TTL)
}

#[inline(always)]
fn values_inc_synacks() {
    let key: u32 = 1;

    let value = bpf_map_lookup_elem(&values, &key) as *mut u64;
    if !value.is_null() {
        sync_fetch_and_add_u64(value, 1);
    }
}

#[inline(always)]
fn check_port_allowed(port: u16) -> bool {
    let mut i: u32 = 0;

    while i < MAX_ALLOWED_PORTS {
        let key: u32 = i;

        let value = bpf_map_lookup_elem(&allowed_ports, &key) as *mut u16;

        if value.is_null() {
            break;
        }
        /* 0 is a terminator value. Check it first to avoid matching on
         * a forbidden port == 0 and returning true.
         */
        let v = unsafe { *value };
        if v == 0 {
            break;
        }

        if v == port {
            return true;
        }
        i += 1;
    }

    false
}

// ---- header dissection and conntrack lookup ----------------------------

struct header_pointers {
    eth: *mut ethhdr,
    ipv4: *mut iphdr,
    ipv6: *mut ipv6hdr,
    tcp: *mut tcphdr,
    tcp_len: u16,
}

#[inline(always)]
fn tcp_dissect(data: *mut u8, data_end: *mut u8, hdr: &mut header_pointers) -> i32 {
    hdr.eth = data as *mut ethhdr;
    if byte_add(hdr.eth as *mut u8, size_of::<ethhdr>()) > data_end {
        return XDP_DROP;
    }

    let proto = u16::from_be(unsafe { (*hdr.eth).h_proto });
    if proto == ETH_P_IP {
        hdr.ipv6 = null_mut();

        hdr.ipv4 = byte_add(hdr.eth as *mut u8, size_of::<ethhdr>()) as *mut iphdr;
        if byte_add(hdr.ipv4 as *mut u8, size_of::<iphdr>()) > data_end {
            return XDP_DROP;
        }
        if (ipv4_ihl(hdr.ipv4) as usize) * 4 < size_of::<iphdr>() {
            return XDP_DROP;
        }
        if unsafe { (*hdr.ipv4).ihl_version } >> 4 != 4 {
            return XDP_DROP;
        }

        if unsafe { (*hdr.ipv4).protocol } != IPPROTO_TCP {
            return XDP_PASS;
        }

        hdr.tcp = byte_add(hdr.ipv4 as *mut u8, (ipv4_ihl(hdr.ipv4) as usize) * 4) as *mut tcphdr;
    } else if proto == ETH_P_IPV6 {
        hdr.ipv4 = null_mut();

        hdr.ipv6 = byte_add(hdr.eth as *mut u8, size_of::<ethhdr>()) as *mut ipv6hdr;
        if byte_add(hdr.ipv6 as *mut u8, size_of::<ipv6hdr>()) > data_end {
            return XDP_DROP;
        }
        if unsafe { (*hdr.ipv6).priority_version } >> 4 != 6 {
            return XDP_DROP;
        }

        /* XXX: Extension headers are not supported and could circumvent
         * XDP SYN flood protection.
         */
        if unsafe { (*hdr.ipv6).nexthdr } != NEXTHDR_TCP {
            return XDP_PASS;
        }

        hdr.tcp = byte_add(hdr.ipv6 as *mut u8, size_of::<ipv6hdr>()) as *mut tcphdr;
    } else {
        /* XXX: VLANs will circumvent XDP SYN flood protection. */
        return XDP_PASS;
    }

    if byte_add(hdr.tcp as *mut u8, size_of::<tcphdr>()) > data_end {
        return XDP_DROP;
    }
    hdr.tcp_len = tcp_doff(hdr.tcp) as u16 * 4;
    if (hdr.tcp_len as usize) < size_of::<tcphdr>() {
        return XDP_DROP;
    }

    XDP_TX
}

#[inline(always)]
fn tcp_lookup<const XDP: bool>(ctx: *mut c_void, hdr: &mut header_pointers) -> i32 {
    let mut ct_lookup_opts = bpf_ct_opts___local {
        netns_id: BPF_F_CURRENT_NETNS,
        error: 0,
        l4proto: IPPROTO_TCP,
        dir: 0,
        reserved: [0; 2],
    };
    let mut tup: bpf_sock_tuple = unsafe { core::mem::zeroed() };
    let tup_size: u32;

    if !hdr.ipv4.is_null() {
        /* TCP doesn't normally use fragments, and XDP can't reassemble
         * them.
         */
        if unsafe { (*hdr.ipv4).frag_off } & (IP_MF | IP_OFFSET).to_be() != 0 {
            return XDP_DROP;
        }

        unsafe {
            tup.ipv4.saddr = (*hdr.ipv4).saddr;
            tup.ipv4.daddr = (*hdr.ipv4).daddr;
            tup.ipv4.sport = (*hdr.tcp).source;
            tup.ipv4.dport = (*hdr.tcp).dest;
        }
        tup_size = size_of::<bpf_sock_tuple_v4>() as u32;
    } else if !hdr.ipv6.is_null() {
        unsafe {
            vcopy32(tup.ipv6.saddr.as_mut_ptr(), (*hdr.ipv6).saddr.as_ptr(), 4);
            vcopy32(tup.ipv6.daddr.as_mut_ptr(), (*hdr.ipv6).daddr.as_ptr(), 4);
            tup.ipv6.sport = (*hdr.tcp).source;
            tup.ipv6.dport = (*hdr.tcp).dest;
        }
        tup_size = size_of::<bpf_sock_tuple_v6>() as u32;
    } else {
        /* The verifier can't track that either ipv4 or ipv6 is not
         * NULL.
         */
        return XDP_ABORTED;
    }
    let ct = unsafe {
        if XDP {
            bpf_xdp_ct_lookup(
                ctx,
                &mut tup as *mut bpf_sock_tuple as *mut c_void,
                tup_size,
                &mut ct_lookup_opts as *mut bpf_ct_opts___local as *mut c_void,
                size_of::<bpf_ct_opts___local>() as u32,
            )
        } else {
            bpf_skb_ct_lookup(
                ctx,
                &mut tup as *mut bpf_sock_tuple as *mut c_void,
                tup_size,
                &mut ct_lookup_opts as *mut bpf_ct_opts___local as *mut c_void,
                size_of::<bpf_ct_opts___local>() as u32,
            )
        }
    };
    if !ct.is_null() {
        let status = ct_status_get(ct as *const nf_conn);

        unsafe { bpf_ct_release(ct) };
        if status & IPS_CONFIRMED != 0 {
            return XDP_PASS;
        }
    } else if ct_lookup_opts.error != -ENOENT {
        return XDP_ABORTED;
    }

    /* error == -ENOENT || !(status & IPS_CONFIRMED) */
    XDP_TX
}

// ---- SYNACK generation -------------------------------------------------

#[inline(always)]
fn tcp_mkoptions(buf: *mut u32, tsopt: *mut u32, mss: u16, wscale: u8) -> u8 {
    let start = buf;
    let mut buf = buf;

    unsafe {
        *buf = ((TCPOPT_MSS << 24) | (TCPOLEN_MSS << 16) | mss as u32).to_be();
        buf = buf.add(1);
    }

    if tsopt.is_null() {
        return ((buf as usize - start as usize) / 4) as u8;
    }

    unsafe {
        if *tsopt & (1u32 << 4).to_be() != 0 {
            *buf = (((TCPOPT_SACK_PERM as u32) << 24)
                | ((TCPOLEN_SACK_PERM as u32) << 16)
                | ((TCPOPT_TIMESTAMP as u32) << 8)
                | TCPOLEN_TIMESTAMP as u32)
                .to_be();
        } else {
            *buf = (((TCPOPT_NOP as u32) << 24)
                | ((TCPOPT_NOP as u32) << 16)
                | ((TCPOPT_TIMESTAMP as u32) << 8)
                | TCPOLEN_TIMESTAMP as u32)
                .to_be();
        }
        buf = buf.add(1);
        *buf = *tsopt;
        buf = buf.add(1);
        *buf = *tsopt.add(1);
        buf = buf.add(1);

        if *tsopt & 0xfu32.to_be() != 0xfu32.to_be() {
            *buf = (((TCPOPT_NOP as u32) << 24)
                | ((TCPOPT_WINDOW as u32) << 16)
                | ((TCPOLEN_WINDOW as u32) << 8)
                | wscale as u32)
                .to_be();
            buf = buf.add(1);
        }
    }

    ((buf as usize - start as usize) / 4) as u8
}

#[inline(always)]
fn tcp_gen_synack(tcp_header: *mut tcphdr, cookie: u32, tsopt: *mut u32, mss: u16, wscale: u8) {
    unsafe {
        *tcp_flag_word(tcp_header) = TCP_FLAG_SYN | TCP_FLAG_ACK;
        if !tsopt.is_null() && *tsopt & (1u32 << 5).to_be() != 0 {
            *tcp_flag_word(tcp_header) |= TCP_FLAG_ECE;
        }
        tcp_set_doff(tcp_header, 5); /* doff is part of tcp_flag_word. */
        let tmp = (*tcp_header).source;
        (*tcp_header).source = (*tcp_header).dest;
        (*tcp_header).dest = tmp;
        (*tcp_header).ack_seq = u32::from_be((*tcp_header).seq).wrapping_add(1).to_be();
        (*tcp_header).seq = cookie.to_be();
        (*tcp_header).window = 0;
        (*tcp_header).urg_ptr = 0;
        (*tcp_header).check = 0; /* Calculate checksum later. */

        let tcp_options = byte_add(tcp_header as *mut u8, size_of::<tcphdr>()) as *mut u32;
        let n = tcp_mkoptions(tcp_options, tsopt, mss, wscale);
        tcp_set_doff(tcp_header, tcp_doff(tcp_header) + n);
    }
}

#[inline(always)]
fn tcpv4_gen_synack(hdr: &mut header_pointers, cookie: u32, tsopt: *mut u32) {
    let (mss, wscale, ttl) = values_get_tcpipopts(false);

    unsafe {
        swap_eth_addr((*hdr.eth).h_source.as_mut_ptr(), (*hdr.eth).h_dest.as_mut_ptr());

        let tmp = (*hdr.ipv4).saddr;
        (*hdr.ipv4).saddr = (*hdr.ipv4).daddr;
        (*hdr.ipv4).daddr = tmp;
        (*hdr.ipv4).check = 0; /* Calculate checksum later. */
        (*hdr.ipv4).tos = 0;
        (*hdr.ipv4).id = 0;
        (*hdr.ipv4).ttl = ttl;
    }

    tcp_gen_synack(hdr.tcp, cookie, tsopt, mss, wscale);

    hdr.tcp_len = tcp_doff(hdr.tcp) as u16 * 4;
    unsafe { (*hdr.ipv4).tot_len = (size_of::<iphdr>() as u16 + hdr.tcp_len).to_be() };
}

#[inline(always)]
fn tcpv6_gen_synack(hdr: &mut header_pointers, cookie: u32, tsopt: *mut u32) {
    let (mss, wscale, ttl) = values_get_tcpipopts(true);

    unsafe {
        swap_eth_addr((*hdr.eth).h_source.as_mut_ptr(), (*hdr.eth).h_dest.as_mut_ptr());

        vswap32((*hdr.ipv6).saddr.as_mut_ptr(), (*hdr.ipv6).daddr.as_mut_ptr(), 4);
        *(hdr.ipv6 as *mut u32) = 0x60000000u32.to_be();
        (*hdr.ipv6).hop_limit = ttl;
    }

    tcp_gen_synack(hdr.tcp, cookie, tsopt, mss, wscale);

    hdr.tcp_len = tcp_doff(hdr.tcp) as u16 * 4;
    unsafe { (*hdr.ipv6).payload_len = hdr.tcp_len.to_be() };
}

#[inline(always)]
fn syncookie_handle_syn<const XDP: bool>(
    hdr: &mut header_pointers,
    ctx: *mut c_void,
    data: *mut u8,
    data_end: *mut u8,
) -> i32 {
    /* Unlike clang 10, clang 11 and 12 generate code that doesn't pass the
     * BPF verifier if tsopt is not volatile. Volatile forces it to store
     * the pointer value and use it directly, otherwise tcp_mkoptions is
     * (mis)compiled like this:
     *   if (!tsopt)
     *       return buf - start;
     *   reg = stored_return_value_of_tscookie_init;
     *   if (reg)
     *       tsopt = tsopt_buf;
     *   else
     *       tsopt = NULL;
     *   ...
     *   *buf++ = tsopt[1];
     * It creates a dead branch where tsopt is assigned NULL, but the
     * verifier can't prove it's dead and blocks the program.
     */
    let mut tsopt_slot: *mut u32 = null_mut();
    unsafe { write_volatile(&mut tsopt_slot, null_mut()) };
    let mut tsopt_buf: [u32; 2] = [0; 2];
    let ip_len: u16;
    let cookie: u32;
    let mut value: i64;

    /* Checksum is not yet verified, but both checksum failure and TCP
     * header checks return XDP_DROP, so the order doesn't matter.
     */
    if tcp_flags(hdr.tcp) & (TCPF_FIN | TCPF_RST) != 0 {
        return XDP_DROP;
    }

    /* Issue SYN cookies on allowed ports, drop SYN packets on blocked
     * ports.
     */
    if !check_port_allowed(u16::from_be(unsafe { (*hdr.tcp).dest })) {
        return XDP_DROP;
    }

    if !hdr.ipv4.is_null() {
        /* Check the IPv4 and TCP checksums before creating a SYNACK. */
        value = bpf_csum_diff(
            core::ptr::null(),
            0,
            hdr.ipv4 as *const c_void,
            ipv4_ihl(hdr.ipv4) as u32 * 4,
            0,
        );
        if value < 0 {
            return XDP_ABORTED;
        }
        if csum_fold(value as u32) != 0 {
            return XDP_DROP; /* Bad IPv4 checksum. */
        }

        value = bpf_csum_diff(core::ptr::null(), 0, hdr.tcp as *const c_void, hdr.tcp_len as u32, 0);
        if value < 0 {
            return XDP_ABORTED;
        }
        if csum_tcpudp_magic(
            unsafe { (*hdr.ipv4).saddr },
            unsafe { (*hdr.ipv4).daddr },
            hdr.tcp_len as u32,
            IPPROTO_TCP,
            value as u32,
        ) != 0
        {
            return XDP_DROP; /* Bad TCP checksum. */
        }

        ip_len = size_of::<iphdr>() as u16;

        value = bpf_tcp_raw_gen_syncookie_ipv4(hdr.ipv4, hdr.tcp, hdr.tcp_len as u32);
    } else if !hdr.ipv6.is_null() {
        /* Check the TCP checksum before creating a SYNACK. */
        value = bpf_csum_diff(core::ptr::null(), 0, hdr.tcp as *const c_void, hdr.tcp_len as u32, 0);
        if value < 0 {
            return XDP_ABORTED;
        }
        if csum_ipv6_magic(
            unsafe { &(*hdr.ipv6).saddr },
            unsafe { &(*hdr.ipv6).daddr },
            hdr.tcp_len as u32,
            IPPROTO_TCP,
            value as u32,
        ) != 0
        {
            return XDP_DROP; /* Bad TCP checksum. */
        }

        ip_len = size_of::<ipv6hdr>() as u16;

        value = bpf_tcp_raw_gen_syncookie_ipv6(hdr.ipv6, hdr.tcp, hdr.tcp_len as u32);
    } else {
        return XDP_ABORTED;
    }

    if value < 0 {
        return XDP_ABORTED;
    }
    cookie = value as u32;

    if tscookie_init(
        hdr.tcp,
        hdr.tcp_len,
        &mut tsopt_buf[0],
        &mut tsopt_buf[1],
        data,
        data_end,
    ) {
        unsafe { write_volatile(&mut tsopt_slot, tsopt_buf.as_mut_ptr()) };
    }

    /* Check that there is enough space for a SYNACK. It also covers
     * the check that the destination of the __builtin_memmove below
     * doesn't overflow.
     */
    if byte_add(data, size_of::<ethhdr>() + ip_len as usize + TCP_MAXLEN) > data_end {
        return XDP_ABORTED;
    }

    if !hdr.ipv4.is_null() {
        if (ipv4_ihl(hdr.ipv4) as usize) * 4 > size_of::<iphdr>() {
            let new_tcp_header =
                byte_add(data, size_of::<ethhdr>() + size_of::<iphdr>()) as *mut tcphdr;
            // __builtin_memmove(new_tcp_header, hdr->tcp, sizeof(*hdr->tcp)):
            // the destination is below the source, so a forward word copy
            // is the memmove.
            unsafe { vcopy32(new_tcp_header as *mut u32, hdr.tcp as *const u32, 5) };
            hdr.tcp = new_tcp_header;

            unsafe {
                (*hdr.ipv4).ihl_version =
                    ((*hdr.ipv4).ihl_version & 0xf0) | (size_of::<iphdr>() / 4) as u8;
            }
        }

        let tsopt = unsafe { read_volatile(&tsopt_slot) };
        tcpv4_gen_synack(hdr, cookie, tsopt);
    } else if !hdr.ipv6.is_null() {
        let tsopt = unsafe { read_volatile(&tsopt_slot) };
        tcpv6_gen_synack(hdr, cookie, tsopt);
    } else {
        return XDP_ABORTED;
    }

    /* Recalculate checksums. */
    unsafe { (*hdr.tcp).check = 0 };
    value = bpf_csum_diff(core::ptr::null(), 0, hdr.tcp as *const c_void, hdr.tcp_len as u32, 0);
    if value < 0 {
        return XDP_ABORTED;
    }
    if !hdr.ipv4.is_null() {
        unsafe {
            (*hdr.tcp).check = csum_tcpudp_magic(
                (*hdr.ipv4).saddr,
                (*hdr.ipv4).daddr,
                hdr.tcp_len as u32,
                IPPROTO_TCP,
                value as u32,
            );

            (*hdr.ipv4).check = 0;
        }
        value = bpf_csum_diff(
            core::ptr::null(),
            0,
            hdr.ipv4 as *const c_void,
            size_of::<iphdr>() as u32,
            0,
        );
        if value < 0 {
            return XDP_ABORTED;
        }
        unsafe { (*hdr.ipv4).check = csum_fold(value as u32) };
    } else if !hdr.ipv6.is_null() {
        unsafe {
            (*hdr.tcp).check = csum_ipv6_magic(
                &(*hdr.ipv6).saddr,
                &(*hdr.ipv6).daddr,
                hdr.tcp_len as u32,
                IPPROTO_TCP,
                value as u32,
            );
        }
    } else {
        return XDP_ABORTED;
    }

    /* Set the new packet size. */
    let old_pkt_size: u32 = (data_end as usize - data as usize) as u32;
    let new_pkt_size: u32 =
        (size_of::<ethhdr>() + ip_len as usize) as u32 + tcp_doff(hdr.tcp) as u32 * 4;
    if XDP {
        if bpf_xdp_adjust_tail(ctx as *mut xdp_md, new_pkt_size.wrapping_sub(old_pkt_size) as i32)
            != 0
        {
            return XDP_ABORTED;
        }
    } else {
        if bpf_skb_change_tail(ctx as *const c_void, new_pkt_size, 0) != 0 {
            return XDP_ABORTED;
        }
    }

    values_inc_synacks();

    XDP_TX
}

#[inline(always)]
fn syncookie_handle_ack(hdr: &mut header_pointers) -> i32 {
    let err: i64;

    if tcp_flags(hdr.tcp) & TCPF_RST != 0 {
        return XDP_DROP;
    }

    if !hdr.ipv4.is_null() {
        err = bpf_tcp_raw_check_syncookie_ipv4(hdr.ipv4, hdr.tcp);
    } else if !hdr.ipv6.is_null() {
        err = bpf_tcp_raw_check_syncookie_ipv6(hdr.ipv6, hdr.tcp);
    } else {
        return XDP_ABORTED;
    }
    if err != 0 {
        return XDP_DROP;
    }

    XDP_PASS
}

#[inline(always)]
fn syncookie_part1<const XDP: bool>(
    ctx: *mut c_void,
    data: *mut u8,
    data_end: *mut u8,
    hdr: &mut header_pointers,
) -> i32 {
    let ret = tcp_dissect(data, data_end, hdr);
    if ret != XDP_TX {
        return ret;
    }

    let ret = tcp_lookup::<XDP>(ctx, hdr);
    if ret != XDP_TX {
        return ret;
    }

    /* Packet is TCP and doesn't belong to an established connection. */

    let flags = tcp_flags(hdr.tcp);
    if ((flags & TCPF_SYN) >> 1) ^ ((flags & TCPF_ACK) >> 4) != 1 {
        return XDP_DROP;
    }

    /* Grow the TCP header to TCP_MAXLEN to be able to pass any hdr->tcp_len
     * to bpf_tcp_raw_gen_syncookie_ipv{4,6} and pass the verifier.
     */
    if XDP {
        if bpf_xdp_adjust_tail(ctx as *mut xdp_md, TCP_MAXLEN as i32 - hdr.tcp_len as i32) != 0 {
            return XDP_ABORTED;
        }
    } else {
        /* Without volatile the verifier throws this error:
         * R9 32-bit pointer arithmetic prohibited
         */
        let mut old_len: u64 = (data_end as usize - data as usize) as u64;
        unsafe {
            write_volatile(&mut old_len, old_len);
            old_len = read_volatile(&old_len);
        }

        if bpf_skb_change_tail(
            ctx as *const c_void,
            (old_len + TCP_MAXLEN as u64 - hdr.tcp_len as u64) as u32,
            0,
        ) != 0
        {
            return XDP_ABORTED;
        }
    }

    XDP_TX
}

#[inline(always)]
fn syncookie_part2<const XDP: bool>(
    ctx: *mut c_void,
    data: *mut u8,
    data_end: *mut u8,
    hdr: &mut header_pointers,
) -> i32 {
    if !hdr.ipv4.is_null() {
        hdr.eth = data as *mut ethhdr;
        hdr.ipv4 = byte_add(hdr.eth as *mut u8, size_of::<ethhdr>()) as *mut iphdr;
        /* IPV4_MAXLEN is needed when calculating checksum.
         * At least sizeof(struct iphdr) is needed here to access ihl.
         */
        if byte_add(hdr.ipv4 as *mut u8, IPV4_MAXLEN) > data_end {
            return XDP_ABORTED;
        }
        hdr.tcp = byte_add(hdr.ipv4 as *mut u8, (ipv4_ihl(hdr.ipv4) as usize) * 4) as *mut tcphdr;
    } else if !hdr.ipv6.is_null() {
        hdr.eth = data as *mut ethhdr;
        hdr.ipv6 = byte_add(hdr.eth as *mut u8, size_of::<ethhdr>()) as *mut ipv6hdr;
        hdr.tcp = byte_add(hdr.ipv6 as *mut u8, size_of::<ipv6hdr>()) as *mut tcphdr;
    } else {
        return XDP_ABORTED;
    }

    if byte_add(hdr.tcp as *mut u8, TCP_MAXLEN) > data_end {
        return XDP_ABORTED;
    }

    /* We run out of registers, tcp_len gets spilled to the stack, and the
     * verifier forgets its min and max values checked above in tcp_dissect.
     */
    hdr.tcp_len = tcp_doff(hdr.tcp) as u16 * 4;
    if (hdr.tcp_len as usize) < size_of::<tcphdr>() {
        return XDP_ABORTED;
    }

    if tcp_flags(hdr.tcp) & TCPF_SYN != 0 {
        syncookie_handle_syn::<XDP>(hdr, ctx, data, data_end)
    } else {
        syncookie_handle_ack(hdr)
    }
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn syncookie_xdp(ctx: *mut xdp_md) -> i32 {
    let mut data_end = vload!((*ctx).data_end) as usize as *mut u8;
    let mut data = vload!((*ctx).data) as usize as *mut u8;
    let mut hdr = header_pointers {
        eth: null_mut(),
        ipv4: null_mut(),
        ipv6: null_mut(),
        tcp: null_mut(),
        tcp_len: 0,
    };

    let ret = syncookie_part1::<true>(ctx as *mut c_void, data, data_end, &mut hdr);
    if ret != XDP_TX {
        return ret;
    }

    data_end = vload!((*ctx).data_end) as usize as *mut u8;
    data = vload!((*ctx).data) as usize as *mut u8;

    syncookie_part2::<true>(ctx as *mut c_void, data, data_end, &mut hdr)
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn syncookie_tc(skb: *mut __sk_buff) -> i32 {
    let mut data_end = vload!((*skb).data_end) as usize as *mut u8;
    let mut data = vload!((*skb).data) as usize as *mut u8;
    let mut hdr = header_pointers {
        eth: null_mut(),
        ipv4: null_mut(),
        ipv6: null_mut(),
        tcp: null_mut(),
        tcp_len: 0,
    };

    let ret = syncookie_part1::<false>(skb as *mut c_void, data, data_end, &mut hdr);
    if ret != XDP_TX {
        return if ret == XDP_PASS { TC_ACT_OK } else { TC_ACT_SHOT };
    }

    data_end = vload!((*skb).data_end) as usize as *mut u8;
    data = vload!((*skb).data) as usize as *mut u8;

    let ret = syncookie_part2::<false>(skb as *mut c_void, data, data_end, &mut hdr);
    if ret == XDP_PASS {
        TC_ACT_OK
    } else if ret == XDP_TX {
        bpf_redirect(vload!((*skb).ifindex), 0) as i32
    } else {
        TC_ACT_SHOT
    }
}

bpf_object!("GPL");
