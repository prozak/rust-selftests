#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_tcp_custom_syncookie.c
// (bpf-rs-core idiom).

use core::ffi::c_void;
use core::mem::size_of;

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::{__sk_buff, TC_ACT_OK, TC_ACT_SHOT};
use bpf_rs_core::helpers::{
    self, bpf_csum_diff, bpf_get_prandom_u32, bpf_loop, bpf_redirect, bpf_sk_release,
    bpf_skb_change_tail, bpf_skc_lookup_tcp, bpf_skc_to_tcp_sock,
};
use bpf_rs_core::vload;

const MAX_PACKET_OFF: u32 = 0xffff;

const COOKIE_BITS: u32 = 8;
const COOKIE_MASK: u32 = (1u32 << COOKIE_BITS) - 1;

const BPF_SYNCOOKIE_WSCALE_MASK: u32 = (1 << 4) - 1;
const BPF_SYNCOOKIE_SACK: u32 = 1 << 4;
const BPF_SYNCOOKIE_ECN: u32 = 1 << 5;

const MSS_LOCAL_IPV4: u16 = 65495;
const MSS_LOCAL_IPV6: u16 = 65476;

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const IPPROTO_TCP: u8 = 6;
const NEXTHDR_TCP: u8 = 6;
const TCP_LISTEN: u32 = 10;

const TCPOPT_EOL: u8 = 0;
const TCPOPT_NOP: u8 = 1;
const TCPOPT_MSS: u8 = 2;
const TCPOPT_WINDOW: u8 = 3;
const TCPOPT_SACK_PERM: u8 = 4;
const TCPOPT_TIMESTAMP: u8 = 8;

const TCPOLEN_MSS: u8 = 4;
const TCPOLEN_WINDOW: u8 = 3;
const TCPOLEN_SACK_PERM: u8 = 2;
const TCPOLEN_TIMESTAMP: u8 = 10;

const TCP_FLAG_FIN: u8 = 1 << 0;
const TCP_FLAG_SYN: u8 = 1 << 1;
const TCP_FLAG_RST: u8 = 1 << 2;
const TCP_FLAG_ACK: u8 = 1 << 4;
const TCP_FLAG_ECE: u8 = 1 << 6;
const TCP_FLAG_CWR: u8 = 1 << 7;

const TEST_KEY_SIPHASH: [u64; 2] = [0x0706050403020100, 0x0f0e0d0c0b0a0908];

#[no_mangle]
static mut handled_syn: bool = false;
#[no_mangle]
static mut handled_ack: bool = false;

#[link_section = ".rodata"]
#[no_mangle]
static msstab4: [u16; 4] = [536, 1300, 1460, MSS_LOCAL_IPV4];

#[link_section = ".rodata"]
#[no_mangle]
static msstab6: [u16; 4] = [1280 - 60, 1480 - 60, 9000 - 60, MSS_LOCAL_IPV6];

// struct ethhdr (linux/if_ether.h).
#[repr(C)]
struct EthHdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

// struct iphdr (linux/ip.h); ihl/version packed into the first byte on
// little-endian (ihl low nibble, version high nibble).
#[repr(C)]
struct IpHdr {
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
// byte on little-endian (priority low nibble, version high nibble).
// saddr/daddr kept as the in6_u.u6_addr32 view, the only one this program
// reads (byte 0 of an address is the low byte of its first u32 word).
#[repr(C)]
struct Ipv6Hdr {
    priority_version: u8,
    flow_lbl: [u8; 3],
    payload_len: u16,
    nexthdr: u8,
    hop_limit: u8,
    saddr: [u32; 4],
    daddr: [u32; 4],
}

// struct tcphdr (linux/tcp.h); the res1/doff/flags __u16 bitfield (bytes
// 12-13 on little-endian) split into two plain bytes: byte 12 is
// doff(hi nibble)|res1(lo nibble), byte 13 is
// cwr,ece,urg,ack,psh,rst,syn,fin from MSB to LSB.
#[repr(C)]
struct TcpHdr {
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

// struct bpf_tcp_req_attrs (include/net/tcp.h), passed by raw pointer+size
// to the bpf_sk_assign_tcp_reqsk kfunc.
#[repr(C)]
#[derive(Clone, Copy)]
struct BpfTcpReqAttrs {
    rcv_tsval: u32,
    rcv_tsecr: u32,
    mss: u16,
    rcv_wscale: u8,
    snd_wscale: u8,
    ecn_ok: u8,
    wscale_ok: u8,
    sack_ok: u8,
    tstamp_ok: u8,
    usec_ts_ok: u8,
    reserved: [u8; 3],
}

// struct bpf_sock (UAPI linux/bpf.h): only `state` is read.
#[repr(C)]
struct BpfSock {
    bound_dev_if: u32,
    family: u32,
    type_: u32,
    protocol: u32,
    mark: u32,
    priority: u32,
    src_ip4: u32,
    src_ip6: [u32; 4],
    src_port: u32,
    dst_port: u16,
    _pad: u16,
    dst_ip4: u32,
    dst_ip6: [u32; 4],
    state: u32,
    rx_queue_mapping: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockTupleV4 {
    saddr: u32,
    daddr: u32,
    sport: u16,
    dport: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockTupleV6 {
    saddr: [u32; 4],
    daddr: [u32; 4],
    sport: u16,
    dport: u16,
}

#[repr(C)]
union BpfSockTuple {
    ipv4: SockTupleV4,
    ipv6: SockTupleV6,
}

// struct { u16 }/{ u32 } wrappers used only to force an unaligned load,
// mirroring C's `get_unaligned_be16/32` (a packed-struct pointer cast).
#[repr(C, packed)]
struct Be16Unaligned(u16);
#[repr(C, packed)]
struct Be32Unaligned(u32);

extern "C" {
    fn bpf_sk_assign_tcp_reqsk(
        skb: *mut __sk_buff,
        sk: *mut c_void,
        attrs: *mut BpfTcpReqAttrs,
        attrs_sz: i32,
    ) -> i32;
}

struct TcpSyncookie {
    skb: *const __sk_buff,
    data: *mut u8,
    data_end: *mut u8,
    eth: *mut EthHdr,
    ipv4: *mut IpHdr,
    ipv6: *mut Ipv6Hdr,
    tcp: *mut TcpHdr,
    ptr32: *mut u32,
    attrs: BpfTcpReqAttrs,
    off: u32,
    cookie: u32,
}

#[inline(always)]
fn new_ctx(skb: *const __sk_buff) -> TcpSyncookie {
    TcpSyncookie {
        skb,
        data: core::ptr::null_mut(),
        data_end: core::ptr::null_mut(),
        eth: core::ptr::null_mut(),
        ipv4: core::ptr::null_mut(),
        ipv6: core::ptr::null_mut(),
        tcp: core::ptr::null_mut(),
        ptr32: core::ptr::null_mut(),
        attrs: BpfTcpReqAttrs {
            rcv_tsval: 0,
            rcv_tsecr: 0,
            mss: 0,
            rcv_wscale: 0,
            snd_wscale: 0,
            ecn_ok: 0,
            wscale_ok: 0,
            sack_ok: 0,
            tstamp_ok: 0,
            usec_ts_ok: 0,
            reserved: [0; 3],
        },
        off: 0,
        cookie: 0,
    }
}

#[inline(always)]
fn byte_add(p: *mut u8, n: usize) -> *mut u8 {
    unsafe { p.add(n) }
}

// Byte-at-a-time volatile copy/swap: LLVM's MemCpyOpt recognizes whole-array
// or whole-struct value copies (even a single `let tmp = *p; *p = *q; *q =
// tmp;` on a `[u32; 4]`) as memcpy-shaped and rewrites them into a call to
// an extern `bpf_arena_memcpy` kfunc, which only exists in arena-program
// BTF and fails "not found in kernel or module BTFs" for a plain TC prog.
// Volatile per-byte access is the one pattern the optimizer won't merge
// back into a memcpy call.
#[inline(always)]
unsafe fn vcopy(dst: *mut u8, src: *const u8, len: usize) {
    let mut i = 0usize;
    while i < len {
        core::ptr::write_volatile(dst.add(i), core::ptr::read_volatile(src.add(i)));
        i += 1;
    }
}

#[inline(always)]
unsafe fn vswap(a: *mut u8, b: *mut u8, len: usize) {
    let mut i = 0usize;
    while i < len {
        let ta = core::ptr::read_volatile(a.add(i));
        let tb = core::ptr::read_volatile(b.add(i));
        core::ptr::write_volatile(a.add(i), tb);
        core::ptr::write_volatile(b.add(i), ta);
        i += 1;
    }
}

// ---- tcphdr flag/doff accessors -------------------------------------

#[inline(always)]
fn tcp_rst(tcp: *const TcpHdr) -> bool {
    unsafe { (*tcp).flags & TCP_FLAG_RST != 0 }
}
#[inline(always)]
fn tcp_syn_flag(tcp: *const TcpHdr) -> bool {
    unsafe { (*tcp).flags & TCP_FLAG_SYN != 0 }
}
#[inline(always)]
fn tcp_ack_flag(tcp: *const TcpHdr) -> bool {
    unsafe { (*tcp).flags & TCP_FLAG_ACK != 0 }
}
#[inline(always)]
fn tcp_ece(tcp: *const TcpHdr) -> bool {
    unsafe { (*tcp).flags & TCP_FLAG_ECE != 0 }
}
#[inline(always)]
fn tcp_cwr(tcp: *const TcpHdr) -> bool {
    unsafe { (*tcp).flags & TCP_FLAG_CWR != 0 }
}

#[inline(always)]
fn set_tcp_ack(tcp: *mut TcpHdr, v: bool) {
    unsafe {
        if v {
            (*tcp).flags |= TCP_FLAG_ACK;
        } else {
            (*tcp).flags &= !TCP_FLAG_ACK;
        }
    }
}
#[inline(always)]
fn set_tcp_ece(tcp: *mut TcpHdr, v: bool) {
    unsafe {
        if v {
            (*tcp).flags |= TCP_FLAG_ECE;
        } else {
            (*tcp).flags &= !TCP_FLAG_ECE;
        }
    }
}
#[inline(always)]
fn set_tcp_cwr(tcp: *mut TcpHdr, v: bool) {
    unsafe {
        if v {
            (*tcp).flags |= TCP_FLAG_CWR;
        } else {
            (*tcp).flags &= !TCP_FLAG_CWR;
        }
    }
}

#[inline(always)]
fn get_tcp_doff(tcp: *const TcpHdr) -> u8 {
    unsafe { (*tcp).doff_res1 >> 4 }
}
#[inline(always)]
fn set_tcp_doff(tcp: *mut TcpHdr, doff: u8) {
    unsafe {
        (*tcp).doff_res1 = ((*tcp).doff_res1 & 0x0F) | (doff << 4);
    }
}

#[inline(always)]
fn get_unaligned_be16(p: *const u8) -> u16 {
    u16::from_be(unsafe { (*(p as *const Be16Unaligned)).0 })
}
#[inline(always)]
fn get_unaligned_be32(p: *const u8) -> u32 {
    u32::from_be(unsafe { (*(p as *const Be32Unaligned)).0 })
}

// ---- lib/checksum.c + asm-generic/checksum.h + net/ipv6/ip6_checksum.c

#[inline(always)]
fn from64to32(x: u64) -> u32 {
    let x = (x & 0xffffffff) + (x >> 32);
    let x = (x & 0xffffffff) + (x >> 32);
    x as u32
}

#[inline(always)]
fn csum_tcpudp_nofold(saddr: u32, daddr: u32, len: u32, proto: u8, sum: u32) -> u32 {
    let mut s: u64 = sum as u64;
    s += saddr as u64;
    s += daddr as u64;
    s += ((proto as u32) + len) as u64 * 256;
    from64to32(s)
}

#[inline(always)]
fn csum_fold(csum: u32) -> u16 {
    let mut sum = csum;
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    (!sum) as u16
}

#[inline(always)]
fn csum_tcpudp_magic(saddr: u32, daddr: u32, len: u32, proto: u8, sum: u32) -> u16 {
    csum_fold(csum_tcpudp_nofold(saddr, daddr, len, proto, sum))
}

#[inline(always)]
fn csum_ipv6_magic(saddr: &[u32; 4], daddr: &[u32; 4], len: u32, proto: u8, csum: u32) -> u16 {
    let mut sum = csum;

    let (s, c) = sum.overflowing_add(saddr[0]);
    sum = s.wrapping_add(c as u32);
    let (s, c) = sum.overflowing_add(saddr[1]);
    sum = s.wrapping_add(c as u32);
    let (s, c) = sum.overflowing_add(saddr[2]);
    sum = s.wrapping_add(c as u32);
    let (s, c) = sum.overflowing_add(saddr[3]);
    sum = s.wrapping_add(c as u32);

    let (s, c) = sum.overflowing_add(daddr[0]);
    sum = s.wrapping_add(c as u32);
    let (s, c) = sum.overflowing_add(daddr[1]);
    sum = s.wrapping_add(c as u32);
    let (s, c) = sum.overflowing_add(daddr[2]);
    sum = s.wrapping_add(c as u32);
    let (s, c) = sum.overflowing_add(daddr[3]);
    sum = s.wrapping_add(c as u32);

    let ulen = len.to_be();
    let (s, c) = sum.overflowing_add(ulen);
    sum = s.wrapping_add(c as u32);

    let uproto = (proto as u32).to_be();
    let (s, c) = sum.overflowing_add(uproto);
    sum = s.wrapping_add(c as u32);

    csum_fold(sum)
}

#[inline(always)]
fn tcp_v4_csum(ctx: &TcpSyncookie, csum: u32) -> u16 {
    let saddr = unsafe { (*ctx.ipv4).saddr };
    let daddr = unsafe { (*ctx.ipv4).daddr };
    let doff = get_tcp_doff(ctx.tcp) as u32;
    csum_tcpudp_magic(saddr, daddr, doff * 4, IPPROTO_TCP, csum)
}

#[inline(always)]
fn tcp_v6_csum(ctx: &TcpSyncookie, csum: u32) -> u16 {
    let saddr = unsafe { (*ctx.ipv6).saddr };
    let daddr = unsafe { (*ctx.ipv6).daddr };
    let doff = get_tcp_doff(ctx.tcp) as u32;
    csum_ipv6_magic(&saddr, &daddr, doff * 4, IPPROTO_TCP, csum)
}

// ---- lib/siphash.c ----------------------------------------------------

const SIPHASH_CONST_0: u64 = 0x736f6d6570736575;
const SIPHASH_CONST_1: u64 = 0x646f72616e646f6d;
const SIPHASH_CONST_2: u64 = 0x6c7967656e657261;
const SIPHASH_CONST_3: u64 = 0x7465646279746573;

#[inline(always)]
fn rol64(word: u64, shift: u32) -> u64 {
    word.rotate_left(shift & 63)
}

macro_rules! siphash_round {
    ($a:expr, $b:expr, $c:expr, $d:expr) => {{
        $a = $a.wrapping_add($b);
        $b = rol64($b, 13);
        $b ^= $a;
        $a = rol64($a, 32);
        $c = $c.wrapping_add($d);
        $d = rol64($d, 16);
        $d ^= $c;
        $a = $a.wrapping_add($d);
        $d = rol64($d, 21);
        $d ^= $a;
        $c = $c.wrapping_add($b);
        $b = rol64($b, 17);
        $b ^= $c;
        $c = rol64($c, 32);
    }};
}

#[inline(always)]
fn siphash_2u64(first: u64, second: u64, key: &[u64; 2]) -> u64 {
    let mut v0 = SIPHASH_CONST_0;
    let mut v1 = SIPHASH_CONST_1;
    let mut v2 = SIPHASH_CONST_2;
    let mut v3 = SIPHASH_CONST_3;
    let b: u64 = 16u64 << 56;
    v3 ^= key[1];
    v2 ^= key[0];
    v1 ^= key[1];
    v0 ^= key[0];

    v3 ^= first;
    siphash_round!(v0, v1, v2, v3);
    siphash_round!(v0, v1, v2, v3);
    v0 ^= first;
    v3 ^= second;
    siphash_round!(v0, v1, v2, v3);
    siphash_round!(v0, v1, v2, v3);
    v0 ^= second;

    v3 ^= b;
    siphash_round!(v0, v1, v2, v3);
    siphash_round!(v0, v1, v2, v3);
    v0 ^= b;
    v2 ^= 0xff;
    siphash_round!(v0, v1, v2, v3);
    siphash_round!(v0, v1, v2, v3);
    siphash_round!(v0, v1, v2, v3);
    siphash_round!(v0, v1, v2, v3);

    (v0 ^ v1) ^ (v2 ^ v3)
}

#[inline(always)]
fn find_mssind(tab: &[u16; 4], mss: u16) -> i32 {
    let mut i: i32 = 3;
    loop {
        if i == 0 {
            break;
        }
        if mss >= tab[i as usize] {
            break;
        }
        i -= 1;
    }
    i
}

// ---- packet parsing -----------------------------------------------------

#[inline(always)]
fn tcp_load_headers(ctx: &mut TcpSyncookie) -> i32 {
    let data = vload!((*ctx.skb).data) as *mut u8;
    let data_end = vload!((*ctx.skb).data_end) as *mut u8;
    ctx.data = data;
    ctx.data_end = data_end;
    ctx.eth = data as *mut EthHdr;

    if byte_add(ctx.eth as *mut u8, size_of::<EthHdr>()) > data_end {
        return -1;
    }

    let h_proto = u16::from_be(unsafe { (*ctx.eth).h_proto });
    match h_proto {
        _ if h_proto == ETH_P_IP => {
            ctx.ipv4 = byte_add(ctx.eth as *mut u8, size_of::<EthHdr>()) as *mut IpHdr;

            if byte_add(ctx.ipv4 as *mut u8, size_of::<IpHdr>()) > data_end {
                return -1;
            }

            let ihl_version = unsafe { (*ctx.ipv4).ihl_version };
            if (ihl_version & 0x0F) as usize != size_of::<IpHdr>() / 4 {
                return -1;
            }
            if (ihl_version >> 4) != 4 {
                return -1;
            }
            if unsafe { (*ctx.ipv4).protocol } != IPPROTO_TCP {
                return -1;
            }

            ctx.tcp = byte_add(ctx.ipv4 as *mut u8, size_of::<IpHdr>()) as *mut TcpHdr;
        }
        _ if h_proto == ETH_P_IPV6 => {
            ctx.ipv6 = byte_add(ctx.eth as *mut u8, size_of::<EthHdr>()) as *mut Ipv6Hdr;

            if byte_add(ctx.ipv6 as *mut u8, size_of::<Ipv6Hdr>()) > data_end {
                return -1;
            }

            let pv = unsafe { (*ctx.ipv6).priority_version };
            if (pv >> 4) != 6 {
                return -1;
            }
            if unsafe { (*ctx.ipv6).nexthdr } != NEXTHDR_TCP {
                return -1;
            }

            ctx.tcp = byte_add(ctx.ipv6 as *mut u8, size_of::<Ipv6Hdr>()) as *mut TcpHdr;
        }
        _ => return -1,
    }

    if byte_add(ctx.tcp as *mut u8, size_of::<TcpHdr>()) > data_end {
        return -1;
    }

    0
}

#[inline(always)]
fn tcp_reload_headers(ctx: &mut TcpSyncookie) -> i32 {
    let d = vload!((*ctx.skb).data) as usize;
    let de = vload!((*ctx.skb).data_end) as usize;
    // Force the pointer subtraction to materialize into a plain scalar
    // right here (matching the C original's `volatile u64 data_len = ...`):
    // otherwise LLVM can reassociate the later `+ 60 - doff*4` back into a
    // 32-bit ALU add directly on the packet-pointer register `d`, which the
    // verifier rejects ("R1 32-bit pointer arithmetic prohibited").
    let mut data_len = (de - d) as u32;
    unsafe {
        core::ptr::write_volatile(&mut data_len, data_len);
        data_len = core::ptr::read_volatile(&data_len);
    }

    let doff = get_tcp_doff(ctx.tcp);
    if (doff as usize) < size_of::<TcpHdr>() / 4 {
        return -1;
    }

    let new_len = data_len + 60 - (doff as u32) * 4;
    if bpf_skb_change_tail(ctx.skb as *const c_void, new_len, 0) != 0 {
        return -1;
    }

    let data = vload!((*ctx.skb).data) as *mut u8;
    let data_end = vload!((*ctx.skb).data_end) as *mut u8;
    ctx.data = data;
    ctx.data_end = data_end;
    ctx.eth = data as *mut EthHdr;

    if !ctx.ipv4.is_null() {
        ctx.ipv4 = byte_add(ctx.eth as *mut u8, size_of::<EthHdr>()) as *mut IpHdr;
        ctx.ipv6 = core::ptr::null_mut();
        ctx.tcp = byte_add(ctx.ipv4 as *mut u8, size_of::<IpHdr>()) as *mut TcpHdr;
    } else {
        ctx.ipv4 = core::ptr::null_mut();
        ctx.ipv6 = byte_add(ctx.eth as *mut u8, size_of::<EthHdr>()) as *mut Ipv6Hdr;
        ctx.tcp = byte_add(ctx.ipv6 as *mut u8, size_of::<Ipv6Hdr>()) as *mut TcpHdr;
    }

    if byte_add(ctx.tcp as *mut u8, 60) > data_end {
        return -1;
    }

    0
}

#[inline(always)]
fn tcp_validate_header(ctx: &mut TcpSyncookie) -> i32 {
    if tcp_reload_headers(ctx) != 0 {
        return -1;
    }

    let doff_bytes = (get_tcp_doff(ctx.tcp) as u32) * 4;
    let csum = bpf_csum_diff(core::ptr::null(), 0, ctx.tcp as *const c_void, doff_bytes, 0);
    if csum < 0 {
        return -1;
    }

    if !ctx.ipv4.is_null() {
        let ihl = unsafe { (*ctx.ipv4).ihl_version } & 0x0F;
        let csum2 = bpf_csum_diff(core::ptr::null(), 0, ctx.ipv4 as *const c_void, (ihl as u32) * 4, 0);
        if csum2 < 0 {
            return -1;
        }
        if csum_fold(csum2 as u32) != 0 {
            return -1;
        }
    }
    // ipv6: nothing to validate (matches the C original's comment-only arm).

    0
}

#[inline(always)]
fn next(ctx: &mut TcpSyncookie, sz: u32) -> *mut u8 {
    let off = ctx.off as u64;

    if off > (MAX_PACKET_OFF - sz) as u64 {
        return core::ptr::null_mut();
    }

    let mut data = byte_add(ctx.data, off as usize);
    helpers::sink(&mut data);
    if byte_add(data, sz as usize) >= ctx.data_end {
        return core::ptr::null_mut();
    }

    ctx.off += sz;
    data
}

extern "C" fn tcp_parse_option(_index: u64, ctx: *mut TcpSyncookie) -> i64 {
    let ctx = unsafe { &mut *ctx };
    let off = ctx.off;

    let opcode = next(ctx, 1);
    if opcode.is_null() {
        return 1;
    }
    let opcode_val = unsafe { *opcode };

    if opcode_val == TCPOPT_EOL {
        return 1;
    }
    if opcode_val == TCPOPT_NOP {
        return 0;
    }

    let opsize = next(ctx, 1);
    if opsize.is_null() {
        return 1;
    }
    let opsize_val = unsafe { *opsize };
    if opsize_val < 2 {
        return 1;
    }

    match opcode_val {
        _ if opcode_val == TCPOPT_MSS => {
            let mss = next(ctx, 2);
            if opsize_val == TCPOLEN_MSS && tcp_syn_flag(ctx.tcp) && !mss.is_null() {
                ctx.attrs.mss = get_unaligned_be16(mss);
            }
        }
        _ if opcode_val == TCPOPT_WINDOW => {
            let wscale = next(ctx, 1);
            if opsize_val == TCPOLEN_WINDOW && tcp_syn_flag(ctx.tcp) && !wscale.is_null() {
                ctx.attrs.wscale_ok = 1;
                ctx.attrs.snd_wscale = unsafe { *wscale };
            }
        }
        _ if opcode_val == TCPOPT_TIMESTAMP => {
            let tsval = next(ctx, 4);
            let tsecr = next(ctx, 4);
            if opsize_val == TCPOLEN_TIMESTAMP && !tsval.is_null() && !tsecr.is_null() {
                ctx.attrs.rcv_tsval = get_unaligned_be32(tsval);
                ctx.attrs.rcv_tsecr = get_unaligned_be32(tsecr);

                if tcp_syn_flag(ctx.tcp) && ctx.attrs.rcv_tsecr != 0 {
                    ctx.attrs.tstamp_ok = 0;
                } else {
                    ctx.attrs.tstamp_ok = 1;
                }
            }
        }
        _ if opcode_val == TCPOPT_SACK_PERM => {
            if opsize_val == TCPOLEN_SACK_PERM && tcp_syn_flag(ctx.tcp) {
                ctx.attrs.sack_ok = 1;
            }
        }
        _ => {}
    }

    ctx.off = off + opsize_val as u32;
    0
}

#[inline(always)]
fn tcp_parse_options(ctx: &mut TcpSyncookie) {
    let tcp_end = byte_add(ctx.tcp as *mut u8, size_of::<TcpHdr>());
    ctx.off = (tcp_end as usize - ctx.data as usize) as u32;

    bpf_loop(40, tcp_parse_option, ctx as *mut TcpSyncookie, 0);
}

#[inline(always)]
fn tcp_validate_sysctl(ctx: &mut TcpSyncookie) -> i32 {
    if (!ctx.ipv4.is_null() && ctx.attrs.mss != MSS_LOCAL_IPV4)
        || (!ctx.ipv6.is_null() && ctx.attrs.mss != MSS_LOCAL_IPV6)
    {
        return -1;
    }

    if ctx.attrs.wscale_ok == 0
        || ctx.attrs.snd_wscale == 0
        || (ctx.attrs.snd_wscale as u32) >= BPF_SYNCOOKIE_WSCALE_MASK
    {
        return -1;
    }

    if ctx.attrs.tstamp_ok == 0 {
        return -1;
    }

    if ctx.attrs.sack_ok == 0 {
        return -1;
    }

    if !tcp_ece(ctx.tcp) || !tcp_cwr(ctx.tcp) {
        return -1;
    }

    0
}

#[inline(always)]
fn tcp_prepare_cookie(ctx: &mut TcpSyncookie) {
    let seq = u32::from_be(unsafe { (*ctx.tcp).seq });
    let mut first: u64 = 0;
    let mut mssind: i32 = 0;

    if !ctx.ipv4.is_null() {
        mssind = find_mssind(&msstab4, ctx.attrs.mss);
        ctx.attrs.mss = msstab4[mssind as usize];

        let saddr = unsafe { (*ctx.ipv4).saddr };
        let daddr = unsafe { (*ctx.ipv4).daddr };
        first = ((saddr as u64) << 32) | (daddr as u64);
    } else if !ctx.ipv6.is_null() {
        mssind = find_mssind(&msstab6, ctx.attrs.mss);
        ctx.attrs.mss = msstab6[mssind as usize];

        let saddr0 = unsafe { (*ctx.ipv6).saddr[0] } & 0xFF;
        let daddr0 = unsafe { (*ctx.ipv6).daddr[0] };
        first = ((saddr0 as u64) << 32) | (daddr0 as u64);
    }

    let source = unsafe { (*ctx.tcp).source };
    let dest = unsafe { (*ctx.tcp).dest };
    let second = ((seq as u64) << 32) | ((source as u64) << 16) | (dest as u64);
    let mut hash = siphash_2u64(first, second, &TEST_KEY_SIPHASH) as u32;

    if ctx.attrs.tstamp_ok != 0 {
        let mut r = bpf_get_prandom_u32();
        r &= !COOKIE_MASK;
        r |= hash & COOKIE_MASK;
        ctx.attrs.rcv_tsecr = r;
    }

    hash &= !COOKIE_MASK;
    hash |= (mssind as u32) << 6;

    if ctx.attrs.wscale_ok != 0 {
        hash |= (ctx.attrs.snd_wscale as u32) & BPF_SYNCOOKIE_WSCALE_MASK;
    }

    if ctx.attrs.sack_ok != 0 {
        hash |= BPF_SYNCOOKIE_SACK;
    }

    if ctx.attrs.tstamp_ok != 0 && tcp_ece(ctx.tcp) && tcp_cwr(ctx.tcp) {
        hash |= BPF_SYNCOOKIE_ECN;
    }

    ctx.cookie = hash;
}

#[inline(always)]
fn tcp_write_options(ctx: &mut TcpSyncookie) {
    ctx.ptr32 = byte_add(ctx.tcp as *mut u8, size_of::<TcpHdr>()) as *mut u32;

    unsafe {
        *ctx.ptr32 =
            (((TCPOPT_MSS as u32) << 24) | ((TCPOLEN_MSS as u32) << 16) | (ctx.attrs.mss as u32))
                .to_be();
        ctx.ptr32 = ctx.ptr32.add(1);

        if ctx.attrs.wscale_ok != 0 {
            *ctx.ptr32 = (((TCPOPT_NOP as u32) << 24)
                | ((TCPOPT_WINDOW as u32) << 16)
                | ((TCPOLEN_WINDOW as u32) << 8)
                | (ctx.attrs.snd_wscale as u32))
                .to_be();
            ctx.ptr32 = ctx.ptr32.add(1);
        }

        if ctx.attrs.tstamp_ok != 0 {
            if ctx.attrs.sack_ok != 0 {
                *ctx.ptr32 = (((TCPOPT_SACK_PERM as u32) << 24)
                    | ((TCPOLEN_SACK_PERM as u32) << 16)
                    | ((TCPOPT_TIMESTAMP as u32) << 8)
                    | (TCPOLEN_TIMESTAMP as u32))
                    .to_be();
            } else {
                *ctx.ptr32 = (((TCPOPT_NOP as u32) << 24)
                    | ((TCPOPT_NOP as u32) << 16)
                    | ((TCPOPT_TIMESTAMP as u32) << 8)
                    | (TCPOLEN_TIMESTAMP as u32))
                    .to_be();
            }
            ctx.ptr32 = ctx.ptr32.add(1);

            *ctx.ptr32 = ctx.attrs.rcv_tsecr.to_be();
            ctx.ptr32 = ctx.ptr32.add(1);
            *ctx.ptr32 = ctx.attrs.rcv_tsval.to_be();
            ctx.ptr32 = ctx.ptr32.add(1);
        } else if ctx.attrs.sack_ok != 0 {
            *ctx.ptr32 = (((TCPOPT_NOP as u32) << 24)
                | ((TCPOPT_NOP as u32) << 16)
                | ((TCPOPT_SACK_PERM as u32) << 8)
                | (TCPOLEN_SACK_PERM as u32))
                .to_be();
            ctx.ptr32 = ctx.ptr32.add(1);
        }
    }
}

#[inline(always)]
fn tcp_handle_syn(ctx: &mut TcpSyncookie) -> i32 {
    if tcp_validate_header(ctx) != 0 {
        return TC_ACT_SHOT;
    }

    tcp_parse_options(ctx);

    if tcp_validate_sysctl(ctx) != 0 {
        return TC_ACT_SHOT;
    }

    tcp_prepare_cookie(ctx);
    tcp_write_options(ctx);

    unsafe {
        let tmp = (*ctx.tcp).source;
        (*ctx.tcp).source = (*ctx.tcp).dest;
        (*ctx.tcp).dest = tmp;
        (*ctx.tcp).check = 0;
        let seq = u32::from_be((*ctx.tcp).seq);
        (*ctx.tcp).ack_seq = seq.wrapping_add(1).to_be();
        (*ctx.tcp).seq = ctx.cookie.to_be();
    }

    let doff = ((ctx.ptr32 as usize - ctx.tcp as usize) >> 2) as u8;
    set_tcp_doff(ctx.tcp, doff);
    set_tcp_ack(ctx.tcp, true);

    if ctx.attrs.tstamp_ok == 0 || !tcp_ece(ctx.tcp) || !tcp_cwr(ctx.tcp) {
        set_tcp_ece(ctx.tcp, false);
    }
    set_tcp_cwr(ctx.tcp, false);

    let doff_bytes = (get_tcp_doff(ctx.tcp) as u32) * 4;
    let mut csum = bpf_csum_diff(core::ptr::null(), 0, ctx.tcp as *const c_void, doff_bytes, 0);
    if csum < 0 {
        return TC_ACT_SHOT;
    }

    if !ctx.ipv4.is_null() {
        unsafe {
            let tmp = (*ctx.ipv4).saddr;
            (*ctx.ipv4).saddr = (*ctx.ipv4).daddr;
            (*ctx.ipv4).daddr = tmp;
        }

        let check = tcp_v4_csum(ctx, csum as u32);
        unsafe {
            (*ctx.tcp).check = check;

            (*ctx.ipv4).check = 0;
            (*ctx.ipv4).tos = 0;
            let total_len = (ctx.ptr32 as usize - ctx.ipv4 as usize) as u16;
            (*ctx.ipv4).tot_len = total_len.to_be();
            (*ctx.ipv4).id = 0;
            (*ctx.ipv4).ttl = 64;
        }

        csum = bpf_csum_diff(
            core::ptr::null(),
            0,
            ctx.ipv4 as *const c_void,
            size_of::<IpHdr>() as u32,
            0,
        );
        if csum < 0 {
            return TC_ACT_SHOT;
        }

        unsafe {
            (*ctx.ipv4).check = csum_fold(csum as u32);
        }
    } else if !ctx.ipv6.is_null() {
        unsafe {
            vswap(
                (*ctx.ipv6).saddr.as_mut_ptr() as *mut u8,
                (*ctx.ipv6).daddr.as_mut_ptr() as *mut u8,
                16,
            );
        }

        let check = tcp_v6_csum(ctx, csum as u32);
        unsafe {
            (*ctx.tcp).check = check;

            *(ctx.ipv6 as *mut u32) = 0x60000000u32.to_be();
            let payload_len = (ctx.ptr32 as usize - ctx.tcp as usize) as u16;
            (*ctx.ipv6).payload_len = payload_len.to_be();
            (*ctx.ipv6).hop_limit = 64;
        }
    }

    unsafe {
        vswap(
            (*ctx.eth).h_source.as_mut_ptr(),
            (*ctx.eth).h_dest.as_mut_ptr(),
            6,
        );
    }

    let new_len = (ctx.ptr32 as usize - ctx.eth as usize) as u32;
    if bpf_skb_change_tail(ctx.skb as *const c_void, new_len, 0) != 0 {
        return TC_ACT_SHOT;
    }

    let ifindex = vload!((*ctx.skb).ifindex);
    bpf_redirect(ifindex, 0) as i32
}

#[inline(always)]
fn tcp_validate_cookie(ctx: &mut TcpSyncookie) -> i32 {
    let cookie = u32::from_be(unsafe { (*ctx.tcp).ack_seq }).wrapping_sub(1);
    let seq = u32::from_be(unsafe { (*ctx.tcp).seq }).wrapping_sub(1);
    let mut first: u64 = 0;

    if !ctx.ipv4.is_null() {
        let saddr = unsafe { (*ctx.ipv4).saddr };
        let daddr = unsafe { (*ctx.ipv4).daddr };
        first = ((saddr as u64) << 32) | (daddr as u64);
    } else if !ctx.ipv6.is_null() {
        let saddr0 = unsafe { (*ctx.ipv6).saddr[0] } & 0xFF;
        let daddr0 = unsafe { (*ctx.ipv6).daddr[0] };
        first = ((saddr0 as u64) << 32) | (daddr0 as u64);
    }

    let source = unsafe { (*ctx.tcp).source };
    let dest = unsafe { (*ctx.tcp).dest };
    let second = ((seq as u64) << 32) | ((source as u64) << 16) | (dest as u64);
    let mut hash = siphash_2u64(first, second, &TEST_KEY_SIPHASH) as u32;

    if ctx.attrs.tstamp_ok != 0 {
        hash = hash.wrapping_sub(ctx.attrs.rcv_tsecr & COOKIE_MASK);
    } else {
        hash &= !COOKIE_MASK;
    }

    hash = hash.wrapping_sub(cookie & !COOKIE_MASK);
    if hash != 0 {
        return -1;
    }

    let mssind = ((cookie >> 6) & 3) as usize;
    if !ctx.ipv4.is_null() {
        ctx.attrs.mss = msstab4[mssind];
    } else {
        ctx.attrs.mss = msstab6[mssind];
    }

    let snd_wscale = (cookie & BPF_SYNCOOKIE_WSCALE_MASK) as u8;
    ctx.attrs.snd_wscale = snd_wscale;
    ctx.attrs.rcv_wscale = snd_wscale;
    ctx.attrs.wscale_ok = (snd_wscale as u32 == BPF_SYNCOOKIE_WSCALE_MASK) as u8;
    ctx.attrs.sack_ok = (cookie & BPF_SYNCOOKIE_SACK) as u8;
    ctx.attrs.ecn_ok = (cookie & BPF_SYNCOOKIE_ECN) as u8;

    0
}

#[inline(always)]
fn tcp_handle_ack(ctx: &mut TcpSyncookie) -> i32 {
    let mut tuple = BpfSockTuple {
        ipv4: SockTupleV4 {
            saddr: 0,
            daddr: 0,
            sport: 0,
            dport: 0,
        },
    };
    let tuple_size: u32;

    let source = unsafe { (*ctx.tcp).source };
    let dest = unsafe { (*ctx.tcp).dest };

    if !ctx.ipv4.is_null() {
        unsafe {
            tuple.ipv4.saddr = (*ctx.ipv4).saddr;
            tuple.ipv4.daddr = (*ctx.ipv4).daddr;
            tuple.ipv4.sport = source;
            tuple.ipv4.dport = dest;
        }
        tuple_size = size_of::<SockTupleV4>() as u32;
    } else if !ctx.ipv6.is_null() {
        unsafe {
            vcopy(
                tuple.ipv6.saddr.as_mut_ptr() as *mut u8,
                (*ctx.ipv6).saddr.as_ptr() as *const u8,
                16,
            );
            vcopy(
                tuple.ipv6.daddr.as_mut_ptr() as *mut u8,
                (*ctx.ipv6).daddr.as_ptr() as *const u8,
                16,
            );
            tuple.ipv6.sport = source;
            tuple.ipv6.dport = dest;
        }
        tuple_size = size_of::<SockTupleV6>() as u32;
    } else {
        return TC_ACT_OK;
    }

    let skc = bpf_skc_lookup_tcp(
        ctx.skb as *const c_void,
        &tuple as *const BpfSockTuple,
        tuple_size,
        (-1i64) as u64,
        0,
    ) as *mut BpfSock;
    if skc.is_null() {
        return TC_ACT_OK;
    }

    let mut ret = TC_ACT_OK;

    if unsafe { (*skc).state } == TCP_LISTEN {
        let sk = bpf_skc_to_tcp_sock(skc as *const c_void);
        if sk.is_null() {
            ret = TC_ACT_SHOT;
        } else if tcp_validate_header(ctx) != 0 {
            ret = TC_ACT_SHOT;
        } else {
            tcp_parse_options(ctx);

            if tcp_validate_cookie(ctx) != 0 {
                ret = TC_ACT_SHOT;
            } else {
                let r = unsafe {
                    bpf_sk_assign_tcp_reqsk(
                        ctx.skb as *mut __sk_buff,
                        sk,
                        &mut ctx.attrs as *mut BpfTcpReqAttrs,
                        size_of::<BpfTcpReqAttrs>() as i32,
                    )
                };
                if r < 0 {
                    ret = TC_ACT_SHOT;
                } else {
                    ret = r;
                }
            }
        }
    }

    bpf_sk_release(skc as *mut c_void);
    ret
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn tcp_custom_syncookie(skb: *const __sk_buff) -> i32 {
    let mut ctx = new_ctx(skb);

    if tcp_load_headers(&mut ctx) != 0 {
        return TC_ACT_OK;
    }

    if tcp_rst(ctx.tcp) {
        return TC_ACT_OK;
    }

    if tcp_syn_flag(ctx.tcp) {
        if tcp_ack_flag(ctx.tcp) {
            return TC_ACT_OK;
        }

        unsafe {
            handled_syn = true;
        }

        return tcp_handle_syn(&mut ctx);
    }

    unsafe {
        handled_ack = true;
    }

    tcp_handle_ack(&mut ctx)
}

bpf_object!("GPL");
