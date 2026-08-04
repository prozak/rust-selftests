#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_pkt_access.c
// (bpf-rs-core idiom).
//
// A TC (SCHED_CLS) program that parses an Ethernet/IPv4-or-IPv6/TCP header
// chain via bounds-checked packet-data pointers, calls a handful of
// noinline bpf2bpf subprograms (some with large stack buffers, purely to
// exercise verifier subprog handling) and cross-checks their return values,
// and finally does a bounds-checked write into the packet (tcp->check++)
// through another subprogram.

use bpf_rs_core::ctx::{__sk_buff, TC_ACT_OK, TC_ACT_SHOT};
use bpf_rs_core::helpers;
use bpf_rs_core::{bpf_object, vload};

const TC_ACT_UNSPEC: i32 = -1;

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;

// struct ethhdr (linux/if_ether.h): full layout.
#[repr(C)]
struct EthHdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

// struct iphdr (linux/ip.h), little-endian bitfield: ihl occupies the low
// nibble of the first byte, version the high nibble.
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

// struct ipv6hdr (linux/ipv6.h): only nexthdr is read; the rest is kept as
// raw fields so the struct's size (and the following tcphdr's offset)
// matches the real header exactly.
#[repr(C)]
struct Ipv6Hdr {
    priority_version: u8,
    flow_lbl: [u8; 3],
    payload_len: u16,
    nexthdr: u8,
    hop_limit: u8,
    saddr: [u8; 16],
    daddr: [u8; 16],
}

// struct tcphdr (linux/tcp.h): only check/urg_ptr are touched; the rest is
// kept as raw fields for the correct struct size.
#[repr(C)]
struct TcpHdr {
    source: u16,
    dest: u16,
    seq: u32,
    ack_seq: u32,
    flags: u16,
    window: u16,
    check: u16,
    urg_ptr: u16,
}

const MAX_STACK: usize = 512 - 2 * 32;

// C: volatile char buf[MAX_STACK] = {}; __sink(buf[MAX_STACK - 1]);
// sink() makes the array address escape, so the whole buffer stays on the
// stack (SROA/DSE cannot split or drop an alloca with escaping uses).
#[inline(always)]
fn stack_buf() {
    let mut buf = [0u8; MAX_STACK];
    let mut p = buf.as_mut_ptr();
    helpers::sink(&mut p);
    unsafe {
        core::ptr::read_volatile(p.add(MAX_STACK - 1));
    }
}

// C: static noinline int test_pkt_access_subprog1(volatile struct __sk_buff *skb)
#[no_mangle]
#[inline(never)]
extern "C" fn test_pkt_access_subprog1(skb: *const __sk_buff) -> i32 {
    (vload!((*skb).len).wrapping_mul(2)) as i32
}

// C: static noinline int test_pkt_access_subprog2(int val, volatile struct __sk_buff *skb)
#[no_mangle]
#[inline(never)]
extern "C" fn test_pkt_access_subprog2(val: i32, skb: *const __sk_buff) -> i32 {
    (vload!((*skb).len) as i32).wrapping_mul(val)
}

#[no_mangle]
#[inline(never)]
extern "C" fn get_skb_len(skb: *const __sk_buff) -> i32 {
    stack_buf();
    unsafe { (*skb).len as i32 }
}

#[no_mangle]
#[inline(never)]
extern "C" fn get_constant(val: i64) -> i32 {
    (val - 122) as i32
}

#[no_mangle]
#[inline(never)]
extern "C" fn get_skb_ifindex(val: i32, skb: *const __sk_buff, var: i32) -> i32 {
    stack_buf();
    (unsafe { (*skb).ifindex } as i32).wrapping_mul(val).wrapping_mul(var)
}

#[no_mangle]
#[inline(never)]
extern "C" fn test_pkt_access_subprog3(val: i32, skb: *const __sk_buff) -> i32 {
    let len_part = get_skb_len(skb);
    let idx_part = get_skb_ifindex(val, skb, get_constant(123));
    len_part.wrapping_mul(idx_part)
}

#[no_mangle]
#[inline(never)]
extern "C" fn test_pkt_write_access_subprog(skb: *const __sk_buff, off: u32) -> i32 {
    let data = vload!((*skb).data) as usize;
    let data_end = vload!((*skb).data_end) as usize;

    if off as usize > core::mem::size_of::<EthHdr>() + core::mem::size_of::<Ipv6Hdr>() {
        return -1;
    }

    let tcp = data.wrapping_add(off as usize) as *mut TcpHdr;
    if (tcp as usize).wrapping_add(core::mem::size_of::<TcpHdr>()) > data_end {
        return -1;
    }

    unsafe {
        (*tcp).check = (*tcp).check.wrapping_add(1);
    }
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_pkt_access(skb: *const __sk_buff) -> i32 {
    let data_end = vload!((*skb).data_end) as usize;
    let data = vload!((*skb).data) as usize;

    let eth = data as *const EthHdr;
    if data.wrapping_add(core::mem::size_of::<EthHdr>()) > data_end {
        return TC_ACT_SHOT;
    }

    let mut proto: u8 = 255;
    let mut tcp: *const TcpHdr = core::ptr::null();

    let h_proto = unsafe { (*eth).h_proto };
    if h_proto == ETH_P_IP.to_be() {
        let iph = unsafe { eth.add(1) as *const IpHdr };
        if (iph as usize).wrapping_add(core::mem::size_of::<IpHdr>()) > data_end {
            return TC_ACT_SHOT;
        }
        let ihl = unsafe { (*iph).ihl_version } & 0x0F;
        let ihl_len = (ihl as usize).wrapping_mul(4);
        proto = unsafe { (*iph).protocol };
        tcp = (iph as usize).wrapping_add(ihl_len) as *const TcpHdr;
    } else if h_proto == ETH_P_IPV6.to_be() {
        let ip6h = unsafe { eth.add(1) as *const Ipv6Hdr };
        if (ip6h as usize).wrapping_add(core::mem::size_of::<Ipv6Hdr>()) > data_end {
            return TC_ACT_SHOT;
        }
        let ihl_len = core::mem::size_of::<Ipv6Hdr>();
        proto = unsafe { (*ip6h).nexthdr };
        tcp = (ip6h as usize).wrapping_add(ihl_len) as *const TcpHdr;
    }

    let skb_len = vload!((*skb).len);
    if test_pkt_access_subprog1(skb) != skb_len.wrapping_mul(2) as i32 {
        return TC_ACT_SHOT;
    }
    if test_pkt_access_subprog2(2, skb) != skb_len.wrapping_mul(2) as i32 {
        return TC_ACT_SHOT;
    }
    let skb_ifindex = vload!((*skb).ifindex);
    if test_pkt_access_subprog3(3, skb)
        != skb_len.wrapping_mul(3).wrapping_mul(skb_ifindex) as i32
    {
        return TC_ACT_SHOT;
    }

    if !tcp.is_null() {
        let off = (tcp as usize).wrapping_sub(data) as u32;
        if test_pkt_write_access_subprog(skb, off) != 0 {
            return TC_ACT_SHOT;
        }
        if (tcp as usize).wrapping_add(20) > data_end || proto != 6 {
            return TC_ACT_SHOT;
        }
        // C: barrier(); -- forces ordering of the two data_end checks.
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        if (tcp as usize).wrapping_add(18) > data_end {
            return TC_ACT_SHOT;
        }
        if unsafe { (*tcp).urg_ptr } == 123 {
            return TC_ACT_OK;
        }
    }

    TC_ACT_UNSPEC
}

bpf_object!("GPL");
