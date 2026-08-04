#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/vrf_socket_lookup.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_sk_lookup_tcp, bpf_sk_lookup_udp, bpf_sk_release, bpf_skc_lookup_tcp};
use bpf_rs_core::vload;
use core::ffi::c_void;

const ETH_P_IP: u16 = 0x0800;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const BPF_F_CURRENT_NETNS: u64 = -1i64 as u64;

const TC_ACT_UNSPEC: i32 = -1;
const XDP_PASS: i32 = 2;

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

// struct ethhdr (linux/if_ether.h).
#[repr(C)]
struct EthHdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

// struct iphdr (linux/ip.h): the bitfield ihl/version pair is kept as a
// single opaque byte since neither is read here, only the struct's size
// and field offsets matter.
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

// struct bpf_sock_tuple's `.ipv4` member (UAPI linux/bpf.h), used only for
// its size: the tuple pointer itself aliases &iph->saddr in the packet, the
// same way the C original does.
#[repr(C)]
struct SockTupleIpv4 {
    saddr: u32,
    daddr: u32,
    sport: u16,
    dport: u16,
}

#[no_mangle]
static mut lookup_status: i32 = 0;
#[no_mangle]
static mut test_xdp: bool = false;
#[no_mangle]
static mut tcp_skc: bool = false;

#[inline(always)]
fn socket_lookup(ctx: *const c_void, data_end: *const u8, data: *const u8) {
    let eth = data as *const EthHdr;
    if unsafe { data.add(core::mem::size_of::<EthHdr>()) } > data_end {
        return;
    }

    if unsafe { (*eth).h_proto } != ETH_P_IP.to_be() {
        return;
    }

    let iph_ptr = unsafe { data.add(core::mem::size_of::<EthHdr>()) };
    let iph = iph_ptr as *const IpHdr;
    if unsafe { iph_ptr.add(core::mem::size_of::<IpHdr>()) } > data_end {
        return;
    }

    let tp_ptr = unsafe { core::ptr::addr_of!((*iph).saddr) } as *const u8;
    let tplen = core::mem::size_of::<SockTupleIpv4>();
    if unsafe { tp_ptr.add(tplen) } > data_end {
        return;
    }
    let tp = tp_ptr as *const c_void;
    let tplen = tplen as u32;

    let protocol = unsafe { (*iph).protocol };
    let sk = if protocol == IPPROTO_TCP {
        if unsafe { tcp_skc } {
            bpf_skc_lookup_tcp(ctx, tp, tplen, BPF_F_CURRENT_NETNS, 0)
        } else {
            bpf_sk_lookup_tcp(ctx, tp, tplen, BPF_F_CURRENT_NETNS, 0)
        }
    } else if protocol == IPPROTO_UDP {
        bpf_sk_lookup_udp(ctx, tp, tplen, BPF_F_CURRENT_NETNS, 0)
    } else {
        return;
    };

    unsafe { lookup_status = 0 };

    if !sk.is_null() {
        bpf_sk_release(sk);
        unsafe { lookup_status = 1 };
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn tc_socket_lookup(skb: *const __sk_buff) -> i32 {
    let data_end = vload!((*skb).data_end) as usize as *const u8;
    let data = vload!((*skb).data) as usize as *const u8;

    if unsafe { test_xdp } {
        return TC_ACT_UNSPEC;
    }

    socket_lookup(skb as *const c_void, data_end, data);
    TC_ACT_UNSPEC
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_socket_lookup(xdp: *const xdp_md) -> i32 {
    let data_end = vload!((*xdp).data_end) as usize as *const u8;
    let data = vload!((*xdp).data) as usize as *const u8;

    if !unsafe { test_xdp } {
        return XDP_PASS;
    }

    socket_lookup(xdp as *const c_void, data_end, data);
    XDP_PASS
}

bpf_object!("GPL");
