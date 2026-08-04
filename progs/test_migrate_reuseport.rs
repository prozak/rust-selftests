#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_migrate_reuseport.c
// (bpf-rs-core idiom).

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_get_socket_cookie, bpf_map_lookup_elem, bpf_sk_select_reuseport, sync_fetch_and_add_i32,
};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::vload;

const XDP_DROP: i32 = 1;
const XDP_PASS: i32 = 2;

const SK_DROP: i32 = 0;
const SK_PASS: i32 = 1;

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const IPPROTO_TCP: u8 = 6;

const BPF_TCP_ESTABLISHED: u32 = 1;
const BPF_TCP_SYN_RECV: u32 = 3;
const BPF_TCP_NEW_SYN_RECV: u32 = 12;

/// enum bpf_map_type::BPF_MAP_TYPE_REUSEPORT_SOCKARRAY.
const REUSEPORT_SOCKARRAY: usize = 20;

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

/// UAPI struct sk_reuseport_md (linux/bpf.h). `data`/`data_end`/`sk`/
/// `migrating_sk` are all `__bpf_md_ptr` (real 64-bit pointers on this
/// arch), unlike xdp_md's plain u32 offsets.
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct sk_reuseport_md {
    pub data: u64,
    pub data_end: u64,
    pub len: u32,
    pub eth_protocol: u32,
    pub ip_protocol: u32,
    pub bind_inany: u32,
    pub hash: u32,
    pub sk: u64,
    pub migrating_sk: u64,
}

// struct ethhdr (linux/if_ether.h). Read only through raw-pointer unaligned
// loads: the XDP data pointer carries no alignment guarantee.
#[repr(C, packed)]
struct EthHdr {
    #[allow(dead_code)]
    h_dest: [u8; 6],
    #[allow(dead_code)]
    h_source: [u8; 6],
    h_proto: u16,
}

#[repr(C, packed)]
struct IpHdr {
    ihl_version: u8, // ihl:4, version:4 (LE bit order)
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

#[repr(C, packed)]
struct Ipv6Hdr {
    #[allow(dead_code)]
    priority_version: u8, // priority:4, version:4 (LE bit order)
    #[allow(dead_code)]
    flow_lbl: [u8; 3],
    #[allow(dead_code)]
    payload_len: u16,
    nexthdr: u8,
    #[allow(dead_code)]
    hop_limit: u8,
    #[allow(dead_code)]
    saddr: [u8; 16],
    #[allow(dead_code)]
    daddr: [u8; 16],
}

#[repr(C, packed)]
struct TcpHdr {
    #[allow(dead_code)]
    source: u16,
    dest: u16,
    #[allow(dead_code)]
    seq: u32,
    #[allow(dead_code)]
    ack_seq: u32,
    #[allow(dead_code)]
    res1_doff: u8, // res1:4, doff:4 (LE bit order)
    flags: u8, // fin:1,syn:1,rst:1,psh:1,ack:1,urg:1,ece:1,cwr:1 (LE bit order)
    #[allow(dead_code)]
    window: u16,
    #[allow(dead_code)]
    check: u16,
    #[allow(dead_code)]
    urg_ptr: u16,
}

#[inline(always)]
fn tcp_syn(b: u8) -> bool {
    (b >> 1) & 0x1 != 0
}
#[inline(always)]
fn tcp_ack(b: u8) -> bool {
    (b >> 4) & 0x1 != 0
}

// Only the fields up to and including `state` are used; the rest exist so
// this matches the real struct bpf_sock byte layout (migrating_sk's field
// access is a fixed-offset ctx conversion in the kernel, independent of our
// own BTF).
#[repr(C)]
#[allow(dead_code)]
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

#[link_section = ".maps"]
#[no_mangle]
static reuseport_map: BpfMap<i32, u64, { REUSEPORT_SOCKARRAY }, 256> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static migrate_map: BpfMap<u64, i32, { maps::HASH }, 256> = BpfMap::new();

#[no_mangle]
static mut migrated_at_close: i32 = 0;
#[no_mangle]
static mut migrated_at_close_fastopen: i32 = 0;
#[no_mangle]
static mut migrated_at_send_synack: i32 = 0;
#[no_mangle]
static mut migrated_at_recv_ack: i32 = 0;
#[no_mangle]
static mut server_port: u16 = 0;

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn drop_ack(xdp: *const xdp_md) -> i32 {
    let data_end = vload!((*xdp).data_end) as usize;
    let data = vload!((*xdp).data) as usize;

    if data + core::mem::size_of::<EthHdr>() > data_end {
        return XDP_PASS;
    }

    let eth = data as *const EthHdr;
    let h_proto = htons(unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*eth).h_proto)) });

    let tcp: usize;

    if h_proto == ETH_P_IP {
        let ip_off = data + core::mem::size_of::<EthHdr>();
        if ip_off + core::mem::size_of::<IpHdr>() > data_end {
            return XDP_PASS;
        }

        let ip = ip_off as *const IpHdr;
        let protocol = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip).protocol)) };
        if protocol != IPPROTO_TCP {
            return XDP_PASS;
        }

        let ihl_version =
            unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip).ihl_version)) };
        let ihl = (ihl_version & 0xF) as usize;
        tcp = ip_off + ihl * 4;
    } else if h_proto == ETH_P_IPV6 {
        let ipv6_off = data + core::mem::size_of::<EthHdr>();
        if ipv6_off + core::mem::size_of::<Ipv6Hdr>() > data_end {
            return XDP_PASS;
        }

        let ipv6 = ipv6_off as *const Ipv6Hdr;
        let nexthdr = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ipv6).nexthdr)) };
        if nexthdr != IPPROTO_TCP {
            return XDP_PASS;
        }

        tcp = ipv6_off + core::mem::size_of::<Ipv6Hdr>();
    } else {
        return XDP_PASS;
    }

    if tcp + core::mem::size_of::<TcpHdr>() > data_end {
        return XDP_PASS;
    }

    let tcp_hdr = tcp as *const TcpHdr;
    let dest = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*tcp_hdr).dest)) };
    let port = unsafe { server_port };
    if dest != port {
        return XDP_PASS;
    }

    let flags = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*tcp_hdr).flags)) };
    if !tcp_syn(flags) && tcp_ack(flags) {
        return XDP_DROP;
    }

    XDP_PASS
}

#[link_section = "sk_reuseport/migrate"]
#[no_mangle]
extern "C" fn migrate_reuseport(reuse_md: *mut sk_reuseport_md) -> i32 {
    let migrating_sk = unsafe { (*reuse_md).migrating_sk };
    if migrating_sk == 0 {
        return SK_PASS;
    }

    let state = unsafe { (*(migrating_sk as *const BpfSock)).state };

    let sk = unsafe { (*reuse_md).sk };
    let cookie = bpf_get_socket_cookie(sk as *mut c_void);

    let key = bpf_map_lookup_elem(&migrate_map, &cookie) as *const i32;
    if key.is_null() {
        return SK_DROP;
    }

    let err = bpf_sk_select_reuseport(reuse_md, &reuseport_map, unsafe { &*key }, 0u64);
    if err != 0 {
        return SK_PASS;
    }

    if state == BPF_TCP_ESTABLISHED {
        sync_fetch_and_add_i32(core::ptr::addr_of_mut!(migrated_at_close), 1);
    } else if state == BPF_TCP_SYN_RECV {
        sync_fetch_and_add_i32(core::ptr::addr_of_mut!(migrated_at_close_fastopen), 1);
    } else if state == BPF_TCP_NEW_SYN_RECV {
        let len = unsafe { (*reuse_md).len };
        if len == 0 {
            sync_fetch_and_add_i32(core::ptr::addr_of_mut!(migrated_at_send_synack), 1);
        } else {
            sync_fetch_and_add_i32(core::ptr::addr_of_mut!(migrated_at_recv_ack), 1);
        }
    }

    SK_PASS
}

bpf_object!("GPL");
