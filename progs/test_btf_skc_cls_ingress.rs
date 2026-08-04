#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_btf_skc_cls_ingress.c, bpf-rs-core
// idiom.
//
// TC ingress program: parses eth/ip(6)/tcp far enough to build an in-packet
// `struct bpf_sock_tuple` (same aliasing trick as test_sk_assign_libbpf.rs:
// the L3 address fields are immediately followed by the L4 header's
// source/dest ports), looks it up with bpf_skc_lookup_tcp(), then branches
// on the returned bpf_sock's state: a TCP_NEW_SYN_RECV request socket has
// its source port recorded and is sk_assign'd to the skb; a TCP_LISTEN
// socket additionally runs the syncookie generate/verify helper and records
// its source port; anything else is just sk_assign'd as-is. Kernel struct
// fields (sock_common.skc_num reached through
// tcp_sock/inet_connection_sock/inet_sock/sock, and through
// request_sock/sock_common) are read via #[btf] CO-RE chains, same pattern
// as cgrp_ls_attach_cgroup.rs's cgroup_of_tcp_sk().

use core::ffi::c_void;

use bpf_rs_core::ctx::{__sk_buff, TC_ACT_OK};
use bpf_rs_core::helpers::{
    bpf_sk_assign, bpf_sk_release, bpf_skc_lookup_tcp, bpf_skc_to_tcp_request_sock,
    bpf_skc_to_tcp_sock, bpf_tcp_check_syncookie, bpf_tcp_gen_syncookie,
};
use bpf_rs_core::{bpf_object, vload};
use btf_macros::btf;

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const IPPROTO_TCP: u8 = 6;
const BPF_F_CURRENT_NETNS: u64 = -1i64 as u64;
const BPF_TCP_LISTEN: u32 = 10;
const BPF_TCP_NEW_SYN_RECV: u32 = 12;
const ENOENT: i64 = 2;

#[inline(always)]
fn htons(x: u16) -> u16 {
    x.to_be()
}

#[inline(always)]
fn ntohl(x: u32) -> u32 {
    x.swap_bytes()
}

// UAPI struct sockaddr_in (netinet/in.h). Named to match the real UAPI type
// exactly: the generated skeleton forward-declares bss globals of a named
// struct type verbatim rather than inlining the layout, so it must resolve
// against the copy of the type the userspace test already has via
// <netinet/in.h>.
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct in_addr {
    pub s_addr: u32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct sockaddr_in {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: in_addr,
    pub sin_zero: [u8; 8],
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct in6_addr {
    pub s6_addr: [u8; 16],
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct sockaddr_in6 {
    pub sin6_family: u16,
    pub sin6_port: u16,
    pub sin6_flowinfo: u32,
    pub sin6_addr: in6_addr,
    pub sin6_scope_id: u32,
}

#[no_mangle]
static mut srv_sa6: sockaddr_in6 = sockaddr_in6 {
    sin6_family: 0,
    sin6_port: 0,
    sin6_flowinfo: 0,
    sin6_addr: in6_addr { s6_addr: [0; 16] },
    sin6_scope_id: 0,
};

#[no_mangle]
static mut srv_sa4: sockaddr_in = sockaddr_in {
    sin_family: 0,
    sin_port: 0,
    sin_addr: in_addr { s_addr: 0 },
    sin_zero: [0; 8],
};

#[no_mangle]
static mut listen_tp_sport: u16 = 0;
#[no_mangle]
static mut req_sk_sport: u16 = 0;
#[no_mangle]
static mut recv_cookie: u32 = 0;
#[no_mangle]
static mut gen_cookie: u32 = 0;
#[no_mangle]
static mut mss: u32 = 0;
#[no_mangle]
static mut linum: u32 = 0;

#[inline(always)]
fn log_err(line: u32) {
    unsafe {
        if linum == 0 {
            linum = line;
        }
    }
}

// Raw packet-memory overlays: plain pointer casts over skb bytes, not
// BTF-checked kernel types, so field names/types just need to reproduce the
// real on-wire layout (same idiom as test_sk_assign_libbpf.rs).
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct EthHdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
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

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Ipv6Hdr {
    priority_version: u8,
    flow_lbl: [u8; 3],
    payload_len: u16,
    nexthdr: u8,
    hop_limit: u8,
    saddr: [u8; 16],
    daddr: [u8; 16],
}

// struct tcphdr (linux/tcp.h). The little-endian bitfield word
// (res1:4,doff:4,fin:1,syn:1,rst:1,psh:1,ack:1,urg:1,ece:1,cwr:1) is two
// plain bytes here: byte0 low nibble = res1, high nibble = doff; byte1 bit0
// = fin, bit1 = syn (only doff/syn are read).
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct TcpHdr {
    source: u16,
    dest: u16,
    seq: u32,
    ack_seq: u32,
    flags0: u8,
    flags1: u8,
    window: u16,
    check: u16,
    urg_ptr: u16,
}

// UAPI struct bpf_sock (linux/bpf.h): only the fields up to and including
// `state` are declared; PTR_TO_SOCK_COMMON field access is checked by fixed
// byte offset against the real UAPI layout, independent of our struct's
// total size (see test_sk_assign_libbpf.rs).
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
}

// Real kernel `struct sock_common`; only `skc_num` (host-byte-order local
// port) is needed. Shared by both the `sock.__sk_common` and
// `request_sock.__req_common` CO-RE chains below.
#[btf]
struct sock_common {
    skc_num: u16,
}

// Real kernel `struct sock`: `struct sock_common __sk_common;` is its first
// member.
#[btf]
struct sock {
    __sk_common: sock_common,
}

// Real kernel `struct inet_sock`: `struct sock sk;` is its first member.
#[btf]
struct inet_sock {
    sk: sock,
}

// Real kernel `struct inet_connection_sock`: `struct inet_sock icsk_inet;`
// is its first member.
#[btf]
struct inet_connection_sock {
    icsk_inet: inet_sock,
}

// Real kernel `struct tcp_sock`: `struct inet_connection_sock inet_conn;`
// is its first member (see tcp_sk()/container_of in linux/tcp.h).
#[btf]
struct tcp_sock {
    inet_conn: inet_connection_sock,
}

// Real kernel `struct request_sock`: `struct sock_common __req_common;` is
// its first member.
#[btf]
struct request_sock {
    __req_common: sock_common,
}

#[inline(always)]
fn test_syncookie_helper(
    iphdr: *const c_void,
    iphdr_size: i32,
    th: *const TcpHdr,
    tp: *mut tcp_sock,
    skb: *const __sk_buff,
) {
    let flags1 = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*th).flags1)) };
    let syn = (flags1 >> 1) & 1;

    if syn != 0 {
        let data_end = vload!((*skb).data_end) as usize;

        let flags0 = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*th).flags0)) };
        let doff = (flags0 >> 4) & 0xf;
        if (doff as u32) * 4 != 40 {
            log_err(line!());
            return;
        }

        if (th as usize) + 40 > data_end {
            log_err(line!());
            return;
        }

        let mss_cookie = bpf_tcp_gen_syncookie(tp, iphdr, iphdr_size as u32, th, 40);
        if mss_cookie < 0 {
            if mss_cookie != -ENOENT {
                log_err(line!());
            }
        } else {
            unsafe {
                gen_cookie = mss_cookie as u32;
                mss = (mss_cookie >> 32) as u32;
            }
        }
    } else if unsafe { gen_cookie } != 0 {
        let ret = bpf_tcp_check_syncookie(
            tp,
            iphdr,
            iphdr_size as u32,
            th,
            core::mem::size_of::<TcpHdr>() as u32,
        );
        if ret < 0 {
            if ret != -ENOENT {
                log_err(line!());
            }
        } else {
            let ack_seq = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*th).ack_seq)) };
            unsafe {
                recv_cookie = ntohl(ack_seq).wrapping_sub(1);
            }
        }
    }
}

fn handle_ip_tcp(eth: *const EthHdr, skb: *const __sk_buff) -> i32 {
    let data_end = vload!((*skb).data_end) as usize;

    let h_proto = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*eth).h_proto)) };

    let th: *const TcpHdr;
    let tuple: usize;
    let tuple_len: usize;
    let iphdr: usize;
    let iphdr_size: i32;

    if h_proto == htons(ETH_P_IP) {
        let ip4h_off = eth as usize + core::mem::size_of::<EthHdr>();
        if ip4h_off + core::mem::size_of::<IpHdr>() > data_end {
            return TC_ACT_OK;
        }
        let ip4h = ip4h_off as *const IpHdr;
        let protocol = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip4h).protocol)) };
        if protocol != IPPROTO_TCP {
            return TC_ACT_OK;
        }
        let th_off = ip4h_off + core::mem::size_of::<IpHdr>();
        if th_off + core::mem::size_of::<TcpHdr>() > data_end {
            return TC_ACT_OK;
        }
        let th_ptr = th_off as *const TcpHdr;
        let dest = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*th_ptr).dest)) };
        let srv_port = unsafe { srv_sa4.sin_port };
        if dest != srv_port {
            return TC_ACT_OK;
        }
        th = th_ptr;
        tuple_len = 12; // sizeof(((struct bpf_sock_tuple *)0)->ipv4)
        tuple = unsafe { core::ptr::addr_of!((*ip4h).saddr) } as usize;
        iphdr = ip4h_off;
        iphdr_size = core::mem::size_of::<IpHdr>() as i32;
    } else if h_proto == htons(ETH_P_IPV6) {
        let ip6h_off = eth as usize + core::mem::size_of::<EthHdr>();
        if ip6h_off + core::mem::size_of::<Ipv6Hdr>() > data_end {
            return TC_ACT_OK;
        }
        let ip6h = ip6h_off as *const Ipv6Hdr;
        let nexthdr = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip6h).nexthdr)) };
        if nexthdr != IPPROTO_TCP {
            return TC_ACT_OK;
        }
        let th_off = ip6h_off + core::mem::size_of::<Ipv6Hdr>();
        if th_off + core::mem::size_of::<TcpHdr>() > data_end {
            return TC_ACT_OK;
        }
        let th_ptr = th_off as *const TcpHdr;
        let dest = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*th_ptr).dest)) };
        let srv_port = unsafe { srv_sa6.sin6_port };
        if dest != srv_port {
            return TC_ACT_OK;
        }
        th = th_ptr;
        tuple_len = 36; // sizeof(((struct bpf_sock_tuple *)0)->ipv6)
        tuple = unsafe { core::ptr::addr_of!((*ip6h).saddr) } as usize;
        iphdr = ip6h_off;
        iphdr_size = core::mem::size_of::<Ipv6Hdr>() as i32;
    } else {
        return TC_ACT_OK;
    }

    if tuple + tuple_len > data_end {
        log_err(line!());
        return TC_ACT_OK;
    }

    let bpf_skc = bpf_skc_lookup_tcp(
        skb as *const c_void,
        tuple as *const c_void,
        tuple_len as u32,
        BPF_F_CURRENT_NETNS,
        0,
    );
    if bpf_skc.is_null() {
        log_err(line!());
        return TC_ACT_OK;
    }

    let state = unsafe { (*(bpf_skc as *const BpfSock)).state };

    if state == BPF_TCP_NEW_SYN_RECV {
        let req_sk = bpf_skc_to_tcp_request_sock(bpf_skc) as *mut request_sock;
        if req_sk.is_null() {
            log_err(line!());
            bpf_sk_release(bpf_skc);
            return TC_ACT_OK;
        }

        if bpf_sk_assign(skb as *const c_void, req_sk as *mut c_void, 0) != 0 {
            log_err(line!());
            bpf_sk_release(bpf_skc);
            return TC_ACT_OK;
        }

        unsafe {
            req_sk_sport = *(&*req_sk).__req_common().skc_num().get().unwrap();
        }

        bpf_sk_release(req_sk as *mut c_void);
        return TC_ACT_OK;
    } else if state == BPF_TCP_LISTEN {
        let tp = bpf_skc_to_tcp_sock(bpf_skc) as *mut tcp_sock;
        if tp.is_null() {
            log_err(line!());
            bpf_sk_release(bpf_skc);
            return TC_ACT_OK;
        }

        if bpf_sk_assign(skb as *const c_void, tp as *mut c_void, 0) != 0 {
            log_err(line!());
            bpf_sk_release(bpf_skc);
            return TC_ACT_OK;
        }

        unsafe {
            listen_tp_sport = *(&*tp)
                .inet_conn()
                .icsk_inet()
                .sk()
                .__sk_common()
                .skc_num()
                .get()
                .unwrap();
        }

        test_syncookie_helper(iphdr as *const c_void, iphdr_size, th, tp, skb);

        bpf_sk_release(tp as *mut c_void);
        return TC_ACT_OK;
    }

    if bpf_sk_assign(skb as *const c_void, bpf_skc, 0) != 0 {
        log_err(line!());
    }

    bpf_sk_release(bpf_skc);
    TC_ACT_OK
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn cls_ingress(skb: *const __sk_buff) -> i32 {
    let data_end = vload!((*skb).data_end) as usize;
    let data = vload!((*skb).data) as usize;

    if data + core::mem::size_of::<EthHdr>() > data_end {
        return TC_ACT_OK;
    }
    let eth = data as *const EthHdr;
    let h_proto = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*eth).h_proto)) };

    if h_proto != htons(ETH_P_IP) && h_proto != htons(ETH_P_IPV6) {
        return TC_ACT_OK;
    }

    handle_ip_tcp(eth, skb)
}

bpf_object!("GPL");
