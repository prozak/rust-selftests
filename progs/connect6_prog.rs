#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/connect6_prog.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_bind, bpf_sk_lookup_tcp, bpf_sk_lookup_udp, bpf_sk_release};
use core::ffi::c_void;

const SRC_REWRITE_IP6_0: u32 = 0;
const SRC_REWRITE_IP6_1: u32 = 0;
const SRC_REWRITE_IP6_2: u32 = 0;
const SRC_REWRITE_IP6_3: u32 = 6;

const DST_REWRITE_IP6_0: u32 = 0;
const DST_REWRITE_IP6_1: u32 = 0;
const DST_REWRITE_IP6_2: u32 = 0;
const DST_REWRITE_IP6_3: u32 = 1;

const DST_REWRITE_PORT6: u16 = 6666;

const SOCK_STREAM: u32 = 1;
const SOCK_DGRAM: u32 = 2;
const AF_INET6: u16 = 10;
const BPF_F_CURRENT_NETNS: u64 = -1i64 as u64;

/// UAPI struct bpf_sock_addr (linux/bpf.h). sk is a __bpf_md_ptr union,
/// represented as u64.
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct bpf_sock_addr {
    pub user_family: u32,
    pub user_ip4: u32,
    pub user_ip6: [u32; 4],
    pub user_port: u32,
    pub family: u32,
    pub r#type: u32,
    pub protocol: u32,
    pub msg_src_ip4: u32,
    pub msg_src_ip6: [u32; 4],
    pub sk: u64,
}

// UAPI struct bpf_sock (linux/bpf.h), full layout. src_port is host byte
// order (unlike dst_port); only src_ip6/src_port are read here.
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct bpf_sock {
    pub bound_dev_if: u32,
    pub family: u32,
    pub r#type: u32,
    pub protocol: u32,
    pub mark: u32,
    pub priority: u32,
    pub src_ip4: u32,
    pub src_ip6: [u32; 4],
    pub src_port: u32,
    pub dst_port: u16,
    pub _pad: u16,
    pub dst_ip4: u32,
    pub dst_ip6: [u32; 4],
    pub state: u32,
    pub rx_queue_mapping: i32,
}

// struct bpf_sock_tuple's `.ipv6` member (UAPI linux/bpf.h). The union's
// other member (`.ipv4`) is never used by this program, so only the ipv6
// shape is declared, at the union's (zero) offset.
#[repr(C)]
struct SockTupleIpv6 {
    saddr: [u32; 4],
    daddr: [u32; 4],
    sport: u16,
    dport: u16,
}

// UAPI struct sockaddr_in6 (linux/in6.h).
#[allow(non_camel_case_types)]
#[repr(C)]
struct sockaddr_in6 {
    sin6_family: u16,
    sin6_port: u16,
    sin6_flowinfo: u32,
    sin6_addr: [u32; 4],
    sin6_scope_id: u32,
}

#[link_section = "cgroup/connect6"]
#[no_mangle]
extern "C" fn connect_v6_prog(ctx: *const bpf_sock_addr) -> i32 {
    let ctx = unsafe { &mut *(ctx as *mut bpf_sock_addr) };

    // Verify that new destination is available.
    let tuple = SockTupleIpv6 {
        saddr: [0; 4],
        daddr: [
            DST_REWRITE_IP6_0.to_be(),
            DST_REWRITE_IP6_1.to_be(),
            DST_REWRITE_IP6_2.to_be(),
            DST_REWRITE_IP6_3.to_be(),
        ],
        sport: 0,
        dport: DST_REWRITE_PORT6.to_be(),
    };

    if ctx.r#type != SOCK_STREAM && ctx.r#type != SOCK_DGRAM {
        return 0;
    }

    let tuple_size = core::mem::size_of::<SockTupleIpv6>() as u32;
    let sk = if ctx.r#type == SOCK_STREAM {
        bpf_sk_lookup_tcp(
            ctx as *const bpf_sock_addr as *const c_void,
            &tuple as *const SockTupleIpv6,
            tuple_size,
            BPF_F_CURRENT_NETNS,
            0,
        )
    } else {
        bpf_sk_lookup_udp(
            ctx as *const bpf_sock_addr as *const c_void,
            &tuple as *const SockTupleIpv6,
            tuple_size,
            BPF_F_CURRENT_NETNS,
            0,
        )
    } as *mut bpf_sock;

    if sk.is_null() {
        return 0;
    }

    let matches = unsafe {
        (*sk).src_ip6[0] == tuple.daddr[0]
            && (*sk).src_ip6[1] == tuple.daddr[1]
            && (*sk).src_ip6[2] == tuple.daddr[2]
            && (*sk).src_ip6[3] == tuple.daddr[3]
            && (*sk).src_port == DST_REWRITE_PORT6 as u32
    };

    bpf_sk_release(sk as *mut c_void);

    if !matches {
        return 0;
    }

    // Rewrite destination.
    ctx.user_ip6[0] = DST_REWRITE_IP6_0.to_be();
    ctx.user_ip6[1] = DST_REWRITE_IP6_1.to_be();
    ctx.user_ip6[2] = DST_REWRITE_IP6_2.to_be();
    ctx.user_ip6[3] = DST_REWRITE_IP6_3.to_be();

    ctx.user_port = DST_REWRITE_PORT6.to_be() as u32;

    // Rewrite source.
    let sa = sockaddr_in6 {
        sin6_family: AF_INET6,
        sin6_port: 0u16.to_be(),
        sin6_flowinfo: 0,
        sin6_addr: [
            SRC_REWRITE_IP6_0.to_be(),
            SRC_REWRITE_IP6_1.to_be(),
            SRC_REWRITE_IP6_2.to_be(),
            SRC_REWRITE_IP6_3.to_be(),
        ],
        sin6_scope_id: 0,
    };

    if bpf_bind(
        ctx as *mut bpf_sock_addr,
        &sa as *const sockaddr_in6 as *mut c_void,
        core::mem::size_of::<sockaddr_in6>() as i32,
    ) != 0
    {
        return 0;
    }

    1
}

#[link_section = "cgroup/connect6"]
#[no_mangle]
extern "C" fn connect_v6_deny_prog(_ctx: *const bpf_sock_addr) -> i32 {
    0
}

bpf_object!("GPL");
