#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/cgrp_ls_attach_cgroup.c
// (bpf-rs-core idiom).

use bpf_rs_core::helpers::{bpf_cgrp_storage_get, bpf_get_socket_cookie, bpf_skc_to_tcp_sock};
use bpf_rs_core::progs::fentry_arg as arg;
use bpf_rs_core::{bpf_map, bpf_object};
use btf_macros::btf;
use core::ffi::c_void;

#[repr(C)]
pub struct socket_cookie {
    pub cookie_key: u64,
    pub cookie_value: u64,
}

bpf_map! {
    socket_cookies {
        r#type: *const [i32; 32],   // BPF_MAP_TYPE_CGRP_STORAGE
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        key: *const i32,
        value: *const socket_cookie,
    }
}

// UAPI struct bpf_sock_addr (linux/bpf.h). sk is a __bpf_md_ptr union,
// represented as u64.
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

// UAPI struct bpf_sock (linux/bpf.h), full layout.
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

// UAPI struct bpf_sock_ops (linux/bpf.h), full layout. The C source's
// leading union { args[4]; reply; replylong[4]; } is represented by its
// largest/first-declared member, args[4], same size either way.
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct bpf_sock_ops {
    pub op: u32,
    pub args: [u32; 4],
    pub family: u32,
    pub remote_ip4: u32,
    pub local_ip4: u32,
    pub remote_ip6: [u32; 4],
    pub local_ip6: [u32; 4],
    pub remote_port: u32,
    pub local_port: u32,
    pub is_fullsock: u32,
    pub snd_cwnd: u32,
    pub srtt_us: u32,
    pub bpf_sock_ops_cb_flags: u32,
    pub state: u32,
    pub rtt_min: u32,
    pub snd_ssthresh: u32,
    pub rcv_nxt: u32,
    pub snd_nxt: u32,
    pub snd_una: u32,
    pub mss_cache: u32,
    pub ecn_flags: u32,
    pub rate_delivered: u32,
    pub rate_interval_us: u32,
    pub packets_out: u32,
    pub retrans_out: u32,
    pub total_retrans: u32,
    pub segs_in: u32,
    pub data_segs_in: u32,
    pub segs_out: u32,
    pub data_segs_out: u32,
    pub lost_out: u32,
    pub sacked_out: u32,
    pub sk_txhash: u32,
    pub bytes_received: u64,
    pub bytes_acked: u64,
    pub sk: *mut bpf_sock,
    pub skb_data: *mut c_void,
    pub skb_data_end: *mut c_void,
    pub skb_len: u32,
    pub skb_tcp_flags: u32,
    pub skb_hwtstamp: u64,
}

// CO-RE view of the real kernel `struct cgroup`; only used as an opaque
// address (the map key), mirroring cgroup_iter.rs / test_cgroup1_hierarchy.rs.
#[btf]
struct kernfs_node {
    id: u64,
}

#[btf]
struct cgroup {
    kn: *mut kernfs_node,
}

#[btf]
struct sock_cgroup_data {
    cgroup: *mut cgroup,
}

// Real kernel `struct sock`; only the `sk_cgrp_data` field is needed, CO-RE
// matches it by name regardless of the many preceding fields left out here.
#[btf]
struct sock {
    sk_cgrp_data: sock_cgroup_data,
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

// Real kernel `struct socket`; only `sk` is needed.
#[btf]
struct socket {
    sk: *mut sock,
}

// Real kernel `struct sockaddr`; only `sa_family` is needed.
#[btf]
struct sockaddr {
    sa_family: u16,
}

const AF_INET6: u32 = 10;
const BPF_SOCK_OPS_TCP_CONNECT_CB: u32 = 3;
const BPF_LOCAL_STORAGE_GET_F_CREATE: u64 = 1;

fn cgroup_of_tcp_sk(tp: *const tcp_sock) -> *mut cgroup {
    unsafe {
        *(&*tp)
            .inet_conn()
            .icsk_inet()
            .sk()
            .sk_cgrp_data()
            .cgroup()
            .as_ptr()
    }
}

fn cgroup_of_sk(sk: *const sock) -> *mut cgroup {
    unsafe { *(&*sk).sk_cgrp_data().cgroup().as_ptr() }
}

#[link_section = "cgroup/connect6"]
#[no_mangle]
extern "C" fn set_cookie(ctx: *mut bpf_sock_addr) -> i32 {
    let ctx = unsafe { &mut *ctx };

    if ctx.family != AF_INET6 || ctx.user_family != AF_INET6 {
        return 1;
    }

    let sk = ctx.sk;
    if sk == 0 {
        return 1;
    }

    let tcp_sk = bpf_skc_to_tcp_sock(sk as *const c_void) as *const tcp_sock;
    if tcp_sk.is_null() {
        return 1;
    }

    let cgrp = cgroup_of_tcp_sk(tcp_sk);
    let p = bpf_cgrp_storage_get(
        &socket_cookies,
        cgrp,
        core::ptr::null_mut(),
        BPF_LOCAL_STORAGE_GET_F_CREATE,
    ) as *mut socket_cookie;
    if p.is_null() {
        return 1;
    }

    unsafe {
        (*p).cookie_value = 0xF;
        (*p).cookie_key = bpf_get_socket_cookie(ctx as *mut bpf_sock_addr);
    }

    1
}

#[link_section = "sockops"]
#[no_mangle]
extern "C" fn update_cookie_sockops(ctx: *mut bpf_sock_ops) -> i32 {
    let ctx = unsafe { &mut *ctx };

    if ctx.family != AF_INET6 || ctx.op != BPF_SOCK_OPS_TCP_CONNECT_CB {
        return 1;
    }

    let sk = ctx.sk;
    if sk.is_null() {
        return 1;
    }

    let tcp_sk = bpf_skc_to_tcp_sock(sk as *const c_void) as *const tcp_sock;
    if tcp_sk.is_null() {
        return 1;
    }

    let cgrp = cgroup_of_tcp_sk(tcp_sk);
    let p = bpf_cgrp_storage_get(&socket_cookies, cgrp, core::ptr::null_mut(), 0) as *mut socket_cookie;
    if p.is_null() {
        return 1;
    }

    if unsafe { (*p).cookie_key } != bpf_get_socket_cookie(ctx as *mut bpf_sock_ops) {
        return 1;
    }

    unsafe { (*p).cookie_value |= (ctx.local_port << 8) as u64 };

    1
}

#[link_section = "fexit/inet_stream_connect"]
#[no_mangle]
extern "C" fn update_cookie_tracing(ctx: *const u64) -> i32 {
    let sock_ptr = arg(ctx, 0) as *const socket;
    let uaddr = arg(ctx, 1) as *const sockaddr;

    let sa_family = unsafe { *(&*uaddr).sa_family().as_ptr() };
    if sa_family as u32 != AF_INET6 {
        return 0;
    }

    let sk = unsafe { *(&*sock_ptr).sk().as_ptr() };

    let cgrp = cgroup_of_sk(sk);
    let p = bpf_cgrp_storage_get(&socket_cookies, cgrp, core::ptr::null_mut(), 0) as *mut socket_cookie;
    if p.is_null() {
        return 0;
    }

    if unsafe { (*p).cookie_key } != bpf_get_socket_cookie(sk) {
        return 0;
    }

    unsafe { (*p).cookie_value |= 0xF0 };

    0
}

bpf_object!("GPL");
