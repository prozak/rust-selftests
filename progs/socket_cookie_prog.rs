#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/socket_cookie_prog.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_get_socket_cookie, bpf_sk_storage_get};
use bpf_rs_core::progs::fentry_arg as arg;
use btf_macros::btf;
use core::ffi::c_void;

const AF_INET6: u32 = 10;
const BPF_SK_STORAGE_GET_F_CREATE: u64 = 1;
const BPF_SOCK_OPS_TCP_CONNECT_CB: u32 = 3;

#[repr(C)]
pub struct socket_cookie {
    pub cookie_key: u64,
    pub cookie_value: u32,
}

bpf_map! {
    socket_cookies {
        r#type: *const [i32; 24],  // BPF_MAP_TYPE_SK_STORAGE
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        key: *const i32,
        value: *const socket_cookie,
    }
}

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

/// UAPI struct bpf_sock_ops (linux/bpf.h), through `sk` only — nothing past
/// it is read, but every earlier field must keep its exact C offset for the
/// kernel's per-field ctx-access rewrite to line up.
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
    pub sk: u64,
}

#[btf]
struct sock {}

#[btf]
struct socket {
    sk: *mut sock,
}

#[btf]
struct sockaddr {
    sa_family: u16,
}

#[link_section = "cgroup/connect6"]
#[no_mangle]
extern "C" fn set_cookie(ctx: *const bpf_sock_addr) -> i32 {
    let ctx_ref = unsafe { &*ctx };

    if ctx_ref.family != AF_INET6 || ctx_ref.user_family != AF_INET6 {
        return 1;
    }

    let sk = ctx_ref.sk as *mut c_void;
    let p = bpf_sk_storage_get(
        &socket_cookies,
        sk,
        core::ptr::null_mut(),
        BPF_SK_STORAGE_GET_F_CREATE,
    ) as *mut socket_cookie;
    if p.is_null() {
        return 1;
    }

    unsafe {
        (*p).cookie_value = 0xF;
        (*p).cookie_key = bpf_get_socket_cookie(ctx);
    }

    1
}

#[link_section = "sockops"]
#[no_mangle]
extern "C" fn update_cookie_sockops(ctx: *const bpf_sock_ops) -> i32 {
    let ctx_ref = unsafe { &*ctx };

    if ctx_ref.family != AF_INET6 {
        return 1;
    }
    if ctx_ref.op != BPF_SOCK_OPS_TCP_CONNECT_CB {
        return 1;
    }

    let sk = ctx_ref.sk as *mut c_void;
    if sk.is_null() {
        return 1;
    }

    let p = bpf_sk_storage_get(&socket_cookies, sk, core::ptr::null_mut(), 0) as *mut socket_cookie;
    if p.is_null() {
        return 1;
    }

    if unsafe { (*p).cookie_key } != bpf_get_socket_cookie(ctx) {
        return 1;
    }

    unsafe { (*p).cookie_value |= ctx_ref.local_port << 8 };

    1
}

#[link_section = "fexit/inet_stream_connect"]
#[no_mangle]
extern "C" fn update_cookie_tracing(ctx: *const u64) -> i32 {
    let sock_ptr = arg(ctx, 0) as *mut socket;
    let uaddr = arg(ctx, 1) as *mut sockaddr;

    let sa_family = *unsafe { &*uaddr }.sa_family().get().unwrap();
    if sa_family as u32 != AF_INET6 {
        return 0;
    }

    let sk = *unsafe { &*sock_ptr }.sk().get().unwrap();
    let p = bpf_sk_storage_get(&socket_cookies, sk, core::ptr::null_mut(), 0) as *mut socket_cookie;
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
