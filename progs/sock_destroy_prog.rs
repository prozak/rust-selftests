#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/sock_destroy_prog.c
// (bpf-rs-core idiom).
//
// tcp6_sock/tcp_sock/inet_connection_sock/inet_sock nesting mirrors the C
// container_of-free direct chain `tcp_sk->tcp.inet_conn.icsk_inet.inet_sport`
// (include/linux/ipv6.h, include/linux/tcp.h, include/net/inet_connection_sock.h,
// include/net/inet_sock.h): each level is the true first member of its
// parent, but the field names still need a real `#[btf]` byte-offset
// relocation, same idiom as cgroup_ancestor.rs / tcp_ca_incompl_cong_ops.rs.
//
// `struct sock *sk = (struct sock *) udp_sk` in the C iter/udp programs is
// address-preserving (`struct inet_sock inet` is udp_sock's first member,
// `struct sock sk` is inet_sock's first member), so the cast is elided and
// the raw `udp_sk`/`c_void` pointer is reused directly for the cookie/kfunc
// calls, matching bpf_iter_unix.rs's analogous `unix_sk as *mut sock` trick.

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_get_socket_cookie, bpf_map_lookup_elem, bpf_map_update_elem, bpf_skc_to_tcp6_sock,
};
use bpf_rs_core::maps::{self, BpfMap};
use btf_macros::btf;

const AF_INET6: u32 = 10;
const AF_INET6_FAMILY: u16 = 10;
const IPPROTO_TCP: u32 = 6;
const IPPROTO_UDP: u32 = 17;

#[no_mangle]
static mut serv_port: u16 = 0;

extern "C" {
    fn bpf_sock_destroy(sk: *mut sock_common) -> i32;
}

#[link_section = ".maps"]
#[no_mangle]
static tcp_conn_sockets: BpfMap<u32, u64, { maps::ARRAY }, 1> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static udp_conn_sockets: BpfMap<u32, u64, { maps::ARRAY }, 1> = BpfMap::new();

/// UAPI struct bpf_sock_addr (linux/bpf.h). sk is a __bpf_md_ptr union,
/// represented as u64.
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_sock_addr {
    user_family: u32,
    user_ip4: u32,
    user_ip6: [u32; 4],
    user_port: u32,
    family: u32,
    r#type: u32,
    protocol: u32,
    msg_src_ip4: u32,
    msg_src_ip6: [u32; 4],
    sk: u64,
}

#[repr(C)]
struct bpf_iter_meta {
    seq: *mut c_void,
    session_id: u64,
    seq_num: u64,
}

#[repr(C)]
struct bpf_iter__tcp {
    meta: *mut bpf_iter_meta,
    sk_common: *mut sock_common,
}

#[repr(C)]
struct bpf_iter__udp {
    meta: *mut bpf_iter_meta,
    udp_sk: *mut udp_sock,
}

#[btf]
struct sock_common {
    skc_family: u16,
}

#[btf]
struct inet_sock {
    inet_sport: u16,
}

#[btf]
struct inet_connection_sock {
    icsk_inet: inet_sock,
}

#[btf]
struct tcp_sock {
    inet_conn: inet_connection_sock,
}

#[btf]
struct tcp6_sock {
    tcp: tcp_sock,
}

#[btf]
struct udp_sock {
    inet: inet_sock,
}

#[link_section = "cgroup/connect6"]
#[no_mangle]
extern "C" fn sock_connect(ctx: *const bpf_sock_addr) -> i32 {
    let ctx_ref = unsafe { &*ctx };

    if ctx_ref.family != AF_INET6 || ctx_ref.user_family != AF_INET6 {
        return 1;
    }

    let sock_cookie = bpf_get_socket_cookie(ctx);

    let key: u32 = 0;
    let keyc: u32 = 0;

    if ctx_ref.protocol == IPPROTO_TCP {
        bpf_map_update_elem(&tcp_conn_sockets, &key, &sock_cookie, 0);
    } else if ctx_ref.protocol == IPPROTO_UDP {
        bpf_map_update_elem(&udp_conn_sockets, &keyc, &sock_cookie, 0);
    } else {
        return 1;
    }

    1
}

#[link_section = "iter/tcp"]
#[no_mangle]
extern "C" fn iter_tcp6_client(ctx: *const bpf_iter__tcp) -> i32 {
    let ctx = unsafe { &*ctx };
    let sk_common = ctx.sk_common;
    if sk_common.is_null() {
        return 0;
    }

    let family = unsafe { *(&*sk_common).skc_family().as_ptr() };
    if family != AF_INET6_FAMILY {
        return 0;
    }

    let sock_cookie = bpf_get_socket_cookie(sk_common as *const sock_common);
    let key: u32 = 0;
    let val = bpf_map_lookup_elem(&tcp_conn_sockets, &key) as *const u64;
    if val.is_null() {
        return 0;
    }

    if sock_cookie == unsafe { *val } {
        unsafe {
            bpf_sock_destroy(sk_common);
        }
    }

    0
}

#[link_section = "iter/tcp"]
#[no_mangle]
extern "C" fn iter_tcp6_server(ctx: *const bpf_iter__tcp) -> i32 {
    let ctx = unsafe { &*ctx };
    let sk_common = ctx.sk_common;
    if sk_common.is_null() {
        return 0;
    }

    let family = unsafe { *(&*sk_common).skc_family().as_ptr() };
    if family != AF_INET6_FAMILY {
        return 0;
    }

    let tcp_sk = bpf_skc_to_tcp6_sock(sk_common as *mut c_void) as *const tcp6_sock;
    if tcp_sk.is_null() {
        return 0;
    }

    let srcp = unsafe { *(&*tcp_sk).tcp().inet_conn().icsk_inet().inet_sport().as_ptr() };

    if srcp == unsafe { serv_port } {
        unsafe {
            bpf_sock_destroy(sk_common);
        }
    }

    0
}

#[link_section = "iter/udp"]
#[no_mangle]
extern "C" fn iter_udp6_client(ctx: *const bpf_iter__udp) -> i32 {
    let ctx = unsafe { &*ctx };
    let udp_sk = ctx.udp_sk;
    let sk = udp_sk as *mut c_void;
    if sk.is_null() {
        return 0;
    }

    let sock_cookie = bpf_get_socket_cookie(sk as *const c_void);
    let key: u32 = 0;
    let val = bpf_map_lookup_elem(&udp_conn_sockets, &key) as *const u64;
    if val.is_null() {
        return 0;
    }

    if sock_cookie == unsafe { *val } {
        unsafe {
            bpf_sock_destroy(sk as *mut sock_common);
        }
    }

    0
}

#[link_section = "iter/udp"]
#[no_mangle]
extern "C" fn iter_udp6_server(ctx: *const bpf_iter__udp) -> i32 {
    let ctx = unsafe { &*ctx };
    let udp_sk = ctx.udp_sk;
    if udp_sk.is_null() {
        return 0;
    }

    let srcp = unsafe { *(&*udp_sk).inet().inet_sport().as_ptr() };

    if srcp == unsafe { serv_port } {
        unsafe {
            bpf_sock_destroy(udp_sk as *mut sock_common);
        }
    }

    0
}

bpf_object!("GPL");
