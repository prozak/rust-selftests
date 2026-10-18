// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(linkage)]

// Direct translation of tools/testing/selftests/bpf/progs/connect4_prog.c
// (bpf-rs-core idiom). cgroup/connect4: binds the socket to two veths and
// back, toggles keepalive and the not-sent low-water mark, looks up the
// server socket at the rewritten destination, switches the congestion
// control to reno and cubic, then rewrites the destination and binds the
// source through do_bind. prog_tests/sock_addr.c runs it against a server;
// fexit_bpf2bpf.c replaces do_bind with freplace_connect4's program, so
// do_bind is the C's weak global subprogram with the UAPI ctx type by name.
// The strings compared with bpf_strncmp are C `char` arrays. fexit_bpf2bpf's
// bpf_prog_test_load() takes the object's FIRST program as the freplace
// target, so the section keeps the C's order (rustc would sort by name and
// put connect_v4_deny_prog, which has no do_bind, first).
// BTF_C_CHAR: u8
// BPF_PROGRAM_ORDER: connect_v4_prog connect_v4_deny_prog

use core::ffi::c_void;
use core::ptr::addr_of;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_bind, bpf_getsockopt, bpf_setsockopt, bpf_sk_lookup_tcp, bpf_sk_lookup_udp,
    bpf_sk_release, bpf_strncmp,
};

const SRC_REWRITE_IP4: u32 = 0x7f000004;
const DST_REWRITE_IP4: u32 = 0x7f000001;
const DST_REWRITE_PORT4: u16 = 4444;

const TCP_CA_NAME_MAX: usize = 16;
const TCP_NOTSENT_LOWAT: i32 = 25;
const IFNAMSIZ: usize = 16;
const SOL_TCP: i32 = 6;
const SOL_SOCKET: i32 = 1;
const SO_BINDTODEVICE: i32 = 25;
const SO_KEEPALIVE: i32 = 9;
const TCP_CONGESTION: i32 = 13;
const TCP_KEEPIDLE: i32 = 4;
const TCP_KEEPINTVL: i32 = 5;
const TCP_KEEPCNT: i32 = 6;
const TCP_SYNCNT: i32 = 7;
const TCP_USER_TIMEOUT: i32 = 18;
const SOCK_STREAM: u32 = 1;
const SOCK_DGRAM: u32 = 2;
const AF_INET: u16 = 2;
const ENODEV: i64 = 19;
const BPF_F_CURRENT_NETNS: u64 = -1i64 as u64;

/// UAPI struct bpf_sock_addr (linux/bpf.h). sk is a __bpf_md_ptr union,
/// represented as u64; the ctx type is only ever pointed at (its padding
/// before sk is the UAPI's).
// translint: allow(padding)
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
// order (unlike dst_port); only src_ip4/src_port are read here.
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

// struct bpf_sock_tuple (UAPI linux/bpf.h): the union of the ipv4 and ipv6
// shapes, 36 bytes; `tuple = {}` zeroes all of it and the lookups take
// sizeof(tuple.ipv4) = 12.
#[repr(C)]
struct SockTupleIpv4 {
    saddr: u32,
    daddr: u32,
    sport: u16,
    dport: u16,
}

#[repr(C)]
struct bpf_sock_tuple {
    ipv4: SockTupleIpv4,
    _ipv6_rest: [u8; 24],
}

// UAPI struct sockaddr_in (linux/in.h).
#[allow(non_camel_case_types)]
#[repr(C)]
struct sockaddr_in {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [u8; 8],
}

#[link_section = ".rodata"]
#[no_mangle]
static reno: [u8; 5] = *b"reno\0";
#[link_section = ".rodata"]
#[no_mangle]
static cubic: [u8; 6] = *b"cubic\0";

#[inline(always)]
fn htons(v: u16) -> u16 {
    v.swap_bytes()
}

#[inline(always)]
fn htonl(v: u32) -> u32 {
    v.swap_bytes()
}

// __attribute__ ((noinline)) __weak int do_bind(struct bpf_sock_addr *ctx)
#[inline(never)]
#[linkage = "weak"]
#[no_mangle]
extern "C" fn do_bind(ctx: *mut bpf_sock_addr) -> i32 {
    let mut sa = sockaddr_in {
        sin_family: AF_INET,
        sin_port: htons(0),
        sin_addr: htonl(SRC_REWRITE_IP4),
        sin_zero: [0; 8],
    };

    if bpf_bind(ctx, &mut sa as *mut sockaddr_in, core::mem::size_of::<sockaddr_in>() as i32) != 0 {
        return 0;
    }

    1
}

#[inline(always)]
fn verify_cc(ctx: *mut bpf_sock_addr, expected: *const u8) -> i32 {
    let mut buf = [0u8; TCP_CA_NAME_MAX];

    if bpf_getsockopt(ctx, SOL_TCP, TCP_CONGESTION, buf.as_mut_ptr() as *mut c_void, TCP_CA_NAME_MAX as i32) != 0 {
        return 1;
    }

    if bpf_strncmp(buf.as_ptr() as *const c_void, TCP_CA_NAME_MAX as u32, expected as *const c_void) != 0 {
        return 1;
    }

    0
}

// the C object keeps set_cc as a local subprogram
#[inline(never)]
#[export_name = "set_cc"]
extern "C" fn set_cc(ctx: *mut bpf_sock_addr) -> i32 {
    if bpf_setsockopt(ctx, SOL_TCP, TCP_CONGESTION, addr_of!(reno) as *const c_void, 5) != 0 {
        return 1;
    }
    if verify_cc(ctx, addr_of!(reno) as *const u8) != 0 {
        return 1;
    }

    if bpf_setsockopt(ctx, SOL_TCP, TCP_CONGESTION, addr_of!(cubic) as *const c_void, 6) != 0 {
        return 1;
    }
    if verify_cc(ctx, addr_of!(cubic) as *const u8) != 0 {
        return 1;
    }

    0
}

/// A 16-byte C `char name[IFNAMSIZ] = "..."` local as its two 8-byte words:
/// an array copy of the literal would become a bpf_arena_memcpy kfunc call
/// that the C object does not make (clang stores the words immediately).
#[repr(C, align(8))]
struct IfName {
    lo: u64,
    hi: u64,
}

impl IfName {
    const fn new(lo: &[u8; 8], hi: &[u8; 8]) -> IfName {
        IfName { lo: u64::from_le_bytes(*lo), hi: u64::from_le_bytes(*hi) }
    }
}

#[inline(always)]
fn bind_to_device(ctx: *mut bpf_sock_addr) -> i32 {
    let veth1 = IfName::new(b"test_soc", b"k_addr1\0");
    let veth2 = IfName::new(b"test_soc", b"k_addr2\0");
    let missing = IfName::new(b"nonexist", b"ent_dev\0");
    let del_bind = IfName { lo: 0, hi: 0 };

    if bpf_setsockopt(ctx, SOL_SOCKET, SO_BINDTODEVICE, &veth1 as *const IfName as *const c_void, IFNAMSIZ as i32) != 0 {
        return 1;
    }
    if bpf_setsockopt(ctx, SOL_SOCKET, SO_BINDTODEVICE, &veth2 as *const IfName as *const c_void, IFNAMSIZ as i32) != 0 {
        return 1;
    }
    if bpf_setsockopt(ctx, SOL_SOCKET, SO_BINDTODEVICE, &missing as *const IfName as *const c_void, IFNAMSIZ as i32)
        != -ENODEV
    {
        return 1;
    }
    if bpf_setsockopt(ctx, SOL_SOCKET, SO_BINDTODEVICE, &del_bind as *const IfName as *const c_void, IFNAMSIZ as i32) != 0 {
        return 1;
    }

    0
}

#[inline(always)]
fn set_keepalive(ctx: *mut bpf_sock_addr) -> i32 {
    let zero: i32 = 0;
    let one: i32 = 1;

    if bpf_setsockopt(ctx, SOL_SOCKET, SO_KEEPALIVE, &one as *const i32 as *const c_void, 4) != 0 {
        return 1;
    }
    if unsafe { (*ctx).r#type } == SOCK_STREAM {
        if bpf_setsockopt(ctx, SOL_TCP, TCP_KEEPIDLE, &one as *const i32 as *const c_void, 4) != 0 {
            return 1;
        }
        if bpf_setsockopt(ctx, SOL_TCP, TCP_KEEPINTVL, &one as *const i32 as *const c_void, 4) != 0 {
            return 1;
        }
        if bpf_setsockopt(ctx, SOL_TCP, TCP_KEEPCNT, &one as *const i32 as *const c_void, 4) != 0 {
            return 1;
        }
        if bpf_setsockopt(ctx, SOL_TCP, TCP_SYNCNT, &one as *const i32 as *const c_void, 4) != 0 {
            return 1;
        }
        if bpf_setsockopt(ctx, SOL_TCP, TCP_USER_TIMEOUT, &one as *const i32 as *const c_void, 4) != 0 {
            return 1;
        }
    }
    if bpf_setsockopt(ctx, SOL_SOCKET, SO_KEEPALIVE, &zero as *const i32 as *const c_void, 4) != 0 {
        return 1;
    }

    0
}

#[inline(always)]
fn set_notsent_lowat(ctx: *mut bpf_sock_addr) -> i32 {
    let lowat: i32 = 65535;

    if unsafe { (*ctx).r#type } == SOCK_STREAM {
        if bpf_setsockopt(ctx, SOL_TCP, TCP_NOTSENT_LOWAT, &lowat as *const i32 as *const c_void, 4) != 0 {
            return 1;
        }
    }

    0
}

#[link_section = "cgroup/connect4"]
#[no_mangle]
extern "C" fn connect_v4_prog(ctx: *mut bpf_sock_addr) -> i32 {
    /* Verify that new destination is available. */
    let tuple = bpf_sock_tuple {
        ipv4: SockTupleIpv4 {
            saddr: 0,
            daddr: htonl(DST_REWRITE_IP4),
            sport: 0,
            dport: htons(DST_REWRITE_PORT4),
        },
        _ipv6_rest: [0; 24],
    };

    /* Bind to device and unbind it. */
    if bind_to_device(ctx) != 0 {
        return 0;
    }

    if set_keepalive(ctx) != 0 {
        return 0;
    }

    if set_notsent_lowat(ctx) != 0 {
        return 0;
    }

    let sock_type = unsafe { (*ctx).r#type };
    if sock_type != SOCK_STREAM && sock_type != SOCK_DGRAM {
        return 0;
    }
    let sk = if sock_type == SOCK_STREAM {
        bpf_sk_lookup_tcp(
            ctx as *const c_void,
            &tuple as *const bpf_sock_tuple,
            core::mem::size_of::<SockTupleIpv4>() as u32,
            BPF_F_CURRENT_NETNS,
            0,
        )
    } else {
        bpf_sk_lookup_udp(
            ctx as *const c_void,
            &tuple as *const bpf_sock_tuple,
            core::mem::size_of::<SockTupleIpv4>() as u32,
            BPF_F_CURRENT_NETNS,
            0,
        )
    } as *mut bpf_sock;

    if sk.is_null() {
        return 0;
    }

    if unsafe { (*sk).src_ip4 } != tuple.ipv4.daddr || unsafe { (*sk).src_port } != DST_REWRITE_PORT4 as u32 {
        bpf_sk_release(sk as *mut c_void);
        return 0;
    }

    bpf_sk_release(sk as *mut c_void);

    /* Rewrite congestion control. */
    if sock_type == SOCK_STREAM && set_cc(ctx) != 0 {
        return 0;
    }

    /* Rewrite destination. */
    unsafe {
        (*ctx).user_ip4 = htonl(DST_REWRITE_IP4);
        (*ctx).user_port = htons(DST_REWRITE_PORT4) as u32;
    }

    if do_bind(ctx) != 0 {
        1
    } else {
        0
    }
}

#[link_section = "cgroup/connect4"]
#[no_mangle]
extern "C" fn connect_v4_deny_prog(_ctx: *mut bpf_sock_addr) -> i32 {
    0
}

bpf_object!("GPL");
