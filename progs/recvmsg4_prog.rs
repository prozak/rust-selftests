// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/recvmsg4_prog.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_getsockopt, bpf_setsockopt};

const AF_INET: u32 = 2;
const SOCK_STREAM: u32 = 1;
const SOCK_DGRAM: u32 = 2;

const SOL_SOCKET: i32 = 1;
const SO_PRIORITY: i32 = 12;

const SERV4_IP: u32 = 0xc0a801fe; /* 192.168.1.254 */
const SERV4_PORT: u16 = 4040;

/// UAPI struct bpf_sock_addr (linux/bpf.h). sk is a __bpf_md_ptr union,
/// represented as u64 (this TU doesn't define __KERNEL__/__VMLINUX_H__, so
/// the real C object's field is also a plain __u64).
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

/// UAPI struct bpf_sock (linux/bpf.h), truncated to the fields this
/// translation reads (`family` at its real byte offset).
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_sock {
    bound_dev_if: u32,
    family: u32,
}

fn get_set_sk_priority(ctx: *mut bpf_sock_addr) -> bool {
    let mut prio: i32 = 0;
    if bpf_getsockopt(
        ctx,
        SOL_SOCKET,
        SO_PRIORITY,
        core::ptr::addr_of_mut!(prio) as *mut core::ffi::c_void,
        core::mem::size_of::<i32>() as i32,
    ) != 0
    {
        return false;
    }
    if bpf_setsockopt(
        ctx,
        SOL_SOCKET,
        SO_PRIORITY,
        core::ptr::addr_of_mut!(prio) as *mut core::ffi::c_void,
        core::mem::size_of::<i32>() as i32,
    ) != 0
    {
        return false;
    }
    true
}

#[link_section = "cgroup/recvmsg4"]
#[no_mangle]
extern "C" fn recvmsg4_prog(ctx: *mut bpf_sock_addr) -> i32 {
    let ctx_ref = unsafe { &mut *ctx };

    let sk = ctx_ref.sk as *const bpf_sock;
    if sk.is_null() {
        return 1;
    }

    if unsafe { (*sk).family } != AF_INET {
        return 1;
    }

    if ctx_ref.r#type != SOCK_STREAM && ctx_ref.r#type != SOCK_DGRAM {
        return 1;
    }

    if !get_set_sk_priority(ctx) {
        return 1;
    }

    ctx_ref.user_ip4 = SERV4_IP.to_be();
    ctx_ref.user_port = SERV4_PORT.to_be() as u32;

    1
}

bpf_object!("GPL");
