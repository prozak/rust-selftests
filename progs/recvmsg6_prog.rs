#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/recvmsg6_prog.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_getsockopt, bpf_setsockopt};

const AF_INET6: u32 = 10;
const SOCK_STREAM: u32 = 1;
const SOCK_DGRAM: u32 = 2;

const SOL_SOCKET: i32 = 1;
const SO_PRIORITY: i32 = 12;

const SERV6_IP_0: u32 = 0xfaceb00c; /* face:b00c:1234:5678::abcd */
const SERV6_IP_1: u32 = 0x12345678;
const SERV6_IP_2: u32 = 0x00000000;
const SERV6_IP_3: u32 = 0x0000abcd;
const SERV6_PORT: u16 = 6060;

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

#[link_section = "cgroup/recvmsg6"]
#[no_mangle]
extern "C" fn recvmsg6_prog(ctx: *mut bpf_sock_addr) -> i32 {
    let ctx_ref = unsafe { &mut *ctx };

    let sk = ctx_ref.sk as *const bpf_sock;
    if sk.is_null() {
        return 1;
    }

    if unsafe { (*sk).family } != AF_INET6 {
        return 1;
    }

    if ctx_ref.r#type != SOCK_STREAM && ctx_ref.r#type != SOCK_DGRAM {
        return 1;
    }

    if !get_set_sk_priority(ctx) {
        return 1;
    }

    ctx_ref.user_ip6[0] = SERV6_IP_0.to_be();
    ctx_ref.user_ip6[1] = SERV6_IP_1.to_be();
    ctx_ref.user_ip6[2] = SERV6_IP_2.to_be();
    ctx_ref.user_ip6[3] = SERV6_IP_3.to_be();
    ctx_ref.user_port = SERV6_PORT.to_be() as u32;

    1
}

bpf_object!("GPL");
