#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/sendmsg6_prog.c
// (bpf-rs-core idiom).

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_getsockopt, bpf_setsockopt};

const SOCK_DGRAM: u32 = 2;

const SOL_SOCKET: i32 = 1;
const SO_PRIORITY: i32 = 12;

const SRC_REWRITE_IP6_0: u32 = 0;
const SRC_REWRITE_IP6_1: u32 = 0;
const SRC_REWRITE_IP6_2: u32 = 0;
const SRC_REWRITE_IP6_3: u32 = 6;

const DST_REWRITE_IP6_0: u32 = 0;
const DST_REWRITE_IP6_1: u32 = 0;
const DST_REWRITE_IP6_2: u32 = 0;
const DST_REWRITE_IP6_3: u32 = 1;

const DST_REWRITE_IP6_V4_MAPPED_0: u32 = 0;
const DST_REWRITE_IP6_V4_MAPPED_1: u32 = 0;
const DST_REWRITE_IP6_V4_MAPPED_2: u32 = 0x0000_FFFF;
const DST_REWRITE_IP6_V4_MAPPED_3: u32 = 0xc0a8_0004; // 192.168.0.4

const DST_REWRITE_PORT6: u16 = 6666;

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

/// Verify that context allows calling bpf_getsockopt and bpf_setsockopt by
/// reading and writing back socket priority.
fn get_set_sk_priority(ctx: *mut c_void) -> bool {
    let mut prio: i32 = 0;
    let prio_ptr = &mut prio as *mut i32 as *mut c_void;

    if bpf_getsockopt(ctx, SOL_SOCKET, SO_PRIORITY, prio_ptr, core::mem::size_of::<i32>() as i32) != 0 {
        return false;
    }
    if bpf_setsockopt(ctx, SOL_SOCKET, SO_PRIORITY, prio_ptr, core::mem::size_of::<i32>() as i32) != 0 {
        return false;
    }

    true
}

#[link_section = "cgroup/sendmsg6"]
#[no_mangle]
extern "C" fn sendmsg_v6_prog(ctx: *const bpf_sock_addr) -> i32 {
    let ctx = unsafe { &mut *(ctx as *mut bpf_sock_addr) };

    if ctx.r#type != SOCK_DGRAM {
        return 0;
    }

    if !get_set_sk_priority(ctx as *mut bpf_sock_addr as *mut c_void) {
        return 0;
    }

    // Rewrite source.
    if ctx.msg_src_ip6[3] == 1u32.to_be() || ctx.msg_src_ip6[3] == 0u32.to_be() {
        ctx.msg_src_ip6[0] = SRC_REWRITE_IP6_0.to_be();
        ctx.msg_src_ip6[1] = SRC_REWRITE_IP6_1.to_be();
        ctx.msg_src_ip6[2] = SRC_REWRITE_IP6_2.to_be();
        ctx.msg_src_ip6[3] = SRC_REWRITE_IP6_3.to_be();
    } else {
        // Unexpected source. Reject sendmsg.
        return 0;
    }

    // Rewrite destination.
    if ctx.user_ip6[0] == 0xFACE_B00Cu32.to_be() {
        ctx.user_ip6[0] = DST_REWRITE_IP6_0.to_be();
        ctx.user_ip6[1] = DST_REWRITE_IP6_1.to_be();
        ctx.user_ip6[2] = DST_REWRITE_IP6_2.to_be();
        ctx.user_ip6[3] = DST_REWRITE_IP6_3.to_be();

        ctx.user_port = DST_REWRITE_PORT6.to_be() as u32;
    } else {
        // Unexpected destination. Reject sendmsg.
        return 0;
    }

    1
}

#[link_section = "cgroup/sendmsg6"]
#[no_mangle]
extern "C" fn sendmsg_v6_v4mapped_prog(ctx: *const bpf_sock_addr) -> i32 {
    let ctx = unsafe { &mut *(ctx as *mut bpf_sock_addr) };

    // Rewrite source.
    ctx.msg_src_ip6[0] = SRC_REWRITE_IP6_0.to_be();
    ctx.msg_src_ip6[1] = SRC_REWRITE_IP6_1.to_be();
    ctx.msg_src_ip6[2] = SRC_REWRITE_IP6_2.to_be();
    ctx.msg_src_ip6[3] = SRC_REWRITE_IP6_3.to_be();

    // Rewrite destination.
    ctx.user_ip6[0] = DST_REWRITE_IP6_V4_MAPPED_0.to_be();
    ctx.user_ip6[1] = DST_REWRITE_IP6_V4_MAPPED_1.to_be();
    ctx.user_ip6[2] = DST_REWRITE_IP6_V4_MAPPED_2.to_be();
    ctx.user_ip6[3] = DST_REWRITE_IP6_V4_MAPPED_3.to_be();

    ctx.user_port = DST_REWRITE_PORT6.to_be() as u32;

    1
}

#[link_section = "cgroup/sendmsg6"]
#[no_mangle]
extern "C" fn sendmsg_v6_wildcard_prog(ctx: *const bpf_sock_addr) -> i32 {
    let ctx = unsafe { &mut *(ctx as *mut bpf_sock_addr) };

    // Rewrite source.
    ctx.msg_src_ip6[0] = SRC_REWRITE_IP6_0.to_be();
    ctx.msg_src_ip6[1] = SRC_REWRITE_IP6_1.to_be();
    ctx.msg_src_ip6[2] = SRC_REWRITE_IP6_2.to_be();
    ctx.msg_src_ip6[3] = SRC_REWRITE_IP6_3.to_be();

    // Rewrite destination.
    ctx.user_ip6[0] = 0u32.to_be();
    ctx.user_ip6[1] = 0u32.to_be();
    ctx.user_ip6[2] = 0u32.to_be();
    ctx.user_ip6[3] = 0u32.to_be();

    ctx.user_port = DST_REWRITE_PORT6.to_be() as u32;

    1
}

#[link_section = "cgroup/sendmsg6"]
#[no_mangle]
extern "C" fn sendmsg_v6_preserve_dst_prog(_ctx: *const bpf_sock_addr) -> i32 {
    1
}

#[link_section = "cgroup/sendmsg6"]
#[no_mangle]
extern "C" fn sendmsg_v6_deny_prog(_ctx: *const bpf_sock_addr) -> i32 {
    0
}

bpf_object!("GPL");
