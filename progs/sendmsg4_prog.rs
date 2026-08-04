#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/sendmsg4_prog.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_getsockopt, bpf_setsockopt};

const SOCK_DGRAM: u32 = 2;

const SOL_SOCKET: i32 = 1;
const SO_PRIORITY: i32 = 12;

const SRC1_IP4: u32 = 0xac100001; /* 172.16.0.1 */
const SRC2_IP4: u32 = 0x00000000;
const SRC_REWRITE_IP4: u32 = 0x7f000004;
const DST_IP4: u32 = 0xc0a801fe; /* 192.168.1.254 */
const DST_REWRITE_IP4: u32 = 0x7f000001;
const DST_PORT: u16 = 4040;
const DST_REWRITE_PORT4: u16 = 4444;

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

#[link_section = "cgroup/sendmsg4"]
#[no_mangle]
extern "C" fn sendmsg_v4_prog(ctx: *mut bpf_sock_addr) -> i32 {
    let ctx_ref = unsafe { &mut *ctx };

    if ctx_ref.r#type != SOCK_DGRAM {
        return 0;
    }

    if !get_set_sk_priority(ctx) {
        return 0;
    }

    /* Rewrite source. */
    if ctx_ref.msg_src_ip4 == SRC1_IP4.to_be() || ctx_ref.msg_src_ip4 == SRC2_IP4.to_be() {
        ctx_ref.msg_src_ip4 = SRC_REWRITE_IP4.to_be();
    } else {
        /* Unexpected source. Reject sendmsg. */
        return 0;
    }

    /* Rewrite destination. */
    if (ctx_ref.user_ip4 >> 24) == (DST_IP4.to_be() >> 24) && ctx_ref.user_port == (DST_PORT.to_be() as u32) {
        ctx_ref.user_ip4 = DST_REWRITE_IP4.to_be();
        ctx_ref.user_port = DST_REWRITE_PORT4.to_be() as u32;
    } else {
        /* Unexpected source. Reject sendmsg. */
        return 0;
    }

    1
}

#[link_section = "cgroup/sendmsg4"]
#[no_mangle]
extern "C" fn sendmsg_v4_deny_prog(_ctx: *mut bpf_sock_addr) -> i32 {
    0
}

bpf_object!("GPL");
