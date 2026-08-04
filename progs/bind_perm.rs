#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bind_perm.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;

const AF_INET: u32 = 2;
const AF_INET6: u32 = 10;
const SOCK_STREAM: u32 = 1;

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

/// UAPI struct bpf_sock (linux/bpf.h), truncated to the fields this
/// translation reads (`family` at its real byte offset).
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_sock {
    bound_dev_if: u32,
    family: u32,
}

fn bind_prog(ctx: *const bpf_sock_addr, family: u32) -> i32 {
    let ctx = unsafe { &*ctx };

    let sk = ctx.sk as *const bpf_sock;
    if sk.is_null() {
        return 0;
    }

    if unsafe { (*sk).family } != family {
        return 0;
    }

    if ctx.r#type != SOCK_STREAM {
        return 0;
    }

    // Return 1 OR'ed with the first bit set to indicate
    // that CAP_NET_BIND_SERVICE should be bypassed.
    if ctx.user_port == 111u16.to_be() as u32 {
        return 1 | 2;
    }

    1
}

#[link_section = "cgroup/bind4"]
#[no_mangle]
extern "C" fn bind_v4_prog(ctx: *const bpf_sock_addr) -> i32 {
    bind_prog(ctx, AF_INET)
}

#[link_section = "cgroup/bind6"]
#[no_mangle]
extern "C" fn bind_v6_prog(ctx: *const bpf_sock_addr) -> i32 {
    bind_prog(ctx, AF_INET6)
}

bpf_object!("GPL");
