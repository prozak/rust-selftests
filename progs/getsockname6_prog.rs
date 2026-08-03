#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/getsockname6_prog.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;

const REWRITE_ADDRESS_IP6_0: u32 = 0xfaceb00c;
const REWRITE_ADDRESS_IP6_1: u32 = 0x12345678;
const REWRITE_ADDRESS_IP6_2: u32 = 0x00000000;
const REWRITE_ADDRESS_IP6_3: u32 = 0x0000abcd;

const REWRITE_ADDRESS_PORT6: u16 = 6060;

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

#[link_section = "cgroup/getsockname6"]
#[no_mangle]
extern "C" fn getsockname_v6_prog(ctx: *const bpf_sock_addr) -> i32 {
    let ctx = unsafe { &mut *(ctx as *mut bpf_sock_addr) };

    ctx.user_ip6[0] = REWRITE_ADDRESS_IP6_0.to_be();
    ctx.user_ip6[1] = REWRITE_ADDRESS_IP6_1.to_be();
    ctx.user_ip6[2] = REWRITE_ADDRESS_IP6_2.to_be();
    ctx.user_ip6[3] = REWRITE_ADDRESS_IP6_3.to_be();
    ctx.user_port = REWRITE_ADDRESS_PORT6.to_be() as u32;

    1
}

bpf_object!("GPL");
