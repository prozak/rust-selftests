#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/getpeername4_prog.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;

const REWRITE_ADDRESS_IP4: u32 = 0xc0a801fe; // 192.168.1.254
const REWRITE_ADDRESS_PORT4: u32 = 4040;

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

#[link_section = "cgroup/getpeername4"]
#[no_mangle]
extern "C" fn getpeername_v4_prog(ctx: *const bpf_sock_addr) -> i32 {
    let ctx = unsafe { &mut *(ctx as *mut bpf_sock_addr) };

    ctx.user_ip4 = REWRITE_ADDRESS_IP4.to_be();
    ctx.user_port = (REWRITE_ADDRESS_PORT4 as u16).to_be() as u32;

    1
}

bpf_object!("GPL");
