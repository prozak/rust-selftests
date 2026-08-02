#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/connect4_dropper.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;

const VERDICT_REJECT: i32 = 0;
const VERDICT_PROCEED: i32 = 1;

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

#[no_mangle]
static mut port: i32 = 0;

#[link_section = "cgroup/connect4"]
#[no_mangle]
extern "C" fn connect_v4_dropper(ctx: *const bpf_sock_addr) -> i32 {
    let ctx = unsafe { &*ctx };

    if ctx.r#type != SOCK_STREAM {
        return VERDICT_PROCEED;
    }
    if ctx.user_port == (unsafe { port } as u16).to_be() as u32 {
        return VERDICT_REJECT;
    }
    VERDICT_PROCEED
}

bpf_object!("GPL");
