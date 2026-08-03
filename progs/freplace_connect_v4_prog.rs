#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/freplace_connect_v4_prog.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;

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

#[link_section = "freplace/connect_v4_prog"]
#[no_mangle]
extern "C" fn new_connect_v4_prog(_ctx: *const bpf_sock_addr) -> i32 {
    // return value that's in invalid range
    255
}

bpf_object!("GPL");
