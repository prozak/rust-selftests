#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/freplace_connect4.c,
// bpf-rs-core idiom.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_bind;

/// UAPI struct bpf_sock_addr (linux/bpf.h). sk is a __bpf_md_ptr union,
/// represented as u64. Matched by BTF struct name for freplace attach
/// compatibility against connect4_prog.c's do_bind().
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

/// struct sockaddr_in (netinet/in.h), 16 bytes.
#[allow(non_camel_case_types)]
#[repr(C)]
struct sockaddr_in {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [u8; 8],
}

#[link_section = "freplace/do_bind"]
#[no_mangle]
extern "C" fn new_do_bind(ctx: *const bpf_sock_addr) -> i32 {
    let mut sa = sockaddr_in {
        sin_family: 0,
        sin_port: 0,
        sin_addr: 0,
        sin_zero: [0; 8],
    };

    bpf_bind(
        ctx as *mut bpf_sock_addr,
        &mut sa,
        core::mem::size_of::<sockaddr_in>() as i32,
    );
    0
}

bpf_object!("GPL");
