#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/connect_ping.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_bind, sync_fetch_and_add_u32};

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

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

/// struct sockaddr_in (netinet/in.h), 16 bytes.
#[allow(non_camel_case_types)]
#[repr(C)]
struct sockaddr_in {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [u8; 8],
}

/// struct sockaddr_in6 (netinet/in.h), 28 bytes.
#[allow(non_camel_case_types)]
#[repr(C)]
struct sockaddr_in6 {
    sin6_family: u16,
    sin6_port: u16,
    sin6_flowinfo: u32,
    sin6_addr: [u8; 16],
    sin6_scope_id: u32,
}

/* 2001:db8::1 */
const BINDADDR_V6: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
];

// Byte-at-a-time volatile copy: a fixed-size array-to-array copy here gets
// MemCpyOpt-recognized and rewritten to an unresolvable bpf_arena_memcpy
// kfunc call even inside an already-noinline function; volatile accesses are
// the one pattern the optimizer can't merge into memcpy.
#[inline(always)]
unsafe fn vcopy(dst: *mut u8, src: *const u8, len: usize) {
    let mut i = 0usize;
    while i < len {
        core::ptr::write_volatile(dst.add(i), core::ptr::read_volatile(src.add(i)));
        i += 1;
    }
}

#[no_mangle]
static mut do_bind: u32 = 0;
#[no_mangle]
static mut has_error: u32 = 0;
#[no_mangle]
static mut invocations_v4: u32 = 0;
#[no_mangle]
static mut invocations_v6: u32 = 0;

#[link_section = "cgroup/connect4"]
#[no_mangle]
extern "C" fn connect_v4_prog(ctx: *const bpf_sock_addr) -> i32 {
    let mut sa = sockaddr_in {
        sin_family: AF_INET,
        sin_port: 0,
        sin_addr: 0x01010101u32.to_be(),
        sin_zero: [0; 8],
    };

    sync_fetch_and_add_u32(core::ptr::addr_of_mut!(invocations_v4), 1);

    if unsafe { do_bind } != 0
        && bpf_bind(
            ctx as *mut bpf_sock_addr,
            &mut sa,
            core::mem::size_of::<sockaddr_in>() as i32,
        ) != 0
    {
        unsafe { has_error = 1 };
    }

    1
}

#[link_section = "cgroup/connect6"]
#[no_mangle]
extern "C" fn connect_v6_prog(ctx: *const bpf_sock_addr) -> i32 {
    let mut sa = sockaddr_in6 {
        sin6_family: AF_INET6,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: [0; 16],
        sin6_scope_id: 0,
    };
    unsafe {
        vcopy(sa.sin6_addr.as_mut_ptr(), BINDADDR_V6.as_ptr(), 16);
    }

    sync_fetch_and_add_u32(core::ptr::addr_of_mut!(invocations_v6), 1);

    if unsafe { do_bind } != 0
        && bpf_bind(
            ctx as *mut bpf_sock_addr,
            &mut sa,
            core::mem::size_of::<sockaddr_in6>() as i32,
        ) != 0
    {
        unsafe { has_error = 1 };
    }

    1
}

bpf_object!("GPL");
