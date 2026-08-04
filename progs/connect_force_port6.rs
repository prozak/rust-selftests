#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/connect_force_port6.c
// (bpf-rs-core idiom).
//
// get_set_sk_priority (from bpf_sockopt_helpers.h) is a plain non-static C
// function, so it shows up as its own GLOBAL FUNC symbol in the clang-built
// object (in .text, not a SEC()-tagged program section) -- it must stay a
// real symbol here too, not get fully inlined away.

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_bind, bpf_getsockopt, bpf_setsockopt, bpf_sk_storage_get};
use core::ffi::c_void;

const AF_INET6: u16 = 10;
const SOL_SOCKET: i32 = 1;
const SO_PRIORITY: i32 = 12;
const BPF_SK_STORAGE_GET_F_CREATE: u64 = 1;

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

/// struct sockaddr_in6 (linux/in6.h), with in6_addr collapsed to its
/// s6_addr32 view -- the only variant this program touches.
#[repr(C)]
struct sockaddr_in6 {
    sin6_family: u16,
    sin6_port: u16,
    sin6_flowinfo: u32,
    sin6_addr: [u32; 4],
    sin6_scope_id: u32,
}

#[repr(C)]
pub struct svc_addr {
    pub addr: [u32; 4],
    pub port: u16,
}

bpf_map! {
    service_mapping {
        r#type: *const [i32; 24],  // BPF_MAP_TYPE_SK_STORAGE
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        key: *const i32,
        value: *const svc_addr,
    }
}

#[no_mangle]
static mut port: u16 = 0;

#[no_mangle]
extern "C" fn get_set_sk_priority(ctx: *mut c_void) -> i32 {
    let mut prio: i32 = 0;

    if bpf_getsockopt(
        ctx,
        SOL_SOCKET,
        SO_PRIORITY,
        &mut prio as *mut i32 as *mut c_void,
        core::mem::size_of::<i32>() as i32,
    ) != 0
    {
        return 0;
    }
    if bpf_setsockopt(
        ctx,
        SOL_SOCKET,
        SO_PRIORITY,
        &mut prio as *mut i32 as *mut c_void,
        core::mem::size_of::<i32>() as i32,
    ) != 0
    {
        return 0;
    }

    1
}

#[link_section = "cgroup/connect6"]
#[no_mangle]
extern "C" fn connect6(ctx: *mut bpf_sock_addr) -> i32 {
    // Force local address to [::1]:22223.
    let mut sa = sockaddr_in6 {
        sin6_family: 0,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: [0; 4],
        sin6_scope_id: 0,
    };
    sa.sin6_family = AF_INET6;
    sa.sin6_port = 22223u16.to_be();
    sa.sin6_addr[3] = 1u32.to_be();

    let ret = bpf_bind(
        ctx,
        &mut sa as *mut sockaddr_in6 as *mut c_void,
        core::mem::size_of::<sockaddr_in6>() as i32,
    );
    if ret != 0 {
        return 0;
    }

    let ctx_ref = unsafe { &mut *ctx };

    // Rewire service [fc00::1]:60000 to backend [::1]:port.
    if ctx_ref.user_port == 60000u16.to_be() as u32 {
        let orig = bpf_sk_storage_get(
            &service_mapping,
            ctx_ref.sk as *mut c_void,
            core::ptr::null_mut(),
            BPF_SK_STORAGE_GET_F_CREATE,
        ) as *mut svc_addr;
        if orig.is_null() {
            return 0;
        }

        unsafe {
            (*orig).addr[0] = ctx_ref.user_ip6[0];
            (*orig).addr[1] = ctx_ref.user_ip6[1];
            (*orig).addr[2] = ctx_ref.user_ip6[2];
            (*orig).addr[3] = ctx_ref.user_ip6[3];
            (*orig).port = ctx_ref.user_port as u16;
        }

        ctx_ref.user_ip6[0] = 0;
        ctx_ref.user_ip6[1] = 0;
        ctx_ref.user_ip6[2] = 0;
        ctx_ref.user_ip6[3] = 1u32.to_be();
        ctx_ref.user_port = (unsafe { port }).to_be() as u32;
    }

    1
}

#[link_section = "cgroup/getsockname6"]
#[no_mangle]
extern "C" fn getsockname6(ctx: *mut bpf_sock_addr) -> i32 {
    if get_set_sk_priority(ctx as *mut c_void) == 0 {
        return 1;
    }

    let ctx_ref = unsafe { &mut *ctx };

    // Expose local server as [fc00::1]:60000 to client.
    if ctx_ref.user_port == (unsafe { port }).to_be() as u32 {
        ctx_ref.user_ip6[0] = 0xfc000000u32.to_be();
        ctx_ref.user_ip6[1] = 0;
        ctx_ref.user_ip6[2] = 0;
        ctx_ref.user_ip6[3] = 1u32.to_be();
        ctx_ref.user_port = 60000u16.to_be() as u32;
    }

    1
}

#[link_section = "cgroup/getpeername6"]
#[no_mangle]
extern "C" fn getpeername6(ctx: *mut bpf_sock_addr) -> i32 {
    if get_set_sk_priority(ctx as *mut c_void) == 0 {
        return 1;
    }

    let ctx_ref = unsafe { &mut *ctx };

    // Expose service [fc00::1]:60000 as peer instead of backend.
    if ctx_ref.user_port == (unsafe { port }).to_be() as u32 {
        let orig = bpf_sk_storage_get(
            &service_mapping,
            ctx_ref.sk as *mut c_void,
            core::ptr::null_mut(),
            0,
        ) as *mut svc_addr;
        if !orig.is_null() {
            unsafe {
                ctx_ref.user_ip6[0] = (*orig).addr[0];
                ctx_ref.user_ip6[1] = (*orig).addr[1];
                ctx_ref.user_ip6[2] = (*orig).addr[2];
                ctx_ref.user_ip6[3] = (*orig).addr[3];
                ctx_ref.user_port = (*orig).port as u32;
            }
        }
    }

    1
}

bpf_object!("GPL");
