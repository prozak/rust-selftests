#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/connect_force_port4.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_bind, bpf_getsockopt, bpf_setsockopt, bpf_sk_storage_get};
use bpf_rs_core::bpf_map;

const SOL_SOCKET: i32 = 1;
const SO_PRIORITY: i32 = 12;

const AF_INET: u16 = 2;

/// enum bpf_map_type::BPF_MAP_TYPE_SK_STORAGE.
const BPF_MAP_TYPE_SK_STORAGE: usize = 24;
/// enum: BPF_F_NO_PREALLOC.
const BPF_F_NO_PREALLOC: usize = 1;
const BPF_SK_STORAGE_GET_F_CREATE: u64 = 1;

#[no_mangle]
static mut port: u16 = 0;

/// struct svc_addr (connect_force_port4.c), 8 bytes with tail padding
/// (addr's 4-byte alignment rounds the struct up).
#[allow(non_camel_case_types)]
#[repr(C)]
struct svc_addr {
    addr: u32,
    port: u16,
}

bpf_map! {
    service_mapping {
        r#type: *const [i32; BPF_MAP_TYPE_SK_STORAGE],
        map_flags: *const [i32; BPF_F_NO_PREALLOC],
        key: *const i32,
        value: *const svc_addr,
    }
}

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

/// struct sockaddr_in (netinet/in.h), 16 bytes.
#[allow(non_camel_case_types)]
#[repr(C)]
struct sockaddr_in {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [u8; 8],
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

#[link_section = "cgroup/connect4"]
#[no_mangle]
extern "C" fn connect4(ctx: *mut bpf_sock_addr) -> i32 {
    let ctx_ref = unsafe { &mut *ctx };

    /* Force local address to 127.0.0.1:22222. */
    let mut sa = sockaddr_in {
        sin_family: AF_INET,
        sin_port: 22222u16.to_be(),
        sin_addr: 0x7f000001u32.to_be(),
        sin_zero: [0; 8],
    };

    if bpf_bind(ctx, &mut sa, core::mem::size_of::<sockaddr_in>() as i32) != 0 {
        return 0;
    }

    /* Rewire service 1.2.3.4:60000 to backend 127.0.0.1:port. */
    if ctx_ref.user_port == (60000u16.to_be() as u32) {
        let orig = bpf_sk_storage_get(
            &service_mapping,
            ctx_ref.sk as *const core::ffi::c_void,
            core::ptr::null(),
            BPF_SK_STORAGE_GET_F_CREATE,
        ) as *mut svc_addr;
        if orig.is_null() {
            return 0;
        }

        unsafe {
            (*orig).addr = ctx_ref.user_ip4;
            (*orig).port = ctx_ref.user_port as u16;
        }

        ctx_ref.user_ip4 = 0x7f000001u32.to_be();
        ctx_ref.user_port = unsafe { port }.to_be() as u32;
    }
    1
}

#[link_section = "cgroup/getsockname4"]
#[no_mangle]
extern "C" fn getsockname4(ctx: *mut bpf_sock_addr) -> i32 {
    let ctx_ref = unsafe { &mut *ctx };

    if !get_set_sk_priority(ctx) {
        return 1;
    }

    /* Expose local server as 1.2.3.4:60000 to client. */
    if ctx_ref.user_port == (unsafe { port }.to_be() as u32) {
        ctx_ref.user_ip4 = 0x01020304u32.to_be();
        ctx_ref.user_port = 60000u16.to_be() as u32;
    }
    1
}

#[link_section = "cgroup/getpeername4"]
#[no_mangle]
extern "C" fn getpeername4(ctx: *mut bpf_sock_addr) -> i32 {
    let ctx_ref = unsafe { &mut *ctx };

    if !get_set_sk_priority(ctx) {
        return 1;
    }

    /* Expose service 1.2.3.4:60000 as peer instead of backend. */
    if ctx_ref.user_port == (unsafe { port }.to_be() as u32) {
        let orig = bpf_sk_storage_get(
            &service_mapping,
            ctx_ref.sk as *const core::ffi::c_void,
            core::ptr::null(),
            0,
        ) as *mut svc_addr;
        if !orig.is_null() {
            unsafe {
                ctx_ref.user_ip4 = (*orig).addr;
                ctx_ref.user_port = (*orig).port as u32;
            }
        }
    }
    1
}

bpf_object!("GPL");
