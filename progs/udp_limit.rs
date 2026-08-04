#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/udp_limit.c, bpf-rs-core idiom.

use bpf_rs_core::helpers::{bpf_sk_storage_get, sync_fetch_and_add_i32};
use bpf_rs_core::{bpf_map, bpf_object};

// UAPI struct bpf_sock (linux/bpf.h), full layout. dst_port is __be16
// followed by a 16-bit zero-padding bitfield.
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct bpf_sock {
    pub bound_dev_if: u32,
    pub family: u32,
    pub r#type: u32,
    pub protocol: u32,
    pub mark: u32,
    pub priority: u32,
    pub src_ip4: u32,
    pub src_ip6: [u32; 4],
    pub src_port: u32,
    pub dst_port: u16,
    pub _pad: u16,
    pub dst_ip4: u32,
    pub dst_ip6: [u32; 4],
    pub state: u32,
    pub rx_queue_mapping: i32,
}

const SOCK_DGRAM: u32 = 2;
const BPF_SK_STORAGE_GET_F_CREATE: u64 = 1;

#[no_mangle]
static mut invocations: i32 = 0;
#[no_mangle]
static mut in_use: i32 = 0;

// No __uint(max_entries, ...) in the C source (BPF_MAP_TYPE_SK_STORAGE is
// sized implicitly), so this needs the bpf_map! escape hatch rather than
// the BpfMap<K, V, TYPE, MAX> generic.
bpf_map! {
    sk_map {
        r#type: *const [i32; 24],    // BPF_MAP_TYPE_SK_STORAGE
        map_flags: *const [i32; 1],  // BPF_F_NO_PREALLOC
        key: *const i32,
        value: *const i32,
    }
}

#[link_section = "cgroup/sock_create"]
#[no_mangle]
extern "C" fn sock(ctx: *mut bpf_sock) -> i32 {
    if unsafe { (*ctx).r#type } != SOCK_DGRAM {
        return 1;
    }

    let sk_storage = bpf_sk_storage_get(
        &sk_map,
        ctx as *mut core::ffi::c_void,
        core::ptr::null_mut(),
        BPF_SK_STORAGE_GET_F_CREATE,
    ) as *mut i32;
    if sk_storage.is_null() {
        return 0;
    }
    unsafe { *sk_storage = 0xdeadbeefu32 as i32 };

    sync_fetch_and_add_i32(core::ptr::addr_of_mut!(invocations), 1);

    if unsafe { in_use } > 0 {
        // BPF_CGROUP_INET_SOCK_RELEASE is _not_ called when we return an
        // error from the BPF program!
        return 0;
    }

    sync_fetch_and_add_i32(core::ptr::addr_of_mut!(in_use), 1);
    1
}

#[link_section = "cgroup/sock_release"]
#[no_mangle]
extern "C" fn sock_release(ctx: *mut bpf_sock) -> i32 {
    if unsafe { (*ctx).r#type } != SOCK_DGRAM {
        return 1;
    }

    let sk_storage = bpf_sk_storage_get(
        &sk_map,
        ctx as *mut core::ffi::c_void,
        core::ptr::null_mut(),
        0,
    ) as *mut i32;
    if sk_storage.is_null() || unsafe { *sk_storage } != 0xdeadbeefu32 as i32 {
        return 0;
    }

    sync_fetch_and_add_i32(core::ptr::addr_of_mut!(invocations), 1);
    sync_fetch_and_add_i32(core::ptr::addr_of_mut!(in_use), -1);
    1
}

bpf_object!("GPL");
