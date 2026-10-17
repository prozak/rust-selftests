// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

#[path = "common/ksock.rs"]
mod ksock;
use ksock::*;
use core::{ffi::c_void, ptr::addr_of_mut};
use bpf_rs_core::{helpers::{bpf_kptr_xchg, bpf_map_lookup_elem, sync_fetch_and_add_u32}, maps::{BpfMap, ARRAY}, btf_type_tags};

const AF_INET: u8 = 2;
const SOCK_DGRAM: u8 = 2;
const IPPROTO_UDP: u8 = 17;
const ENOENT: i32 = 2;
const EEXIST: i32 = 17;

#[repr(C, align(8))]
struct bpf_wq { __opaque: [u64; 2] }
#[repr(C)]
struct ksock_wq_value { work: bpf_wq }
#[no_mangle]
#[link_section = ".maps"]
static work_map: BpfMap<u32, ksock_wq_value, ARRAY, 2> = BpfMap::new();

// char send_data[] = "hello from bpf workqueue";
#[no_mangle]
static mut send_data: [u8; 25] = *b"hello from bpf workqueue\0";

#[no_mangle]
static mut remote_port: u16 = 0; // __be16
#[no_mangle]
static mut connect_send_ret: i32 = 0;
#[no_mangle]
static mut create_ret: i32 = 0;
#[no_mangle]
static mut callback_done: u32 = 0;

// struct sockaddr_in / union bpf_ksock_addr (linux/bpf_ksock.h): the union
// of sockaddr_in and sockaddr_in6 is 28 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
struct sockaddr_in {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
    __pad: [u8; 8],
}
#[repr(C)]
union bpf_ksock_addr {
    sin: sockaddr_in,
    sin6: [u8; 28],
}

extern "C" {
    fn bpf_wq_init(wq: *mut bpf_wq, map: *const c_void, flags: u32) -> i32;
    fn bpf_wq_set_callback(wq: *mut bpf_wq, cb: extern "C" fn(*mut c_void, *mut i32, *mut c_void) -> i32, flags: u32) -> i32;
    fn bpf_wq_start(wq: *mut bpf_wq, flags: u32) -> i32;
}

// ksock_common.h's inline helpers over __ksock_ctx_map.
#[inline(always)]
fn ksock_ctx_value_lookup() -> *mut __ksock_ctx_value {
    let key: u32 = 0;
    bpf_map_lookup_elem(&__ksock_ctx_map, &key) as *mut __ksock_ctx_value
}

#[inline(always)]
unsafe fn ksock_ctx_get() -> *mut bpf_ksock {
    let v = ksock_ctx_value_lookup();
    if v.is_null() {
        return core::ptr::null_mut();
    }
    let mut ks: *mut bpf_ksock = core::ptr::null_mut();
    bpf_rcu_read_lock();
    let tmp = (*v).ctx;
    if !tmp.is_null() {
        ks = bpf_ksock_acquire(tmp);
    }
    bpf_rcu_read_unlock();
    ks
}

#[inline(always)]
unsafe fn ksock_ctx_insert(ctx: *mut bpf_ksock) -> i32 {
    let v = ksock_ctx_value_lookup();
    if v.is_null() {
        bpf_ksock_release(ctx);
        return -ENOENT;
    }
    let old = bpf_kptr_xchg(addr_of_mut!((*v).ctx).cast(), ctx.cast()) as *mut bpf_ksock;
    if !old.is_null() {
        bpf_ksock_release(old);
        return -EEXIST;
    }
    0
}

extern "C" fn ksock_wq_create_cb(_map: *mut c_void, _key: *mut i32, _value: *mut c_void) -> i32 {
    let opts = bpf_ksock_create_opts { family: AF_INET, r#type: SOCK_DGRAM, protocol: IPPROTO_UDP, reserved: 0 };
    let mut err: i32 = 0;
    unsafe {
        let ks = bpf_ksock_create(&opts, core::mem::size_of::<bpf_ksock_create_opts>() as u32, &mut err);
        if !ks.is_null() {
            bpf_ksock_release(ks);
        }
        create_ret = err;
    }
    sync_fetch_and_add_u32(addr_of_mut!(callback_done), 1);
    0
}

extern "C" fn ksock_wq_connect_send_cb(_map: *mut c_void, _key: *mut i32, _value: *mut c_void) -> i32 {
    let mut addr: bpf_ksock_addr = unsafe { core::mem::zeroed() };
    addr.sin = sockaddr_in {
        sin_family: AF_INET as u16,
        sin_port: unsafe { remote_port },
        sin_addr: 0x7f000001u32.to_be(), // bpf_htonl(0x7f000001)
        __pad: [0; 8],
    };
    let mut err: i32 = -ENOENT;
    unsafe {
        let ks = ksock_ctx_get();
        if !ks.is_null() {
            err = bpf_ksock_connect(ks, &addr as *const bpf_ksock_addr as *const c_void, core::mem::size_of::<bpf_ksock_addr>() as u32);
            if err == 0 {
                err = bpf_ksock_send(ks, core::ptr::addr_of!(send_data) as *const c_void, 25);
            }
            bpf_ksock_release(ks);
        }
        connect_send_ret = err;
    }
    sync_fetch_and_add_u32(addr_of_mut!(callback_done), 1);
    0
}

#[inline(always)]
unsafe fn wq_set_callback_start(callback_fn: extern "C" fn(*mut c_void, *mut i32, *mut c_void) -> i32, key: u32) -> i32 {
    let value = bpf_map_lookup_elem(&work_map, &key) as *mut ksock_wq_value;
    if value.is_null() {
        return -ENOENT;
    }
    let work = addr_of_mut!((*value).work);
    let err = bpf_wq_init(work, &work_map as *const _ as *const c_void, 0);
    if err != 0 {
        return err;
    }
    let err = bpf_wq_set_callback(work, callback_fn, 0);
    if err != 0 {
        return err;
    }
    let err = bpf_wq_start(work, 0);
    if err != 0 {
        return err;
    }
    0
}

#[no_mangle]
#[link_section = "syscall"]
extern "C" fn ksock_wq_start(_ctx: *const c_void) -> i32 {
    let opts = bpf_ksock_create_opts { family: AF_INET, r#type: SOCK_DGRAM, protocol: IPPROTO_UDP, reserved: 0 };
    let mut err: i32 = 0;
    unsafe {
        let ks = bpf_ksock_create(&opts, core::mem::size_of::<bpf_ksock_create_opts>() as u32, &mut err);
        if ks.is_null() {
            return err;
        }
        let err = ksock_ctx_insert(ks);
        if err != 0 {
            return err;
        }
        let err = wq_set_callback_start(ksock_wq_connect_send_cb, 0);
        if err != 0 {
            return err;
        }
        let err = wq_set_callback_start(ksock_wq_create_cb, 1);
        if err != 0 {
            return err;
        }
    }
    0
}

btf_type_tags! { __ksock_ctx_value.ctx: kptr; }
#[no_mangle]
#[link_section = "license"]
static __license: [u8; 4] = *b"GPL\0";
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }
