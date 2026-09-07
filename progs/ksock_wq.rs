#![no_std]
#![no_main]

#[path = "common/ksock.rs"]
mod ksock;
use ksock::*;
use core::{ffi::c_void, ptr::addr_of_mut};
use bpf_rs_core::{helpers::{bpf_map_lookup_elem, sync_fetch_and_add_u32}, maps::{BpfMap, ARRAY}, btf_type_tags};

#[repr(C, align(8))]
struct bpf_wq { __opaque: [u64; 2] }
#[repr(C)]
struct ksock_wq_value { work: bpf_wq }
#[no_mangle]
#[link_section = ".maps"]
static work_map: BpfMap<u32, ksock_wq_value, ARRAY, 1> = BpfMap::new();

#[no_mangle]
static mut create_err: i32 = 0;
#[no_mangle]
static mut callback_done: u32 = 0;

extern "C" {
    fn bpf_wq_init(wq: *mut bpf_wq, map: *const c_void, flags: u32) -> i32;
    fn bpf_wq_set_callback(wq: *mut bpf_wq, cb: extern "C" fn(*mut c_void, *mut i32, *mut c_void) -> i32, flags: u32) -> i32;
    fn bpf_wq_start(wq: *mut bpf_wq, flags: u32) -> i32;
}

#[no_mangle]
extern "C" fn ksock_wq_callback(_arg0: *mut c_void, _arg1: *mut i32, _arg2: *mut c_void) -> i32 {
    let opts = bpf_ksock_create_opts { family: 2, r#type: 2, protocol: 17, reserved: 0 };
    let mut err = 0;
    unsafe {
        let ks = bpf_ksock_create(&opts, 4, &mut err);
        if !ks.is_null() { bpf_ksock_release(ks); }
        create_err = err;
    }
    sync_fetch_and_add_u32(addr_of_mut!(callback_done), 1);
    0
}

#[no_mangle]
#[link_section = "syscall"]
extern "C" fn ksock_wq_start(_arg3: *const c_void) -> i32 {
    let value = bpf_map_lookup_elem(&work_map, &0u32) as *mut ksock_wq_value;
    if value.is_null() { return -2; }
    unsafe {
        let work = addr_of_mut!((*value).work);
        let err = bpf_wq_init(work, &work_map as *const _ as *const c_void, 0);
        if err != 0 { return err; }
        let err = bpf_wq_set_callback(work, ksock_wq_callback, 0);
        if err != 0 { return err; }
        bpf_wq_start(work, 0)
    }
}

btf_type_tags! { __ksock_ctx_value.ctx: kptr; }
#[no_mangle]
#[link_section = "license"]
static __license: [u8; 4] = *b"GPL\0";
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }
