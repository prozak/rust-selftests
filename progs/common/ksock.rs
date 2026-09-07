use core::ffi::c_void;
use bpf_rs_core::maps::{BpfMap, ARRAY};

#[repr(C)]
pub struct bpf_ksock { _opaque: [u8; 0] }
#[repr(C)]
pub struct bpf_ksock_create_opts {
    pub family: u8, pub r#type: u8, pub protocol: u8, pub reserved: u8,
}
#[repr(C)]
pub struct __ksock_ctx_value { pub ctx: *mut bpf_ksock }
#[no_mangle]
#[link_section = ".maps"]
pub static __ksock_ctx_map: BpfMap<i32, __ksock_ctx_value, ARRAY, 1> = BpfMap::new();

extern "C" {
    pub fn bpf_ksock_create(opts: *const bpf_ksock_create_opts, size: u32, err: *mut i32) -> *mut bpf_ksock;
    pub fn bpf_ksock_release(ks: *mut bpf_ksock);
    pub fn bpf_ksock_connect(ks: *mut bpf_ksock, addr: *const c_void, size: u32) -> i32;
    pub fn bpf_ksock_acquire(ks: *mut bpf_ksock) -> *mut bpf_ksock;
    pub fn bpf_ksock_send(ks: *mut bpf_ksock, data: *const c_void, size: u32) -> i32;
    pub fn bpf_rcu_read_lock();
    pub fn bpf_rcu_read_unlock();
}
