#![no_std]
#![no_main]
// BTF_C_CHAR: u8

use core::{ffi::c_void, ptr::addr_of_mut};
use bpf_rs_core::{helpers::{bpf_dynptr_from_mem, bpf_get_current_pid_tgid}, progs::fentry_arg, test_tags};

#[repr(C)]
struct socket { _opaque: [u8; 0] }
extern "C" {
    fn bpf_sock_read_xattr(sock: *mut socket, name: *const u8, value: *mut c_void) -> i32;
}

#[no_mangle]
static mut value: [u8; 16] = [0; 16];
#[no_mangle]
static mut read_ret: i32 = -1;
#[no_mangle]
static mut monitored_pid: u32 = 0;

#[inline(always)]
fn read_xattr(sock: *mut socket) -> i32 {
    let mut value_ptr = core::mem::MaybeUninit::<[u64; 2]>::uninit();
    bpf_dynptr_from_mem(addr_of_mut!(value).cast(), 16, 0, value_ptr.as_mut_ptr().cast());
    unsafe { bpf_sock_read_xattr(sock, b"user.bpf_test\0".as_ptr(), value_ptr.as_mut_ptr().cast()) }
}

#[no_mangle]
#[link_section = "lsm.s/socket_connect"]
extern "C" fn trusted_sock_ptr_sleepable(ctx: *const u64) -> i32 {
    read_xattr(fentry_arg(ctx, 0) as *mut socket);
    0
}

#[no_mangle]
#[link_section = "lsm/socket_connect"]
extern "C" fn trusted_sock_ptr_non_sleepable(ctx: *const u64) -> i32 {
    read_xattr(fentry_arg(ctx, 0) as *mut socket);
    0
}

#[no_mangle]
#[link_section = "lsm.s/socket_connect"]
extern "C" fn read_sock_xattr(ctx: *const u64) -> i32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if pid != unsafe { monitored_pid } { return 0; }
    unsafe { read_ret = read_xattr(fentry_arg(ctx, 0) as *mut socket); }
    0
}

test_tags! {
    trusted_sock_ptr_sleepable: __success;
    trusted_sock_ptr_non_sleepable: __success;
    read_sock_xattr: __success;
}
bpf_rs_core::bpf_object!("GPL");
