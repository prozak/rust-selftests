#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/sock_addr_kern.c
// (bpf-rs-core idiom). Each SEC("syscall") program forwards the ctx_in
// pointer (struct init_sock_args / addr_args / sendmsg_args from
// ../test_kmods/bpf_testmod_kfunc.h) straight to the matching bpf_testmod
// kfunc; the kfunc's real BTF signature (from module BTF) is what the
// verifier checks, so an opaque pointer here is sufficient.

use bpf_rs_core::bpf_object;
use core::ffi::c_void;

extern "C" {
    fn bpf_kfunc_init_sock(args: *mut c_void) -> i32;
    fn bpf_kfunc_close_sock();
    fn bpf_kfunc_call_kernel_connect(args: *mut c_void) -> i32;
    fn bpf_kfunc_call_kernel_bind(args: *mut c_void) -> i32;
    fn bpf_kfunc_call_kernel_listen() -> i32;
    fn bpf_kfunc_call_kernel_sendmsg(args: *mut c_void) -> i32;
    fn bpf_kfunc_call_sock_sendmsg(args: *mut c_void) -> i32;
    fn bpf_kfunc_call_kernel_getsockname(args: *mut c_void) -> i32;
    fn bpf_kfunc_call_kernel_getpeername(args: *mut c_void) -> i32;
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn init_sock(args: *mut c_void) -> i32 {
    unsafe { bpf_kfunc_init_sock(args) };
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn close_sock(_ctx: *mut c_void) -> i32 {
    unsafe { bpf_kfunc_close_sock() };
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn kernel_connect(args: *mut c_void) -> i32 {
    unsafe { bpf_kfunc_call_kernel_connect(args) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn kernel_bind(args: *mut c_void) -> i32 {
    unsafe { bpf_kfunc_call_kernel_bind(args) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn kernel_listen(_ctx: *mut c_void) -> i32 {
    unsafe { bpf_kfunc_call_kernel_listen() }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn kernel_sendmsg(args: *mut c_void) -> i32 {
    unsafe { bpf_kfunc_call_kernel_sendmsg(args) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn sock_sendmsg(args: *mut c_void) -> i32 {
    unsafe { bpf_kfunc_call_sock_sendmsg(args) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn kernel_getsockname(args: *mut c_void) -> i32 {
    unsafe { bpf_kfunc_call_kernel_getsockname(args) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn kernel_getpeername(args: *mut c_void) -> i32 {
    unsafe { bpf_kfunc_call_kernel_getpeername(args) }
}

bpf_object!("GPL");
