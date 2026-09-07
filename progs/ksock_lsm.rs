#![no_std]
#![no_main]

#[path = "common/ksock.rs"]
mod ksock;
use ksock::*;
use core::{ffi::c_void, ptr::addr_of_mut};
use bpf_rs_core::{helpers::{bpf_map_lookup_elem, bpf_kptr_xchg, bpf_get_current_pid_tgid}, progs::fentry_arg, btf_type_tags};

#[no_mangle]
static mut send_data: [u8; 32] = *b"hello from bpf ksock\0\0\0\0\0\0\0\0\0\0\0\0";
#[no_mangle]
static mut ipv4_remote: u32 = 0;
#[no_mangle]
static mut remote_port: u16 = 0;
#[no_mangle]
static mut target_pid: i32 = 0;
#[no_mangle]
static mut send_ret: i32 = -1;

// sockaddr_in6 determines the union's size/alignment; unused bytes stay zero.
#[repr(C)]
struct SockAddr { family: u16, port: u16, addr: u32, rest: [u32; 5] }

#[no_mangle]
#[link_section = "syscall"]
extern "C" fn ksock_setup(_arg0: *const c_void) -> i32 {
    let opts = bpf_ksock_create_opts { family: 2, r#type: 2, protocol: 17, reserved: 0 };
    let mut err = 0;
    unsafe {
        let ks = bpf_ksock_create(&opts, 4, &mut err);
        if ks.is_null() { return err; }
        let addr = SockAddr { family: 2, port: remote_port.to_be(), addr: ipv4_remote, rest: [0; 5] };
        err = bpf_ksock_connect(ks, (&addr as *const SockAddr).cast(), 28);
        if err != 0 { bpf_ksock_release(ks); return err; }
        let v = bpf_map_lookup_elem(&__ksock_ctx_map, &0u32) as *mut __ksock_ctx_value;
        if v.is_null() { bpf_ksock_release(ks); return -2; }
        let old = bpf_kptr_xchg(addr_of_mut!((*v).ctx).cast(), ks.cast()) as *mut bpf_ksock;
        if !old.is_null() { bpf_ksock_release(old); }
    }
    0
}

#[no_mangle]
#[link_section = "lsm.s/socket_bind"]
extern "C" fn ksock_socket_bind(ctx: *const u64) -> i32 {
    let ret = fentry_arg(ctx, 3) as i32;
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if ret != 0 || pid != unsafe { target_pid } as u32 { return ret; }
    unsafe {
        let v = bpf_map_lookup_elem(&__ksock_ctx_map, &0u32) as *mut __ksock_ctx_value;
        let mut ks = core::ptr::null_mut();
        if !v.is_null() {
            bpf_rcu_read_lock();
            let tmp = (*v).ctx;
            if !tmp.is_null() { ks = bpf_ksock_acquire(tmp); }
            bpf_rcu_read_unlock();
        }
        if ks.is_null() { send_ret = -2; return ret; }
        send_ret = bpf_ksock_send(ks, addr_of_mut!(send_data).cast(), 32);
        bpf_ksock_release(ks);
    }
    ret
}

btf_type_tags! { __ksock_ctx_value.ctx: kptr; }
#[no_mangle]
#[link_section = "license"]
static __license: [u8; 4] = *b"GPL\0";
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }
