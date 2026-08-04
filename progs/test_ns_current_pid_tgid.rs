#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_ns_current_pid_tgid.c
// (bpf-rs-core idiom).

use core::ffi::c_void;
use core::mem::size_of;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_ns_current_pid_tgid;
use bpf_rs_core::maps::BpfMap;

// BPF_MAP_TYPE_SOCKMAP == 15.
#[link_section = ".maps"]
#[no_mangle]
static sock_map: BpfMap<u32, u32, 15, 2> = BpfMap::new();

#[no_mangle]
static mut user_pid: u64 = 0;
#[no_mangle]
static mut user_tgid: u64 = 0;
#[no_mangle]
static mut dev: u64 = 0;
#[no_mangle]
static mut ino: u64 = 0;

/// UAPI struct bpf_pidns_info (linux/bpf.h).
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_pidns_info {
    pid: u32,
    tgid: u32,
}

#[inline(always)]
fn get_pid_tgid() {
    let mut nsdata = bpf_pidns_info { pid: 0, tgid: 0 };

    let (d, i) = unsafe { (dev, ino) };
    let ret = bpf_get_ns_current_pid_tgid(
        d,
        i,
        &mut nsdata as *mut bpf_pidns_info as *mut c_void,
        size_of::<bpf_pidns_info>() as u32,
    );
    if ret != 0 {
        return;
    }

    unsafe {
        user_pid = nsdata.pid as u64;
        user_tgid = nsdata.tgid as u64;
    }
}

#[link_section = "?tracepoint/syscalls/sys_enter_nanosleep"]
#[no_mangle]
extern "C" fn tp_handler(_ctx: *const c_void) -> i32 {
    get_pid_tgid();
    0
}

/// UAPI struct bpf_sock_addr (linux/bpf.h). sk is a __bpf_md_ptr union,
/// represented as u64.
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_sock_addr {
    user_family: u32,
    user_ip4: u32,
    user_ip6: [u32; 4],
    user_port: u32,
    family: u32,
    r#type: u32,
    protocol: u32,
    msg_src_ip4: u32,
    msg_src_ip6: [u32; 4],
    sk: u64,
}

#[link_section = "?cgroup/bind4"]
#[no_mangle]
extern "C" fn cgroup_bind4(_ctx: *mut bpf_sock_addr) -> i32 {
    get_pid_tgid();
    1
}

#[link_section = "?sk_msg"]
#[no_mangle]
extern "C" fn sk_msg(_msg: *mut c_void) -> i32 {
    get_pid_tgid();
    1 // SK_PASS
}

bpf_object!("GPL");
