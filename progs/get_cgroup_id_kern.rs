#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/get_cgroup_id_kern.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_get_current_cgroup_id, bpf_get_current_pid_tgid};
use core::ffi::c_void;

#[no_mangle]
static mut cg_id: u64 = 0;

#[no_mangle]
static mut expected_pid: u64 = 0;

#[link_section = "tracepoint/syscalls/sys_enter_nanosleep"]
#[no_mangle]
extern "C" fn trace(_ctx: *const c_void) -> i32 {
    let pid = bpf_get_current_pid_tgid() as u32;

    if unsafe { expected_pid } == pid as u64 {
        unsafe { cg_id = bpf_get_current_cgroup_id() };
    }

    0
}

bpf_object!("GPL");
