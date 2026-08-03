#![no_std]
#![no_main]

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_get_current_task, bpf_probe_read_kernel, bpf_probe_read_kernel_str};
use btf_macros::btf;
use core::ffi::c_void;

const TEST_COMM_LEN: usize = 16;

#[btf]
struct task_struct {
    tgid: i32,
    comm: [u8; TEST_COMM_LEN],
}

bpf_map! {
    cgroup_map {
        r#type: *const [i32; 8], // BPF_MAP_TYPE_CGROUP_ARRAY
        max_entries: *const [i32; 1],
        key: *const u32,
        value: *const u32,
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_skb_helpers(_skb: *const __sk_buff) -> i32 {
    let task = bpf_get_current_task() as *const task_struct;
    let mut tpid: u32 = 0;
    let mut comm: [u8; TEST_COMM_LEN] = [0; TEST_COMM_LEN];

    bpf_probe_read_kernel(
        &mut tpid,
        core::mem::size_of::<u32>() as u32,
        unsafe { &*task }.tgid().as_ptr() as *const c_void,
    );
    bpf_probe_read_kernel_str(
        comm.as_mut_ptr() as *mut c_void,
        TEST_COMM_LEN as u32,
        unsafe { &*task }.comm().as_ptr() as *const c_void,
    );

    0
}

bpf_object!("GPL");
