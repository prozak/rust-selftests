#![no_std]
#![no_main]

use bpf_rs_core::bpf_object;

#[link_section = "lsm_cgroup/inet_csk_clone"]
#[no_mangle]
extern "C" fn nonvoid_socket_clone(_ctx: *const u64) -> i32 {
    // Can not return any errors from void LSM hooks.
    0
}

bpf_object!("GPL");
