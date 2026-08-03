#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/rcu_tasks_trace_gp.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;

extern "C" {
    fn bpf_kfunc_call_test_call_rcu_tasks_trace(done: *mut i32) -> i32;
}

#[no_mangle]
static mut done: i32 = 0;

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn call_rcu_tasks_trace(_ctx: *const core::ffi::c_void) -> i32 {
    unsafe { bpf_kfunc_call_test_call_rcu_tasks_trace(core::ptr::addr_of_mut!(done)) }
}

bpf_object!("GPL");
