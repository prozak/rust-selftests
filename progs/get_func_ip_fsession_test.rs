#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/get_func_ip_fsession_test.c,
// bpf-rs-core idiom.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_func_ip;
use core::ffi::c_void;

extern "C" {
    fn bpf_fentry_test1(a: i32) -> i32;
    fn bpf_session_is_return(ctx: *mut c_void) -> bool;
}

#[no_mangle]
static mut test1_entry_result: u64 = 0;
#[no_mangle]
static mut test1_exit_result: u64 = 0;

#[link_section = "fsession/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test1(ctx: *const u64) -> i32 {
    let addr = bpf_get_func_ip(ctx as *const c_void);
    let target = bpf_fentry_test1 as usize as u64;
    let matched = (addr == target) as u64;

    if unsafe { bpf_session_is_return(ctx as *mut c_void) } {
        unsafe { test1_exit_result = matched };
    } else {
        unsafe { test1_entry_result = matched };
    }
    0
}

bpf_object!("GPL");
