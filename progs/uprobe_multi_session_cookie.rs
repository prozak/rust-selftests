#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/uprobe_multi_session_cookie.c
// bpf-rs-core idiom.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_current_pid_tgid;
use core::ffi::c_void;

extern "C" {
    fn bpf_session_cookie(ctx: *mut c_void) -> *mut u64;
    fn bpf_session_is_return(ctx: *mut c_void) -> bool;
}

#[no_mangle]
static mut pid: i32 = 0;

#[no_mangle]
static mut test_uprobe_1_result: u64 = 0;
#[no_mangle]
static mut test_uprobe_2_result: u64 = 0;
#[no_mangle]
static mut test_uprobe_3_result: u64 = 0;

unsafe fn check_cookie(ctx: *mut c_void, val: u64, result: *mut u64) -> i32 {
    if (bpf_get_current_pid_tgid() >> 32) as i32 != pid {
        return 1;
    }

    let cookie = bpf_session_cookie(ctx);

    if bpf_session_is_return(ctx) {
        *result = if *cookie == val { val } else { 0 };
    } else {
        *cookie = val;
    }
    0
}

#[link_section = "uprobe.session//proc/self/exe:uprobe_multi_func_1"]
#[no_mangle]
extern "C" fn uprobe_1(ctx: *mut c_void) -> i32 {
    unsafe { check_cookie(ctx, 1, core::ptr::addr_of_mut!(test_uprobe_1_result)) }
}

#[link_section = "uprobe.session//proc/self/exe:uprobe_multi_func_2"]
#[no_mangle]
extern "C" fn uprobe_2(ctx: *mut c_void) -> i32 {
    unsafe { check_cookie(ctx, 2, core::ptr::addr_of_mut!(test_uprobe_2_result)) }
}

#[link_section = "uprobe.session//proc/self/exe:uprobe_multi_func_3"]
#[no_mangle]
extern "C" fn uprobe_3(ctx: *mut c_void) -> i32 {
    unsafe { check_cookie(ctx, 3, core::ptr::addr_of_mut!(test_uprobe_3_result)) }
}

bpf_object!("GPL");
