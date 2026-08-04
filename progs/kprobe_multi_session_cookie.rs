#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/kprobe_multi_session_cookie.c
// (bpf-rs-core idiom). ctx (`struct pt_regs *`) is never dereferenced by the
// C source, only forwarded to the bpf_session_* kfuncs, so it stays opaque
// here (same pattern as kprobe_multi_override.rs).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_current_pid_tgid;
use core::ffi::c_void;

extern "C" {
    fn bpf_session_is_return(ctx: *mut c_void) -> bool;
    fn bpf_session_cookie(ctx: *mut c_void) -> *mut u64;
}

#[no_mangle]
static mut pid: i32 = 0;

#[no_mangle]
static mut test_kprobe_1_result: u64 = 0;
#[no_mangle]
static mut test_kprobe_2_result: u64 = 0;
#[no_mangle]
static mut test_kprobe_3_result: u64 = 0;

/*
 * No tests in here, just to trigger 'bpf_fentry_test*'
 * through tracing test_run
 */
#[link_section = "fentry/bpf_modify_return_test"]
#[no_mangle]
extern "C" fn trigger(_ctx: *const u64) -> i32 {
    0
}

#[inline(never)]
fn check_cookie(ctx: *mut c_void, val: u64, result: *mut u64) -> i32 {
    if bpf_get_current_pid_tgid() >> 32 != unsafe { pid } as u64 {
        return 1;
    }

    let cookie = unsafe { bpf_session_cookie(ctx) };

    if unsafe { bpf_session_is_return(ctx) } {
        let v = unsafe { *cookie };
        unsafe { *result = if v == val { val } else { 0 } };
    } else {
        unsafe { *cookie = val };
    }
    0
}

#[link_section = "kprobe.session/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test_kprobe_1(ctx: *mut c_void) -> i32 {
    check_cookie(ctx, 1, unsafe { core::ptr::addr_of_mut!(test_kprobe_1_result) })
}

#[link_section = "kprobe.session/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test_kprobe_2(ctx: *mut c_void) -> i32 {
    check_cookie(ctx, 2, unsafe { core::ptr::addr_of_mut!(test_kprobe_2_result) })
}

#[link_section = "kprobe.session/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test_kprobe_3(ctx: *mut c_void) -> i32 {
    check_cookie(ctx, 3, unsafe { core::ptr::addr_of_mut!(test_kprobe_3_result) })
}

bpf_object!("GPL");
