#![no_std]
#![no_main]

// Translation of
// tools/testing/selftests/bpf/progs/uprobe_multi_session_recursive.c,
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
static mut idx_entry: i32 = 0;
#[no_mangle]
static mut idx_return: i32 = 0;

#[no_mangle]
static mut test_uprobe_cookie_entry: [u64; 6] = [0; 6];
#[no_mangle]
static mut test_uprobe_cookie_return: [u64; 3] = [0; 3];

#[inline(always)]
fn check_cookie(ctx: *mut c_void) -> i32 {
    let cookie = unsafe { bpf_session_cookie(ctx) };

    if unsafe { bpf_session_is_return(ctx) } {
        let idx = unsafe { idx_return };
        if idx as usize >= 3 {
            return 1;
        }
        unsafe {
            test_uprobe_cookie_return[idx as usize] = *cookie;
            idx_return = idx + 1;
        }
        return 0;
    }

    let idx = unsafe { idx_entry };
    if idx as usize >= 6 {
        return 1;
    }
    unsafe {
        *cookie = test_uprobe_cookie_entry[idx as usize];
        idx_entry = idx + 1;
    }
    idx % 2
}

#[link_section = "uprobe.session//proc/self/exe:uprobe_session_recursive"]
#[no_mangle]
extern "C" fn uprobe_recursive(ctx: *mut c_void) -> i32 {
    if (bpf_get_current_pid_tgid() >> 32) as i32 != unsafe { pid } {
        return 1;
    }

    check_cookie(ctx)
}

bpf_object!("GPL");
