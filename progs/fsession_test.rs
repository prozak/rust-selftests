#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/fsession_test.c
// (bpf-next), bpf-rs-core idiom.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_func_ip;
use bpf_rs_core::progs::fentry_arg as arg;
use bpf_rs_core::{vload, vstore};
use core::ffi::c_void;

extern "C" {
    fn bpf_session_is_return(ctx: *mut c_void) -> bool;
    fn bpf_session_cookie(ctx: *mut c_void) -> *mut u64;
    fn bpf_fentry_test1(a: i32) -> i32;
}

#[no_mangle]
static mut test1_entry_result: u64 = 0;
#[no_mangle]
static mut test1_exit_result: u64 = 0;

#[link_section = "fsession/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test1(ctx: *const u64) -> i32 {
    let a = arg(ctx, 0) as i32;
    let ret = arg(ctx, 1) as i32;
    let is_exit = unsafe { bpf_session_is_return(ctx as *mut c_void) };
    if !is_exit {
        unsafe { test1_entry_result = (a == 1 && ret == 0) as u64 };
        return 0;
    }
    unsafe { test1_exit_result = (a == 1 && ret == 2) as u64 };
    0
}

#[no_mangle]
static mut test2_entry_result: u64 = 0;
#[no_mangle]
static mut test2_exit_result: u64 = 0;

#[link_section = "fsession/bpf_fentry_test3"]
#[no_mangle]
extern "C" fn test2(ctx: *const u64) -> i32 {
    let a = arg(ctx, 0) as i8;
    let b = arg(ctx, 1) as i32;
    let c = arg(ctx, 2);
    let ret = arg(ctx, 3) as i32;
    let is_exit = unsafe { bpf_session_is_return(ctx as *mut c_void) };
    if !is_exit {
        unsafe { test2_entry_result = (a == 4 && b == 5 && c == 6 && ret == 0) as u64 };
        return 0;
    }
    unsafe { test2_exit_result = (a == 4 && b == 5 && c == 6 && ret == 15) as u64 };
    0
}

#[no_mangle]
static mut test3_entry_result: u64 = 0;
#[no_mangle]
static mut test3_exit_result: u64 = 0;

#[link_section = "fsession/bpf_fentry_test4"]
#[no_mangle]
extern "C" fn test3(ctx: *const u64) -> i32 {
    let a = arg(ctx, 0); // void *
    let b = arg(ctx, 1) as i8;
    let c = arg(ctx, 2) as i32;
    let d = arg(ctx, 3);
    let ret = arg(ctx, 4) as i32;
    let is_exit = unsafe { bpf_session_is_return(ctx as *mut c_void) };
    if !is_exit {
        unsafe {
            test3_entry_result = (a == 7 && b == 8 && c == 9 && d == 10 && ret == 0) as u64;
        }
        return 0;
    }
    unsafe {
        test3_exit_result = (a == 7 && b == 8 && c == 9 && d == 10 && ret == 34) as u64;
    }
    0
}

#[no_mangle]
static mut test4_entry_result: u64 = 0;
#[no_mangle]
static mut test4_exit_result: u64 = 0;

#[link_section = "fsession/bpf_fentry_test5"]
#[no_mangle]
extern "C" fn test4(ctx: *const u64) -> i32 {
    let a = arg(ctx, 0);
    let b = arg(ctx, 1); // void *
    let c = arg(ctx, 2) as i16;
    let d = arg(ctx, 3) as i32;
    let e = arg(ctx, 4);
    let ret = arg(ctx, 5) as i32;
    let is_exit = unsafe { bpf_session_is_return(ctx as *mut c_void) };
    if !is_exit {
        unsafe {
            test4_entry_result =
                (a == 11 && b == 12 && c == 13 && d == 14 && e == 15 && ret == 0) as u64;
        }
        return 0;
    }
    unsafe {
        test4_exit_result =
            (a == 11 && b == 12 && c == 13 && d == 14 && e == 15 && ret == 65) as u64;
    }
    0
}

#[no_mangle]
static mut test5_entry_result: u64 = 0;
#[no_mangle]
static mut test5_exit_result: u64 = 0;

// struct bpf_fentry_test_t { struct bpf_fentry_test_t *a; }; only the
// null-ness of the pointer itself is checked, never dereferenced.

#[link_section = "fsession/bpf_fentry_test7"]
#[no_mangle]
extern "C" fn test5(ctx: *const u64) -> i32 {
    let arg_ptr = arg(ctx, 0) as *const u64;
    let ret = arg(ctx, 1) as i32;
    let is_exit = unsafe { bpf_session_is_return(ctx as *mut c_void) };
    if !is_exit {
        if arg_ptr.is_null() {
            unsafe { test5_entry_result = (ret == 0) as u64 };
        }
        return 0;
    }
    if arg_ptr.is_null() {
        unsafe { test5_exit_result = 1 };
    }
    0
}

#[no_mangle]
static mut test6_entry_result: u64 = 0;
#[no_mangle]
static mut test6_exit_result: u64 = 0;

#[link_section = "fsession/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test6(ctx: *const u64) -> i32 {
    let addr = bpf_get_func_ip(ctx as *const c_void);
    let target = bpf_fentry_test1 as *const () as usize as u64;
    let is_exit = unsafe { bpf_session_is_return(ctx as *mut c_void) };
    if is_exit {
        unsafe { test6_exit_result = (addr == target) as u64 };
    } else {
        unsafe { test6_entry_result = (addr == target) as u64 };
    }
    0
}

#[no_mangle]
static mut test7_entry_ok: u64 = 0;
#[no_mangle]
static mut test7_exit_ok: u64 = 0;

#[link_section = "fsession/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test7(ctx: *const u64) -> i32 {
    let cookie = unsafe { bpf_session_cookie(ctx as *mut c_void) };
    let is_exit = unsafe { bpf_session_is_return(ctx as *mut c_void) };
    if !is_exit {
        vstore!(*cookie, 0xAAAABBBBCCCCDDDDu64);
        unsafe { test7_entry_ok = (vload!(*cookie) == 0xAAAABBBBCCCCDDDDu64) as u64 };
        return 0;
    }
    unsafe { test7_exit_ok = (vload!(*cookie) == 0xAAAABBBBCCCCDDDDu64) as u64 };
    0
}

#[no_mangle]
static mut test8_entry_ok: u64 = 0;
#[no_mangle]
static mut test8_exit_ok: u64 = 0;

#[link_section = "fsession/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test8(ctx: *const u64) -> i32 {
    let cookie = unsafe { bpf_session_cookie(ctx as *mut c_void) };
    let is_exit = unsafe { bpf_session_is_return(ctx as *mut c_void) };
    if !is_exit {
        vstore!(*cookie, 0x1111222233334444u64);
        unsafe { test8_entry_ok = (vload!(*cookie) == 0x1111222233334444u64) as u64 };
        return 0;
    }
    unsafe { test8_exit_ok = (vload!(*cookie) == 0x1111222233334444u64) as u64 };
    0
}

#[no_mangle]
static mut test9_entry_result: u64 = 0;
#[no_mangle]
static mut test9_exit_result: u64 = 0;

#[link_section = "fsession/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test9(ctx: *const u64) -> i32 {
    let a = arg(ctx, 0) as i32;
    let ret = arg(ctx, 1) as i32;
    let cookie = unsafe { bpf_session_cookie(ctx as *mut c_void) };
    let is_exit = unsafe { bpf_session_is_return(ctx as *mut c_void) };
    if !is_exit {
        unsafe {
            test9_entry_result = (a == 1 && ret == 0) as u64;
            *cookie = 0x123456u64;
        }
        return 0;
    }
    unsafe {
        test9_exit_result = (a == 1 && ret == 2 && *cookie == 0x123456u64) as u64;
    }
    0
}

#[no_mangle]
static mut test10_result: u64 = 0;

#[link_section = "fexit/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test10(ctx: *const u64) -> i32 {
    let a = arg(ctx, 0) as i32;
    let ret = arg(ctx, 1) as i32;
    unsafe { test10_result = (a == 1 && ret == 2) as u64 };
    0
}

#[no_mangle]
static mut test11_result: u64 = 0;

#[link_section = "fentry/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test11(ctx: *const u64) -> i32 {
    let a = arg(ctx, 0) as i32;
    unsafe { test11_result = (a == 1) as u64 };
    0
}

bpf_object!("GPL");
