#![no_std]
#![no_main]

use bpf_rs_core::bpf_object;

#[no_mangle]
static mut prog1_called: bool = false;
#[no_mangle]
static mut prog2_called: bool = false;
#[no_mangle]
static mut prog3_called: bool = false;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn prog1(_ctx: *const core::ffi::c_void) -> i32 {
    unsafe {
        prog1_called = true;
    }
    0
}

#[link_section = "raw_tp/sys_exit"]
#[no_mangle]
extern "C" fn prog2(_ctx: *const core::ffi::c_void) -> i32 {
    unsafe {
        prog2_called = true;
    }
    0
}

#[link_section = "fentry/unexisting-kprobe-will-fail-if-loaded"]
#[no_mangle]
extern "C" fn prog3(ctx: *const core::ffi::c_void) -> i32 {
    let fake = ctx as *mut i32;
    unsafe {
        *fake = 123;
        prog3_called = true;
    }
    0
}

bpf_object!("GPL");
