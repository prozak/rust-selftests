#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_custom_sec_handlers.c
// (bpf-rs-core idiom). Section handling (autoload/type/attach) for the
// nonstandard "abc"/"abc/..."/"custom"/"custom/..."/"kprobe"/"xyz/..."
// SEC() strings is entirely driven by the userspace test's registered
// libbpf_register_prog_handler() callbacks, not by anything in this file.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_copy_from_user;
use core::ffi::c_void;

#[link_section = ".rodata"]
#[no_mangle]
static my_pid: i32 = 0;

#[no_mangle]
static mut abc1_called: bool = false;
#[no_mangle]
static mut abc2_called: bool = false;
#[no_mangle]
static mut custom1_called: bool = false;
#[no_mangle]
static mut custom2_called: bool = false;
#[no_mangle]
static mut kprobe1_called: bool = false;
#[no_mangle]
static mut xyz_called: bool = false;

#[link_section = "abc"]
#[no_mangle]
extern "C" fn abc1(_ctx: *const c_void) -> i32 {
    unsafe { abc1_called = true };
    0
}

#[link_section = "abc/whatever"]
#[no_mangle]
extern "C" fn abc2(_ctx: *const c_void) -> i32 {
    unsafe { abc2_called = true };
    0
}

#[link_section = "custom"]
#[no_mangle]
extern "C" fn custom1(_ctx: *const c_void) -> i32 {
    unsafe { custom1_called = true };
    0
}

#[link_section = "custom/something"]
#[no_mangle]
extern "C" fn custom2(_ctx: *const c_void) -> i32 {
    unsafe { custom2_called = true };
    0
}

#[link_section = "kprobe"]
#[no_mangle]
extern "C" fn kprobe1(_ctx: *const c_void) -> i32 {
    unsafe { kprobe1_called = true };
    0
}

#[link_section = "xyz/blah"]
#[no_mangle]
extern "C" fn xyz(_ctx: *const c_void) -> i32 {
    let mut whatever: i32 = 0;
    bpf_copy_from_user(
        &mut whatever as *mut i32 as *mut c_void,
        core::mem::size_of::<i32>() as u32,
        core::ptr::null(),
    );
    unsafe { xyz_called = true };
    0
}

bpf_object!("GPL");
