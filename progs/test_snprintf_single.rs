#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_snprintf_single.c (bpf-rs-core
// idiom). Userspace patches `fmt` (in .rodata) before load; the load
// itself is the thing under test (prog_tests/snprintf.c's
// test_snprintf_negative loads this object with a variety of format
// strings and asserts most of them fail verification).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_snprintf;
use core::ffi::c_void;

#[link_section = ".rodata"]
#[no_mangle]
static fmt: [u8; 10] = [0; 10];

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn handler(_ctx: *const c_void) -> i32 {
    let arg: u64 = 42;

    bpf_snprintf(
        core::ptr::null_mut(),
        0,
        core::ptr::addr_of!(fmt) as *const c_void,
        &arg as *const u64 as *const c_void,
        core::mem::size_of::<u64>() as u32,
    );

    0
}

bpf_object!("GPL");
