#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/trace_printk.c
// (bpf-rs-core idiom).
//
// Three bpf_trace_printk calls whose RETURN CODES are the assertions:
// prog_tests/trace_printk.c checks that the ASCII and UTF-8 formats are
// accepted and that a `%` followed by a non-ASCII byte is rejected. The
// exact format bytes therefore matter, including the UTF-8 ones.

#![allow(non_upper_case_globals)]

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_trace_printk, bpf_trace_printk1};
use core::ffi::c_void;

#[no_mangle]
static mut trace_printk_ret: i32 = 0;
#[no_mangle]
static mut trace_printk_ran: i32 = 0;
#[no_mangle]
static mut trace_printk_invalid_spec_ret: i32 = 0;
#[no_mangle]
static mut trace_printk_utf8_ret: i32 = 0;
#[no_mangle]
static mut trace_printk_utf8_ran: i32 = 0;

// C: `const char fmt[]` at file scope — a non-static global const, so it is
// a named .rodata object the skeleton can see, not a function-local literal
#[link_section = ".rodata"]
#[no_mangle]
static fmt: [u8; 20] = *b"Testing,testing %d\n\0";

// "中文,测试 %d\n" as UTF-8 bytes
static utf8_fmt: [u8; 18] = [
    0xe4, 0xb8, 0xad, 0xe6, 0x96, 0x87, b',', 0xe6, 0xb5, 0x8b, 0xe8, 0xaf,
    0x95, b' ', b'%', b'd', b'\n', 0x00,
];

// Non-ASCII byte after '%' must still be rejected.
static invalid_spec_fmt: [u8; 4] = [b'%', 0x80, b'\n', 0x00];

#[link_section = "fentry/__x64_sys_nanosleep"]
#[no_mangle]
extern "C" fn sys_enter(_ctx: *const c_void) -> i32 {
    unsafe {
        trace_printk_ran += 1;
        trace_printk_ret = bpf_trace_printk1(
            fmt.as_ptr() as *const c_void,
            fmt.len() as u32,
            trace_printk_ran as u64,
        ) as i32;

        trace_printk_utf8_ran += 1;
        trace_printk_utf8_ret = bpf_trace_printk1(
            utf8_fmt.as_ptr() as *const c_void,
            utf8_fmt.len() as u32,
            trace_printk_utf8_ran as u64,
        ) as i32;

        trace_printk_invalid_spec_ret = bpf_trace_printk(
            invalid_spec_fmt.as_ptr() as *const c_void,
            invalid_spec_fmt.len() as u32,
            0,
            0,
            0,
        ) as i32;
    }
    0
}

bpf_object!("GPL");
