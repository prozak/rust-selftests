#![no_std]
#![no_main]

use bpf_rs_core::bpf_object;

const IN16: u16 = 0x1234;
const IN32: u32 = 0x1234_5678;
const IN64: u64 = 0x1234_5678_9abc_def0;

#[no_mangle]
static mut in16: u16 = 0;
#[no_mangle]
static mut in32: u32 = 0;
#[no_mangle]
static mut in64: u64 = 0;

#[no_mangle]
static mut out16: u16 = 0;
#[no_mangle]
static mut out32: u32 = 0;
#[no_mangle]
static mut out64: u64 = 0;

#[no_mangle]
static mut const16: u16 = 0;
#[no_mangle]
static mut const32: u32 = 0;
#[no_mangle]
static mut const64: u64 = 0;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn sys_enter(_ctx: *const core::ffi::c_void) -> i32 {
    unsafe {
        out16 = in16.swap_bytes();
        out32 = in32.swap_bytes();
        out64 = in64.swap_bytes();
        const16 = IN16.swap_bytes();
        const32 = IN32.swap_bytes();
        const64 = IN64.swap_bytes();
    }

    0
}

bpf_object!("GPL");
