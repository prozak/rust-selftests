#![no_std]
#![no_main]

use bpf_rs_core::bpf_object;

#[no_mangle]
static mut r#in: i32 = 0;
#[no_mangle]
static mut out: i32 = 0;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn raw_tp_prog(_ctx: *const core::ffi::c_void) -> i32 {
    unsafe {
        out = r#in;
    }
    0
}

#[link_section = "tp_btf/sys_enter"]
#[no_mangle]
extern "C" fn tp_btf_prog(_ctx: *const core::ffi::c_void) -> i32 {
    unsafe {
        out = r#in;
    }
    0
}

bpf_object!("GPL");
