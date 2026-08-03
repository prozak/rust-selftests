#![no_std]
#![no_main]

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::sync_fetch_and_add_u32;

#[no_mangle]
static mut run_cnt: u32 = 0;

#[link_section = "perf_event"]
#[no_mangle]
extern "C" fn handler(_ctx: *const core::ffi::c_void) -> i32 {
    sync_fetch_and_add_u32(core::ptr::addr_of_mut!(run_cnt), 1);
    0
}

bpf_object!("GPL");
