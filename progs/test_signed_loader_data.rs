#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_signed_loader_data.c,
// bpf-rs-core idiom.

use bpf_rs_core::bpf_object;

#[no_mangle]
static mut magic: u64 = 0x5eed1234abad1dea;

#[link_section = "socket"]
#[no_mangle]
extern "C" fn probe(_ctx: *const core::ffi::c_void) -> i32 {
    unsafe { magic as i32 }
}

bpf_object!("GPL");
