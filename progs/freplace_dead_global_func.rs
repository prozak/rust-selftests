#![no_std]
#![no_main]

use bpf_rs_core::bpf_object;

#[link_section = "freplace"]
#[no_mangle]
extern "C" fn freplace_prog() -> i32 {
    0
}

bpf_object!("GPL");
