#![no_std]
#![no_main]

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::bpf_skb_load_bytes;

#[no_mangle]
static mut load_offset: u32 = 0;
#[no_mangle]
static mut test_result: i32 = 0;

#[link_section = "tc"]
#[no_mangle]
extern "C" fn skb_process(skb: *const __sk_buff) -> i32 {
    let mut buf = [0u8; 16];
    let off = unsafe { load_offset };

    let ret = bpf_skb_load_bytes(
        skb as *const core::ffi::c_void,
        off,
        buf.as_mut_ptr() as *mut core::ffi::c_void,
        10,
    );

    unsafe { test_result = ret as i32 };

    0
}

bpf_object!("GPL");
