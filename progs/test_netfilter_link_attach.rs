#![no_std]
#![no_main]

use bpf_rs_core::bpf_object;

const NF_ACCEPT: i32 = 1;

#[link_section = "netfilter"]
#[no_mangle]
extern "C" fn nf_link_attach_test(_ctx: *const core::ffi::c_void) -> i32 {
    NF_ACCEPT
}

bpf_object!("GPL");
