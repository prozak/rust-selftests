#![no_std]
#![no_main]

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;

#[link_section = "freplace/global_func2"]
#[no_mangle]
extern "C" fn test_freplace_int_with_void(_skb: *const __sk_buff) {}

bpf_object!("GPL");
