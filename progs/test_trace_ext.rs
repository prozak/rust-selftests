#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_trace_ext.c,
// bpf-rs-core idiom.

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::{bpf_object, vload};

#[no_mangle]
static mut ext_called: u64 = 0;

#[link_section = "freplace/test_pkt_md_access"]
#[no_mangle]
extern "C" fn test_pkt_md_access_new(skb: *const __sk_buff) -> i32 {
    let len = vload!((*skb).len);
    unsafe { ext_called = len as u64 };
    0
}

bpf_object!("GPL");
