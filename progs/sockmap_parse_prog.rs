#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/sockmap_parse_prog.c
// (bpf-rs-core idiom).

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::{bpf_object, vload};

#[link_section = "sk_skb1"]
#[no_mangle]
extern "C" fn bpf_prog1(skb: *const __sk_buff) -> i32 {
    vload!((*skb).len) as i32
}

bpf_object!("GPL");
