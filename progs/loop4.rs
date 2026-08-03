#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/loop4.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::vload;

#[link_section = "socket"]
#[no_mangle]
extern "C" fn combinations(skb: *const __sk_buff) -> i32 {
    let mut ret: i32 = 0;
    for i in 0..20u32 {
        if vload!((*skb).len) != 0 {
            ret |= 1 << i;
        }
    }
    ret
}

bpf_object!("GPL");
