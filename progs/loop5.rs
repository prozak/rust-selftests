#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/loop5.c
// bpf-rs-core idiom.

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::vload;

#[link_section = "socket"]
#[no_mangle]
extern "C" fn while_true(skb: *const __sk_buff) -> i32 {
    let mut i: i32 = 0;

    loop {
        if vload!((*skb).len) != 0 {
            i += 3;
        } else {
            i += 7;
        }
        if i == 9 {
            break;
        }
        if i == 10 {
            break;
        }
        if i == 13 {
            break;
        }
        if i == 14 {
            break;
        }
    }

    i
}

bpf_object!("GPL");
