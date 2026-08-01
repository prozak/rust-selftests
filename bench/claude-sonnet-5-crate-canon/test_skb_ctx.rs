#![no_std]
#![no_main]

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;

#[link_section = "tc"]
#[no_mangle]
extern "C" fn process(skb: *const __sk_buff) -> i32 {
    let skb = skb as *mut __sk_buff;

    macro_rules! check_cb {
        ($i:expr) => {
            unsafe {
                if (*skb).cb[$i] != $i as u32 + 1 {
                    return 1;
                }
                (*skb).cb[$i] += 1;
            }
        };
    }
    check_cb!(0);
    check_cb!(1);
    check_cb!(2);
    check_cb!(3);
    check_cb!(4);

    unsafe {
        (*skb).priority += 1;
        (*skb).tstamp += 1;
        (*skb).mark += 1;

        if (*skb).wire_len != 100 {
            return 1;
        }
        if (*skb).gso_segs != 8 {
            return 1;
        }
        if (*skb).gso_size != 10 {
            return 1;
        }
        if (*skb).ingress_ifindex != 11 {
            return 1;
        }
        if (*skb).ifindex != 1 {
            return 1;
        }
        if (*skb).hwtstamp != 11 {
            return 1;
        }
    }

    0
}

bpf_object!("GPL");
