#![no_std]
#![no_main]

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::bpf_ktime_get_tai_ns;
use bpf_rs_core::{bpf_object, vstore};

#[link_section = "tc"]
#[no_mangle]
extern "C" fn time_tai(skb: *mut __sk_buff) -> i32 {
    let ts1 = bpf_ktime_get_tai_ns();
    let ts2 = bpf_ktime_get_tai_ns();

    vstore!((*skb).tstamp, ts1);
    vstore!((*skb).cb[0], (ts2 & 0xffffffff) as u32);
    vstore!((*skb).cb[1], (ts2 >> 32) as u32);

    0
}

bpf_object!("GPL");
