#![no_std]
#![no_main]

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_skb_change_tail, bpf_skb_pull_data};
use bpf_rs_core::{bpf_map, bpf_object, vload};

const SK_PASS: i32 = 1;

const __PAGE_SIZE: u32 = 4096;
const BPF_SKB_MAX_LEN: u32 = __PAGE_SIZE << 2;

bpf_map! {
    sock_map_rx {
        r#type: *const [i32; 15], // BPF_MAP_TYPE_SOCKMAP
        max_entries: *const [i32; 1],
        key: *const i32,
        value: *const i32,
    }
}

#[no_mangle]
static mut change_tail_ret: i64 = 1;

#[link_section = "sk_skb"]
#[no_mangle]
extern "C" fn prog_skb_verdict(skb: *const __sk_buff) -> i32 {
    bpf_skb_pull_data(skb as *const core::ffi::c_void, 1);

    let data = vload!((*skb).data) as usize as *const u8;
    let data_end = vload!((*skb).data_end) as usize as *const u8;

    if unsafe { data.add(1) } > data_end {
        return SK_PASS;
    }

    let c = unsafe { core::ptr::read_volatile(data) };

    if c == b'T' {
        let len = vload!((*skb).len);
        let ret = bpf_skb_change_tail(skb as *const core::ffi::c_void, len - 1, 0);
        unsafe { change_tail_ret = ret };
    } else if c == b'G' {
        let len = vload!((*skb).len);
        let ret = bpf_skb_change_tail(skb as *const core::ffi::c_void, len + 1, 0);
        unsafe { change_tail_ret = ret };
    } else if c == b'E' {
        let ret = bpf_skb_change_tail(skb as *const core::ffi::c_void, BPF_SKB_MAX_LEN, 0);
        unsafe { change_tail_ret = ret };
    }

    SK_PASS
}

bpf_object!("GPL");
