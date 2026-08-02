#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/xfrm_info.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::{__sk_buff, TC_ACT_SHOT};

const TC_ACT_UNSPEC: i32 = -1;

#[repr(C)]
struct bpf_xfrm_info___local {
    if_id: u32,
    link: i32,
}

extern "C" {
    fn bpf_skb_set_xfrm_info(
        skb_ctx: *mut __sk_buff,
        from: *const bpf_xfrm_info___local,
    ) -> i32;
    fn bpf_skb_get_xfrm_info(skb_ctx: *mut __sk_buff, to: *mut bpf_xfrm_info___local) -> i32;
}

#[no_mangle]
static mut req_if_id: u32 = 0;
#[no_mangle]
static mut resp_if_id: u32 = 0;

#[link_section = "tc"]
#[no_mangle]
extern "C" fn set_xfrm_info(skb: *const __sk_buff) -> i32 {
    let info = bpf_xfrm_info___local {
        if_id: unsafe { req_if_id },
        link: 0,
    };

    let ret = unsafe { bpf_skb_set_xfrm_info(skb as *mut __sk_buff, &info) };
    if ret != 0 {
        TC_ACT_SHOT
    } else {
        TC_ACT_UNSPEC
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn get_xfrm_info(skb: *const __sk_buff) -> i32 {
    let mut info = bpf_xfrm_info___local { if_id: 0, link: 0 };

    let ret = unsafe { bpf_skb_get_xfrm_info(skb as *mut __sk_buff, &mut info) };
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    unsafe { resp_if_id = info.if_id };

    TC_ACT_UNSPEC
}

bpf_object!("GPL");
