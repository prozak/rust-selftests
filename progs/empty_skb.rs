#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/empty_skb.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_clone_redirect, bpf_skb_adjust_room};

const BPF_F_INGRESS: u64 = 1 << 0;
const BPF_ADJ_ROOM_NET: u32 = 0;

#[no_mangle]
static mut ifindex: i32 = 0;
#[no_mangle]
static mut ret: i32 = 0;

#[link_section = "lwt_xmit"]
#[no_mangle]
extern "C" fn redirect_ingress(skb: *const __sk_buff) -> i32 {
    let idx = unsafe { ifindex };
    let r = bpf_clone_redirect(skb as *const _, idx as u32, BPF_F_INGRESS) as i32;
    unsafe { ret = r };
    0
}

#[link_section = "lwt_xmit"]
#[no_mangle]
extern "C" fn redirect_egress(skb: *const __sk_buff) -> i32 {
    let idx = unsafe { ifindex };
    let r = bpf_clone_redirect(skb as *const _, idx as u32, 0) as i32;
    unsafe { ret = r };
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn tc_redirect_ingress(skb: *const __sk_buff) -> i32 {
    let idx = unsafe { ifindex };
    let r = bpf_clone_redirect(skb as *const _, idx as u32, BPF_F_INGRESS) as i32;
    unsafe { ret = r };
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn tc_redirect_egress(skb: *const __sk_buff) -> i32 {
    let idx = unsafe { ifindex };
    let r = bpf_clone_redirect(skb as *const _, idx as u32, 0) as i32;
    unsafe { ret = r };
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn tc_adjust_room(skb: *const __sk_buff) -> i32 {
    let r = bpf_skb_adjust_room(skb as *const _, 4, BPF_ADJ_ROOM_NET, 0) as i32;
    unsafe { ret = r };
    0
}

bpf_object!("GPL");
