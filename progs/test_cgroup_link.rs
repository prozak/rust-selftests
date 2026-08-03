#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_cgroup_link.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::sync_fetch_and_add_u32;

#[no_mangle]
static mut calls: u32 = 0;
#[no_mangle]
static mut alt_calls: u32 = 0;

#[link_section = "cgroup_skb/egress"]
#[no_mangle]
extern "C" fn egress(_skb: *mut __sk_buff) -> i32 {
    sync_fetch_and_add_u32(core::ptr::addr_of_mut!(calls), 1);
    1
}

#[link_section = "cgroup_skb/egress"]
#[no_mangle]
extern "C" fn egress_alt(_skb: *mut __sk_buff) -> i32 {
    sync_fetch_and_add_u32(core::ptr::addr_of_mut!(alt_calls), 1);
    1
}

bpf_object!("GPL");
