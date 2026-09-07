#![no_std]
#![no_main]

use bpf_rs_core::{ctx::__sk_buff, helpers::{sync_fetch_and_add_u64, bpf_redirect}};
use core::ptr::addr_of_mut;

#[no_mangle]
static mut redirect_ifindex: i32 = 1;
#[no_mangle]
static mut verdict_calls: u64 = 0;
#[no_mangle]
static mut helper_calls: u64 = 0;

#[no_mangle]
#[link_section = "tc"]
extern "C" fn qevent_redirect_verdict(_arg0: *const __sk_buff) -> i32 {
    sync_fetch_and_add_u64(addr_of_mut!(verdict_calls), 1);
    7 // TCX_REDIRECT
}

#[no_mangle]
#[link_section = "tc"]
extern "C" fn qevent_redirect_helper(_arg1: *const __sk_buff) -> i32 {
    sync_fetch_and_add_u64(addr_of_mut!(helper_calls), 1);
    bpf_redirect(unsafe { redirect_ifindex } as u32, 0) as i32
}

bpf_rs_core::bpf_object!("GPL");
