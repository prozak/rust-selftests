#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/uprobe_multi_usdt.c (bpf-rs-core
// idiom).

#![allow(non_upper_case_globals)]

use bpf_rs_core::bpf_object;

#[no_mangle]
static mut count: i32 = 0;

#[link_section = "usdt"]
#[no_mangle]
extern "C" fn usdt0(_ctx: *const u64) -> i32 {
    unsafe { count += 1 };
    0
}

bpf_object!("GPL");
