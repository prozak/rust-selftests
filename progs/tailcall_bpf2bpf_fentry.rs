#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/tailcall_bpf2bpf_fentry.c,
// bpf-rs-core idiom.

use bpf_rs_core::bpf_object;

#[no_mangle]
static mut count: i32 = 0;

#[link_section = "fentry/subprog_tail"]
#[no_mangle]
extern "C" fn fentry(_ctx: *const u64) -> i32 {
    unsafe { count += 1 };
    0
}

bpf_object!("GPL");
