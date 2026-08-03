#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/summarization_freplace.c
// bpf-rs-core idiom.

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_copy_from_user, bpf_skb_pull_data};

// The C source's might_sleep/does_not_sleep take `struct pt_regs *ctx
// __arg_ctx`: the freplace target (summarization.c's global subprog) is
// tagged as a context arg. rustc can't emit that BTF_KIND_DECL_TAG, but
// naming the pointee struct exactly `pt_regs` (real x86_64 kernel layout,
// 21 u64 slots, matching test_uprobe.rs/test_perf_skip.rs) lets the
// kernel's BTF-name-based context-type match still recognize arg0 as a
// pointer to context.
#[allow(non_camel_case_types)]
#[repr(C)]
struct pt_regs {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    bp: u64,
    bx: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    ax: u64,
    cx: u64,
    dx: u64,
    si: u64,
    di: u64,
    orig_ax: u64,
    ip: u64,
    cs: u64,
    flags: u64,
    sp: u64,
    ss: u64,
}

#[link_section = "?freplace"]
#[no_mangle]
extern "C" fn changes_pkt_data(sk: *const __sk_buff) -> i32 {
    bpf_skb_pull_data(sk as *const core::ffi::c_void, 0) as i32
}

#[link_section = "?freplace"]
#[no_mangle]
extern "C" fn does_not_change_pkt_data(_sk: *const __sk_buff) -> i32 {
    0
}

#[link_section = "?freplace"]
#[no_mangle]
extern "C" fn might_sleep(_ctx: *const pt_regs) -> i32 {
    let mut i: i32 = 0;
    bpf_copy_from_user(
        &mut i as *mut i32 as *mut core::ffi::c_void,
        core::mem::size_of::<i32>() as u32,
        core::ptr::null(),
    ) as i32;
    i
}

#[link_section = "?freplace"]
#[no_mangle]
extern "C" fn does_not_sleep(_ctx: *const pt_regs) -> i32 {
    0
}

bpf_object!("GPL");
