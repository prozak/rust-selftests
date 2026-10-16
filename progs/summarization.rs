// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/summarization.c
// (bpf-rs-core idiom).
//
// changes_pkt_data / does_not_change_pkt_data and might_sleep /
// does_not_sleep are global __noinline subprograms that must survive as
// standalone BTF FUNCs: prog_tests/summarization.c's test_aux() attaches a
// freplace extension directly to each of them by name (via
// bpf_program__set_attach_target(freplace_prog, main_prog_fd,
// "changes_pkt_data")), not just to the SEC'd main programs. The freplace
// target's ctx must be BTF-typed as the named `struct pt_regs`, matching
// [[freplace-target-needs-named-pt_regs-ctx-type]] (test_uprobe.rs's
// 21x-u64 layout).
//
// does_not_change_pkt_data / does_not_sleep are __weak in the C source with
// trivial `return 0;` bodies; per
// [[weak-trivial-subprog-ipsccp-eliminated]] that alone lets opt's IPSCCP
// delete the call and inline the constant even past #[inline(never)], so
// their return values are routed through helpers::barrier_var() to keep
// them real, separately-callable subprograms.

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{self, bpf_copy_from_user, bpf_skb_pull_data};
use core::ffi::c_void;

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

#[no_mangle]
#[inline(never)]
extern "C" fn changes_pkt_data(sk: *const __sk_buff) -> i64 {
    bpf_skb_pull_data(sk as *const c_void, 0)
}

#[no_mangle]
#[inline(never)]
extern "C" fn does_not_change_pkt_data(_sk: *const __sk_buff) -> i64 {
    let mut ret: i64 = 0;
    let mut ret_barrier = ret as usize;
    helpers::barrier_var(&mut ret_barrier);
    ret = ret_barrier as i64;
    ret
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn main_changes_with_subprogs(sk: *const __sk_buff) -> i32 {
    // The verifier invalidates r1's tracked type after any subprog call;
    // clang's build reloads sk from a callee-saved register before the
    // second call. LLVM's BPF backend doesn't reliably do the equivalent
    // reload on its own, so force a genuine stack round-trip: a plain
    // register self-move survives register allocation's own value-identity
    // proof (it just reuses r1), but a volatile store/load cannot.
    let mut saved: *const __sk_buff = core::ptr::null();
    unsafe { core::ptr::write_volatile(&mut saved, sk) };
    changes_pkt_data(sk);
    let sk2 = unsafe { core::ptr::read_volatile(&saved) };
    does_not_change_pkt_data(sk2);
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn main_changes(sk: *const __sk_buff) -> i32 {
    bpf_skb_pull_data(sk as *const c_void, 0);
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn main_does_not_change(_sk: *const __sk_buff) -> i32 {
    0
}

#[no_mangle]
#[inline(never)]
extern "C" fn might_sleep(_ctx: *const pt_regs) -> i64 {
    let mut i: i32 = 0;
    bpf_copy_from_user(
        &mut i as *mut i32 as *mut c_void,
        core::mem::size_of::<i32>() as u32,
        core::ptr::null(),
    );
    i as i64
}

#[no_mangle]
#[inline(never)]
extern "C" fn does_not_sleep(_ctx: *const pt_regs) -> i64 {
    let mut ret: i64 = 0;
    let mut ret_barrier = ret as usize;
    helpers::barrier_var(&mut ret_barrier);
    ret = ret_barrier as i64;
    ret
}

#[link_section = "?uprobe.s"]
#[no_mangle]
extern "C" fn main_might_sleep_with_subprogs(ctx: *const pt_regs) -> i32 {
    // Same r1-reload issue as main_changes_with_subprogs: force a stack
    // round-trip so the second call doesn't rely on r1 surviving the first.
    let mut saved: *const pt_regs = core::ptr::null();
    unsafe { core::ptr::write_volatile(&mut saved, ctx) };
    might_sleep(ctx);
    let ctx2 = unsafe { core::ptr::read_volatile(&saved) };
    does_not_sleep(ctx2);
    0
}

#[link_section = "?uprobe.s"]
#[no_mangle]
extern "C" fn main_might_sleep(_ctx: *const pt_regs) -> i32 {
    let mut i: i32 = 0;
    bpf_copy_from_user(
        &mut i as *mut i32 as *mut c_void,
        core::mem::size_of::<i32>() as u32,
        core::ptr::null(),
    );
    i
}

#[link_section = "?uprobe.s"]
#[no_mangle]
extern "C" fn main_does_not_sleep(_ctx: *const pt_regs) -> i32 {
    0
}

bpf_object!("GPL");
