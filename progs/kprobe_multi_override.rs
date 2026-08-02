#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/kprobe_multi_override.c
// (bpf-rs-core idiom). ctx (`struct pt_regs *`) is never dereferenced by the
// C source, only forwarded to bpf_override_return, so it stays opaque here.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_get_current_pid_tgid, bpf_override_return};
use core::ffi::c_void;

#[no_mangle]
static mut pid: i32 = 0;

#[inline(never)]
fn override_if_matching_pid(ctx: *const c_void) {
    let tgid = (bpf_get_current_pid_tgid() >> 32) as i32;
    if tgid != unsafe { pid } {
        return;
    }

    bpf_override_return(ctx, 123);
}

#[link_section = "kprobe.multi"]
#[no_mangle]
extern "C" fn test_override(ctx: *const c_void) -> i32 {
    override_if_matching_pid(ctx);
    0
}

#[link_section = "kprobe"]
#[no_mangle]
extern "C" fn test_kprobe_override(ctx: *const c_void) -> i32 {
    override_if_matching_pid(ctx);
    0
}

bpf_object!("GPL");
