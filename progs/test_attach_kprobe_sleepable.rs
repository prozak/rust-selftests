#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_attach_kprobe_sleepable.c
// (bpf-rs-core idiom). This program is manually made sleepable on the
// userspace side and should thus fail to attach.

use bpf_rs_core::bpf_object;
use core::ffi::c_void;

#[no_mangle]
static mut kprobe_res: i32 = 0;

#[link_section = "kprobe/__x64_sys_nanosleep"]
#[no_mangle]
extern "C" fn handle_kprobe_sleepable(_ctx: *const c_void) -> i32 {
    unsafe {
        kprobe_res = 1;
    }
    0
}

bpf_object!("GPL");
