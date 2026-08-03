#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/get_func_ip_uprobe_test.c
// (bpf-rs-core idiom).
//
// BPF_UPROBE ctx is `*const u64` (kprobe-family raw pt_regs slots), same as
// test_uprobe.rs; this program never reads a register so `_ctx` is unused
// beyond the bpf_get_func_ip() helper call, which takes the raw ctx pointer.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_func_ip;
use core::ffi::c_void;

#[no_mangle]
static mut uprobe_trigger_body: usize = 0;

#[no_mangle]
static mut test1_result: u64 = 0;

#[link_section = "uprobe//proc/self/exe:uprobe_trigger_body+1"]
#[no_mangle]
extern "C" fn test1(ctx: *const u64) -> i32 {
    let addr = bpf_get_func_ip(ctx as *const c_void) as usize;

    unsafe {
        test1_result = (addr == uprobe_trigger_body + 1) as u64;
    }
    0
}

bpf_object!("GPL");
