#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_enable_stats.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::sync_fetch_and_add_u64;

#[no_mangle]
static mut count: u64 = 0;

#[link_section = "raw_tracepoint/sys_enter"]
#[no_mangle]
extern "C" fn test_enable_stats(_ctx: *const core::ffi::c_void) -> i32 {
    sync_fetch_and_add_u64(unsafe { core::ptr::addr_of_mut!(count) }, 1);
    0
}

bpf_object!("GPL");
