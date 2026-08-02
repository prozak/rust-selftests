#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/kprobe_multi_empty.c
// bpf-rs-core idiom.

use bpf_rs_core::bpf_object;

#[link_section = "kprobe.multi/"]
#[no_mangle]
extern "C" fn test_kprobe_empty(_ctx: *const core::ffi::c_void) -> i32 {
    0
}

bpf_object!("GPL");
