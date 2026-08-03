#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/uprobe_multi_bench.c
// bpf-rs-core idiom.

use bpf_rs_core::bpf_object;

#[no_mangle]
static mut count: i32 = 0;

#[link_section = "uprobe.multi/./uprobe_multi:uprobe_multi_func_*"]
#[no_mangle]
extern "C" fn uprobe_bench(_ctx: *const core::ffi::c_void) -> i32 {
    unsafe { count += 1 };
    0
}

bpf_object!("GPL");
