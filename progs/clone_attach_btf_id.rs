#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/clone_attach_btf_id.c
// bpf-rs-core idiom.

use bpf_rs_core::bpf_object;

#[link_section = "fentry/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn fentry_handler(_ctx: *const u64) -> i32 {
    0
}

bpf_object!("GPL");
