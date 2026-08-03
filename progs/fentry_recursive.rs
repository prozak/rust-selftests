#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/fentry_recursive.c
// (bpf-next), bpf-rs-core idiom.

use bpf_rs_core::bpf_object;

// Dummy fentry bpf prog for testing fentry attachment chains
#[link_section = "fentry/XXX"]
#[no_mangle]
extern "C" fn recursive_attach(_ctx: *const u64) -> i32 {
    0
}

bpf_object!("GPL");
