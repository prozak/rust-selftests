#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/tracing_multi_bench.c
// (bpf-next 520d7d79), bpf-rs-core idiom.

use bpf_rs_core::bpf_object;

#[link_section = "fentry.multi"]
#[no_mangle]
extern "C" fn bench(_ctx: *const u64) -> i32 {
    0
}

bpf_object!("GPL");
