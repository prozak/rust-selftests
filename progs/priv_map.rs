#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/priv_map.c,
// bpf-rs-core idiom.
//
// Maps-only object: no programs, just one QUEUE map with no key type
// (queue/stack maps have no key member in BTF). prog_tests/token.c's
// obj_priv_map subtest is the consumer: it open/loads this skeleton
// with a restricted BPF token to exercise BPF_MAP_CREATE permission
// checks for BPF_MAP_TYPE_QUEUE.

use bpf_rs_core::{bpf_map, bpf_object};

bpf_map! {
    priv_map {
        r#type: *const [i32; 22], // BPF_MAP_TYPE_QUEUE
        max_entries: *const [i32; 1],
        value: *const u32,
    }
}

bpf_object!("GPL");
