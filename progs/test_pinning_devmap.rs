#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_pinning_devmap.c, bpf-rs-core
// idiom.
//
// Maps-only object: two DEVMAP maps whose BTF drives libbpf's auto-pinning
// logic (prog_tests/pinning_devmap_reuse.c is the consumer).
// `__uint(pinning, LIBBPF_PIN_BY_NAME)` is encoded like any other __uint: a
// `int (*)[V]` member — LIBBPF_PIN_BY_NAME = 1 — so both maps need the
// bpf_map! escape hatch (DEVMAP also isn't in the generic's TYPE list).

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;

bpf_map! {
    pinmap1 {
        r#type: *const [i32; 14], // BPF_MAP_TYPE_DEVMAP = 14
        max_entries: *const [i32; 1],
        key: *const u32,
        value: *const u32,
        pinning: *const [i32; 1], // LIBBPF_PIN_BY_NAME = 1
    }
}

bpf_map! {
    pinmap2 {
        r#type: *const [i32; 14], // BPF_MAP_TYPE_DEVMAP = 14
        max_entries: *const [i32; 2],
        key: *const u32,
        value: *const u32,
        pinning: *const [i32; 1], // LIBBPF_PIN_BY_NAME = 1
    }
}

bpf_object!("GPL");
