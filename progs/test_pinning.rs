#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_pinning.c, bpf-rs-core idiom.
//
// Maps-only object: no programs, just three map definitions whose BTF
// drives libbpf's auto-pinning logic (prog_tests/pinning.c is the
// consumer). `__uint(pinning, V)` is encoded like any other __uint:
// a `int (*)[V]` member — LIBBPF_PIN_BY_NAME = 1, LIBBPF_PIN_NONE = 0,
// so pinmap/nopinmap2 need the bpf_map! escape hatch.

use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::{bpf_map, bpf_object};

bpf_map! {
    pinmap {
        r#type: *const [i32; 2], // BPF_MAP_TYPE_ARRAY = 2
        max_entries: *const [i32; 1],
        key: *const u32,
        value: *const u64,
        pinning: *const [i32; 1], // LIBBPF_PIN_BY_NAME = 1
    }
}

#[link_section = ".maps"]
#[no_mangle]
static nopinmap: BpfMap<u32, u64, { maps::HASH }, 1> = BpfMap::new();

bpf_map! {
    nopinmap2 {
        r#type: *const [i32; 1], // BPF_MAP_TYPE_HASH = 1
        max_entries: *const [i32; 1],
        key: *const u32,
        value: *const u64,
        pinning: *const [i32; 0], // LIBBPF_PIN_NONE = 0
    }
}

bpf_object!("GPL");
