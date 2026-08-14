#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/lpm_trie_map.c
// (bpf-rs-core idiom).
//
// Maps-only object: no programs. benchs/bench_bpf_lpm_trie_map.c creates
// and frees this trie to measure LPM_TRIE teardown, so the map definition
// IS the ABI. Uses the bpf_map! escape hatch rather than BpfMap<> because
// the C carries a map_flags member (BPF_F_NO_PREALLOC), which LPM_TRIE
// requires, and the typed wrapper has no field for it.

use bpf_rs_core::{bpf_map, bpf_object};

#[repr(C)]
struct trie_key {
    prefixlen: u32,
    data: u32,
}

bpf_map! {
    trie_free_map {
        r#type: *const [i32; 11],       // BPF_MAP_TYPE_LPM_TRIE
        key: *const trie_key,
        value: *const u32,
        map_flags: *const [i32; 1],     // BPF_F_NO_PREALLOC
        max_entries: *const [i32; 100_000_000],
    }
}

bpf_object!("GPL");
