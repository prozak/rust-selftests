#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_pinning_invalid.c, bpf-rs-core
// idiom.
//
// Maps-only object: a single map with an invalid pinning value, used by
// prog_tests/pinning.c to check that bpf_object__open_file() rejects it
// with -EINVAL before load. `__uint(pinning, 2)` is not a valid
// LIBBPF_PIN_* value, so nopinmap3 needs the bpf_map! escape hatch.

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;

bpf_map! {
    nopinmap3 {
        r#type: *const [i32; 2], // BPF_MAP_TYPE_ARRAY = 2
        max_entries: *const [i32; 1],
        key: *const u32,
        value: *const u64,
        pinning: *const [i32; 2], // invalid
    }
}

bpf_object!("GPL");
