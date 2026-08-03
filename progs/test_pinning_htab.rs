#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_pinning_htab.c, bpf-rs-core idiom.
//
// No BPF programs, just two BPF_MAP_TYPE_HASH maps holding a struct with an
// embedded struct bpf_timer. The kernel recognizes the timer field purely by
// the member's BTF struct name ("bpf_timer") and size (16), so the struct
// below must reach BTF with exactly that name and layout (same pattern as
// timer_start_delete_race.rs).

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use bpf_rs_core::maps::{self, BpfMap};

// struct bpf_timer { __u64 __opaque[2]; } __attribute__((aligned(8)));
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_timer {
    __opaque: [u64; 2],
}

#[allow(non_camel_case_types, dead_code)]
#[repr(C)]
struct timer_val {
    timer: bpf_timer,
}

#[link_section = ".maps"]
#[no_mangle]
static timer_prealloc: BpfMap<u32, timer_val, { maps::HASH }, 1> = BpfMap::new();

bpf_map! {
    timer_no_prealloc {
        r#type: *const [i32; maps::HASH],
        key: *const u32,
        value: *const timer_val,
        max_entries: *const [i32; 1],
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
    }
}

bpf_object!("GPL");
