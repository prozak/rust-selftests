#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_hash_large_key.c,
// bpf-rs-core idiom.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_map_lookup_elem, bpf_map_update_elem};
use bpf_rs_core::maps::{self, BpfMap};

#[allow(non_camel_case_types)]
#[repr(C)]
struct bigelement {
    a: i32,
    b: [u8; 4096],
    c: i64,
}

#[link_section = ".maps"]
#[no_mangle]
static hash_map: BpfMap<bigelement, u32, { maps::HASH }, 2> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static key_map: BpfMap<u32, bigelement, { maps::PERCPU_ARRAY }, 1> = BpfMap::new();

const BPF_ANY: u64 = 0;

#[link_section = "raw_tracepoint/sys_enter"]
#[no_mangle]
extern "C" fn bpf_hash_large_key_test(_ctx: *const core::ffi::c_void) -> i32 {
    let zero: u32 = 0;
    let value: u32 = 42;

    let key = bpf_map_lookup_elem(&key_map, &zero) as *mut bigelement;
    if key.is_null() {
        return 0;
    }

    unsafe { (*key).c = 1 };

    if bpf_map_update_elem(&hash_map, unsafe { &*key }, &value, BPF_ANY) != 0 {
        return 0;
    }

    0
}

bpf_object!("GPL");
