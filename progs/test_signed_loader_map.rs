#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_signed_loader_map.c,
// bpf-rs-core idiom.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_map_lookup_elem;
use bpf_rs_core::maps::{self, BpfMap};
use core::ffi::c_void;

#[link_section = ".maps"]
#[no_mangle]
static amap: BpfMap<u32, u64, { maps::ARRAY }, 4> = BpfMap::new();

#[link_section = "socket"]
#[no_mangle]
extern "C" fn probe(_ctx: *const c_void) -> i32 {
    let key: u32 = 0;
    let val = bpf_map_lookup_elem(&amap, &key) as *const u64;
    if val.is_null() {
        0
    } else {
        unsafe { *val as i32 }
    }
}

bpf_object!("GPL");
