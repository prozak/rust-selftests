#![no_std]
#![no_main]

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_map_lookup_elem, sink};
use bpf_rs_core::maps::{self, BpfMap};

#[link_section = ".maps"]
#[no_mangle]
static test_map_id: BpfMap<u32, u64, { maps::ARRAY }, 1> = BpfMap::new();

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn test_obj_id(_ctx: *const core::ffi::c_void) -> i32 {
    let key: u32 = 0;
    let mut value = bpf_map_lookup_elem(&test_map_id, &key) as *mut u64;
    sink(&mut value);
    0
}

bpf_object!("GPL");
