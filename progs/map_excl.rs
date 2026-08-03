#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/map_excl.c
// (bpf-rs-core idiom).

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_map_update_elem;
use bpf_rs_core::maps::{self, BpfMap};

#[link_section = ".maps"]
#[no_mangle]
static excl_map: BpfMap<u32, u32, { maps::ARRAY }, 1> = BpfMap::new();

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn should_have_access(_ctx: *const c_void) -> i32 {
    let key: u32 = 0;
    let value: u32 = 0xdeadbeef;
    bpf_map_update_elem(&excl_map, &key, &value, 0);
    0
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn should_not_have_access(_ctx: *const c_void) -> i32 {
    let key: u32 = 0;
    let value: u32 = 0xdeadbeef;
    bpf_map_update_elem(&excl_map, &key, &value, 0);
    0
}

bpf_object!("GPL");
