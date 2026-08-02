#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/for_each_map_elem_write_key.c,
// bpf-rs-core idiom.
//
// prog_tests/for_each.c's test_write_map_key() asserts
// for_each_map_elem_write_key__open_and_load() FAILS (ASSERT_ERR_PTR): the
// callback writes into the bpf_for_each_map_elem key argument via
// bpf_get_current_comm, and the verifier statically rejects any write
// through a PTR_TO_MAP_KEY register ("write to change key ... not
// allowed"). No __failure/__msg BTF decl tag involved — this is a real,
// unconditional verifier rejection, so the straightforward translation
// reproduces it.

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_for_each_map_elem, bpf_get_current_comm};
use bpf_rs_core::maps::{self, BpfMap};

type ArrayMap = BpfMap<u32, u64, { maps::ARRAY }, 1>;

#[link_section = ".maps"]
#[no_mangle]
static array_map: ArrayMap = BpfMap::new();

extern "C" fn check_array_elem(
    _map: *mut ArrayMap,
    key: *mut u32,
    _val: *mut u64,
    _data: *mut c_void,
) -> i64 {
    bpf_get_current_comm(key as *mut c_void, core::mem::size_of::<u32>() as u32);
    0
}

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn test_map_key_write(_ctx: *const c_void) -> i32 {
    bpf_for_each_map_elem(
        &array_map,
        check_array_elem,
        core::ptr::null_mut::<c_void>(),
        0,
    );
    0
}

bpf_object!("GPL");
