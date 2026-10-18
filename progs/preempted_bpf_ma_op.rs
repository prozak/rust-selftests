// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/preempted_bpf_ma_op.c
// (bpf-rs-core idiom). Four fentry programs each own a 512-element window
// of the array map: a bpf_loop drops the kptr of every element, a second one
// allocates a fresh bin_data for each. prog_tests/preempted_bpf_ma_op.c runs
// them from four threads pinned to one CPU and asserts no allocation failed
// (nomem_err) and every run returned 0. bin_data is allocated with
// bpf_obj_new(typeof(*new)), the id of this object's own struct.
// BTF_TYPE_ID: bin_data_id local struct bin_data

use core::ffi::c_void;
use core::ptr::addr_of_mut;

use bpf_rs_core::helpers::{bpf_kptr_xchg, bpf_loop, bpf_map_lookup_elem};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::{bpf_object, btf_type_tags};

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_spin_lock {
    val: u32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bin_data {
    data: [u8; 256],
    lock: bpf_spin_lock,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct map_value {
    data: *mut bin_data,
}

btf_type_tags! {
    map_value.data: kptr;
}

#[link_section = ".maps"]
#[no_mangle]
static array: BpfMap<i32, map_value, { maps::ARRAY }, 2048> = BpfMap::new();

extern "C" {
    fn bin_data_id() -> u64;
    fn bpf_obj_new(local_type_id: u64) -> *mut c_void;
    fn bpf_obj_drop(obj: *mut c_void);
}

// write-only status flag, so the C `bool` stays a bool (the test takes a
// `bool *` to it)
#[no_mangle]
static mut nomem_err: bool = false;

extern "C" fn del_array(_i: u64, from: *mut i32) -> i64 {
    unsafe {
        let value = bpf_map_lookup_elem(&array, &*from) as *mut map_value;
        if value.is_null() {
            return 1;
        }

        let old = bpf_kptr_xchg(addr_of_mut!((*value).data).cast(), core::ptr::null_mut());
        if !old.is_null() {
            bpf_obj_drop(old);
        }

        *from += 1;
    }
    0
}

extern "C" fn add_array(_i: u64, from: *mut i32) -> i64 {
    unsafe {
        let value = bpf_map_lookup_elem(&array, &*from) as *mut map_value;
        if value.is_null() {
            return 1;
        }

        let new = bpf_obj_new(bin_data_id());
        if new.is_null() {
            nomem_err = true;
            return 1;
        }

        let old = bpf_kptr_xchg(addr_of_mut!((*value).data).cast(), new);
        if !old.is_null() {
            bpf_obj_drop(old);
        }

        *from += 1;
    }
    0
}

#[inline(always)]
fn del_then_add_array(from: i32) {
    let mut i: i32 = from;
    bpf_loop(512, del_array, &mut i, 0);

    i = from;
    bpf_loop(512, add_array, &mut i, 0);
}

// BPF_PROG2(test0, int, a)
#[link_section = "fentry/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test0(_ctx: *const u64) -> i32 {
    del_then_add_array(0);
    0
}

// BPF_PROG2(test1, int, a, u64, b)
#[link_section = "fentry/bpf_fentry_test2"]
#[no_mangle]
extern "C" fn test1(_ctx: *const u64) -> i32 {
    del_then_add_array(512);
    0
}

// BPF_PROG2(test2, char, a, int, b, u64, c)
#[link_section = "fentry/bpf_fentry_test3"]
#[no_mangle]
extern "C" fn test2(_ctx: *const u64) -> i32 {
    del_then_add_array(1024);
    0
}

// BPF_PROG2(test3, void *, a, char, b, int, c, u64, d)
#[link_section = "fentry/bpf_fentry_test4"]
#[no_mangle]
extern "C" fn test3(_ctx: *const u64) -> i32 {
    del_then_add_array(1536);
    0
}

bpf_object!("GPL");
