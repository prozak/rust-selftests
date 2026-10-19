// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(linkage)]
#![allow(non_upper_case_globals, non_camel_case_types)]

// Direct translation of tools/testing/selftests/bpf/progs/linked_maps2.c
// (bpf-rs-core idiom). Half of linked_maps.skel.h (Makefile.skel:
// `linked_maps.skel.h-deps := linked_maps1.bpf.o linked_maps2.bpf.o`):
// prog_tests/linked_maps.c attaches both halves' raw tracepoints and
// checks linked_maps1's outputs, which this half's sys_enter handler
// feeds (2000 in map1, 2 in map2 and map_weak); prog_tests/linked_externs.c's
// relink_maps subtest links the two .bpf.o files by name and checks every
// `.maps` extern resolved.
//
// `map2` is this half's definition, `map1` the other half's (`// BTF_EXTERN:`,
// scripts/ksym_vars.py mirrors the C object's extern map definition with its
// members for the static linker); `map_weak` is defined `__weak` in both
// halves and the linker requires the two definitions to match exactly. The
// C's `key_type`/`value_type` typedefs of struct my_key/my_value are
// skipped by the linker's comparison, so the structs are used directly
// under the C's names. The C names its license global `LICENSE`
// (bpftool_ringbuf.rs).

use core::ffi::c_void;
use core::ptr::addr_of;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_map_lookup_elem, bpf_map_update_elem};
use bpf_rs_core::maps::{self, BpfMap};

/* modifiers and typedefs are ignored when comparing key/value types */
#[repr(C)]
struct my_key {
    x: i64,
}
#[repr(C)]
struct my_value {
    x: i64,
}

// BTF_EXTERN: map1
extern "C" {
    static map1: BpfMap<my_key, my_value, { maps::HASH }, 16>;
}

#[link_section = ".maps"]
#[no_mangle]
static map2: BpfMap<i32, i32, { maps::ARRAY }, 8> = BpfMap::new();

/* this definition will lose, but it has to exactly match the winner */
#[linkage = "weak"]
#[link_section = ".maps"]
#[no_mangle]
static map_weak: BpfMap<i32, i32, { maps::ARRAY }, 16> = BpfMap::new();

#[no_mangle]
static mut output_first2: i32 = 0;
#[no_mangle]
static mut output_second2: i32 = 0;
#[no_mangle]
static mut output_weak2: i32 = 0;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn handler_enter2(_ctx: *const c_void) -> i32 {
    /* update values with key = 2 */
    let key: i32 = 2;
    let val: i32 = 2;
    let key_struct = my_key { x: 2 };
    let val_struct = my_value { x: 2000 };

    unsafe {
        bpf_map_update_elem(addr_of!(map1), &key_struct, &val_struct, 0);
        bpf_map_update_elem(addr_of!(map2), &key, &val, 0);
        bpf_map_update_elem(addr_of!(map_weak), &key, &val, 0);
    }

    0
}

#[link_section = "raw_tp/sys_exit"]
#[no_mangle]
extern "C" fn handler_exit2(_ctx: *const c_void) -> i32 {
    /* lookup values with key = 1, set in another file */
    let key: i32 = 1;
    let key_struct = my_key { x: 1 };

    unsafe {
        let value_struct = bpf_map_lookup_elem(addr_of!(map1), &key_struct) as *const my_value;
        if !value_struct.is_null() {
            output_first2 = (*value_struct).x as i32;
        }

        let val = bpf_map_lookup_elem(addr_of!(map2), &key) as *const i32;
        if !val.is_null() {
            output_second2 = *val;
        }

        let val = bpf_map_lookup_elem(addr_of!(map_weak), &key) as *const i32;
        if !val.is_null() {
            output_weak2 = *val;
        }
    }

    0
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 4] = bpf_rs_core::__lic_bytes::<4>("GPL");

bpf_object!("GPL");
