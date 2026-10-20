// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/call_rcu_fail.c,
// bpf-rs-core idiom (call_rcu.rs is the positive counterpart).
//
// Five NEGATIVE verifier tests on bpf_call_rcu's arguments
// (prog_tests/call_rcu.c RUN_TESTS this object): a bpf_rcu_head from one
// map with another map as the owner, a map value with no bpf_rcu_head, a
// pointer at the wrong offset inside the value, a bpf_rcu_head on the
// stack, and a callback calling a sleepable helper from a non-sleepable
// program.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_copy_from_user, bpf_map_lookup_elem};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::test_tags;
use core::ffi::c_void;
use core::ptr::addr_of_mut;

#[no_mangle]
static mut user_ptr: *const c_void = core::ptr::null();

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_rcu_head {
    __opaque: [u64; 6],
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct elem {
    pad: u64,
    rh: bpf_rcu_head,
    val: u64,
}

#[link_section = ".maps"]
#[no_mangle]
static arr: BpfMap<u32, elem, { maps::ARRAY }, 1> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static arr2: BpfMap<u32, elem, { maps::ARRAY }, 1> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static plain: BpfMap<u32, u64, { maps::ARRAY }, 1> = BpfMap::new();

#[no_mangle]
static mut key: u32 = 0;

#[inline(always)]
fn key_ref() -> &'static u32 {
    unsafe { &*core::ptr::addr_of!(key) }
}

type ReclaimFn = extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> i32;

extern "C" {
    fn bpf_call_rcu(rh: *mut c_void, map: *mut c_void, callback: ReclaimFn) -> i32;
}

extern "C" fn reclaim(_map: *mut c_void, _key: *mut c_void, _value: *mut c_void) -> i32 {
    0
}

extern "C" fn sleepable_reclaim(_map: *mut c_void, _key: *mut c_void, value: *mut c_void) -> i32 {
    let e = value as *mut elem;

    unsafe { bpf_copy_from_user(addr_of_mut!((*e).val) as *mut c_void, 8, user_ptr) };
    0
}

test_tags! {
    mismatch_map: __failure, __msg("bpf_rcu_head pointer in R1"), __msg("doesn't match map pointer in R2");
    no_rcu_head: __failure, __msg("map 'plain' has no valid bpf_rcu_head");
    wrong_offset: __failure, __msg("doesn't point to 'struct bpf_rcu_head' that is at 8");
    rcu_head_on_stack: __failure, __msg("R1 type=fp expected=map_value");
    sleepable_callback: __failure, __msg("sleepable helper bpf_copy_from_user"), __msg("in non-sleepable prog");
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn mismatch_map(_ctx: *mut c_void) -> i32 {
    let e = bpf_map_lookup_elem(&arr, key_ref()) as *mut elem;
    if e.is_null() {
        return 0;
    }
    unsafe { bpf_call_rcu(addr_of_mut!((*e).rh) as *mut c_void, &arr2 as *const _ as *mut c_void, reclaim) };
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn no_rcu_head(_ctx: *mut c_void) -> i32 {
    let val = bpf_map_lookup_elem(&plain, key_ref()) as *mut u64;
    if val.is_null() {
        return 0;
    }
    unsafe { bpf_call_rcu(val as *mut c_void, &plain as *const _ as *mut c_void, reclaim) };
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn wrong_offset(_ctx: *mut c_void) -> i32 {
    let e = bpf_map_lookup_elem(&arr, key_ref()) as *mut elem;
    if e.is_null() {
        return 0;
    }
    unsafe { bpf_call_rcu(addr_of_mut!((*e).pad) as *mut c_void, &arr as *const _ as *mut c_void, reclaim) };
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn rcu_head_on_stack(_ctx: *mut c_void) -> i32 {
    let mut rh = bpf_rcu_head { __opaque: [0; 6] };

    unsafe { bpf_call_rcu(&mut rh as *mut bpf_rcu_head as *mut c_void, &arr as *const _ as *mut c_void, reclaim) };
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn sleepable_callback(_ctx: *mut c_void) -> i32 {
    let e = bpf_map_lookup_elem(&arr, key_ref()) as *mut elem;
    if e.is_null() {
        return 0;
    }
    unsafe { bpf_call_rcu(addr_of_mut!((*e).rh) as *mut c_void, &arr as *const _ as *mut c_void, sleepable_reclaim) };
    0
}

bpf_object!("GPL");
