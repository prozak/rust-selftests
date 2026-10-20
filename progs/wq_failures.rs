// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/wq_failures.c
// (bpf-rs-core idiom).
//
// bpf_wq_init/bpf_wq_set_callback argument rejections (prog_tests/wq.c:
// RUN_TESTS(wq_failures)); the kfunc externs are the ones of wq.rs
// (add_ksyms.py mirrors the kernel prototypes, the KF_IMPLICIT_ARGS aux
// argument of bpf_wq_set_callback is omitted as in the C). The static
// callbacks call bpf_testmod kfuncs, plain extern "C".

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_get_prandom_u32, bpf_map_lookup_elem};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::{bpf_object, test_tags};
use core::ffi::c_void;
use core::ptr::addr_of_mut;

// struct bpf_wq { __u64 __opaque[2]; } __attribute__((aligned(8)));
#[allow(non_camel_case_types)]
#[repr(C, align(8))]
struct bpf_wq {
    __opaque: [u64; 2],
}

#[repr(C)]
struct elem {
    w: bpf_wq,
}

#[link_section = ".maps"]
#[no_mangle]
static array: BpfMap<i32, elem, { maps::ARRAY }, 2> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static lru: BpfMap<i32, elem, { maps::LRU_HASH }, 4> = BpfMap::new();

extern "C" {
    fn bpf_wq_init(wq: *mut bpf_wq, map: *mut c_void, flags: u32) -> i32;
    fn bpf_wq_set_callback(
        wq: *mut bpf_wq,
        callback_fn: extern "C" fn(*mut c_void, *mut i32, *mut c_void) -> i32,
        flags: u32,
    ) -> i32;
    fn bpf_kfunc_common_test();
    fn bpf_kfunc_call_test_sleepable();
}

// callback for non sleepable workqueue
extern "C" fn wq_callback(_map: *mut c_void, _key: *mut i32, _value: *mut c_void) -> i32 {
    unsafe { bpf_kfunc_common_test() };
    0
}

// callback for sleepable workqueue
extern "C" fn wq_cb_sleepable(_map: *mut c_void, _key: *mut i32, _value: *mut c_void) -> i32 {
    unsafe { bpf_kfunc_call_test_sleepable() };
    0
}

// test that bpf_wq_init takes a map as a second argument
#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_wq_init_nomap(_ctx: *mut __sk_buff) -> i64 {
    let mut key: i32 = 0;

    let val = bpf_map_lookup_elem(&array, &key) as *mut elem;
    if val.is_null() {
        return -1;
    }

    let wq = unsafe { addr_of_mut!((*val).w) };
    if unsafe { bpf_wq_init(wq, &mut key as *mut i32 as *mut c_void, 0) } != 0 {
        return -3;
    }

    0
}

// test that the workqueue is part of the map in bpf_wq_init
#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_wq_init_wrong_map(_ctx: *mut __sk_buff) -> i64 {
    let key: i32 = 0;

    let val = bpf_map_lookup_elem(&array, &key) as *mut elem;
    if val.is_null() {
        return -1;
    }

    let wq = unsafe { addr_of_mut!((*val).w) };
    if unsafe { bpf_wq_init(wq, &lru as *const _ as *mut c_void, 0) } != 0 {
        return -3;
    }

    0
}

// check that the first argument of bpf_wq_set_callback()
// is a correct bpf_wq pointer.
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn test_wrong_wq_pointer(_ctx: *mut __sk_buff) -> i64 {
    let key: i32 = 0;

    let mut wq = bpf_map_lookup_elem(&array, &key) as *mut bpf_wq;
    if wq.is_null() {
        return 1;
    }

    if unsafe { bpf_wq_init(wq, &array as *const _ as *mut c_void, 0) } != 0 {
        return 2;
    }

    // bpf_wq_set_callback((void *)&wq, wq_callback, 0)
    if unsafe { bpf_wq_set_callback(&mut wq as *mut *mut bpf_wq as *mut bpf_wq, wq_callback, 0) }
        != 0
    {
        return 3;
    }

    -22
}

// check that the first argument of bpf_wq_set_callback()
// is a correct bpf_wq pointer.
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn test_wrong_wq_pointer_offset(_ctx: *mut __sk_buff) -> i64 {
    let key: i32 = 0;

    let wq = bpf_map_lookup_elem(&array, &key) as *mut bpf_wq;
    if wq.is_null() {
        return 1;
    }

    if unsafe { bpf_wq_init(wq, &array as *const _ as *mut c_void, 0) } != 0 {
        return 2;
    }

    // bpf_wq_set_callback((void *)wq + 1, wq_cb_sleepable, 0)
    if unsafe { bpf_wq_set_callback((wq as *mut u8).add(1) as *mut bpf_wq, wq_cb_sleepable, 0) }
        != 0
    {
        return 3;
    }

    -22
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_bad_wq_off(_ctx: *mut __sk_buff) -> i64 {
    let key: i32 = 42;

    let val = bpf_map_lookup_elem(&array, &key) as *mut elem;
    if val.is_null() {
        return -2;
    }

    let unknown = bpf_get_prandom_u32() as u64;
    // wq = &val->w + unknown
    let wq = unsafe { addr_of_mut!((*val).w).add(unknown as usize) };
    if unsafe { bpf_wq_init(wq, &array as *const _ as *mut c_void, 0) } != 0 {
        return -3;
    }
    0
}

test_tags! {
    test_wq_init_nomap: __log_level(2), __flag(BPF_F_TEST_STATE_FREQ), __failure, __msg(": (85) call bpf_wq_init#"), __msg("R2 type=fp expected=map_ptr");
    test_wq_init_wrong_map: __log_level(2), __flag(BPF_F_TEST_STATE_FREQ), __failure, __msg(": (85) call bpf_wq_init#"), __msg("workqueue pointer in R1 map_uid=0 doesn't match map pointer in R2 map_uid=0");
    test_wrong_wq_pointer: __log_level(2), __failure, __msg(": (85) call bpf_wq_set_callback#"), __msg("R1 type=fp expected=map_value");
    test_wrong_wq_pointer_offset: __log_level(2), __failure, __msg(": (85) call bpf_wq_set_callback#"), __msg("off 1 doesn't point to 'struct bpf_wq' that is at 0");
    test_bad_wq_off: __log_level(2), __failure, __msg(": (85) call bpf_wq_init#"), __msg("R1 doesn't have constant offset. bpf_wq has to be at the constant offset");
}

bpf_object!("GPL");
