// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/rhash_timer.c
// (bpf-rs-core idiom). prog_tests/rhash_timer.c seeds the RHASH map with one
// element, runs arm_deleted_timer (the for_each callback deletes the element
// and then arms a timer in it), replaces the element and runs
// cancel_recycled_timer until a cancel finds a live timer in a recycled
// element. The bss counters and error slots are what the test reads.

use core::ffi::c_void;

use bpf_rs_core::helpers::{
    bpf_for_each_map_elem, bpf_map_delete_elem, bpf_timer_cancel, bpf_timer_init,
    bpf_timer_set_callback, bpf_timer_start, sync_fetch_and_add_u64,
};
use bpf_rs_core::{bpf_map, bpf_object};

const CLOCK_MONOTONIC: u64 = 1;
const TIMER_NSEC: u64 = 60 * 1000 * 1000 * 1000;
const BPF_F_TIMER_CPU_PIN: u64 = 2;
const EINVAL: i64 = 22;

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_timer {
    __opaque: [u64; 2],
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct timer_value {
    timer: bpf_timer,
    #[allow(dead_code)]
    data: u64,
}

bpf_map! {
    timer_map {
        r#type: *const [i32; 35],      // BPF_MAP_TYPE_RHASH
        map_flags: *const [i32; 1],    // BPF_F_NO_PREALLOC
        max_entries: *const [i32; 1],
        key: *const u64,
        value: *const timer_value,
    }
}

#[no_mangle]
static mut armed: u64 = 0;
#[no_mangle]
static mut cancelled: u64 = 0;
#[no_mangle]
static mut timer_init_err: i64 = 0;
#[no_mangle]
static mut timer_set_callback_err: i64 = 0;
#[no_mangle]
static mut timer_start_err: i64 = 0;
#[no_mangle]
static mut timer_cancel_err: i64 = 0;

extern "C" fn timer_cb(_map: *mut c_void, _key: *mut u64, _value: *mut timer_value) -> i64 {
    0
}

extern "C" fn arm_timer_cb(
    map: *mut c_void,
    key: *mut u64,
    value: *mut timer_value,
    _ctx: *mut c_void,
) -> i64 {
    unsafe {
        let key_copy: u64 = *key;

        let err = bpf_map_delete_elem(map as *const c_void, &key_copy);
        if err != 0 {
            return 1;
        }

        let timer = core::ptr::addr_of_mut!((*value).timer);
        let err = bpf_timer_init(timer, map as *const c_void, CLOCK_MONOTONIC);
        if err != 0 {
            timer_init_err = err;
            return 1;
        }

        let err = bpf_timer_set_callback(timer, timer_cb);
        if err != 0 {
            timer_set_callback_err = err;
            return 1;
        }

        let err = bpf_timer_start(timer, TIMER_NSEC, BPF_F_TIMER_CPU_PIN);
        if err != 0 {
            timer_start_err = err;
            return 1;
        }

        sync_fetch_and_add_u64(core::ptr::addr_of_mut!(armed), 1);
    }
    1
}

extern "C" fn cancel_timer_cb(
    _map: *mut c_void,
    _key: *mut u64,
    value: *mut timer_value,
    _ctx: *mut c_void,
) -> i64 {
    unsafe {
        let err = bpf_timer_cancel(core::ptr::addr_of_mut!((*value).timer));
        if err == -EINVAL {
            return 1;
        }
        if err < 0 {
            timer_cancel_err = err;
            return 1;
        }

        sync_fetch_and_add_u64(core::ptr::addr_of_mut!(cancelled), 1);
    }
    1
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn arm_deleted_timer(_ctx: *mut c_void) -> i32 {
    bpf_for_each_map_elem(
        &timer_map as *const timer_map as *const c_void,
        arm_timer_cb,
        core::ptr::null_mut::<c_void>(),
        0,
    );
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn cancel_recycled_timer(_ctx: *mut c_void) -> i32 {
    bpf_for_each_map_elem(
        &timer_map as *const timer_map as *const c_void,
        cancel_timer_cb,
        core::ptr::null_mut::<c_void>(),
        0,
    );
    0
}

bpf_object!("GPL");
