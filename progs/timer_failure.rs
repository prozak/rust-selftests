// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Direct translation of tools/testing/selftests/bpf/progs/timer_failure.c,
// bpf-rs-core idiom (timer.rs has the map/timer/callback idiom).
//
// Two NEGATIVE verifier tests on timer callbacks (prog_tests/timer.c
// RUN_TESTS this object): test_bad_ret sets the C's `__naked` callback,
// carried as a `// BPF_NAKED:` body matching the C object instruction by
// instruction, whose branch path returns a random value where an async
// callback must return 0 (the log-level-2 messages check R0 is marked
// precise on both paths); test_infinite_loop_cb sets a callback that never
// terminates. The naked callback keeps the C's parameterless prototype and
// is cast to the callback type at the bpf_timer_set_callback call.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_map_lookup_elem, bpf_timer_init, bpf_timer_set_callback, bpf_timer_start};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::test_tags;

const CLOCK_BOOTTIME: u64 = 7;

// struct bpf_timer { __u64 __opaque[2]; } __attribute__((aligned(8)));
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_timer {
    __opaque: [u64; 2],
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct elem {
    t: bpf_timer,
}

type TimerMap = BpfMap<i32, elem, { maps::ARRAY }, 1>;

#[link_section = ".maps"]
#[no_mangle]
static timer_map: TimerMap = BpfMap::new();

test_tags! {
    test_bad_ret: __log_level(2), __flag(BPF_F_TEST_STATE_FREQ), __failure, __msg("mark_precise: frame0: regs=r0 stack= before"), __msg(": (85) call bpf_get_prandom_u32#7"), __msg("mark_precise: frame0: regs=r0 stack= before "), __msg(": (85) call bpf_get_prandom_u32#7"), __msg("should have been in [0, 0]");
    test_infinite_loop_cb: __failure, __msg("infinite loop detected");
}

/* async callback is expected to return 0, so the branch skipping r0 = 0
 * should lead to a failure, but if the exit instruction doesn't enforce
 * r0's precision, this callback will be successfully verified */
#[no_mangle]
#[inline(never)]
// BPF_NAKED: timer_cb_ret_bad
extern "C" fn timer_cb_ret_bad() -> i64 {
    unsafe { core::arch::asm!("call 7;if r0 s> 1000 goto +1;r0 = 0;goto +0;exit;", options(noreturn)); }
}

#[link_section = "fentry/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test_bad_ret(_ctx: *const u64) -> i64 {
    let key: i32 = 0;

    let timer = bpf_map_lookup_elem(&timer_map, &key) as *mut bpf_timer;
    if !timer.is_null() {
        let cb: extern "C" fn(*mut TimerMap, *mut i32, *mut elem) -> i64 =
            unsafe { core::mem::transmute(timer_cb_ret_bad as extern "C" fn() -> i64) };
        bpf_timer_init(timer, &timer_map, CLOCK_BOOTTIME);
        bpf_timer_set_callback(timer, cb);
        bpf_timer_start(timer, 1000, 0);
    }

    0
}

/*
 * A real loop inside an async callback must still be rejected: both entries
 * into the callback have the same async_entry_cnt, so telling entries apart
 * does not apply here.
 */
extern "C" fn timer_cb_infinite_loop(_map: *mut TimerMap, _key: *mut i32, _val: *mut elem) -> i64 {
    loop {}
}

#[link_section = "fentry/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test_infinite_loop_cb(_ctx: *const u64) -> i64 {
    let key: i32 = 0;

    let timer = bpf_map_lookup_elem(&timer_map, &key) as *mut bpf_timer;
    if !timer.is_null() {
        bpf_timer_init(timer, &timer_map, CLOCK_BOOTTIME);
        bpf_timer_set_callback(timer, timer_cb_infinite_loop);
        bpf_timer_start(timer, 1000, 0);
    }

    0
}


bpf_object!("GPL");
