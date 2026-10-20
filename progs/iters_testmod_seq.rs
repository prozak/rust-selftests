// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/iters_testmod_seq.c
// (bpf-rs-core idiom): the bpf_testmod open-coded iterator
// bpf_iter_testmod_seq_{new,next,destroy} plus its bpf_iter_testmod_seq_value
// getter, which the verifier only accepts on an initialized iterator. The
// C's bpf_for_each() is the new / next-until-NULL / destroy triple, destroy
// exactly once on every exit from the loop. The test_loader decl tags are
// declared with test_tags! and appended to the object's BTF by
// scripts/btf_test_tags.py.

use bpf_rs_core::bpf_object;
use bpf_rs_core::test_tags;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ptr::read_volatile;

// C: struct bpf_iter_testmod_seq { u64 :64; u64 :64; }; -- 16 opaque bytes.
#[repr(C, align(8))]
struct bpf_iter_testmod_seq {
    __opaque: [u64; 2],
}

extern "C" {
    fn bpf_iter_testmod_seq_new(it: *mut bpf_iter_testmod_seq, value: i64, cnt: i32) -> i32;
    fn bpf_iter_testmod_seq_next(it: *mut bpf_iter_testmod_seq) -> *mut i64;
    fn bpf_iter_testmod_seq_value(blah: i32, it: *mut bpf_iter_testmod_seq) -> i64;
    fn bpf_iter_testmod_seq_destroy(it: *mut bpf_iter_testmod_seq);
}

test_tags! {
    testmod_seq_empty: __success, __log_level(2), __msg("fp-16=iter_testmod_seq(id=1,state=active,depth=0)"), __msg("fp-16=iter_testmod_seq(id=1,state=drained,depth=0)"), __msg("call bpf_iter_testmod_seq_destroy");
    testmod_seq_full: __success, __log_level(2), __msg("fp-16=iter_testmod_seq(id=1,state=active,depth=0)"), __msg("fp-16=iter_testmod_seq(id=1,state=drained,depth=0)"), __msg("call bpf_iter_testmod_seq_destroy");
    testmod_seq_truncated: __success, __log_level(2), __msg("fp-16=iter_testmod_seq(id=1,state=active,depth=0)"), __msg("fp-16=iter_testmod_seq(id=1,state=drained,depth=0)"), __msg("call bpf_iter_testmod_seq_destroy");
    testmod_seq_getter_before_bad: __failure, __msg("expected an initialized iter_testmod_seq as R2");
    testmod_seq_getter_after_bad: __failure, __msg("expected an initialized iter_testmod_seq as R2");
    testmod_seq_getter_good: __success, __retval(1000000);
}

// C: const volatile __s64 exp_empty = 0 + 1; __s64 res_empty;
#[link_section = ".rodata"]
#[no_mangle]
static exp_empty: i64 = 0 + 1;
#[no_mangle]
static mut res_empty: i64 = 0;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn testmod_seq_empty(_ctx: *const c_void) -> i32 {
    let mut sum: i64 = 0;
    let mut it = MaybeUninit::<bpf_iter_testmod_seq>::uninit();

    // C: bpf_for_each(testmod_seq, i, 1000, 0) sum += *i;
    unsafe {
        bpf_iter_testmod_seq_new(it.as_mut_ptr(), 1000, 0);
        loop {
            let i = bpf_iter_testmod_seq_next(it.as_mut_ptr());
            if i.is_null() {
                break;
            }
            sum = sum.wrapping_add(*i);
        }
        bpf_iter_testmod_seq_destroy(it.as_mut_ptr());
        res_empty = sum.wrapping_add(1);
    }

    0
}

// C: const volatile __s64 exp_full = 1000000; __s64 res_full;
#[link_section = ".rodata"]
#[no_mangle]
static exp_full: i64 = 1000000;
#[no_mangle]
static mut res_full: i64 = 0;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn testmod_seq_full(_ctx: *const c_void) -> i32 {
    let mut sum: i64 = 0;
    let mut it = MaybeUninit::<bpf_iter_testmod_seq>::uninit();

    // C: bpf_for_each(testmod_seq, i, 1000, 1000) sum += *i;
    unsafe {
        bpf_iter_testmod_seq_new(it.as_mut_ptr(), 1000, 1000);
        loop {
            let i = bpf_iter_testmod_seq_next(it.as_mut_ptr());
            if i.is_null() {
                break;
            }
            sum = sum.wrapping_add(*i);
        }
        bpf_iter_testmod_seq_destroy(it.as_mut_ptr());
        res_full = sum;
    }

    0
}

// C: const volatile __s64 exp_truncated = 10 * 1000000; __s64 res_truncated;
#[link_section = ".rodata"]
#[no_mangle]
static exp_truncated: i64 = 10 * 1000000;
#[no_mangle]
static mut res_truncated: i64 = 0;

// C: static volatile int zero = 0;
#[no_mangle]
static mut zero: i32 = 0;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn testmod_seq_truncated(_ctx: *const c_void) -> i32 {
    let mut sum: i64 = 0;
    let mut cnt: i32 = unsafe { read_volatile(&raw const zero) };
    let mut it = MaybeUninit::<bpf_iter_testmod_seq>::uninit();

    // C: bpf_for_each(testmod_seq, i, 10, 2000000) { ...; if (cnt >= 1000000) break; }
    unsafe {
        bpf_iter_testmod_seq_new(it.as_mut_ptr(), 10, 2000000);
        loop {
            let i = bpf_iter_testmod_seq_next(it.as_mut_ptr());
            if i.is_null() {
                break;
            }
            sum = sum.wrapping_add(*i);
            cnt = cnt.wrapping_add(1);
            if cnt >= 1000000 {
                break;
            }
        }
        bpf_iter_testmod_seq_destroy(it.as_mut_ptr());
        res_truncated = sum;
    }

    0
}

#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn testmod_seq_getter_before_bad(_ctx: *const c_void) -> i32 {
    let mut it = MaybeUninit::<bpf_iter_testmod_seq>::uninit();

    unsafe { bpf_iter_testmod_seq_value(0, it.as_mut_ptr()) as i32 }
}

#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn testmod_seq_getter_after_bad(_ctx: *const c_void) -> i32 {
    let mut it = MaybeUninit::<bpf_iter_testmod_seq>::uninit();
    let mut sum: i64 = 0;

    unsafe {
        bpf_iter_testmod_seq_new(it.as_mut_ptr(), 100, 100);

        loop {
            let v = bpf_iter_testmod_seq_next(it.as_mut_ptr());
            if v.is_null() {
                break;
            }
            sum = sum.wrapping_add(*v);
        }

        bpf_iter_testmod_seq_destroy(it.as_mut_ptr());

        sum.wrapping_add(bpf_iter_testmod_seq_value(0, it.as_mut_ptr())) as i32
    }
}

#[link_section = "?socket"]
#[no_mangle]
extern "C" fn testmod_seq_getter_good(_ctx: *const c_void) -> i32 {
    let mut it = MaybeUninit::<bpf_iter_testmod_seq>::uninit();
    let mut sum: i64 = 0;

    unsafe {
        bpf_iter_testmod_seq_new(it.as_mut_ptr(), 100, 100);

        loop {
            let v = bpf_iter_testmod_seq_next(it.as_mut_ptr());
            if v.is_null() {
                break;
            }
            sum = sum.wrapping_add(*v);
        }

        sum = sum.wrapping_mul(bpf_iter_testmod_seq_value(0, it.as_mut_ptr()));

        bpf_iter_testmod_seq_destroy(it.as_mut_ptr());

        sum as i32
    }
}

bpf_object!("GPL");
