#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/iters_num.c
// (bpf-rs-core idiom). `bpf_for(i, start, end) sum += i;` is C's
// open-coded expansion over bpf_iter_num_new/_next/_destroy (same
// `struct bpf_iter_num { __u64 __opaque[1]; }` shape as pyperf600_iter.rs);
// translated here as an explicit new/next-loop/destroy helper reused by
// every sum-computing program.

use core::ffi::c_void;

use bpf_rs_core::bpf_object;

#[repr(C)]
struct bpf_iter_num {
    __opaque: [u64; 1],
}

extern "C" {
    fn bpf_iter_num_new(it: *mut bpf_iter_num, start: i32, end: i32) -> i32;
    fn bpf_iter_num_next(it: *mut bpf_iter_num) -> *mut i32;
    fn bpf_iter_num_destroy(it: *mut bpf_iter_num);
}

const INT_MIN: i32 = i32::MIN;
const INT_MAX: i32 = i32::MAX;
const EINVAL: i64 = 22;
const E2BIG: i64 = 7;
const BPF_MAX_LOOPS: i32 = 8 * 1024 * 1024;

#[inline(never)]
fn sum_range(start: i32, end: i32) -> i64 {
    let mut sum: i64 = 0;
    let mut it = bpf_iter_num { __opaque: [0; 1] };
    unsafe { bpf_iter_num_new(&mut it, start, end) };
    loop {
        let v = unsafe { bpf_iter_num_next(&mut it) };
        if v.is_null() {
            break;
        }
        sum += unsafe { *v } as i64;
    }
    unsafe { bpf_iter_num_destroy(&mut it) };
    sum
}

#[link_section = ".rodata"]
#[no_mangle]
static exp_empty_zero: i64 = 0 + 1;
#[no_mangle]
static mut res_empty_zero: i64 = 0;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn num_empty_zero(_ctx: *const c_void) -> i32 {
    let sum = sum_range(0, 0);
    unsafe { res_empty_zero = 1 + sum };
    0
}

#[link_section = ".rodata"]
#[no_mangle]
static exp_empty_int_min: i64 = 0 + 2;
#[no_mangle]
static mut res_empty_int_min: i64 = 0;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn num_empty_int_min(_ctx: *const c_void) -> i32 {
    let sum = sum_range(INT_MIN, INT_MIN);
    unsafe { res_empty_int_min = 2 + sum };
    0
}

#[link_section = ".rodata"]
#[no_mangle]
static exp_empty_int_max: i64 = 0 + 3;
#[no_mangle]
static mut res_empty_int_max: i64 = 0;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn num_empty_int_max(_ctx: *const c_void) -> i32 {
    let sum = sum_range(INT_MAX, INT_MAX);
    unsafe { res_empty_int_max = 3 + sum };
    0
}

#[link_section = ".rodata"]
#[no_mangle]
static exp_empty_minus_one: i64 = 0 + 4;
#[no_mangle]
static mut res_empty_minus_one: i64 = 0;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn num_empty_minus_one(_ctx: *const c_void) -> i32 {
    let sum = sum_range(-1, -1);
    unsafe { res_empty_minus_one = 4 + sum };
    0
}

#[link_section = ".rodata"]
#[no_mangle]
static exp_simple_sum: i64 = 9 * 10 / 2;
#[no_mangle]
static mut res_simple_sum: i64 = 0;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn num_simple_sum(_ctx: *const c_void) -> i32 {
    let sum = sum_range(0, 10);
    unsafe { res_simple_sum = sum };
    0
}

#[link_section = ".rodata"]
#[no_mangle]
static exp_neg_sum: i64 = -11 * 10 / 2;
#[no_mangle]
static mut res_neg_sum: i64 = 0;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn num_neg_sum(_ctx: *const c_void) -> i32 {
    let sum = sum_range(-10, 0);
    unsafe { res_neg_sum = sum };
    0
}

#[link_section = ".rodata"]
#[no_mangle]
static exp_very_neg_sum: i64 = INT_MIN as i64 + (INT_MIN as i64 + 1);
#[no_mangle]
static mut res_very_neg_sum: i64 = 0;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn num_very_neg_sum(_ctx: *const c_void) -> i32 {
    let sum = sum_range(INT_MIN, INT_MIN + 2);
    unsafe { res_very_neg_sum = sum };
    0
}

#[link_section = ".rodata"]
#[no_mangle]
static exp_very_big_sum: i64 = (INT_MAX as i64 - 1) + (INT_MAX as i64 - 2);
#[no_mangle]
static mut res_very_big_sum: i64 = 0;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn num_very_big_sum(_ctx: *const c_void) -> i32 {
    let sum = sum_range(INT_MAX - 2, INT_MAX);
    unsafe { res_very_big_sum = sum };
    0
}

#[link_section = ".rodata"]
#[no_mangle]
static exp_neg_pos_sum: i64 = -3;
#[no_mangle]
static mut res_neg_pos_sum: i64 = 0;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn num_neg_pos_sum(_ctx: *const c_void) -> i32 {
    let sum = sum_range(-3, 3);
    unsafe { res_neg_pos_sum = sum };
    0
}

#[link_section = ".rodata"]
#[no_mangle]
static exp_invalid_range: i64 = -EINVAL;
#[no_mangle]
static mut res_invalid_range: i64 = 0;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn num_invalid_range(_ctx: *const c_void) -> i32 {
    let mut it = bpf_iter_num { __opaque: [0; 1] };
    let ret = unsafe { bpf_iter_num_new(&mut it, 1, 0) };
    unsafe { bpf_iter_num_destroy(&mut it) };
    unsafe { res_invalid_range = ret as i64 };
    0
}

#[link_section = ".rodata"]
#[no_mangle]
static exp_max_range: i64 = 0 + 10;
#[no_mangle]
static mut res_max_range: i64 = 0;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn num_max_range(_ctx: *const c_void) -> i32 {
    let mut it = bpf_iter_num { __opaque: [0; 1] };
    let ret = unsafe { bpf_iter_num_new(&mut it, 0, BPF_MAX_LOOPS) };
    unsafe { bpf_iter_num_destroy(&mut it) };
    unsafe { res_max_range = 10 + ret as i64 };
    0
}

#[link_section = ".rodata"]
#[no_mangle]
static exp_e2big_range: i64 = -E2BIG;
#[no_mangle]
static mut res_e2big_range: i64 = 0;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn num_e2big_range(_ctx: *const c_void) -> i32 {
    let mut it = bpf_iter_num { __opaque: [0; 1] };
    let ret = unsafe { bpf_iter_num_new(&mut it, -1, BPF_MAX_LOOPS) };
    unsafe { bpf_iter_num_destroy(&mut it) };
    unsafe { res_e2big_range = ret as i64 };
    0
}

#[link_section = ".rodata"]
#[no_mangle]
static exp_succ_elem_cnt: i64 = 10;
#[no_mangle]
static mut res_succ_elem_cnt: i64 = 0;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn num_succ_elem_cnt(_ctx: *const c_void) -> i32 {
    let mut cnt: i32 = 0;
    let mut it = bpf_iter_num { __opaque: [0; 1] };
    unsafe { bpf_iter_num_new(&mut it, 0, 10) };
    loop {
        let v = unsafe { bpf_iter_num_next(&mut it) };
        if v.is_null() {
            break;
        }
        cnt += 1;
    }
    unsafe { bpf_iter_num_destroy(&mut it) };
    unsafe { res_succ_elem_cnt = cnt as i64 };
    0
}

#[link_section = ".rodata"]
#[no_mangle]
static exp_overfetched_elem_cnt: i64 = 5;
#[no_mangle]
static mut res_overfetched_elem_cnt: i64 = 0;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn num_overfetched_elem_cnt(_ctx: *const c_void) -> i32 {
    let mut cnt: i32 = 0;
    let mut it = bpf_iter_num { __opaque: [0; 1] };
    unsafe { bpf_iter_num_new(&mut it, 0, 5) };
    let mut i = 0;
    while i < 10 {
        let v = unsafe { bpf_iter_num_next(&mut it) };
        if !v.is_null() {
            cnt += 1;
        }
        i += 1;
    }
    unsafe { bpf_iter_num_destroy(&mut it) };
    unsafe { res_overfetched_elem_cnt = cnt as i64 };
    0
}

#[link_section = ".rodata"]
#[no_mangle]
static exp_fail_elem_cnt: i64 = 20 + 0;
#[no_mangle]
static mut res_fail_elem_cnt: i64 = 0;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn num_fail_elem_cnt(_ctx: *const c_void) -> i32 {
    let mut cnt: i32 = 0;
    let mut it = bpf_iter_num { __opaque: [0; 1] };
    unsafe { bpf_iter_num_new(&mut it, 100, 10) };
    let mut i = 0;
    while i < 10 {
        let v = unsafe { bpf_iter_num_next(&mut it) };
        if !v.is_null() {
            cnt += 1;
        }
        i += 1;
    }
    unsafe { bpf_iter_num_destroy(&mut it) };
    unsafe { res_fail_elem_cnt = 20 + cnt as i64 };
    0
}

bpf_object!("GPL");
