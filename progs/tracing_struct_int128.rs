// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

use bpf_rs_core::progs::fentry_arg as arg;

#[no_mangle]
static mut t_b: i64 = 0;
#[no_mangle]
static mut t_c: i64 = 0;
#[no_mangle]
static mut t_ret: i64 = 0;

#[no_mangle]
#[link_section = "fexit/bpf_testmod_test_int128_arg"]
extern "C" fn test_int128_arg_fexit(ctx: *const u64) -> i32 {
    unsafe {
        t_b = arg(ctx, 2) as i32 as i64;
        t_c = arg(ctx, 3) as i64;
        t_ret = arg(ctx, 4) as i64;
    }
    0
}

// The arguments come packed in the BPF convention whatever holes the
// kernel convention left between them: an eightbyte each, and two for the
// struct holding an __int128.
#[no_mangle]
static mut s_g: i64 = 0;
#[no_mangle]
static mut s_h_lo: i64 = 0;
#[no_mangle]
static mut s_h_hi: i64 = 0;
#[no_mangle]
static mut s_i: i64 = 0;
#[no_mangle]
static mut s_ret: i64 = 0;

#[no_mangle]
#[link_section = "fentry/bpf_testmod_test_int128_stack"]
extern "C" fn test_int128_stack_fentry(ctx: *const u64) -> i32 {
    unsafe {
        s_g = arg(ctx, 6) as i64;
        s_h_lo = arg(ctx, 7) as i64;
        s_h_hi = arg(ctx, 8) as i64;
        s_i = arg(ctx, 9) as i64;
    }
    0
}

#[no_mangle]
#[link_section = "fexit/bpf_testmod_test_int128_stack"]
extern "C" fn test_int128_stack_fexit(ctx: *const u64) -> i32 {
    unsafe {
        s_ret = arg(ctx, 10) as i64;
    }
    0
}

#[no_mangle]
static mut b_f_a: i64 = 0;
#[no_mangle]
static mut b_f_b: i64 = 0;
#[no_mangle]
static mut b_g: i64 = 0;
#[no_mangle]
static mut b_h: i64 = 0;
#[no_mangle]
static mut b_i_lo: i64 = 0;
#[no_mangle]
static mut b_i_hi: i64 = 0;
#[no_mangle]
static mut b_ret: i64 = 0;

#[no_mangle]
#[link_section = "fentry/bpf_testmod_test_int128_backfill"]
extern "C" fn test_int128_backfill_fentry(ctx: *const u64) -> i32 {
    unsafe {
        b_f_a = arg(ctx, 5) as i64;
        b_f_b = arg(ctx, 6) as i64;
        b_g = arg(ctx, 7) as i64;
        b_h = arg(ctx, 8) as i64;
        b_i_lo = arg(ctx, 9) as i64;
        b_i_hi = arg(ctx, 10) as i64;
    }
    0
}

#[no_mangle]
#[link_section = "fexit/bpf_testmod_test_int128_backfill"]
extern "C" fn test_int128_backfill_fexit(ctx: *const u64) -> i32 {
    unsafe {
        b_ret = arg(ctx, 11) as i64;
    }
    0
}

bpf_rs_core::bpf_object!("GPL");
