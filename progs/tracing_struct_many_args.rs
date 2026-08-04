#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/tracing_struct_many_args.c
// bpf-rs-core idiom.

use bpf_rs_core::bpf_object;
use bpf_rs_core::progs::fentry_arg as arg;

#[no_mangle]
static mut t7_a: isize = 0;
#[no_mangle]
static mut t7_b: isize = 0;
#[no_mangle]
static mut t7_c: isize = 0;
#[no_mangle]
static mut t7_d: isize = 0;
#[no_mangle]
static mut t7_e: isize = 0;
#[no_mangle]
static mut t7_f_a: isize = 0;
#[no_mangle]
static mut t7_f_b: isize = 0;
#[no_mangle]
static mut t7_ret: isize = 0;

#[no_mangle]
static mut t8_a: isize = 0;
#[no_mangle]
static mut t8_b: isize = 0;
#[no_mangle]
static mut t8_c: isize = 0;
#[no_mangle]
static mut t8_d: isize = 0;
#[no_mangle]
static mut t8_e: isize = 0;
#[no_mangle]
static mut t8_f_a: isize = 0;
#[no_mangle]
static mut t8_f_b: isize = 0;
#[no_mangle]
static mut t8_g: isize = 0;
#[no_mangle]
static mut t8_ret: isize = 0;

#[no_mangle]
static mut t9_a: isize = 0;
#[no_mangle]
static mut t9_b: isize = 0;
#[no_mangle]
static mut t9_c: isize = 0;
#[no_mangle]
static mut t9_d: isize = 0;
#[no_mangle]
static mut t9_e: isize = 0;
#[no_mangle]
static mut t9_f: isize = 0;
#[no_mangle]
static mut t9_g: isize = 0;
#[no_mangle]
static mut t9_h_a: isize = 0;
#[no_mangle]
static mut t9_h_b: isize = 0;
#[no_mangle]
static mut t9_h_c: isize = 0;
#[no_mangle]
static mut t9_h_d: isize = 0;
#[no_mangle]
static mut t9_i: isize = 0;
#[no_mangle]
static mut t9_ret: isize = 0;

// struct bpf_testmod_struct_arg_4 { u64 a; int b; }: sizeof 16, passed as
// two 8-byte registers -- slot0 = a (full u64), slot1 low 4 bytes = b.
//
// struct bpf_testmod_struct_arg_5 { char a; short b; int c; long d; }:
// layout a@0 b@2 c@4 d@8, sizeof 16, passed as two 8-byte registers --
// slot0 packs a/b/c into one register, slot1 = d.

#[link_section = "fentry/bpf_testmod_test_struct_arg_7"]
#[no_mangle]
extern "C" fn test_struct_many_args_1(ctx: *const u64) -> i32 {
    let a = arg(ctx, 0);
    let b = arg(ctx, 1);
    let c = arg(ctx, 2) as i16;
    let d = arg(ctx, 3) as i32;
    let e = arg(ctx, 4);
    let f_slot0 = arg(ctx, 5);
    let f_slot1 = arg(ctx, 6);
    let f_a = f_slot0;
    let f_b = f_slot1 as u32 as i32;
    unsafe {
        t7_a = a as isize;
        t7_b = b as i64 as isize;
        t7_c = c as isize;
        t7_d = d as isize;
        t7_e = e as i64 as isize;
        t7_f_a = f_a as isize;
        t7_f_b = f_b as isize;
    }
    0
}

#[link_section = "fexit/bpf_testmod_test_struct_arg_7"]
#[no_mangle]
extern "C" fn test_struct_many_args_2(ctx: *const u64) -> i32 {
    let ret = arg(ctx, 7) as i32;
    unsafe {
        t7_ret = ret as isize;
    }
    0
}

#[link_section = "fentry/bpf_testmod_test_struct_arg_8"]
#[no_mangle]
extern "C" fn test_struct_many_args_3(ctx: *const u64) -> i32 {
    let a = arg(ctx, 0);
    let b = arg(ctx, 1);
    let c = arg(ctx, 2) as i16;
    let d = arg(ctx, 3) as i32;
    let e = arg(ctx, 4);
    let f_slot0 = arg(ctx, 5);
    let f_slot1 = arg(ctx, 6);
    let f_a = f_slot0;
    let f_b = f_slot1 as u32 as i32;
    let g = arg(ctx, 7) as i32;
    unsafe {
        t8_a = a as isize;
        t8_b = b as i64 as isize;
        t8_c = c as isize;
        t8_d = d as isize;
        t8_e = e as i64 as isize;
        t8_f_a = f_a as isize;
        t8_f_b = f_b as isize;
        t8_g = g as isize;
    }
    0
}

#[link_section = "fexit/bpf_testmod_test_struct_arg_8"]
#[no_mangle]
extern "C" fn test_struct_many_args_4(ctx: *const u64) -> i32 {
    let ret = arg(ctx, 8) as i32;
    unsafe {
        t8_ret = ret as isize;
    }
    0
}

#[link_section = "fentry/bpf_testmod_test_struct_arg_9"]
#[no_mangle]
extern "C" fn test_struct_many_args_5(ctx: *const u64) -> i32 {
    let a = arg(ctx, 0);
    let b = arg(ctx, 1);
    let c = arg(ctx, 2) as i16;
    let d = arg(ctx, 3) as i32;
    let e = arg(ctx, 4);
    let f = arg(ctx, 5) as i8;
    let g = arg(ctx, 6) as i16;
    let h_slot0 = arg(ctx, 7);
    let h_slot1 = arg(ctx, 8);
    let h_a = h_slot0 as u8 as i8;
    let h_b = (h_slot0 >> 16) as u16 as i16;
    let h_c = (h_slot0 >> 32) as u32 as i32;
    let h_d = h_slot1 as i64;
    let i = arg(ctx, 9) as i64;
    unsafe {
        t9_a = a as isize;
        t9_b = b as i64 as isize;
        t9_c = c as isize;
        t9_d = d as isize;
        t9_e = e as i64 as isize;
        t9_f = f as isize;
        t9_g = g as isize;
        t9_h_a = h_a as isize;
        t9_h_b = h_b as isize;
        t9_h_c = h_c as isize;
        t9_h_d = h_d as isize;
        t9_i = i as isize;
    }
    0
}

#[link_section = "fexit/bpf_testmod_test_struct_arg_9"]
#[no_mangle]
extern "C" fn test_struct_many_args_6(ctx: *const u64) -> i32 {
    let ret = arg(ctx, 10) as i32;
    unsafe {
        t9_ret = ret as isize;
    }
    0
}

bpf_object!("GPL");
