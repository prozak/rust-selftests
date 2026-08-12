#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/tracing_struct.c
// bpf-rs-core idiom.
//
// BPF_PROG2's ctx array packs each formal argument into ceil(sizeof/8)
// consecutive u64 slots, in declaration order (see ___bpf_treg_cnt /
// ___bpf_union_arg in bpf_tracing.h): <=8-byte args take one slot,
// 16-byte struct/union args take two, and each slot is the raw bit
// pattern of that piece of the argument (union-punned, not sign/zero
// extended by the macro itself). `progs::fentry_arg` reads one such slot.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_get_func_arg, bpf_get_func_arg_cnt};
use bpf_rs_core::progs::fentry_arg as arg;
use core::ffi::c_void;

#[no_mangle]
static mut t1_a_a: isize = 0;
#[no_mangle]
static mut t1_a_b: isize = 0;
#[no_mangle]
static mut t1_b: isize = 0;
#[no_mangle]
static mut t1_c: isize = 0;
#[no_mangle]
static mut t1_ret: isize = 0;
#[no_mangle]
static mut t1_nregs: isize = 0;
#[no_mangle]
static mut t1_reg0: u64 = 0;
#[no_mangle]
static mut t1_reg1: u64 = 0;
#[no_mangle]
static mut t1_reg2: u64 = 0;
#[no_mangle]
static mut t1_reg3: u64 = 0;

#[no_mangle]
static mut t2_a: isize = 0;
#[no_mangle]
static mut t2_b_a: isize = 0;
#[no_mangle]
static mut t2_b_b: isize = 0;
#[no_mangle]
static mut t2_c: isize = 0;
#[no_mangle]
static mut t2_ret: isize = 0;

#[no_mangle]
static mut t3_a: isize = 0;
#[no_mangle]
static mut t3_b: isize = 0;
#[no_mangle]
static mut t3_c_a: isize = 0;
#[no_mangle]
static mut t3_c_b: isize = 0;
#[no_mangle]
static mut t3_ret: isize = 0;

#[no_mangle]
static mut t4_a_a: isize = 0;
#[no_mangle]
static mut t4_b: isize = 0;
#[no_mangle]
static mut t4_c: isize = 0;
#[no_mangle]
static mut t4_d: isize = 0;
#[no_mangle]
static mut t4_e_a: isize = 0;
#[no_mangle]
static mut t4_e_b: isize = 0;
#[no_mangle]
static mut t4_ret: isize = 0;

#[no_mangle]
static mut t5_ret: isize = 0;

#[no_mangle]
static mut t6: i32 = 0;

#[no_mangle]
static mut ut1_a_a: isize = 0;
#[no_mangle]
static mut ut1_b: isize = 0;
#[no_mangle]
static mut ut1_c: isize = 0;

#[no_mangle]
static mut ut2_a: isize = 0;
#[no_mangle]
static mut ut2_b_a: isize = 0;
#[no_mangle]
static mut ut2_b_b: isize = 0;

// struct bpf_testmod_struct_arg_1 { int a; }: sizeof 4, one slot.
// struct bpf_testmod_struct_arg_2 { long a; long b; }: sizeof 16, two slots.
// union bpf_testmod_union_arg_1 { char a; short b; struct ...arg_1 arg; }:
//   sizeof 4, one slot (arg.a aliases the low 32 bits).
// union bpf_testmod_union_arg_2 { int a; long b; struct ...arg_2 arg; }:
//   sizeof 16, two slots (arg aliases both slots).

#[link_section = "fentry/bpf_testmod_test_struct_arg_1"]
#[no_mangle]
extern "C" fn test_struct_arg_1(ctx: *const u64) -> i32 {
    let a_a = arg(ctx, 0) as isize;
    let a_b = arg(ctx, 1) as isize;
    let b = arg(ctx, 2) as i32 as isize;
    let c = arg(ctx, 3) as i32 as isize;
    unsafe {
        t1_a_a = a_a;
        t1_a_b = a_b;
        t1_b = b;
        t1_c = c;
    }
    0
}

#[link_section = "fexit/bpf_testmod_test_struct_arg_1"]
#[no_mangle]
extern "C" fn test_struct_arg_2(ctx: *const u64) -> i32 {
    let raw_ctx = ctx as *const c_void;
    // C passes the GLOBALS directly to bpf_get_func_arg, so a failed call
    // leaves the previous value in place; staging through zeroed locals
    // would instead publish 0 on failure.
    unsafe {
        t1_nregs = bpf_get_func_arg_cnt(raw_ctx) as isize;
        bpf_get_func_arg(raw_ctx, 0, &mut t1_reg0);
        bpf_get_func_arg(raw_ctx, 1, &mut t1_reg1);
        bpf_get_func_arg(raw_ctx, 2, &mut t1_reg2);
        t1_reg2 = (t1_reg2 as u32 as i32) as i64 as u64;
        bpf_get_func_arg(raw_ctx, 3, &mut t1_reg3);
        t1_reg3 = (t1_reg3 as u32 as i32) as i64 as u64;
        t1_ret = arg(ctx, 4) as i32 as isize;
    }
    0
}

#[link_section = "fentry/bpf_testmod_test_struct_arg_2"]
#[no_mangle]
extern "C" fn test_struct_arg_3(ctx: *const u64) -> i32 {
    let a = arg(ctx, 0) as i32 as isize;
    let b_a = arg(ctx, 1) as isize;
    let b_b = arg(ctx, 2) as isize;
    let c = arg(ctx, 3) as i32 as isize;
    unsafe {
        t2_a = a;
        t2_b_a = b_a;
        t2_b_b = b_b;
        t2_c = c;
    }
    0
}

#[link_section = "fexit/bpf_testmod_test_struct_arg_2"]
#[no_mangle]
extern "C" fn test_struct_arg_4(ctx: *const u64) -> i32 {
    let ret = arg(ctx, 4) as i32 as isize;
    unsafe {
        t2_ret = ret;
    }
    0
}

#[link_section = "fentry/bpf_testmod_test_struct_arg_3"]
#[no_mangle]
extern "C" fn test_struct_arg_5(ctx: *const u64) -> i32 {
    let a = arg(ctx, 0) as i32 as isize;
    let b = arg(ctx, 1) as i32 as isize;
    let c_a = arg(ctx, 2) as isize;
    let c_b = arg(ctx, 3) as isize;
    unsafe {
        t3_a = a;
        t3_b = b;
        t3_c_a = c_a;
        t3_c_b = c_b;
    }
    0
}

#[link_section = "fexit/bpf_testmod_test_struct_arg_3"]
#[no_mangle]
extern "C" fn test_struct_arg_6(ctx: *const u64) -> i32 {
    let ret = arg(ctx, 4) as i32 as isize;
    unsafe {
        t3_ret = ret;
    }
    0
}

#[link_section = "fentry/bpf_testmod_test_struct_arg_4"]
#[no_mangle]
extern "C" fn test_struct_arg_7(ctx: *const u64) -> i32 {
    let a_a = arg(ctx, 0) as i32 as isize;
    let b = arg(ctx, 1) as i32 as isize;
    let c = arg(ctx, 2) as i32 as isize;
    let d = arg(ctx, 3) as i32 as isize;
    let e_a = arg(ctx, 4) as isize;
    let e_b = arg(ctx, 5) as isize;
    unsafe {
        t4_a_a = a_a;
        t4_b = b;
        t4_c = c;
        t4_d = d;
        t4_e_a = e_a;
        t4_e_b = e_b;
    }
    0
}

#[link_section = "fexit/bpf_testmod_test_struct_arg_4"]
#[no_mangle]
extern "C" fn test_struct_arg_8(ctx: *const u64) -> i32 {
    let ret = arg(ctx, 6) as i32 as isize;
    unsafe {
        t4_ret = ret;
    }
    0
}

#[link_section = "fentry/bpf_testmod_test_struct_arg_5"]
#[no_mangle]
extern "C" fn test_struct_arg_9(_ctx: *const u64) -> i32 {
    0
}

#[link_section = "fexit/bpf_testmod_test_struct_arg_5"]
#[no_mangle]
extern "C" fn test_struct_arg_10(ctx: *const u64) -> i32 {
    let ret = arg(ctx, 0) as i32 as isize;
    unsafe {
        t5_ret = ret;
    }
    0
}

#[link_section = "fentry/bpf_testmod_test_struct_arg_6"]
#[no_mangle]
extern "C" fn test_struct_arg_11(ctx: *const u64) -> i32 {
    // struct bpf_testmod_struct_arg_3 { int a; int b[]; } *a: a->b[0] is
    // the i32 right after `a`, i.e. index 1 of the struct reinterpreted
    // as an i32 array.
    let p = arg(ctx, 0) as *const i32;
    let v = unsafe { *p.add(1) };
    unsafe {
        t6 = v;
    }
    0
}

#[link_section = "fexit/bpf_testmod_test_union_arg_1"]
#[no_mangle]
extern "C" fn test_union_arg_1(ctx: *const u64) -> i32 {
    let a_arg_a = arg(ctx, 0) as u32 as i32 as isize;
    let b = arg(ctx, 1) as i32 as isize;
    let c = arg(ctx, 2) as i32 as isize;
    unsafe {
        ut1_a_a = a_arg_a;
        ut1_b = b;
        ut1_c = c;
    }
    0
}

#[link_section = "fexit/bpf_testmod_test_union_arg_2"]
#[no_mangle]
extern "C" fn test_union_arg_2(ctx: *const u64) -> i32 {
    let a = arg(ctx, 0) as i32 as isize;
    let b_arg_a = arg(ctx, 1) as isize;
    let b_arg_b = arg(ctx, 2) as isize;
    unsafe {
        ut2_a = a;
        ut2_b_a = b_arg_a;
        ut2_b_b = b_arg_b;
    }
    0
}

bpf_object!("GPL");
