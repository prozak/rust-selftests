// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Direct translation of tools/testing/selftests/bpf/progs/exceptions_assert.c
// (bpf-rs-core idiom).
//
// Verifier state tests for bpf_assert() (prog_tests/exceptions.c:
// RUN_TESTS(exceptions_assert)); every program is __failure at log level
// 2 and the __msg is the register state the assertion leaves behind. The
// C's bpf_cmp_unlikely(num, op, value) is the `if lhs op rhs goto l_true`
// asm goto of bpf_experimental.h, rendered with asm!'s label operand: a
// 4-byte constant is an immediate ("ri"), an 8-byte one a register ("r"),
// and a signed lhs gets the s-prefixed operator. bpf_assert_range() is
// the two __bpf_assert asm blocks (`r1 = 0` is the cookie) after
// barrier_var(), as in res_spin_lock_fail.rs, without clobbers like the C
// so the ctx pointer stays in R1 for the state line.

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::bpf_ktime_get_ns;
use bpf_rs_core::{bpf_object, test_tags};
use core::ffi::c_void;

// UAPI struct bpf_sock (linux/bpf.h), full layout.
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_sock {
    bound_dev_if: u32,
    family: u32,
    r#type: u32,
    protocol: u32,
    mark: u32,
    priority: u32,
    src_ip4: u32,
    src_ip6: [u32; 4],
    src_port: u32,
    dst_port: u16,
    _pad: u16,
    dst_ip4: u32,
    dst_ip6: [u32; 4],
    state: u32,
    rx_queue_mapping: i32,
}

extern "C" {
    fn bpf_throw(cookie: u64);
}

// check_assert(type, op, name, value) with a 4-byte value (immediate) or
// an 8-byte one (register).
macro_rules! check_assert {
    ($name:ident, $op:literal, imm $value:expr) => {
        #[link_section = "?tc"]
        #[no_mangle]
        extern "C" fn $name(_ctx: *mut c_void) -> i32 {
            unsafe {
                let num = bpf_ktime_get_ns() as i64;
                let mut ret = false;
                core::arch::asm!(
                    concat!("if {lhs} ", $op, " {rhs} goto {l}"),
                    lhs = in(reg) num,
                    rhs = const $value,
                    l = label { ret = true; },
                );
                if !ret {
                    bpf_throw(0);
                }
                *(num as *const u64) as i32
            }
        }
    };
    ($name:ident, $op:literal, reg $value:expr) => {
        #[link_section = "?tc"]
        #[no_mangle]
        extern "C" fn $name(_ctx: *mut c_void) -> i32 {
            unsafe {
                let num = bpf_ktime_get_ns() as i64;
                let mut ret = false;
                core::arch::asm!(
                    concat!("if {lhs} ", $op, " {rhs} goto {l}"),
                    lhs = in(reg) num,
                    rhs = in(reg) $value,
                    l = label { ret = true; },
                );
                if !ret {
                    bpf_throw(0);
                }
                *(num as *const u64) as i32
            }
        }
    };
}

check_assert!(check_assert_eq_int_min, "==", imm i32::MIN);
check_assert!(check_assert_eq_int_max, "==", imm i32::MAX);
check_assert!(check_assert_eq_zero, "==", imm 0i32);
check_assert!(check_assert_eq_llong_min, "==", reg i64::MIN);
check_assert!(check_assert_eq_llong_max, "==", reg i64::MAX);

check_assert!(check_assert_lt_pos, "s<", imm i32::MAX);
check_assert!(check_assert_lt_zero, "s<", imm 0i32);
check_assert!(check_assert_lt_neg, "s<", imm i32::MIN);

check_assert!(check_assert_le_pos, "s<=", imm i32::MAX);
check_assert!(check_assert_le_zero, "s<=", imm 0i32);
check_assert!(check_assert_le_neg, "s<=", imm i32::MIN);

check_assert!(check_assert_gt_pos, "s>", imm i32::MAX);
check_assert!(check_assert_gt_zero, "s>", imm 0i32);
check_assert!(check_assert_gt_neg, "s>", imm i32::MIN);

check_assert!(check_assert_ge_pos, "s>=", imm i32::MAX);
check_assert!(check_assert_ge_zero, "s>=", imm 0i32);
check_assert!(check_assert_ge_neg, "s>=", imm i32::MIN);

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn check_assert_range_s64(ctx: *mut __sk_buff) -> i32 {
    unsafe {
        let sk = (*ctx).sk as *mut bpf_sock;
        if sk.is_null() {
            return 0;
        }
        let mut num = (*sk).rx_queue_mapping as i64;
        // bpf_assert_range(num, INT_MIN + 2, INT_MAX - 2)
        core::arch::asm!(
            "if {num} s>= {beg} goto +2",
            "r1 = 0",
            "call {throw}",
            "if {num} s<= {end} goto +2",
            "r1 = 0",
            "call {throw}",
            num = inout(reg) num,
            beg = const i32::MIN + 2,
            end = const i32::MAX - 2,
            throw = sym bpf_throw,
        );
        *(ctx as *const u8).offset(num as isize) as i32
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn check_assert_range_u64(ctx: *mut __sk_buff) -> i32 {
    unsafe {
        let mut num = (*ctx).len as u64;
        // bpf_assert_range(num, 4096, 8192)
        core::arch::asm!(
            "if {num} >= {beg} goto +2",
            "r1 = 0",
            "call {throw}",
            "if {num} <= {end} goto +2",
            "r1 = 0",
            "call {throw}",
            num = inout(reg) num,
            beg = const 4096,
            end = const 8192,
            throw = sym bpf_throw,
        );
        *(ctx as *const u8).add(num as usize) as i32
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn check_assert_single_range_s64(ctx: *mut __sk_buff) -> i32 {
    unsafe {
        let sk = (*ctx).sk as *mut bpf_sock;
        if sk.is_null() {
            return 0;
        }
        let mut num = (*sk).rx_queue_mapping as i64;
        // bpf_assert_range(num, 4096, 4096)
        core::arch::asm!(
            "if {num} s>= {beg} goto +2",
            "r1 = 0",
            "call {throw}",
            "if {num} s<= {end} goto +2",
            "r1 = 0",
            "call {throw}",
            num = inout(reg) num,
            beg = const 4096,
            end = const 4096,
            throw = sym bpf_throw,
        );
        *(ctx as *const u8).offset(num as isize) as i32
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn check_assert_single_range_u64(ctx: *mut __sk_buff) -> i32 {
    unsafe {
        let mut num = (*ctx).len as u64;
        // bpf_assert_range(num, 4096, 4096)
        core::arch::asm!(
            "if {num} >= {beg} goto +2",
            "r1 = 0",
            "call {throw}",
            "if {num} <= {end} goto +2",
            "r1 = 0",
            "call {throw}",
            num = inout(reg) num,
            beg = const 4096,
            end = const 4096,
            throw = sym bpf_throw,
        );
        *(ctx as *const u8).add(num as usize) as i32
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn check_assert_generic(ctx: *mut __sk_buff) -> i32 {
    unsafe {
        let data_end = (*ctx).data_end as u64 as *const u8;
        let data = (*ctx).data as u64 as *const u8;

        // bpf_assert(data + 64 <= data_end)
        if !(data.wrapping_add(64) <= data_end) {
            bpf_throw(0);
        }
        *data.add(128) as i32
    }
}

#[link_section = "?fentry/bpf_check"]
#[no_mangle]
extern "C" fn check_assert_with_return(ctx: *mut c_void) -> i32 {
    // bpf_assert_with(!ctx, 64)
    if !ctx.is_null() {
        unsafe { bpf_throw(64) };
    }
    0
}

test_tags! {
    check_assert_eq_int_min: __msg("R{{.}}=0xffffffff80000000"), __log_level(2), __failure;
    check_assert_eq_int_max: __msg("R{{.}}=0x7fffffff"), __log_level(2), __failure;
    check_assert_eq_zero: __msg("R{{.}}=0"), __log_level(2), __failure;
    check_assert_eq_llong_min: __msg("R{{.}}=0x8000000000000000"), __log_level(2), __failure;
    check_assert_eq_llong_max: __msg("R{{.}}=0x7fffffffffffffff"), __log_level(2), __failure;
    check_assert_lt_pos: __msg("R{{.}}=scalar(id=1,smax=0x7ffffffe)"), __log_level(2), __failure;
    check_assert_lt_zero: __msg("R{{.}}=scalar(id=1,smax=-1,umin=0x8000000000000000,var_off=(0x8000000000000000; 0x7fffffffffffffff))"), __log_level(2), __failure;
    check_assert_lt_neg: __msg("R{{.}}=scalar(id=1,smax=0xffffffff7fffffff"), __log_level(2), __failure;
    check_assert_le_pos: __msg("R{{.}}=scalar(id=1,smax=0x7fffffff)"), __log_level(2), __failure;
    check_assert_le_zero: __msg("R{{.}}=scalar(id=1,smax=0)"), __log_level(2), __failure;
    check_assert_le_neg: __msg("R{{.}}=scalar(id=1,smax=0xffffffff80000000"), __log_level(2), __failure;
    check_assert_gt_pos: __msg("R{{.}}=scalar(id=1,smin=umin=0x80000000,umax=0x7fffffffffffffff,var_off=(0x0; 0x7fffffffffffffff))"), __log_level(2), __failure;
    check_assert_gt_zero: __msg("R{{.}}=scalar(id=1,smin=umin=1,umax=0x7fffffffffffffff,var_off=(0x0; 0x7fffffffffffffff))"), __log_level(2), __failure;
    check_assert_gt_neg: __msg("R{{.}}=scalar(id=1,smin=0xffffffff80000001"), __log_level(2), __failure;
    check_assert_ge_pos: __msg("R{{.}}=scalar(id=1,smin=umin=0x7fffffff,umax=0x7fffffffffffffff,var_off=(0x0; 0x7fffffffffffffff))"), __log_level(2), __failure;
    check_assert_ge_zero: __msg("R{{.}}=scalar(id=1,smin=0,umax=0x7fffffffffffffff,var_off=(0x0; 0x7fffffffffffffff))"), __log_level(2), __failure;
    check_assert_ge_neg: __msg("R{{.}}=scalar(id=1,smin=0xffffffff80000000"), __log_level(2), __failure;
    check_assert_range_s64: __log_level(2), __failure, __msg(": R1=ctx() R2=scalar(smin=0xffffffff80000002,smax=smax32=0x7ffffffd,smin32=0x80000002) R10=fp0");
    check_assert_range_u64: __log_level(2), __failure, __msg(": R1=ctx() R2=scalar(smin=umin=smin32=umin32=4096,smax=umax=smax32=umax32=8192,var_off=(0x0; 0x3fff))");
    check_assert_single_range_s64: __log_level(2), __failure, __msg(": R1=ctx() R2=4096 R10=fp0");
    check_assert_single_range_u64: __log_level(2), __failure, __msg(": R1=ctx() R2=4096 R10=fp0");
    check_assert_generic: __log_level(2), __failure, __msg(": R6=pkt(r=64) R10=fp0");
    check_assert_with_return: __failure, __msg("At program exit the register R1 has smin=64 smax=64");
}

bpf_object!("GPL");
