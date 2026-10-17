// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_div_mod_bounds.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_div_mod_bounds` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: udiv32_pos_divisor udiv32_zero_divisor udiv64_pos_divisor udiv64_zero_divisor sdiv32_pos_divisor_1 sdiv32_pos_divisor_2 sdiv32_pos_divisor_3 sdiv32_neg_divisor_1 sdiv32_neg_divisor_2 sdiv32_neg_divisor_3 sdiv32_zero_divisor sdiv32_overflow_1 sdiv32_overflow_2 sdiv64_pos_divisor_1 sdiv64_pos_divisor_2 sdiv64_pos_divisor_3 sdiv64_neg_divisor_1 sdiv64_neg_divisor_2 sdiv64_neg_divisor_3 sdiv64_zero_divisor sdiv64_overflow_1 sdiv64_overflow_2 umod32_pos_divisor umod32_pos_divisor_unchanged umod32_zero_divisor umod64_pos_divisor umod64_pos_divisor_unchanged umod64_zero_divisor smod32_pos_divisor_1 smod32_pos_divisor_2 smod32_pos_divisor_3 smod32_pos_divisor_unchanged smod32_neg_divisor_1 smod32_neg_divisor_2 smod32_neg_divisor_3 smod32_neg_divisor_unchanged smod32_zero_divisor smod32_overflow_1 smod32_overflow_2 smod64_pos_divisor_1 smod64_pos_divisor_2 smod64_pos_divisor_3 smod64_pos_divisor_unchanged smod64_neg_divisor_1 smod64_neg_divisor_2 smod64_neg_divisor_3 smod64_neg_divisor_unchanged smod64_zero_divisor smod64_overflow_1 smod64_overflow_2

use bpf_rs_core::{test_tags};

test_tags! {
    udiv32_pos_divisor:
        __description("UDIV32, positive divisor"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("w1 /= 3 {{.*}}; R1=scalar(smin=smin32=0,smax=umax=smax32=umax32=3,var_off=(0x0; 0x3))");
    udiv32_zero_divisor:
        __description("UDIV32, zero divisor"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("w1 /= w2 {{.*}}; R1=0");
    udiv64_pos_divisor:
        __description("UDIV64, positive divisor"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("r1 /= 3 {{.*}}; R1=scalar(smin=smin32=0,smax=umax=smax32=umax32=3,var_off=(0x0; 0x3))");
    udiv64_zero_divisor:
        __description("UDIV64, zero divisor"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("r1 /= r2 {{.*}}; R1=0");
    sdiv32_pos_divisor_1:
        __description("SDIV32, positive divisor, positive dividend"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("w1 s/= 3 {{.*}}; R1=scalar(smin=umin=smin32=umin32=2,smax=umax=smax32=umax32=3,var_off=(0x2; 0x1))");
    sdiv32_pos_divisor_2:
        __description("SDIV32, positive divisor, negative dividend"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("w1 s/= 3 {{.*}}; R1=scalar(smin=umin=umin32=0xfffffffd,smax=umax=umax32=0xfffffffe,smin32=-3,smax32=-2,var_off=(0xfffffffc; 0x3))");
    sdiv32_pos_divisor_3:
        __description("SDIV32, positive divisor, mixed sign dividend"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("w1 s/= 3 {{.*}}; R1=scalar(smin=0,smax=umax=0xffffffff,smin32=-2,smax32=3,var_off=(0x0; 0xffffffff))");
    sdiv32_neg_divisor_1:
        __description("SDIV32, negative divisor, positive dividend"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("w1 s/= -3 {{.*}}; R1=scalar(smin=umin=umin32=0xfffffffd,smax=umax=umax32=0xfffffffe,smin32=-3,smax32=-2,var_off=(0xfffffffc; 0x3))");
    sdiv32_neg_divisor_2:
        __description("SDIV32, negative divisor, positive dividend"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("w1 s/= -3 {{.*}}; R1=scalar(smin=umin=smin32=umin32=2,smax=umax=smax32=umax32=3,var_off=(0x2; 0x1))");
    sdiv32_neg_divisor_3:
        __description("SDIV32, negative divisor, mixed sign dividend"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("w1 s/= -3 {{.*}}; R1=scalar(smin=0,smax=umax=0xffffffff,smin32=-3,smax32=2,var_off=(0x0; 0xffffffff))");
    sdiv32_zero_divisor:
        __description("SDIV32, zero divisor"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("w1 s/= w2 {{.*}}; R1=0");
    sdiv32_overflow_1:
        __description("SDIV32, overflow (S32_MIN/-1)"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("w1 s/= -1 {{.*}}; R1=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))");
    sdiv32_overflow_2:
        __description("SDIV32, overflow (S32_MIN/-1), constant dividend"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("w1 s/= -1 {{.*}}; R1=0x80000000");
    sdiv64_pos_divisor_1:
        __description("SDIV64, positive divisor, positive dividend"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("r1 s/= 3 {{.*}}; R1=scalar(smin=umin=smin32=umin32=2,smax=umax=smax32=umax32=3,var_off=(0x2; 0x1))");
    sdiv64_pos_divisor_2:
        __description("SDIV64, positive divisor, negative dividend"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("r1 s/= 3 {{.*}}; R1=scalar(smin=smin32=-3,smax=smax32=-2,umin=0xfffffffffffffffd,umax=0xfffffffffffffffe,umin32=0xfffffffd,umax32=0xfffffffe,var_off=(0xfffffffffffffffc; 0x3))");
    sdiv64_pos_divisor_3:
        __description("SDIV64, positive divisor, mixed sign dividend"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("r1 s/= 3 {{.*}}; R1=scalar(smin=smin32=-2,smax=smax32=3)");
    sdiv64_neg_divisor_1:
        __description("SDIV64, negative divisor, positive dividend"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("r1 s/= -3 {{.*}}; R1=scalar(smin=smin32=-3,smax=smax32=-2,umin=0xfffffffffffffffd,umax=0xfffffffffffffffe,umin32=0xfffffffd,umax32=0xfffffffe,var_off=(0xfffffffffffffffc; 0x3))");
    sdiv64_neg_divisor_2:
        __description("SDIV64, negative divisor, positive dividend"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("r1 s/= -3 {{.*}}; R1=scalar(smin=umin=smin32=umin32=2,smax=umax=smax32=umax32=3,var_off=(0x2; 0x1))");
    sdiv64_neg_divisor_3:
        __description("SDIV64, negative divisor, mixed sign dividend"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("r1 s/= -3 {{.*}}; R1=scalar(smin=smin32=-3,smax=smax32=2)");
    sdiv64_zero_divisor:
        __description("SDIV64, zero divisor"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("r1 s/= r2 {{.*}}; R1=0");
    sdiv64_overflow_1:
        __description("SDIV64, overflow (S64_MIN/-1)"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("r1 s/= -1 {{.*}}; R1=scalar()");
    sdiv64_overflow_2:
        __description("SDIV64, overflow (S64_MIN/-1), constant dividend"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("r1 s/= -1 {{.*}}; R1=0x8000000000000000");
    umod32_pos_divisor:
        __description("UMOD32, positive divisor"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("w1 %= 3 {{.*}}; R1=scalar(smin=smin32=0,smax=umax=smax32=umax32=2,var_off=(0x0; 0x3))");
    umod32_pos_divisor_unchanged:
        __description("UMOD32, positive divisor, small dividend"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("w1 %= 10 {{.*}}; R1=scalar(smin=umin=smin32=umin32=1,smax=umax=smax32=umax32=9,var_off=(0x1; 0x8))");
    umod32_zero_divisor:
        __description("UMOD32, zero divisor"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("w1 %= w2 {{.*}}; R1=scalar(smin=umin=smin32=umin32=1,smax=umax=smax32=umax32=9,var_off=(0x1; 0x8))");
    umod64_pos_divisor:
        __description("UMOD64, positive divisor"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("r1 %= 3 {{.*}}; R1=scalar(smin=smin32=0,smax=umax=smax32=umax32=2,var_off=(0x0; 0x3))");
    umod64_pos_divisor_unchanged:
        __description("UMOD64, positive divisor, small dividend"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("r1 %= 10 {{.*}}; R1=scalar(smin=umin=smin32=umin32=1,smax=umax=smax32=umax32=9,var_off=(0x1; 0x8))");
    umod64_zero_divisor:
        __description("UMOD64, zero divisor"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("r1 %= r2 {{.*}}; R1=scalar(smin=umin=smin32=umin32=1,smax=umax=smax32=umax32=9,var_off=(0x1; 0x8))");
    smod32_pos_divisor_1:
        __description("SMOD32, positive divisor, positive dividend"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("w1 s%= 3 {{.*}}; R1=scalar(smin=smin32=0,smax=umax=smax32=umax32=2,var_off=(0x0; 0x3))");
    smod32_pos_divisor_2:
        __description("SMOD32, positive divisor, negative dividend"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("w1 s%= 3 {{.*}}; R1=scalar(smin=0,smax=umax=0xffffffff,smin32=-2,smax32=0,var_off=(0x0; 0xffffffff))");
    smod32_pos_divisor_3:
        __description("SMOD32, positive divisor, mixed sign dividend"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("w1 s%= 3 {{.*}}; R1=scalar(smin=0,smax=umax=0xffffffff,smin32=-2,smax32=2,var_off=(0x0; 0xffffffff))");
    smod32_pos_divisor_unchanged:
        __description("SMOD32, positive divisor, small dividend"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("w1 s%= 11 {{.*}}; R1=scalar(smin=0,smax=umax=0xffffffff,smin32=-8,smax32=10,var_off=(0x0; 0xffffffff))");
    smod32_neg_divisor_1:
        __description("SMOD32, negative divisor, positive dividend"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("w1 s%= -3 {{.*}}; R1=scalar(smin=smin32=0,smax=umax=smax32=umax32=2,var_off=(0x0; 0x3))");
    smod32_neg_divisor_2:
        __description("SMOD32, negative divisor, negative dividend"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("w1 s%= -3 {{.*}}; R1=scalar(smin=0,smax=umax=0xffffffff,smin32=-2,smax32=0,var_off=(0x0; 0xffffffff))");
    smod32_neg_divisor_3:
        __description("SMOD32, negative divisor, mixed sign dividend"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("w1 s%= -3 {{.*}}; R1=scalar(smin=0,smax=umax=0xffffffff,smin32=-2,smax32=2,var_off=(0x0; 0xffffffff))");
    smod32_neg_divisor_unchanged:
        __description("SMOD32, negative divisor, small dividend"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("w1 s%= -11 {{.*}}; R1=scalar(smin=0,smax=umax=0xffffffff,smin32=-8,smax32=10,var_off=(0x0; 0xffffffff))");
    smod32_zero_divisor:
        __description("SMOD32, zero divisor"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("w1 s%= w2 {{.*}}; R1=scalar(smin=0,smax=umax=0xffffffff,smin32=-8,smax32=10,var_off=(0x0; 0xffffffff))");
    smod32_overflow_1:
        __description("SMOD32, overflow (S32_MIN%-1)"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("w1 s%= -1 {{.*}}; R1=0");
    smod32_overflow_2:
        __description("SMOD32, overflow (S32_MIN%-1), constant dividend"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("w1 s%= -1 {{.*}}; R1=0");
    smod64_pos_divisor_1:
        __description("SMOD64, positive divisor, positive dividend"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("r1 s%= 3 {{.*}}; R1=scalar(smin=smin32=0,smax=umax=smax32=umax32=2,var_off=(0x0; 0x3))");
    smod64_pos_divisor_2:
        __description("SMOD64, positive divisor, negative dividend"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("r1 s%= 3 {{.*}}; R1=scalar(smin=smin32=-2,smax=smax32=0)");
    smod64_pos_divisor_3:
        __description("SMOD64, positive divisor, mixed sign dividend"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("r1 s%= 3 {{.*}}; R1=scalar(smin=smin32=-2,smax=smax32=2)");
    smod64_pos_divisor_unchanged:
        __description("SMOD64, positive divisor, small dividend"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("r1 s%= 11 {{.*}}; R1=scalar(smin=smin32=-8,smax=smax32=10)");
    smod64_neg_divisor_1:
        __description("SMOD64, negative divisor, positive dividend"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("r1 s%= -3 {{.*}}; R1=scalar(smin=smin32=0,smax=umax=smax32=umax32=2,var_off=(0x0; 0x3))");
    smod64_neg_divisor_2:
        __description("SMOD64, negative divisor, negative dividend"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("r1 s%= -3 {{.*}}; R1=scalar(smin=smin32=-2,smax=smax32=0)");
    smod64_neg_divisor_3:
        __description("SMOD64, negative divisor, mixed sign dividend"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("r1 s%= -3 {{.*}}; R1=scalar(smin=smin32=-2,smax=smax32=2)");
    smod64_neg_divisor_unchanged:
        __description("SMOD64, negative divisor, small dividend"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("r1 s%= -11 {{.*}}; R1=scalar(smin=smin32=-8,smax=smax32=10)");
    smod64_zero_divisor:
        __description("SMOD64, zero divisor"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("r1 s%= r2 {{.*}}; R1=scalar(smin=smin32=-8,smax=smax32=10)");
    smod64_overflow_1:
        __description("SMOD64, overflow (S64_MIN%-1)"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("r1 s%= -1 {{.*}}; R1=0");
    smod64_overflow_2:
        __description("SMOD64, overflow (S64_MIN%-1), constant dividend"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("r1 s%= -1 {{.*}}; R1=0");
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: udiv32_pos_divisor
extern "C" fn udiv32_pos_divisor() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w1 = w0;",
            "w1 &= 8;",
            "w1 |= 1;",
            "w1 /= 3;",
            "if w1 > 3 goto l0_0;",
            "r0 = 0;",
            "exit;",
            "l0_0:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: udiv32_zero_divisor
extern "C" fn udiv32_zero_divisor() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w1 = w0;",
            "w1 &= 8;",
            "w1 |= 1;",
            "w2 = 0;",
            "w1 /= w2;",
            "if w1 != 0 goto l0_1;",
            "r0 = 0;",
            "exit;",
            "l0_1:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: udiv64_pos_divisor
extern "C" fn udiv64_pos_divisor() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = r0;",
            "r1 &= 8;",
            "r1 |= 1;",
            "r1 /= 3;",
            "if r1 > 3 goto l0_2;",
            "r0 = 0;",
            "exit;",
            "l0_2:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: udiv64_zero_divisor
extern "C" fn udiv64_zero_divisor() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = r0;",
            "r1 &= 8;",
            "r1 |= 1;",
            "r2 = 0;",
            "r1 /= r2;",
            "if r1 != 0 goto l0_3;",
            "r0 = 0;",
            "exit;",
            "l0_3:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv32_pos_divisor_1
extern "C" fn sdiv32_pos_divisor_1() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w1 = w0;",
            "if w1 s< 8 goto l0_4;",
            "if w1 s> 10 goto l0_4;",
            "w1 s/= 3;",
            "if w1 s< 2 goto l1_4;",
            "if w1 s> 3 goto l1_4;",
            "l0_4:",
            "r0 = 0;",
            "exit;",
            "l1_4:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv32_pos_divisor_2
extern "C" fn sdiv32_pos_divisor_2() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w1 = w0;",
            "if w1 s> -8 goto l0_5;",
            "if w1 s< -10 goto l0_5;",
            "w1 s/= 3;",
            "if w1 s< -3 goto l1_5;",
            "if w1 s> -2 goto l1_5;",
            "l0_5:",
            "r0 = 0;",
            "exit;",
            "l1_5:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv32_pos_divisor_3
extern "C" fn sdiv32_pos_divisor_3() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w1 = w0;",
            "if w1 s< -8 goto l0_6;",
            "if w1 s> 10 goto l0_6;",
            "w1 s/= 3;",
            "if w1 s< -2 goto l1_6;",
            "if w1 s> 3 goto l1_6;",
            "l0_6:",
            "r0 = 0;",
            "exit;",
            "l1_6:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv32_neg_divisor_1
extern "C" fn sdiv32_neg_divisor_1() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w1 = w0;",
            "if w1 s< 8 goto l0_7;",
            "if w1 s> 10 goto l0_7;",
            "w1 s/= -3;",
            "if w1 s< -3 goto l1_7;",
            "if w1 s> -2 goto l1_7;",
            "l0_7:",
            "r0 = 0;",
            "exit;",
            "l1_7:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv32_neg_divisor_2
extern "C" fn sdiv32_neg_divisor_2() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w1 = w0;",
            "if w1 s> -8 goto l0_8;",
            "if w1 s< -10 goto l0_8;",
            "w1 s/= -3;",
            "if w1 s< 2 goto l1_8;",
            "if w1 s> 3 goto l1_8;",
            "l0_8:",
            "r0 = 0;",
            "exit;",
            "l1_8:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv32_neg_divisor_3
extern "C" fn sdiv32_neg_divisor_3() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w1 = w0;",
            "if w1 s< -8 goto l0_9;",
            "if w1 s> 10 goto l0_9;",
            "w1 s/= -3;",
            "if w1 s< -3 goto l1_9;",
            "if w1 s> 2 goto l1_9;",
            "l0_9:",
            "r0 = 0;",
            "exit;",
            "l1_9:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv32_zero_divisor
extern "C" fn sdiv32_zero_divisor() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w1 = w0;",
            "w1 &= 8;",
            "w1 |= 1;",
            "w2 = 0;",
            "w1 s/= w2;",
            "if w1 != 0 goto l0_10;",
            "r0 = 0;",
            "exit;",
            "l0_10:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv32_overflow_1
extern "C" fn sdiv32_overflow_1() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w1 = w0;",
            "w2 = -2147483648;",
            "w2 += 10;",
            "if w1 s> w2 goto l0_11;",
            "w1 s/= -1;",
            "r2 = r1;",
            "l0_11:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv32_overflow_2
extern "C" fn sdiv32_overflow_2() {
    unsafe {
        core::arch::asm!(
            "w1 = -2147483648;",
            "w1 s/= -1;",
            "if w1 != -2147483648 goto l0_12;",
            "r0 = 0;",
            "exit;",
            "l0_12:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv64_pos_divisor_1
extern "C" fn sdiv64_pos_divisor_1() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = r0;",
            "if r1 s< 8 goto l0_13;",
            "if r1 s> 10 goto l0_13;",
            "r1 s/= 3;",
            "if r1 s< 2 goto l1_13;",
            "if r1 s> 3 goto l1_13;",
            "l0_13:",
            "r0 = 0;",
            "exit;",
            "l1_13:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv64_pos_divisor_2
extern "C" fn sdiv64_pos_divisor_2() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = r0;",
            "if r1 s> -8 goto l0_14;",
            "if r1 s< -10 goto l0_14;",
            "r1 s/= 3;",
            "if r1 s< -3 goto l1_14;",
            "if r1 s> -2 goto l1_14;",
            "l0_14:",
            "r0 = 0;",
            "exit;",
            "l1_14:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv64_pos_divisor_3
extern "C" fn sdiv64_pos_divisor_3() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = r0;",
            "if r1 s< -8 goto l0_15;",
            "if r1 s> 10 goto l0_15;",
            "r1 s/= 3;",
            "if r1 s< -2 goto l1_15;",
            "if r1 s> 3 goto l1_15;",
            "l0_15:",
            "r0 = 0;",
            "exit;",
            "l1_15:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv64_neg_divisor_1
extern "C" fn sdiv64_neg_divisor_1() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = r0;",
            "if r1 s< 8 goto l0_16;",
            "if r1 s> 10 goto l0_16;",
            "r1 s/= -3;",
            "if r1 s< -3 goto l1_16;",
            "if r1 s> -2 goto l1_16;",
            "l0_16:",
            "r0 = 0;",
            "exit;",
            "l1_16:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv64_neg_divisor_2
extern "C" fn sdiv64_neg_divisor_2() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = r0;",
            "if r1 s> -8 goto l0_17;",
            "if r1 s< -10 goto l0_17;",
            "r1 s/= -3;",
            "if r1 s< 2 goto l1_17;",
            "if r1 s> 3 goto l1_17;",
            "l0_17:",
            "r0 = 0;",
            "exit;",
            "l1_17:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv64_neg_divisor_3
extern "C" fn sdiv64_neg_divisor_3() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = r0;",
            "if r1 s< -8 goto l0_18;",
            "if r1 s> 10 goto l0_18;",
            "r1 s/= -3;",
            "if r1 s< -3 goto l1_18;",
            "if r1 s> 2 goto l1_18;",
            "l0_18:",
            "r0 = 0;",
            "exit;",
            "l1_18:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv64_zero_divisor
extern "C" fn sdiv64_zero_divisor() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = r0;",
            "r1 &= 8;",
            "r1 |= 1;",
            "r2 = 0;",
            "r1 s/= r2;",
            "if r1 != 0 goto l0_19;",
            "r0 = 0;",
            "exit;",
            "l0_19:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv64_overflow_1
extern "C" fn sdiv64_overflow_1() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "r1 = r0;",
            "r2 = -9223372036854775808 ll;",
            "r2 += 10;",
            "if r1 s> r2 goto l0_20;",
            "r1 s/= -1;",
            "r2 = r1;",
            "l0_20:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv64_overflow_2
extern "C" fn sdiv64_overflow_2() {
    unsafe {
        core::arch::asm!(
            "r1 = -9223372036854775808 ll;",
            "r1 s/= -1;",
            "r2 = -9223372036854775808 ll;",
            "if r1 != r2 goto l0_21;",
            "r0 = 0;",
            "exit;",
            "l0_21:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: umod32_pos_divisor
extern "C" fn umod32_pos_divisor() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w1 = w0;",
            "w1 &= 8;",
            "w1 |= 1;",
            "w1 %= 3;",
            "if w1 > 3 goto l0_22;",
            "r0 = 0;",
            "exit;",
            "l0_22:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: umod32_pos_divisor_unchanged
extern "C" fn umod32_pos_divisor_unchanged() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w1 = w0;",
            "w1 &= 8;",
            "w1 |= 1;",
            "w1 %= 10;",
            "if w1 < 1 goto l0_23;",
            "if w1 > 9 goto l0_23;",
            "if w1 & 1 != 1 goto l0_23;",
            "r0 = 0;",
            "exit;",
            "l0_23:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: umod32_zero_divisor
extern "C" fn umod32_zero_divisor() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w1 = w0;",
            "w1 &= 8;",
            "w1 |= 1;",
            "w2 = 0;",
            "w1 %= w2;",
            "if w1 < 1 goto l0_24;",
            "if w1 > 9 goto l0_24;",
            "if w1 & 1 != 1 goto l0_24;",
            "r0 = 0;",
            "exit;",
            "l0_24:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: umod64_pos_divisor
extern "C" fn umod64_pos_divisor() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = r0;",
            "r1 &= 8;",
            "r1 |= 1;",
            "r1 %= 3;",
            "if r1 > 3 goto l0_25;",
            "r0 = 0;",
            "exit;",
            "l0_25:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: umod64_pos_divisor_unchanged
extern "C" fn umod64_pos_divisor_unchanged() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = r0;",
            "r1 &= 8;",
            "r1 |= 1;",
            "r1 %= 10;",
            "if r1 < 1 goto l0_26;",
            "if r1 > 9 goto l0_26;",
            "if r1 & 1 != 1 goto l0_26;",
            "r0 = 0;",
            "exit;",
            "l0_26:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: umod64_zero_divisor
extern "C" fn umod64_zero_divisor() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = r0;",
            "r1 &= 8;",
            "r1 |= 1;",
            "r2 = 0;",
            "r1 %= r2;",
            "if r1 < 1 goto l0_27;",
            "if r1 > 9 goto l0_27;",
            "if r1 & 1 != 1 goto l0_27;",
            "r0 = 0;",
            "exit;",
            "l0_27:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod32_pos_divisor_1
extern "C" fn smod32_pos_divisor_1() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w1 = w0;",
            "if w1 s< 8 goto l0_28;",
            "if w1 s> 10 goto l0_28;",
            "w1 s%= 3;",
            "if w1 s< 0 goto l1_28;",
            "if w1 s> 2 goto l1_28;",
            "l0_28:",
            "r0 = 0;",
            "exit;",
            "l1_28:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod32_pos_divisor_2
extern "C" fn smod32_pos_divisor_2() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w1 = w0;",
            "if w1 s> -8 goto l0_29;",
            "if w1 s< -10 goto l0_29;",
            "w1 s%= 3;",
            "if w1 s< -2 goto l1_29;",
            "if w1 s> 0 goto l1_29;",
            "l0_29:",
            "r0 = 0;",
            "exit;",
            "l1_29:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod32_pos_divisor_3
extern "C" fn smod32_pos_divisor_3() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w1 = w0;",
            "if w1 s< -8 goto l0_30;",
            "if w1 s> 10 goto l0_30;",
            "w1 s%= 3;",
            "if w1 s< -2 goto l1_30;",
            "if w1 s> 2 goto l1_30;",
            "l0_30:",
            "r0 = 0;",
            "exit;",
            "l1_30:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod32_pos_divisor_unchanged
extern "C" fn smod32_pos_divisor_unchanged() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w1 = w0;",
            "if w1 s< -8 goto l0_31;",
            "if w1 s> 10 goto l0_31;",
            "w1 s%= 11;",
            "if w1 s< -8 goto l1_31;",
            "if w1 s> 10 goto l1_31;",
            "l0_31:",
            "r0 = 0;",
            "exit;",
            "l1_31:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod32_neg_divisor_1
extern "C" fn smod32_neg_divisor_1() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w1 = w0;",
            "if w1 s< 8 goto l0_32;",
            "if w1 s> 10 goto l0_32;",
            "w1 s%= -3;",
            "if w1 s< 0 goto l1_32;",
            "if w1 s> 2 goto l1_32;",
            "l0_32:",
            "r0 = 0;",
            "exit;",
            "l1_32:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod32_neg_divisor_2
extern "C" fn smod32_neg_divisor_2() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w1 = w0;",
            "if w1 s> -8 goto l0_33;",
            "if w1 s< -10 goto l0_33;",
            "w1 s%= -3;",
            "if w1 s< -2 goto l1_33;",
            "if w1 s> 0 goto l1_33;",
            "l0_33:",
            "r0 = 0;",
            "exit;",
            "l1_33:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod32_neg_divisor_3
extern "C" fn smod32_neg_divisor_3() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w1 = w0;",
            "if w1 s< -8 goto l0_34;",
            "if w1 s> 10 goto l0_34;",
            "w1 s%= -3;",
            "if w1 s< -2 goto l1_34;",
            "if w1 s> 2 goto l1_34;",
            "l0_34:",
            "r0 = 0;",
            "exit;",
            "l1_34:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod32_neg_divisor_unchanged
extern "C" fn smod32_neg_divisor_unchanged() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w1 = w0;",
            "if w1 s< -8 goto l0_35;",
            "if w1 s> 10 goto l0_35;",
            "w1 s%= -11;",
            "if w1 s< -8 goto l1_35;",
            "if w1 s> 10 goto l1_35;",
            "l0_35:",
            "r0 = 0;",
            "exit;",
            "l1_35:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod32_zero_divisor
extern "C" fn smod32_zero_divisor() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w1 = w0;",
            "if w1 s< -8 goto l0_36;",
            "if w1 s> 10 goto l0_36;",
            "w2 = 0;",
            "w1 s%= w2;",
            "if w1 s< -8 goto l1_36;",
            "if w1 s> 10 goto l1_36;",
            "l0_36:",
            "r0 = 0;",
            "exit;",
            "l1_36:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod32_overflow_1
extern "C" fn smod32_overflow_1() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w1 = w0;",
            "w2 = -2147483648;",
            "w2 += 10;",
            "if w1 s> w2 goto l0_37;",
            "w1 s%= -1;",
            "if w1 != 0 goto l1_37;",
            "l0_37:",
            "r0 = 0;",
            "exit;",
            "l1_37:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod32_overflow_2
extern "C" fn smod32_overflow_2() {
    unsafe {
        core::arch::asm!(
            "w1 = -2147483648;",
            "w1 s%= -1;",
            "if w1 != 0 goto l0_38;",
            "r0 = 0;",
            "exit;",
            "l0_38:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod64_pos_divisor_1
extern "C" fn smod64_pos_divisor_1() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = r0;",
            "if r1 s< 8 goto l0_39;",
            "if r1 s> 10 goto l0_39;",
            "r1 s%= 3;",
            "if r1 s< 0 goto l1_39;",
            "if r1 s> 2 goto l1_39;",
            "l0_39:",
            "r0 = 0;",
            "exit;",
            "l1_39:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod64_pos_divisor_2
extern "C" fn smod64_pos_divisor_2() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = r0;",
            "if r1 s> -8 goto l0_40;",
            "if r1 s< -10 goto l0_40;",
            "r1 s%= 3;",
            "if r1 s< -2 goto l1_40;",
            "if r1 s> 0 goto l1_40;",
            "l0_40:",
            "r0 = 0;",
            "exit;",
            "l1_40:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod64_pos_divisor_3
extern "C" fn smod64_pos_divisor_3() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = r0;",
            "if r1 s< -8 goto l0_41;",
            "if r1 s> 10 goto l0_41;",
            "r1 s%= 3;",
            "if r1 s< -2 goto l1_41;",
            "if r1 s> 2 goto l1_41;",
            "l0_41:",
            "r0 = 0;",
            "exit;",
            "l1_41:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod64_pos_divisor_unchanged
extern "C" fn smod64_pos_divisor_unchanged() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = r0;",
            "if r1 s< -8 goto l0_42;",
            "if r1 s> 10 goto l0_42;",
            "r1 s%= 11;",
            "if r1 s< -8 goto l1_42;",
            "if r1 s> 10 goto l1_42;",
            "l0_42:",
            "r0 = 0;",
            "exit;",
            "l1_42:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod64_neg_divisor_1
extern "C" fn smod64_neg_divisor_1() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = r0;",
            "if r1 s< 8 goto l0_43;",
            "if r1 s> 10 goto l0_43;",
            "r1 s%= -3;",
            "if r1 s< 0 goto l1_43;",
            "if r1 s> 2 goto l1_43;",
            "l0_43:",
            "r0 = 0;",
            "exit;",
            "l1_43:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod64_neg_divisor_2
extern "C" fn smod64_neg_divisor_2() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = r0;",
            "if r1 s> -8 goto l0_44;",
            "if r1 s< -10 goto l0_44;",
            "r1 s%= -3;",
            "if r1 s< -2 goto l1_44;",
            "if r1 s> 0 goto l1_44;",
            "l0_44:",
            "r0 = 0;",
            "exit;",
            "l1_44:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod64_neg_divisor_3
extern "C" fn smod64_neg_divisor_3() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = r0;",
            "if r1 s< -8 goto l0_45;",
            "if r1 s> 10 goto l0_45;",
            "r1 s%= -3;",
            "if r1 s< -2 goto l1_45;",
            "if r1 s> 2 goto l1_45;",
            "l0_45:",
            "r0 = 0;",
            "exit;",
            "l1_45:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod64_neg_divisor_unchanged
extern "C" fn smod64_neg_divisor_unchanged() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = r0;",
            "if r1 s< -8 goto l0_46;",
            "if r1 s> 10 goto l0_46;",
            "r1 s%= -11;",
            "if r1 s< -8 goto l1_46;",
            "if r1 s> 10 goto l1_46;",
            "l0_46:",
            "r0 = 0;",
            "exit;",
            "l1_46:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod64_zero_divisor
extern "C" fn smod64_zero_divisor() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = r0;",
            "if r1 s< -8 goto l0_47;",
            "if r1 s> 10 goto l0_47;",
            "r2 = 0;",
            "r1 s%= r2;",
            "if r1 s< -8 goto l1_47;",
            "if r1 s> 10 goto l1_47;",
            "l0_47:",
            "r0 = 0;",
            "exit;",
            "l1_47:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod64_overflow_1
extern "C" fn smod64_overflow_1() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "r1 = r0;",
            "r2 = -9223372036854775808 ll;",
            "r2 += 10;",
            "if r1 s> r2 goto l0_48;",
            "r1 s%= -1;",
            "if r1 != 0 goto l1_48;",
            "l0_48:",
            "r0 = 0;",
            "exit;",
            "l1_48:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod64_overflow_2
extern "C" fn smod64_overflow_2() {
    unsafe {
        core::arch::asm!(
            "r1 = -9223372036854775808 ll;",
            "r1 s%= -1;",
            "if r1 != 0 goto l0_49;",
            "r0 = 0;",
            "exit;",
            "l0_49:",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

// The C source declares no license.
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
