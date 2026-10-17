// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_bounds_deduction.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_bounds_deduction` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: deducing_bounds_from_const_1 deducing_bounds_from_const_2 deducing_bounds_from_const_3 deducing_bounds_from_const_4 deducing_bounds_from_const_5 deducing_bounds_from_const_6 deducing_bounds_from_const_7 deducing_bounds_from_const_8 deducing_bounds_from_const_9 deducing_bounds_from_const_10

use bpf_rs_core::{bpf_object, test_tags};

test_tags! {
    deducing_bounds_from_const_1:
        __description("check deducing bounds from const, 1"),
        __failure,
        __msg("R0 tried to subtract pointer from scalar"),
        __msg_unpriv("R1 has pointer with unsupported alu operation");
    deducing_bounds_from_const_2:
        __description("check deducing bounds from const, 2"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R1 has pointer with unsupported alu operation"),
        __retval("1");
    deducing_bounds_from_const_3:
        __description("check deducing bounds from const, 3"),
        __failure,
        __msg("R0 tried to subtract pointer from scalar"),
        __msg_unpriv("R1 has pointer with unsupported alu operation");
    deducing_bounds_from_const_4:
        __description("check deducing bounds from const, 4"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R6 has pointer with unsupported alu operation"),
        __retval("0");
    deducing_bounds_from_const_5:
        __description("check deducing bounds from const, 5"),
        __failure,
        __msg("R0 tried to subtract pointer from scalar"),
        __msg_unpriv("R1 has pointer with unsupported alu operation");
    deducing_bounds_from_const_6:
        __description("check deducing bounds from const, 6"),
        __failure,
        __msg("R0 tried to subtract pointer from scalar"),
        __msg_unpriv("R1 has pointer with unsupported alu operation");
    deducing_bounds_from_const_7:
        __description("check deducing bounds from const, 7"),
        __failure,
        __msg("dereference of modified ctx ptr"),
        __msg_unpriv("R1 has pointer with unsupported alu operation"),
        __flag("BPF_F_ANY_ALIGNMENT");
    deducing_bounds_from_const_8:
        __description("check deducing bounds from const, 8"),
        __failure,
        __msg("negative offset ctx ptr R1 off=-1 disallowed"),
        __msg_unpriv("R1 has pointer with unsupported alu operation"),
        __flag("BPF_F_ANY_ALIGNMENT");
    deducing_bounds_from_const_9:
        __description("check deducing bounds from const, 9"),
        __failure,
        __msg("R0 tried to subtract pointer from scalar"),
        __msg_unpriv("R1 has pointer with unsupported alu operation");
    deducing_bounds_from_const_10:
        __description("check deducing bounds from const, 10"),
        __failure,
        __msg("math between ctx pointer and register with unbounded min value is not allowed"),
        __failure_unpriv;
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deducing_bounds_from_const_1
extern "C" fn deducing_bounds_from_const_1() {
    unsafe {
        core::arch::asm!(
            "r0 = 1;",
            "if r0 s>= 1 goto l0_0;",
            "l0_0:",
            "r0 -= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deducing_bounds_from_const_2
extern "C" fn deducing_bounds_from_const_2() {
    unsafe {
        core::arch::asm!(
            "r0 = 1;",
            "if r0 s>= 1 goto l0_1;",
            "exit;",
            "l0_1:",
            "if r0 s<= 1 goto l1_1;",
            "exit;",
            "l1_1:",
            "r1 -= r0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deducing_bounds_from_const_3
extern "C" fn deducing_bounds_from_const_3() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "if r0 s<= 0 goto l0_2;",
            "l0_2:",
            "r0 -= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deducing_bounds_from_const_4
extern "C" fn deducing_bounds_from_const_4() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r0 = 0;",
            "if r0 s<= 0 goto l0_3;",
            "exit;",
            "l0_3:",
            "if r0 s>= 0 goto l1_3;",
            "exit;",
            "l1_3:",
            "r6 -= r0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deducing_bounds_from_const_5
extern "C" fn deducing_bounds_from_const_5() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "if r0 s>= 1 goto l0_4;",
            "r0 -= r1;",
            "l0_4:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deducing_bounds_from_const_6
extern "C" fn deducing_bounds_from_const_6() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "if r0 s>= 0 goto l0_5;",
            "exit;",
            "l0_5:",
            "r0 -= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deducing_bounds_from_const_7
extern "C" fn deducing_bounds_from_const_7() {
    unsafe {
        core::arch::asm!(
            "r0 = -1;",
            "if r0 s>= 0 goto l0_6;",
            "l0_6:",
            "r1 -= r0;",
            "r0 = *(u32*)(r1 + 8);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deducing_bounds_from_const_8
extern "C" fn deducing_bounds_from_const_8() {
    unsafe {
        core::arch::asm!(
            "r0 = -1;",
            "if r0 s>= 0 goto l0_7;",
            "r1 += r0;",
            "l0_7:",
            "r0 = *(u32*)(r1 + 8);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deducing_bounds_from_const_9
extern "C" fn deducing_bounds_from_const_9() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "if r0 s>= 0 goto l0_8;",
            "l0_8:",
            "r0 -= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deducing_bounds_from_const_10
extern "C" fn deducing_bounds_from_const_10() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r0 = 0;",
            "if r0 s<= 0 goto l0_9;",
            "l0_9:",
            "call 7;",
            "r0 -= r6;",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
