// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_reg_equal.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_reg_equal` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: subreg_equality_1 subreg_equality_2

use bpf_rs_core::{bpf_object, test_tags};

test_tags! {
    subreg_equality_1:
        __description("check w reg equal if r reg upper32 bits 0"),
        __success;
    subreg_equality_2:
        __description("check w reg not equal if r reg upper32 bits not 0"),
        __failure,
        __msg("R1 !read_ok");
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: subreg_equality_1
extern "C" fn subreg_equality_1() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "*(u64 *)(r10 - 8) = r0;",
            "r2 = *(u32 *)(r10 - 8);",
            "w3 = w2;",
            "if w2 < 9 goto l0_0;",
            "exit;",
            "l0_0:",
            "if r3 < 9 goto l1_0;",
            "r0 -= r1;",
            "l1_0:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: subreg_equality_2
extern "C" fn subreg_equality_2() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "r2 = r0;",
            "w3 = w2;",
            "if w2 < 9 goto l0_1;",
            "exit;",
            "l0_1:",
            "if r3 < 9 goto l1_1;",
            "r0 -= r1;",
            "l1_1:",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
