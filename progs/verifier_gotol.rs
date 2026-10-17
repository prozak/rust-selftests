// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_gotol.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_gotol` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: gotol_small_imm gotol_large_imm

use bpf_rs_core::{bpf_object, test_tags};

test_tags! {
    gotol_small_imm:
        __description("gotol, small_imm"),
        __success,
        __success_unpriv,
        __retval("1");
    gotol_large_imm:
        __description("gotol, large_imm"),
        __success,
        __failure_unpriv,
        __retval("40000");
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: gotol_small_imm
extern "C" fn gotol_small_imm() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "if r0 == 0 goto l0_0;",
            "gotol l1_0;",
            "l2_0:",
            "gotol l3_0;",
            "l1_0:",
            "r0 = 1;",
            "gotol l2_0;",
            "l0_0:",
            "r0 = 2;",
            "l3_0:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: gotol_large_imm
extern "C" fn gotol_large_imm() {
    unsafe {
        core::arch::asm!(
            "gotol 1f;",
            "0:",
            "r0 = 0;",
            ".rept 40000;",
            "r0 += 1;",
            ".endr;",
            "exit;",
            "1:",
            "gotol 0b;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
