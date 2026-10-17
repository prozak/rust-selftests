// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_unpriv_perf.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_unpriv_perf` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

use bpf_rs_core::{bpf_object, test_tags};

test_tags! {
    fill_of_different_pointers_ldx:
        __description("unpriv: spill/fill of different pointers ldx"),
        __failure,
        __msg("same insn cannot be used with different pointers");
}

#[link_section = "perf_event"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: fill_of_different_pointers_ldx
extern "C" fn fill_of_different_pointers_ldx() {
    unsafe {
        core::arch::asm!(
            "r6 = r10;",
            "r6 += -8;",
            "if r1 == 0 goto l0_0;",
            "r2 = r10;",
            "r2 += -176;",
            "*(u64*)(r6 + 0) = r2;",
            "l0_0:",
            "if r1 != 0 goto l1_0;",
            "*(u64*)(r6 + 0) = r1;",
            "l1_0:",
            "r1 = *(u64*)(r6 + 0);",
            "r1 = *(u64*)(r1 + 168);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
