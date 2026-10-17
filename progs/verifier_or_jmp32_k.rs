// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_or_jmp32_k.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_or_jmp32_k` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

use bpf_rs_core::{bpf_object, test_tags};

test_tags! {
    or_jmp32_k:
        __description("or_jmp32_k: bit ops + branch on unknown value"),
        __failure,
        __msg("R0 invalid mem access 'scalar'");
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: or_jmp32_k
extern "C" fn or_jmp32_k() {
    unsafe {
        core::arch::asm!(
            "r0 = 0xffffffff;",
            "r0 /= 1;",
            "r1 = 0;",
            "w1 = -1;",
            "w1 >>= 1;",
            "w0 &= w1;",
            "w0 |= 2;",
            "if w0 != 0x7ffffffd goto l1;",
            "r0 = 1;",
            "exit;",
            "l3:",
            "r0 = 5;",
            "*(u64*)(r0 - 8) = r0;",
            "exit;",
            "l2:",
            "w0 -= 0xe;",
            "if w0 == 1 goto l3;",
            "r0 = 4;",
            "exit;",
            "l1:",
            "w0 -= 0x7ffffff0;",
            "if w0 s>= 0xe goto l2;",
            "r0 = 3;",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
