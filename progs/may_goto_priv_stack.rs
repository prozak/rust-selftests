// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/may_goto_priv_stack.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py may_goto_priv_stack` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: priv_stack_64 priv_stack_128

use bpf_rs_core::{bpf_object};

#[no_mangle]
#[allow(non_upper_case_globals)]
static mut regs_64: [u64; 7] = [0; 7];

#[no_mangle]
#[allow(non_upper_case_globals)]
static mut regs_128: [u64; 7] = [0; 7];

#[link_section = "fentry/bpf_fentry_test1"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: priv_stack_64
extern "C" fn priv_stack_64() {
    unsafe {
        core::arch::asm!(
            "r6 = 0;",
            "*(u64 *)(r10 - 64) = r6;",
            "r7 = {regs} ll;",
            "r0 = 0;",
            "r1 = 0;",
            "r2 = 0;",
            "r3 = 0;",
            "r4 = 0;",
            "r5 = 0;",
            "1:",
            ".8byte 131301;",
            "r6 += 1;",
            "goto 1b;",
            "*(u64 *)(r7 + 0) = r0;",
            "*(u64 *)(r7 + 8) = r1;",
            "*(u64 *)(r7 + 16) = r2;",
            "*(u64 *)(r7 + 24) = r3;",
            "*(u64 *)(r7 + 32) = r4;",
            "*(u64 *)(r7 + 40) = r5;",
            "*(u64 *)(r7 + 48) = r6;",
            "r0 = 0;",
            "exit;",
            regs = sym regs_64,
            options(nostack)
        );
    }
}

#[link_section = "fentry/bpf_fentry_test2"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: priv_stack_128
extern "C" fn priv_stack_128() {
    unsafe {
        core::arch::asm!(
            "r6 = 0;",
            "*(u64 *)(r10 - 128) = r6;",
            "r7 = {regs} ll;",
            "r0 = 0;",
            "r1 = 0;",
            "r2 = 0;",
            "r3 = 0;",
            "r4 = 0;",
            "r5 = 0;",
            "1:",
            ".8byte 131301;",
            "r6 += 1;",
            "goto 1b;",
            "*(u64 *)(r7 + 0) = r0;",
            "*(u64 *)(r7 + 8) = r1;",
            "*(u64 *)(r7 + 16) = r2;",
            "*(u64 *)(r7 + 24) = r3;",
            "*(u64 *)(r7 + 32) = r4;",
            "*(u64 *)(r7 + 40) = r5;",
            "*(u64 *)(r7 + 48) = r6;",
            "r0 = 0;",
            "exit;",
            regs = sym regs_128,
            options(nostack)
        );
    }
}

bpf_object!("GPL");
