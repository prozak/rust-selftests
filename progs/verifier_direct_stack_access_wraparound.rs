// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_direct_stack_access_wraparound.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_direct_stack_access_wraparound` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: with_32_bit_wraparound_test1 with_32_bit_wraparound_test2 with_32_bit_wraparound_test3

use bpf_rs_core::{bpf_object, test_tags};

test_tags! {
    with_32_bit_wraparound_test1:
        __description("direct stack access with 32-bit wraparound. test1"),
        __failure,
        __msg("fp pointer and 2147483647"),
        __failure_unpriv;
    with_32_bit_wraparound_test2:
        __description("direct stack access with 32-bit wraparound. test2"),
        __failure,
        __msg("fp pointer and 1073741823"),
        __failure_unpriv;
    with_32_bit_wraparound_test3:
        __description("direct stack access with 32-bit wraparound. test3"),
        __failure,
        __msg("fp pointer offset 1073741822"),
        __msg_unpriv("R1 stack pointer arithmetic goes out of range");
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: with_32_bit_wraparound_test1
extern "C" fn with_32_bit_wraparound_test1() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += 0x7fffffff;",
            "r1 += 0x7fffffff;",
            "w0 = 0;",
            "*(u8*)(r1 + 0) = r0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: with_32_bit_wraparound_test2
extern "C" fn with_32_bit_wraparound_test2() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += 0x3fffffff;",
            "r1 += 0x3fffffff;",
            "w0 = 0;",
            "*(u8*)(r1 + 0) = r0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: with_32_bit_wraparound_test3
extern "C" fn with_32_bit_wraparound_test3() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += 0x1fffffff;",
            "r1 += 0x1fffffff;",
            "w0 = 0;",
            "*(u8*)(r1 + 0) = r0;",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
