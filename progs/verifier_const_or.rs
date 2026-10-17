// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_const_or.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_const_or` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: constant_should_keep_constant_type not_bypass_stack_boundary_checks_1 register_should_keep_constant_type not_bypass_stack_boundary_checks_2

use bpf_rs_core::{bpf_object, test_tags};

test_tags! {
    constant_should_keep_constant_type:
        __description("constant register |= constant should keep constant type"),
        __success;
    not_bypass_stack_boundary_checks_1:
        __description("constant register |= constant should not bypass stack boundary checks"),
        __failure,
        __msg("invalid write to stack R1 off=-48 size=58");
    register_should_keep_constant_type:
        __description("constant register |= constant register should keep constant type"),
        __success;
    not_bypass_stack_boundary_checks_2:
        __description("constant register |= constant register should not bypass stack boundary checks"),
        __failure,
        __msg("invalid write to stack R1 off=-48 size=58");
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: constant_should_keep_constant_type
extern "C" fn constant_should_keep_constant_type() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -48;",
            "r2 = 34;",
            "r2 |= 13;",
            "r3 = 0;",
            "call 113;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: not_bypass_stack_boundary_checks_1
extern "C" fn not_bypass_stack_boundary_checks_1() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -48;",
            "r2 = 34;",
            "r2 |= 24;",
            "r3 = 0;",
            "call 113;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: register_should_keep_constant_type
extern "C" fn register_should_keep_constant_type() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -48;",
            "r2 = 34;",
            "r4 = 13;",
            "r2 |= r4;",
            "r3 = 0;",
            "call 113;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: not_bypass_stack_boundary_checks_2
extern "C" fn not_bypass_stack_boundary_checks_2() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -48;",
            "r2 = 34;",
            "r4 = 24;",
            "r2 |= r4;",
            "r3 = 0;",
            "call 113;",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
