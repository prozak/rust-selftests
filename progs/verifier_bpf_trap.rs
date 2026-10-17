// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_bpf_trap.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_bpf_trap.rs
// (include!d below): bpf_trap_with_simple_c.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_bpf_trap` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: bpf_trap_with_simple_c bpf_trap_at_func_end dead_bpf_trap_in_middle live_bpf_trap_in_middle

use bpf_rs_core::{bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    bpf_trap_with_simple_c:
        __description("__bpf_trap with simple c code"),
        __failure,
        __msg("unexpected __bpf_trap() due to uninitialized variable?");
    bpf_trap_at_func_end:
        __description("__bpf_trap as the second-from-last insn"),
        __failure,
        __msg("unexpected __bpf_trap() due to uninitialized variable?");
    dead_bpf_trap_in_middle:
        __description("dead code __bpf_trap in the middle of code"),
        __success;
    live_bpf_trap_in_middle:
        __description("reachable __bpf_trap in the middle of code"),
        __failure,
        __msg("unexpected __bpf_trap() due to uninitialized variable?");
}

extern "C" {
    fn __bpf_trap();
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bpf_trap_at_func_end
extern "C" fn bpf_trap_at_func_end() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "call {__bpf_trap};",
            "exit;",
            __bpf_trap = sym __bpf_trap,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: dead_bpf_trap_in_middle
extern "C" fn dead_bpf_trap_in_middle() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "if r0 == 0 goto +1;",
            "call {__bpf_trap};",
            "r0 = 2;",
            "exit;",
            __bpf_trap = sym __bpf_trap,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: live_bpf_trap_in_middle
extern "C" fn live_bpf_trap_in_middle() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "if r0 == 1 goto +1;",
            "call {__bpf_trap};",
            "r0 = 2;",
            "exit;",
            __bpf_trap = sym __bpf_trap,
            options(nostack)
        );
    }
}

include!("hand/verifier_bpf_trap.rs");

bpf_object!("GPL");
