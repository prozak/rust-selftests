// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_uninit.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_uninit` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: read_uninitialized_register read_invalid_register t_init_r0_before_exit before_exit_in_all_branches

use bpf_rs_core::{bpf_object, test_tags};

test_tags! {
    read_uninitialized_register:
        __description("read uninitialized register"),
        __failure,
        __msg("R2 !read_ok"),
        __msg("R2 has never been initialized on this path"),
        __failure_unpriv;
    read_invalid_register:
        __description("read invalid register"),
        __failure,
        __msg("R15 is invalid"),
        __failure_unpriv;
    t_init_r0_before_exit:
        __description("program doesn't init R0 before exit"),
        __failure,
        __msg("R0 !read_ok"),
        __failure_unpriv;
    before_exit_in_all_branches:
        __description("program doesn't init R0 before exit in all branches"),
        __failure,
        __msg("R0 !read_ok"),
        __msg_unpriv("R1 pointer comparison");
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: read_uninitialized_register
extern "C" fn read_uninitialized_register() {
    unsafe {
        core::arch::asm!(
            "r0 = r2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: read_invalid_register
extern "C" fn read_invalid_register() {
    unsafe {
        core::arch::asm!(
            ".8byte 61631;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: t_init_r0_before_exit
extern "C" fn t_init_r0_before_exit() {
    unsafe {
        core::arch::asm!(
            "r2 = r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: before_exit_in_all_branches
extern "C" fn before_exit_in_all_branches() {
    unsafe {
        core::arch::asm!(
            "if r1 >= 0 goto l0_0;",
            "r0 = 1;",
            "r0 += 2;",
            "l0_0:",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
