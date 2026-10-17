// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_basic_stack.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_basic_stack` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: stack_out_of_bounds uninitialized_stack1 uninitialized_stack2 invalid_fp_arithmetic non_invalid_fp_arithmetic misaligned_read_from_stack stack_ptr_arith_preserves_frameno

use bpf_rs_core::{bpf_map, bpf_object, test_tags};

test_tags! {
    stack_out_of_bounds:
        __description("stack out of bounds"),
        __failure,
        __msg("invalid write to stack"),
        __failure_unpriv;
    uninitialized_stack1:
        __description("uninitialized stack1"),
        __success,
        __log_level("4"),
        __msg("subprog 0 (uninitialized_stack1) main {{.*}} stack 8"),
        __failure_unpriv,
        __msg_unpriv("invalid read from stack");
    uninitialized_stack2:
        __description("uninitialized stack2"),
        __success,
        __log_level("4"),
        __msg("subprog 0 (uninitialized_stack2) main insns_self {{[0-9]+}} insns_total {{[0-9]+}} stack 8"),
        __failure_unpriv,
        __msg_unpriv("invalid read from stack");
    invalid_fp_arithmetic:
        __description("invalid fp arithmetic"),
        __failure,
        __msg("R1 subtraction from stack pointer"),
        __failure_unpriv;
    non_invalid_fp_arithmetic:
        __description("non-invalid fp arithmetic"),
        __success,
        __success_unpriv,
        __retval("0");
    misaligned_read_from_stack:
        __description("misaligned read from stack"),
        __failure,
        __msg("misaligned stack access"),
        __failure_unpriv;
    stack_ptr_arith_preserves_frameno:
        __description("stack pointer arithmetic preserves frame number"),
        __failure,
        __msg("R7 invalid mem access 'scalar'");
}

bpf_map! {
    map_hash_8b {
        r#type: *const [i32; 1],
        max_entries: *const [i32; 1],
        key: *const i64,
        value: *const i64,
    }
}

#[link_section = "socket"]
#[no_mangle]
// BPF_NAKED: stack_out_of_bounds
extern "C" fn stack_out_of_bounds() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 + 8) = r1;",
            "exit;",
            options(noreturn)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
// BPF_NAKED: uninitialized_stack1
extern "C" fn uninitialized_stack1() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(noreturn)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
// BPF_NAKED: uninitialized_stack2
extern "C" fn uninitialized_stack2() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r0 = *(u64*)(r2 - 8);",
            "exit;",
            options(noreturn)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
// BPF_NAKED: invalid_fp_arithmetic
extern "C" fn invalid_fp_arithmetic() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "r1 = r10;",
            "r1 -= 8;",
            "*(u64*)(r1 + 0) = r0;",
            "exit;",
            options(noreturn)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
// BPF_NAKED: non_invalid_fp_arithmetic
extern "C" fn non_invalid_fp_arithmetic() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "*(u64*)(r10 - 8) = r0;",
            "exit;",
            options(noreturn)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
// BPF_NAKED: misaligned_read_from_stack
extern "C" fn misaligned_read_from_stack() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r0 = *(u64*)(r2 - 4);",
            "exit;",
            options(noreturn)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
// BPF_NAKED: stack_ptr_arith_preserves_frameno
extern "C" fn stack_ptr_arith_preserves_frameno() {
    unsafe {
        core::arch::asm!(
            "r3 = 0;",
            "*(u64 *)(r10 - 8) = r3;",
            "r1 = {map_hash_8b} ll;",
            "r2 = r10;",
            "r2 += -8;",
            "call 1;",
            "if r0 != 0 goto +2;",
            "r0 = 0;",
            "exit;",
            "r1 = r0;",
            "r2 = 0;",
            "r3 = 0;",
            "call {stack_ptr_arith_preserves_frameno_subprog};",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            stack_ptr_arith_preserves_frameno_subprog = sym stack_ptr_arith_preserves_frameno_subprog,
            options(noreturn)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_ptr_arith_preserves_frameno_subprog
extern "C" fn stack_ptr_arith_preserves_frameno_subprog() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 8) = r1;",
            "r6 = -8;",
            "r6 += r10;",
            "*(u64 *)(r6 + 0) = r2;",
            "r7 = *(u64 *)(r10 - 8);",
            "*(u64 *)(r7 + 0) = r3;",
            "r0 = 0;",
            "exit;",
            options(noreturn)
        );
    }
}

bpf_object!("GPL");
