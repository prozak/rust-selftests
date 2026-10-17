// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_map_ret_val.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_map_ret_val` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: map_fd_for_function_call check_return_value_before_access access_memory_with_incorrect_alignment_1 access_memory_with_incorrect_alignment_2

use bpf_rs_core::{bpf_map, bpf_object, test_tags};

test_tags! {
    map_fd_for_function_call:
        __description("invalid map_fd for function call"),
        __failure,
        __msg("fd 0 is not pointing to valid bpf_map"),
        __failure_unpriv;
    check_return_value_before_access:
        __description("don't check return value before access"),
        __failure,
        __msg("R0 invalid mem access 'map_value_or_null'"),
        __failure_unpriv;
    access_memory_with_incorrect_alignment_1:
        __description("access memory with incorrect alignment"),
        __failure,
        __msg("misaligned value access"),
        __failure_unpriv,
        __flag("BPF_F_STRICT_ALIGNMENT");
    access_memory_with_incorrect_alignment_2:
        __description("sometimes access memory with incorrect alignment"),
        __failure,
        __msg("R0 invalid mem access"),
        __msg_unpriv("R0 leaks addr"),
        __flag("BPF_F_STRICT_ALIGNMENT");
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
#[inline(never)]
// BPF_NAKED: map_fd_for_function_call
extern "C" fn map_fd_for_function_call() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u64*)(r10 - 8) = r2;",
            "r2 = r10;",
            "r2 += -8;",
            ".8byte 4376;",
            ".8byte 0;",
            "call 3;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: check_return_value_before_access
extern "C" fn check_return_value_before_access() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "r1 = 0;",
            "*(u64*)(r0 + 0) = r1;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: access_memory_with_incorrect_alignment_1
extern "C" fn access_memory_with_incorrect_alignment_1() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_0;",
            "r1 = 0;",
            "*(u64*)(r0 + 4) = r1;",
            "l0_0:",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: access_memory_with_incorrect_alignment_2
extern "C" fn access_memory_with_incorrect_alignment_2() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_1;",
            "r1 = 0;",
            "*(u64*)(r0 + 0) = r1;",
            "exit;",
            "l0_1:",
            "r1 = 1;",
            "*(u64*)(r0 + 0) = r1;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

bpf_object!("GPL");
