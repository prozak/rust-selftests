// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_leak_ptr.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_leak_ptr` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: leak_pointer_into_ctx_1 leak_pointer_into_ctx_2 leak_pointer_into_ctx_3 leak_pointer_into_map_val

use bpf_rs_core::{bpf_map, bpf_object, test_tags};

test_tags! {
    leak_pointer_into_ctx_1:
        __description("leak pointer into ctx 1"),
        __failure,
        __msg("BPF_ATOMIC stores into R1 ctx is not allowed"),
        __failure_unpriv,
        __msg_unpriv("R2 leaks addr into mem");
    leak_pointer_into_ctx_2:
        __description("leak pointer into ctx 2"),
        __failure,
        __msg("BPF_ATOMIC stores into R1 ctx is not allowed"),
        __failure_unpriv,
        __msg_unpriv("R10 leaks addr into mem");
    leak_pointer_into_ctx_3:
        __description("leak pointer into ctx 3"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R2 leaks addr into ctx"),
        __retval("0");
    leak_pointer_into_map_val:
        __description("leak pointer into map val"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R6 leaks addr into mem"),
        __retval("0");
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
// BPF_NAKED: leak_pointer_into_ctx_1
extern "C" fn leak_pointer_into_ctx_1() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "*(u64*)(r1 + 48) = r0;",
            "r2 = {map_hash_8b} ll;",
            "lock *(u64 *)(r1 + 48) += r2;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: leak_pointer_into_ctx_2
extern "C" fn leak_pointer_into_ctx_2() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "*(u64*)(r1 + 48) = r0;",
            "lock *(u64 *)(r1 + 48) += r10;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: leak_pointer_into_ctx_3
extern "C" fn leak_pointer_into_ctx_3() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "r2 = {map_hash_8b} ll;",
            "*(u64*)(r1 + 48) = r2;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: leak_pointer_into_map_val
extern "C" fn leak_pointer_into_map_val() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_0;",
            "r3 = 0;",
            "*(u64*)(r0 + 0) = r3;",
            "lock *(u64 *)(r0 + 0) += r6;",
            "l0_0:",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

bpf_object!("GPL");
