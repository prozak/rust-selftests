// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_btf_ctx_access.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_btf_ctx_access` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: btf_ctx_access_accept ctx_access_u32_pointer_accept ctx_access_u32_pointer_reject_32 ctx_access_u32_pointer_reject_16 ctx_access_u32_pointer_reject_8 ctx_access_const_void_pointer_accept

use bpf_rs_core::{bpf_object, test_tags};

test_tags! {
    btf_ctx_access_accept:
        __description("btf_ctx_access accept"),
        __success,
        __retval("0");
    ctx_access_u32_pointer_accept:
        __description("btf_ctx_access u32 pointer accept"),
        __success,
        __retval("0");
    ctx_access_u32_pointer_reject_32:
        __description("btf_ctx_access u32 pointer reject u32"),
        __failure,
        __msg("size 4 must be 8");
    ctx_access_u32_pointer_reject_16:
        __description("btf_ctx_access u32 pointer reject u16"),
        __failure,
        __msg("size 2 must be 8");
    ctx_access_u32_pointer_reject_8:
        __description("btf_ctx_access u32 pointer reject u8"),
        __failure,
        __msg("size 1 must be 8");
    ctx_access_const_void_pointer_accept:
        __description("btf_ctx_access const void pointer accept"),
        __success,
        __retval("0");
}

#[link_section = "fentry/bpf_modify_return_test"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: btf_ctx_access_accept
extern "C" fn btf_ctx_access_accept() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u64 *)(r1 + 8);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "fentry/bpf_fentry_test9"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ctx_access_u32_pointer_accept
extern "C" fn ctx_access_u32_pointer_accept() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u64 *)(r1 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "fentry/bpf_fentry_test9"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ctx_access_u32_pointer_reject_32
extern "C" fn ctx_access_u32_pointer_reject_32() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32 *)(r1 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "fentry/bpf_fentry_test9"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ctx_access_u32_pointer_reject_16
extern "C" fn ctx_access_u32_pointer_reject_16() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u16 *)(r1 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "fentry/bpf_fentry_test9"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ctx_access_u32_pointer_reject_8
extern "C" fn ctx_access_u32_pointer_reject_8() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u8 *)(r1 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "fentry/bpf_fentry_test10"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ctx_access_const_void_pointer_accept
extern "C" fn ctx_access_const_void_pointer_accept() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u64 *)(r1 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
