// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_ctx_ptr_param.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_ctx_ptr_param` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: fentry_ppvoid_as_scalar fentry_pppvoid_as_scalar fentry_ppfile_as_scalar fexit_ppfile_as_scalar

use bpf_rs_core::{bpf_object, test_tags};

test_tags! {
    fentry_ppvoid_as_scalar:
        __description("fentry/void**: void ** inferred as scalar"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("R1=ctx() R2=scalar()");
    fentry_pppvoid_as_scalar:
        __description("fentry/void***: void *** inferred as scalar"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("R1=ctx() R2=scalar()");
    fentry_ppfile_as_scalar:
        __description("fentry/struct file**: struct file ** inferred as scalar"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("R1=ctx() R2=scalar()");
    fexit_ppfile_as_scalar:
        __description("fexit/return struct file**: returned struct file ** inferred as scalar"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("R1=ctx() R2=scalar()");
}

#[link_section = "fentry/bpf_fentry_test_ppvoid"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: fentry_ppvoid_as_scalar
extern "C" fn fentry_ppvoid_as_scalar() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u64 *)(r1 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "fentry/bpf_fentry_test_pppvoid"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: fentry_pppvoid_as_scalar
extern "C" fn fentry_pppvoid_as_scalar() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u64 *)(r1 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "fentry/bpf_fentry_test_ppfile"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: fentry_ppfile_as_scalar
extern "C" fn fentry_ppfile_as_scalar() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u64 *)(r1 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "fexit/bpf_fexit_test_ret_ppfile"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: fexit_ppfile_as_scalar
extern "C" fn fexit_ppfile_as_scalar() {
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
