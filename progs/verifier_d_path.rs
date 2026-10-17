// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_d_path.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_d_path` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: d_path_accept d_path_reject

use bpf_rs_core::{bpf_object, test_tags};

test_tags! {
    d_path_accept:
        __description("d_path accept"),
        __success,
        __retval("0");
    d_path_reject:
        __description("d_path reject"),
        __failure,
        __msg("helper call is not allowed in probe");
}

#[link_section = "fentry/dentry_open"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: d_path_accept
extern "C" fn d_path_accept() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64 *)(r1 + 0);",
            "r2 = r10;",
            "r2 += -8;",
            "r6 = 0;",
            "*(u64*)(r2 + 0) = r6;",
            "r3 = 8 ll;",
            "call 147;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "fentry/d_path"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: d_path_reject
extern "C" fn d_path_reject() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64 *)(r1 + 0);",
            "r2 = r10;",
            "r2 += -8;",
            "r6 = 0;",
            "*(u64*)(r2 + 0) = r6;",
            "r3 = 8 ll;",
            "call 147;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
