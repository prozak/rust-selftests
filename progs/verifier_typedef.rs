// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_typedef.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_typedef` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

use bpf_rs_core::{bpf_object, test_tags};

test_tags! {
    resolve_typedef:
        __description("typedef: resolve"),
        __success,
        __retval("0");
}

#[link_section = "fentry/bpf_fentry_test_sinfo"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: resolve_typedef
extern "C" fn resolve_typedef() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64 *)(r1 +0);",
            "r2 = *(u64 *)(r1 +48);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
