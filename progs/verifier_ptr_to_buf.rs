// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_ptr_to_buf.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_ptr_to_buf` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

use bpf_rs_core::{bpf_object, test_tags};

test_tags! {
    ptr_to_buf_reject_negative_const_offset:
        __description("PTR_TO_BUF: reject negative const offset"),
        __failure,
        __msg("invalid negative rdwr buffer offset");
}

#[link_section = "iter/bpf_map_elem"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_to_buf_reject_negative_const_offset
extern "C" fn ptr_to_buf_reject_negative_const_offset() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "r2 = *(u64 *)(r1 + 24);",
            "if r2 == 0 goto l0_0;",
            "r2 += -8;",
            "r0 = *(u64 *)(r2 + 0);",
            "l0_0:",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
