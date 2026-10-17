// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_raw_tp_writable.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_raw_tp_writable` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: tracepoint_writable_reject_variable_offset tracepoint_writable_reject_negative_const_offset

use bpf_rs_core::{bpf_map, bpf_object, test_tags};

test_tags! {
    tracepoint_writable_reject_variable_offset:
        __description("raw_tracepoint_writable: reject variable offset"),
        __failure,
        __msg("R6 invalid variable buffer offset: off=0, var_off=(0x0; 0xffffffff)"),
        __flag("BPF_F_ANY_ALIGNMENT");
    tracepoint_writable_reject_negative_const_offset:
        __description("raw_tracepoint_writable: reject negative const offset"),
        __failure,
        __msg("invalid negative tracepoint buffer offset");
}

bpf_map! {
    map_hash_8b {
        r#type: *const [i32; 1],
        max_entries: *const [i32; 1],
        key: *const i64,
        value: *const i64,
    }
}

#[link_section = "raw_tracepoint.w"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: tracepoint_writable_reject_variable_offset
extern "C" fn tracepoint_writable_reject_variable_offset() {
    unsafe {
        core::arch::asm!(
            "r6 = *(u64*)(r1 + 0);",
            "r1 = {map_hash_8b} ll;",
            "w0 = 0;",
            "r2 = r10;",
            "r2 += -8;",
            "*(u64*)(r2 + 0) = r0;",
            "call 1;",
            "if r0 != 0 goto l0_0;",
            "exit;",
            "l0_0:",
            "r0 = *(u32*)(r0 + 0);",
            "r6 += r0;",
            "r7 = 4242;",
            "*(u64*)(r6 + 0) = r7;",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "raw_tracepoint.w"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: tracepoint_writable_reject_negative_const_offset
extern "C" fn tracepoint_writable_reject_negative_const_offset() {
    unsafe {
        core::arch::asm!(
            "r6 = *(u64 *)(r1 + 0);",
            "r6 += -8;",
            "r0 = *(u64 *)(r6 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
