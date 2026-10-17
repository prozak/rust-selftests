// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_flow_keys.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_flow_keys` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: flow_keys_const_inbounds flow_keys_const_oob_read flow_keys_const_oob_write flow_keys_insn_off_oob flow_keys_var_read

use bpf_rs_core::{bpf_object, test_tags};

test_tags! {
    flow_keys_const_inbounds:
        __description("flow_keys: in-bounds constant pointer arithmetic accepted"),
        __success;
    flow_keys_const_oob_read:
        __description("flow_keys: OOB via constant pointer arithmetic rejected"),
        __failure,
        __msg("invalid access to flow keys off=4096 size=8");
    flow_keys_const_oob_write:
        __description("flow_keys: OOB write via constant pointer arithmetic rejected"),
        __failure,
        __msg("invalid access to flow keys off=4096 size=8");
    flow_keys_insn_off_oob:
        __description("flow_keys: OOB via insn->off rejected"),
        __failure,
        __msg("invalid access to flow keys off=4096 size=8");
    flow_keys_var_read:
        __description("flow_keys: variable pointer arithmetic rejected"),
        __failure,
        __msg("R1 pointer arithmetic on flow_keys prohibited");
}

#[link_section = "flow_dissector"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: flow_keys_const_inbounds
extern "C" fn flow_keys_const_inbounds() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64 *)(r1 + 144);",
            "r1 += 8;",
            "r0 = *(u64 *)(r1 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "flow_dissector"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: flow_keys_const_oob_read
extern "C" fn flow_keys_const_oob_read() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64 *)(r1 + 144);",
            "r1 += 4096;",
            "r0 = *(u64 *)(r1 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "flow_dissector"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: flow_keys_const_oob_write
extern "C" fn flow_keys_const_oob_write() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64 *)(r1 + 144);",
            "r1 += 4096;",
            "r2 = 0;",
            "*(u64 *)(r1 + 0) = r2;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "flow_dissector"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: flow_keys_insn_off_oob
extern "C" fn flow_keys_insn_off_oob() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64 *)(r1 + 144);",
            "r0 = *(u64 *)(r1 + 4096);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "flow_dissector"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: flow_keys_var_read
extern "C" fn flow_keys_var_read() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "call 7;",
            "r0 &= 0xFFFF;",
            "r1 = *(u64 *)(r6 + 144);",
            "r1 += r0;",
            "r0 = *(u64 *)(r1 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
