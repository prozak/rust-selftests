// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_xadd.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_xadd` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: xadd_w_check_unaligned_stack xadd_w_check_unaligned_map xadd_w_check_unaligned_pkt src_dst_got_mangled_1 src_dst_got_mangled_2 xadd_variable_stack_offset

use bpf_rs_core::{bpf_map, bpf_object, test_tags};

test_tags! {
    xadd_w_check_unaligned_stack:
        __description("xadd/w check unaligned stack"),
        __failure,
        __msg("misaligned stack access off");
    xadd_w_check_unaligned_map:
        __description("xadd/w check unaligned map"),
        __failure,
        __msg("misaligned value access off");
    xadd_w_check_unaligned_pkt:
        __description("xadd/w check unaligned pkt"),
        __failure,
        __msg("BPF_ATOMIC stores into R2 pkt is not allowed"),
        __flag("BPF_F_ANY_ALIGNMENT");
    src_dst_got_mangled_1:
        __description("xadd/w check whether src/dst got mangled, 1"),
        __success,
        __retval("3");
    src_dst_got_mangled_2:
        __description("xadd/w check whether src/dst got mangled, 2"),
        __success,
        __retval("3");
    xadd_variable_stack_offset:
        __description("xadd with variable stack offset"),
        __failure,
        __msg("variable offset stack pointer cannot be passed into helper function"),
        __msg("Verification failed: Memory Safety: Variable-offset stack access"),
        __msg("The instruction would access the stack"),
        __msg("Use a fixed stack offset for the instruction");
}

bpf_map! {
    map_hash_8b {
        r#type: *const [i32; 1],
        max_entries: *const [i32; 1],
        key: *const i64,
        value: *const i64,
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: xadd_w_check_unaligned_stack
extern "C" fn xadd_w_check_unaligned_stack() {
    unsafe {
        core::arch::asm!(
            "r0 = 1;",
            "*(u64*)(r10 - 8) = r0;",
            "lock *(u32 *)(r10 - 7) += w0;",
            "r0 = *(u64*)(r10 - 8);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: xadd_w_check_unaligned_map
extern "C" fn xadd_w_check_unaligned_map() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 != 0 goto l0_0;",
            "exit;",
            "l0_0:",
            "r1 = 1;",
            "lock *(u32 *)(r0 + 3) += w1;",
            "r0 = *(u32*)(r0 + 3);",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: xadd_w_check_unaligned_pkt
extern "C" fn xadd_w_check_unaligned_pkt() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 8;",
            "if r1 < r3 goto l0_1;",
            "r0 = 99;",
            "goto l1_1;",
            "l0_1:",
            "r0 = 1;",
            "r1 = 0;",
            "*(u32*)(r2 + 0) = r1;",
            "r1 = 0;",
            "*(u32*)(r2 + 3) = r1;",
            "lock *(u32 *)(r2 + 1) += w0;",
            "lock *(u32 *)(r2 + 2) += w0;",
            "r0 = *(u32*)(r2 + 1);",
            "l1_1:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: src_dst_got_mangled_1
extern "C" fn src_dst_got_mangled_1() {
    unsafe {
        core::arch::asm!(
            "r0 = 1;",
            "r6 = r0;",
            "r7 = r10;",
            "*(u64*)(r10 - 8) = r0;",
            "lock *(u64 *)(r10 - 8) += r0;",
            "lock *(u64 *)(r10 - 8) += r0;",
            "if r6 != r0 goto l0_2;",
            "if r7 != r10 goto l0_2;",
            "r0 = *(u64*)(r10 - 8);",
            "exit;",
            "l0_2:",
            "r0 = 42;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: src_dst_got_mangled_2
extern "C" fn src_dst_got_mangled_2() {
    unsafe {
        core::arch::asm!(
            "r0 = 1;",
            "r6 = r0;",
            "r7 = r10;",
            "*(u32*)(r10 - 8) = r0;",
            "lock *(u32 *)(r10 - 8) += w0;",
            "lock *(u32 *)(r10 - 8) += w0;",
            "if r6 != r0 goto l0_3;",
            "if r7 != r10 goto l0_3;",
            "r0 = *(u32*)(r10 - 8);",
            "exit;",
            "l0_3:",
            "r0 = 42;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: xadd_variable_stack_offset
extern "C" fn xadd_variable_stack_offset() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64 *)(r10 - 16) = r1;",
            "*(u64 *)(r10 - 8) = r1;",
            "call 7;",
            "r0 &= 8;",
            "r1 = r10;",
            "r1 += -16;",
            "r1 += r0;",
            "r2 = 1;",
            "lock *(u64 *)(r1 + 0) += r2;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
