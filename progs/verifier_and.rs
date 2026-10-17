// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_and.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_and` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: invalid_and_of_negative_number invalid_range_check known_subreg_with_unknown_reg

use bpf_rs_core::{bpf_map, bpf_object, test_tags};

test_tags! {
    invalid_and_of_negative_number:
        __description("invalid and of negative number"),
        __failure,
        __msg("R0 max value is outside of the allowed memory range"),
        __failure_unpriv,
        __flag("BPF_F_ANY_ALIGNMENT");
    invalid_range_check:
        __description("invalid range check"),
        __failure,
        __msg("R0 max value is outside of the allowed memory range"),
        __failure_unpriv,
        __flag("BPF_F_ANY_ALIGNMENT");
    known_subreg_with_unknown_reg:
        __description("check known subreg with unknown reg"),
        __success,
        __success_unpriv,
        __retval("0"),
        __xlated_unpriv("if w0 < 0x1 goto pc+2"),
        __xlated_unpriv("nospec"),
        __xlated_unpriv("goto pc-1"),
        __xlated_unpriv("r0 = 0");
}

// Map key/value types, shaped like the C object's BTF (the kernel
// checks some of them member by member, so no explicit padding).
// translint: allow(padding)
#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct test_val {
    index: u32,
    foo: [i32; 11],
}

bpf_map! {
    map_hash_48b {
        r#type: *const [i32; 1],
        max_entries: *const [i32; 1],
        key: *const i64,
        value: *const test_val,
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: invalid_and_of_negative_number
extern "C" fn invalid_and_of_negative_number() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_0;",
            "r1 = *(u8*)(r0 + 0);",
            "r1 &= -4;",
            "r1 <<= 2;",
            "r0 += r1;",
            "l0_0:",
            "r1 = 4;",
            "*(u64*)(r0 + 0) = r1;",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: invalid_range_check
extern "C" fn invalid_range_check() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_1;",
            "r1 = *(u32*)(r0 + 0);",
            "r9 = 1;",
            "w1 %= 2;",
            "w1 += 1;",
            "w9 &= w1;",
            "w9 += 1;",
            "w9 >>= 1;",
            "w3 = 1;",
            "w3 -= w9;",
            "w3 *= 0x10000000;",
            "r0 += r3;",
            "*(u32*)(r0 + 0) = r3;",
            "l0_1:",
            "r0 = r0;",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: known_subreg_with_unknown_reg
extern "C" fn known_subreg_with_unknown_reg() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 <<= 32;",
            "r0 += 1;",
            "r0 &= 0xFFFF1234;",
            "if w0 < 1 goto l0_2;",
            "r1 = *(u32*)(r1 + 512);",
            "l0_2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
