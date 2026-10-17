// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_bounds_mix_sign_unsign.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_bounds_mix_sign_unsign` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: signed_and_unsigned_positive_bounds checks_mixing_signed_and_unsigned signed_and_unsigned_variant_2 signed_and_unsigned_variant_3 signed_and_unsigned_variant_4 signed_and_unsigned_variant_5 signed_and_unsigned_variant_6 signed_and_unsigned_variant_7 signed_and_unsigned_variant_8 signed_and_unsigned_variant_9 signed_and_unsigned_variant_10 signed_and_unsigned_variant_11 signed_and_unsigned_variant_12 signed_and_unsigned_variant_13 signed_and_unsigned_variant_14 signed_and_unsigned_variant_15

use bpf_rs_core::{bpf_map, bpf_object, test_tags};

test_tags! {
    signed_and_unsigned_positive_bounds:
        __description("bounds checks mixing signed and unsigned, positive bounds"),
        __failure,
        __msg("unbounded min value"),
        __failure_unpriv;
    checks_mixing_signed_and_unsigned:
        __description("bounds checks mixing signed and unsigned"),
        __failure,
        __msg("unbounded min value"),
        __failure_unpriv;
    signed_and_unsigned_variant_2:
        __description("bounds checks mixing signed and unsigned, variant 2"),
        __failure,
        __msg("unbounded min value"),
        __failure_unpriv;
    signed_and_unsigned_variant_3:
        __description("bounds checks mixing signed and unsigned, variant 3"),
        __failure,
        __msg("unbounded min value"),
        __failure_unpriv;
    signed_and_unsigned_variant_4:
        __description("bounds checks mixing signed and unsigned, variant 4"),
        __success,
        __success_unpriv,
        __retval("0");
    signed_and_unsigned_variant_5:
        __description("bounds checks mixing signed and unsigned, variant 5"),
        __failure,
        __msg("unbounded min value"),
        __failure_unpriv;
    signed_and_unsigned_variant_6:
        __description("bounds checks mixing signed and unsigned, variant 6"),
        __failure,
        __msg("R4 min value is negative, either use unsigned"),
        __failure_unpriv;
    signed_and_unsigned_variant_7:
        __description("bounds checks mixing signed and unsigned, variant 7"),
        __success,
        __success_unpriv,
        __retval("0");
    signed_and_unsigned_variant_8:
        __description("bounds checks mixing signed and unsigned, variant 8"),
        __failure,
        __msg("unbounded min value"),
        __failure_unpriv;
    signed_and_unsigned_variant_9:
        __description("bounds checks mixing signed and unsigned, variant 9"),
        __success,
        __success_unpriv,
        __retval("0");
    signed_and_unsigned_variant_10:
        __description("bounds checks mixing signed and unsigned, variant 10"),
        __failure,
        __msg("unbounded min value"),
        __failure_unpriv;
    signed_and_unsigned_variant_11:
        __description("bounds checks mixing signed and unsigned, variant 11"),
        __failure,
        __msg("unbounded min value"),
        __failure_unpriv;
    signed_and_unsigned_variant_12:
        __description("bounds checks mixing signed and unsigned, variant 12"),
        __failure,
        __msg("unbounded min value"),
        __failure_unpriv;
    signed_and_unsigned_variant_13:
        __description("bounds checks mixing signed and unsigned, variant 13"),
        __failure,
        __msg("unbounded min value"),
        __failure_unpriv;
    signed_and_unsigned_variant_14:
        __description("bounds checks mixing signed and unsigned, variant 14"),
        __failure,
        __msg("unbounded min value"),
        __failure_unpriv;
    signed_and_unsigned_variant_15:
        __description("bounds checks mixing signed and unsigned, variant 15"),
        __failure,
        __msg("unbounded min value"),
        __failure_unpriv;
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
// BPF_NAKED: signed_and_unsigned_positive_bounds
extern "C" fn signed_and_unsigned_positive_bounds() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "*(u64*)(r10 - 16) = r0;",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_0;",
            "r1 = *(u64*)(r10 - 16);",
            "r2 = 2;",
            "if r2 >= r1 goto l0_0;",
            "if r1 s> 4 goto l0_0;",
            "r0 += r1;",
            "r1 = 0;",
            "*(u8*)(r0 + 0) = r1;",
            "l0_0:",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: checks_mixing_signed_and_unsigned
extern "C" fn checks_mixing_signed_and_unsigned() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "*(u64*)(r10 - 16) = r0;",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_1;",
            "r1 = *(u64*)(r10 - 16);",
            "r2 = -1;",
            "if r1 > r2 goto l0_1;",
            "if r1 s> 1 goto l0_1;",
            "r0 += r1;",
            "r1 = 0;",
            "*(u8*)(r0 + 0) = r1;",
            "l0_1:",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: signed_and_unsigned_variant_2
extern "C" fn signed_and_unsigned_variant_2() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "*(u64*)(r10 - 16) = r0;",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_2;",
            "r1 = *(u64*)(r10 - 16);",
            "r2 = -1;",
            "if r1 > r2 goto l0_2;",
            "r8 = 0;",
            "r8 += r1;",
            "if r8 s> 1 goto l0_2;",
            "r0 += r8;",
            "r0 = 0;",
            "*(u8*)(r8 + 0) = r0;",
            "l0_2:",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: signed_and_unsigned_variant_3
extern "C" fn signed_and_unsigned_variant_3() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "*(u64*)(r10 - 16) = r0;",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_3;",
            "r1 = *(u64*)(r10 - 16);",
            "r2 = -1;",
            "if r1 > r2 goto l0_3;",
            "r8 = r1;",
            "if r8 s> 1 goto l0_3;",
            "r0 += r8;",
            "r0 = 0;",
            "*(u8*)(r8 + 0) = r0;",
            "l0_3:",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: signed_and_unsigned_variant_4
extern "C" fn signed_and_unsigned_variant_4() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "*(u64*)(r10 - 16) = r0;",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_4;",
            "r1 = *(u64*)(r10 - 16);",
            "r2 = 1;",
            "r1 &= r2;",
            "if r1 s> 1 goto l0_4;",
            "r0 += r1;",
            "r1 = 0;",
            "*(u8*)(r0 + 0) = r1;",
            "l0_4:",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: signed_and_unsigned_variant_5
extern "C" fn signed_and_unsigned_variant_5() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "*(u64*)(r10 - 16) = r0;",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_5;",
            "r1 = *(u64*)(r10 - 16);",
            "r2 = -1;",
            "if r1 > r2 goto l0_5;",
            "if r1 s> 1 goto l0_5;",
            "r0 += 4;",
            "r0 -= r1;",
            "r1 = 0;",
            "*(u8*)(r0 + 0) = r1;",
            "r0 = 0;",
            "l0_5:",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: signed_and_unsigned_variant_6
extern "C" fn signed_and_unsigned_variant_6() {
    unsafe {
        core::arch::asm!(
            "r9 = r1;",
            "call 5;",
            "*(u64*)(r10 - 16) = r0;",
            "r1 = r9;",
            "r2 = 0;",
            "r3 = r10;",
            "r3 += -512;",
            "r4 = *(u64*)(r10 - 16);",
            "r6 = -1;",
            "if r4 > r6 goto l0_6;",
            "if r4 s> 1 goto l0_6;",
            "r4 += 1;",
            "r5 = 0;",
            "r6 = 0;",
            "*(u16*)(r10 - 512) = r6;",
            "call 26;",
            "l0_6:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: signed_and_unsigned_variant_7
extern "C" fn signed_and_unsigned_variant_7() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "*(u64*)(r10 - 16) = r0;",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_7;",
            "r1 = *(u64*)(r10 - 16);",
            "r2 = 1073741824;",
            "if r1 > r2 goto l0_7;",
            "if r1 s> 1 goto l0_7;",
            "r0 += r1;",
            "r1 = 0;",
            "*(u8*)(r0 + 0) = r1;",
            "l0_7:",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: signed_and_unsigned_variant_8
extern "C" fn signed_and_unsigned_variant_8() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "*(u64*)(r10 - 16) = r0;",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_8;",
            "r1 = *(u64*)(r10 - 16);",
            "r2 = -1;",
            "if r2 > r1 goto l1_8;",
            "r0 = 0;",
            "exit;",
            "l1_8:",
            "if r1 s> 1 goto l0_8;",
            "r0 += r1;",
            "r1 = 0;",
            "*(u8*)(r0 + 0) = r1;",
            "l0_8:",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: signed_and_unsigned_variant_9
extern "C" fn signed_and_unsigned_variant_9() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "*(u64*)(r10 - 16) = r0;",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_9;",
            "r1 = *(u64*)(r10 - 16);",
            "r2 = -9223372036854775808ULL ll;",
            "if r2 > r1 goto l1_9;",
            "r0 = 0;",
            "exit;",
            "l1_9:",
            "if r1 s> 1 goto l0_9;",
            "r0 += r1;",
            "r1 = 0;",
            "*(u8*)(r0 + 0) = r1;",
            "l0_9:",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: signed_and_unsigned_variant_10
extern "C" fn signed_and_unsigned_variant_10() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "*(u64*)(r10 - 16) = r0;",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_10;",
            "r1 = *(u64*)(r10 - 16);",
            "r2 = -1;",
            "if r2 > r1 goto l1_10;",
            "r0 = 0;",
            "exit;",
            "l1_10:",
            "if r1 s> 1 goto l0_10;",
            "r0 += r1;",
            "r1 = 0;",
            "*(u8*)(r0 + 0) = r1;",
            "l0_10:",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: signed_and_unsigned_variant_11
extern "C" fn signed_and_unsigned_variant_11() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "*(u64*)(r10 - 16) = r0;",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_11;",
            "r1 = *(u64*)(r10 - 16);",
            "r2 = -1;",
            "if r2 >= r1 goto l1_11;",
            "r0 = 0;",
            "exit;",
            "l1_11:",
            "if r1 s> 1 goto l0_11;",
            "r0 += r1;",
            "r1 = 0;",
            "*(u8*)(r0 + 0) = r1;",
            "l0_11:",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: signed_and_unsigned_variant_12
extern "C" fn signed_and_unsigned_variant_12() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "*(u64*)(r10 - 16) = r0;",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_12;",
            "r1 = *(u64*)(r10 - 16);",
            "r2 = -6;",
            "if r2 >= r1 goto l1_12;",
            "r0 = 0;",
            "exit;",
            "l1_12:",
            "if r1 s> 1 goto l0_12;",
            "r0 += r1;",
            "r1 = 0;",
            "*(u8*)(r0 + 0) = r1;",
            "l0_12:",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: signed_and_unsigned_variant_13
extern "C" fn signed_and_unsigned_variant_13() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "*(u64*)(r10 - 16) = r0;",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_13;",
            "r1 = *(u64*)(r10 - 16);",
            "r2 = 2;",
            "if r2 >= r1 goto l0_13;",
            "r7 = 1;",
            "if r7 s> 0 goto l1_13;",
            "l0_13:",
            "r0 = 0;",
            "exit;",
            "l1_13:",
            "r7 += r1;",
            "if r7 s> 4 goto l2_13;",
            "r0 += r7;",
            "r1 = 0;",
            "*(u8*)(r0 + 0) = r1;",
            "l2_13:",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: signed_and_unsigned_variant_14
extern "C" fn signed_and_unsigned_variant_14() {
    unsafe {
        core::arch::asm!(
            "r9 = *(u32*)(r1 + 8);",
            "call 5;",
            "*(u64*)(r10 - 16) = r0;",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_14;",
            "r1 = *(u64*)(r10 - 16);",
            "r2 = -1;",
            "r8 = 2;",
            "if r9 == 42 goto l1_14;",
            "if r8 s> r1 goto l2_14;",
            "l3_14:",
            "if r1 s> 1 goto l2_14;",
            "r0 += r1;",
            "l0_14:",
            "r1 = 0;",
            "*(u8*)(r0 + 0) = r1;",
            "l2_14:",
            "r0 = 0;",
            "exit;",
            "l1_14:",
            "if r1 > r2 goto l2_14;",
            "goto l3_14;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: signed_and_unsigned_variant_15
extern "C" fn signed_and_unsigned_variant_15() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "*(u64*)(r10 - 16) = r0;",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_15;",
            "r1 = *(u64*)(r10 - 16);",
            "r2 = -6;",
            "if r2 >= r1 goto l1_15;",
            "l0_15:",
            "r0 = 0;",
            "exit;",
            "l1_15:",
            "r0 += r1;",
            "if r0 > 1 goto l2_15;",
            "r0 = 0;",
            "exit;",
            "l2_15:",
            "r1 = 0;",
            "*(u8*)(r0 + 0) = r1;",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

bpf_object!("GPL");
