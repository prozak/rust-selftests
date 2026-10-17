// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_regalloc.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_regalloc` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: regalloc_basic regalloc_negative regalloc_src_reg_mark regalloc_src_reg_negative regalloc_and_spill regalloc_and_spill_negative regalloc_three_regs regalloc_after_call regalloc_after_call__1 regalloc_in_callee regalloc_in_callee__1 regalloc_spill_jeq

use bpf_rs_core::{bpf_map, bpf_object, test_tags};

test_tags! {
    regalloc_basic:
        __description("regalloc basic"),
        __success,
        __flag("BPF_F_ANY_ALIGNMENT");
    regalloc_negative:
        __description("regalloc negative"),
        __failure,
        __msg("invalid access to map value, value_size=48 off=48 size=1");
    regalloc_src_reg_mark:
        __description("regalloc src_reg mark"),
        __success,
        __flag("BPF_F_ANY_ALIGNMENT");
    regalloc_src_reg_negative:
        __description("regalloc src_reg negative"),
        __failure,
        __msg("invalid access to map value, value_size=48 off=44 size=8"),
        __flag("BPF_F_ANY_ALIGNMENT");
    regalloc_and_spill:
        __description("regalloc and spill"),
        __success,
        __flag("BPF_F_ANY_ALIGNMENT");
    regalloc_and_spill_negative:
        __description("regalloc and spill negative"),
        __failure,
        __msg("invalid access to map value, value_size=48 off=48 size=8"),
        __flag("BPF_F_ANY_ALIGNMENT");
    regalloc_three_regs:
        __description("regalloc three regs"),
        __success,
        __flag("BPF_F_ANY_ALIGNMENT");
    regalloc_after_call:
        __description("regalloc after call"),
        __success,
        __flag("BPF_F_ANY_ALIGNMENT");
    regalloc_in_callee:
        __description("regalloc in callee"),
        __success,
        __flag("BPF_F_ANY_ALIGNMENT");
    regalloc_spill_jeq:
        __description("regalloc, spill, JEQ"),
        __success;
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

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: regalloc_basic
extern "C" fn regalloc_basic() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_0;",
            "r7 = r0;",
            "call 7;",
            "r2 = r0;",
            "if r0 s> 20 goto l0_0;",
            "if r2 s< 0 goto l0_0;",
            "r7 += r0;",
            "r7 += r2;",
            "r0 = *(u64*)(r7 + 0);",
            "l0_0:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: regalloc_negative
extern "C" fn regalloc_negative() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_1;",
            "r7 = r0;",
            "call 7;",
            "r2 = r0;",
            "if r0 s> 24 goto l0_1;",
            "if r2 s< 0 goto l0_1;",
            "r7 += r0;",
            "r7 += r2;",
            "r0 = *(u8*)(r7 + 0);",
            "l0_1:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: regalloc_src_reg_mark
extern "C" fn regalloc_src_reg_mark() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_2;",
            "r7 = r0;",
            "call 7;",
            "r2 = r0;",
            "if r0 s> 20 goto l0_2;",
            "r3 = 0;",
            "if r3 s>= r2 goto l0_2;",
            "r7 += r0;",
            "r7 += r2;",
            "r0 = *(u64*)(r7 + 0);",
            "l0_2:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: regalloc_src_reg_negative
extern "C" fn regalloc_src_reg_negative() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_3;",
            "r7 = r0;",
            "call 7;",
            "r2 = r0;",
            "if r0 s> 22 goto l0_3;",
            "r3 = 0;",
            "if r3 s>= r2 goto l0_3;",
            "r7 += r0;",
            "r7 += r2;",
            "r0 = *(u64*)(r7 + 0);",
            "l0_3:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: regalloc_and_spill
extern "C" fn regalloc_and_spill() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_4;",
            "r7 = r0;",
            "call 7;",
            "r2 = r0;",
            "if r0 s> 20 goto l0_4;",
            "*(u64*)(r10 - 8) = r2;",
            "r0 = 0;",
            "r2 = 0;",
            "r3 = *(u64*)(r10 - 8);",
            "if r0 s>= r3 goto l0_4;",
            "r7 += r3;",
            "r0 = *(u64*)(r7 + 0);",
            "l0_4:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: regalloc_and_spill_negative
extern "C" fn regalloc_and_spill_negative() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_5;",
            "r7 = r0;",
            "call 7;",
            "r2 = r0;",
            "if r0 s> 48 goto l0_5;",
            "*(u64*)(r10 - 8) = r2;",
            "r0 = 0;",
            "r2 = 0;",
            "r3 = *(u64*)(r10 - 8);",
            "if r0 s>= r3 goto l0_5;",
            "r7 += r3;",
            "r0 = *(u64*)(r7 + 0);",
            "l0_5:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: regalloc_three_regs
extern "C" fn regalloc_three_regs() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_6;",
            "r7 = r0;",
            "call 7;",
            "r2 = r0;",
            "r4 = r2;",
            "if r0 s> 12 goto l0_6;",
            "if r2 s< 0 goto l0_6;",
            "r7 += r0;",
            "r7 += r2;",
            "r7 += r4;",
            "r0 = *(u64*)(r7 + 0);",
            "l0_6:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: regalloc_after_call
extern "C" fn regalloc_after_call() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_7;",
            "r7 = r0;",
            "call 7;",
            "r8 = r0;",
            "r9 = r0;",
            "call {regalloc_after_call__1};",
            "if r8 s> 20 goto l0_7;",
            "if r9 s< 0 goto l0_7;",
            "r7 += r8;",
            "r7 += r9;",
            "r0 = *(u64*)(r7 + 0);",
            "l0_7:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            regalloc_after_call__1 = sym regalloc_after_call__1,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: regalloc_after_call__1
extern "C" fn regalloc_after_call__1() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: regalloc_in_callee
extern "C" fn regalloc_in_callee() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_8;",
            "r7 = r0;",
            "call 7;",
            "r1 = r0;",
            "r2 = r0;",
            "r3 = r7;",
            "call {regalloc_in_callee__1};",
            "l0_8:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            regalloc_in_callee__1 = sym regalloc_in_callee__1,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: regalloc_in_callee__1
extern "C" fn regalloc_in_callee__1() {
    unsafe {
        core::arch::asm!(
            "if r1 s> 20 goto l0_9;",
            "if r2 s< 0 goto l0_9;",
            "r3 += r1;",
            "r3 += r2;",
            "r0 = *(u64*)(r3 + 0);",
            "exit;",
            "l0_9:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: regalloc_spill_jeq
extern "C" fn regalloc_spill_jeq() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "*(u64*)(r10 - 8) = r0;",
            "if r0 == 0 goto l0_10;",
            "l0_10:",
            "call 7;",
            "r2 = r0;",
            "if r2 == 20 goto l1_10;",
            "l1_10:",
            "r3 = *(u64*)(r10 - 8);",
            "if r3 == 0 goto l2_10;",
            "r0 = *(u64*)(r3 + 0);",
            "l2_10:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

bpf_object!("GPL");
