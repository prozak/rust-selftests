// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_bpf_get_stack.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_bpf_get_stack` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: stack_return_r0_within_range return_r0_range_is_refined

use bpf_rs_core::{bpf_map, bpf_object, test_tags};

test_tags! {
    stack_return_r0_within_range:
        __description("bpf_get_stack return R0 within range"),
        __success;
    return_r0_range_is_refined:
        __description("bpf_get_task_stack return R0 range is refined"),
        __success;
}

// Map key/value types, shaped like the C object's BTF (the kernel
// checks some of them member by member, so no explicit padding).
// translint: allow(padding)
#[allow(non_camel_case_types)]
#[repr(C)]
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

bpf_map! {
    map_array_48b {
        r#type: *const [i32; 2],
        max_entries: *const [i32; 1],
        key: *const i32,
        value: *const test_val,
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_return_r0_within_range
extern "C" fn stack_return_r0_within_range() {
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
            "r9 = 24;",
            "r1 = r6;",
            "r2 = r7;",
            "r3 = 24;",
            "r4 = 256;",
            "call 67;",
            "r1 = 0;",
            "r8 = r0;",
            "r8 <<= 32;",
            "r8 s>>= 32;",
            "if r1 s> r8 goto l0_0;",
            "r9 -= r8;",
            "r2 = r7;",
            "r2 += r8;",
            "r1 = r9;",
            "r1 <<= 32;",
            "r1 s>>= 32;",
            "r3 = r2;",
            "r3 += r1;",
            "r1 = r7;",
            "r5 = 24;",
            "r1 += r5;",
            "if r3 >= r1 goto l0_0;",
            "r1 = r6;",
            "r3 = r9;",
            "r4 = 0;",
            "call 67;",
            "l0_0:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "iter/task"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: return_r0_range_is_refined
extern "C" fn return_r0_range_is_refined() {
    unsafe {
        core::arch::asm!(
            "r6 = *(u64*)(r1 + 0);",
            "r6 = *(u64*)(r6 + 0);",
            "r7 = *(u64*)(r1 + 8);",
            "r1 = {map_array_48b} ll;",
            "r2 = 0;",
            "*(u64*)(r10 - 8) = r2;",
            "r2 = r10;",
            "r2 += -8;",
            "call 1;",
            "if r0 != 0 goto l0_1;",
            "r0 = 0;",
            "exit;",
            "l0_1:",
            "if r7 != 0 goto l1_1;",
            "r0 = 0;",
            "exit;",
            "l1_1:",
            "r1 = r7;",
            "r2 = r0;",
            "r9 = r0;",
            "r3 = 48;",
            "r4 = 0;",
            "call 141;",
            "if r0 s> 0 goto l2_1;",
            "r0 = 0;",
            "exit;",
            "l2_1:",
            "r1 = r6;",
            "r2 = r9;",
            "r3 = r0;",
            "call 127;",
            "r0 = 0;",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

bpf_object!("GPL");
