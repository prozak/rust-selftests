// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_search_pruning.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_search_pruning` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: state_equality_check_way_1 state_equality_check_way_2 liveness_pruning_and_write_screening varlen_map_value_access_pruning should_be_verified_nop_operation be_verified_invalid_stack_access tracking_for_u32_spill_fill for_u32_spills_u64_fill allocated_stack and_register_parent_chain_bug short_loop1

use bpf_rs_core::{bpf_map, bpf_object, test_tags};

test_tags! {
    state_equality_check_way_1:
        __description("pointer/scalar confusion in state equality check (way 1)"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R0 leaks addr as return value"),
        __retval("0xbadcafe");
    state_equality_check_way_2:
        __description("pointer/scalar confusion in state equality check (way 2)"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R0 leaks addr as return value"),
        __retval("0xbadcafe");
    liveness_pruning_and_write_screening:
        __description("liveness pruning and write screening"),
        __failure,
        __msg("R0 !read_ok");
    varlen_map_value_access_pruning:
        __description("varlen_map_value_access pruning"),
        __failure,
        __msg("R0 unbounded memory access"),
        __failure_unpriv,
        __msg_unpriv("R0 leaks addr"),
        __flag("BPF_F_ANY_ALIGNMENT");
    should_be_verified_nop_operation:
        __description("search pruning: all branches should be verified (nop operation)"),
        __failure,
        __msg("R6 invalid mem access 'scalar'");
    be_verified_invalid_stack_access:
        __description("search pruning: all branches should be verified (invalid stack access)"),
        __success,
        __failure_unpriv,
        __msg_unpriv("invalid read from stack off -16+0 size 8"),
        __retval("0");
    tracking_for_u32_spill_fill:
        __description("precision tracking for u32 spill/fill"),
        __failure,
        __msg("R0 min value is outside of the allowed memory range");
    for_u32_spills_u64_fill:
        __description("precision tracking for u32 spills, u64 fill"),
        __failure,
        __msg("div by zero");
    allocated_stack:
        __description("allocated_stack"),
        __success,
        __msg("processed 15 insns"),
        __success_unpriv,
        __msg_unpriv(""),
        __log_level("1"),
        __retval("0");
    and_register_parent_chain_bug:
        __description("write tracking and register parent chain bug"),
        __success,
        __failure_unpriv,
        __msg_unpriv("invalid read from stack off -8+1 size 8"),
        __retval("0"),
        __flag("BPF_F_TEST_STATE_FREQ");
    short_loop1:
        __failure,
        __log_level("4"),
        __msg("BPF program is too large.");
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
    map_hash_8b {
        r#type: *const [i32; 1],
        max_entries: *const [i32; 1],
        key: *const i64,
        value: *const i64,
    }
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
// BPF_NAKED: state_equality_check_way_1
extern "C" fn state_equality_check_way_1() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_0;",
            "r0 = *(u64*)(r0 + 0);",
            "goto l1_0;",
            "l0_0:",
            "r0 = r10;",
            "l1_0:",
            "goto l2_0;",
            "l2_0:",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: state_equality_check_way_2
extern "C" fn state_equality_check_way_2() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 != 0 goto l0_1;",
            "r0 = r10;",
            "goto l1_1;",
            "l0_1:",
            "r0 = *(u64*)(r0 + 0);",
            "l1_1:",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "lwt_in"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: liveness_pruning_and_write_screening
extern "C" fn liveness_pruning_and_write_screening() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "if r2 >= 0 goto l0_2;",
            "r0 = 0;",
            "l0_2:",
            "if r2 >= 0 goto l1_2;",
            "r0 = 0;",
            "l1_2:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: varlen_map_value_access_pruning
extern "C" fn varlen_map_value_access_pruning() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_3;",
            "r1 = *(u64*)(r0 + 0);",
            "w2 = 11;",
            "if r2 s> r1 goto l1_3;",
            "w1 = 0;",
            "l1_3:",
            "w1 <<= 2;",
            "r0 += r1;",
            "goto l2_3;",
            "l2_3:",
            "r1 = 4;",
            "*(u64*)(r0 + 0) = r1;",
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
// BPF_NAKED: should_be_verified_nop_operation
extern "C" fn should_be_verified_nop_operation() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_4;",
            "r3 = *(u64*)(r0 + 0);",
            "if r3 == 0xbeef goto l1_4;",
            "r4 = 0;",
            "goto l2_4;",
            "l1_4:",
            "r4 = 1;",
            "l2_4:",
            "*(u64*)(r10 - 16) = r4;",
            "call 5;",
            "r5 = *(u64*)(r10 - 16);",
            "if r5 == 0 goto l0_4;",
            "r6 = 0;",
            "r1 = 0xdead;",
            "*(u64*)(r6 + 0) = r1;",
            "l0_4:",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: be_verified_invalid_stack_access
extern "C" fn be_verified_invalid_stack_access() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_5;",
            "r3 = *(u64*)(r0 + 0);",
            "r4 = 0;",
            "if r3 == 0xbeef goto l1_5;",
            "*(u64*)(r10 - 16) = r4;",
            "goto l2_5;",
            "l1_5:",
            "*(u64*)(r10 - 24) = r4;",
            "l2_5:",
            "call 5;",
            "r5 = *(u64*)(r10 - 16);",
            "l0_5:",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: tracking_for_u32_spill_fill
extern "C" fn tracking_for_u32_spill_fill() {
    unsafe {
        core::arch::asm!(
            "r7 = r1;",
            "call 7;",
            "w6 = 32;",
            "if r0 == 0 goto l0_6;",
            "w6 = 4;",
            "l0_6:",
            "call 7;",
            "r3 = 0;",
            "r3 = 0;",
            "if r0 == 0 goto l1_6;",
            "r3 = 0;",
            "l1_6:",
            "*(u32*)(r10 - 8) = r6;",
            "r8 = *(u32*)(r10 - 8);",
            "r1 = 0;",
            "*(u64*)(r10 - 16) = r1;",
            "r2 = r10;",
            "r2 += -16;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l2_6;",
            "r0 += r8;",
            "r1 = *(u32*)(r0 + 0);",
            "l2_6:",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: for_u32_spills_u64_fill
extern "C" fn for_u32_spills_u64_fill() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r6 = r0;",
            "w7 = 0xffffffff;",
            "r3 = 1;",
            "r3 = 1;",
            "r3 = 1;",
            "r3 = 1;",
            "call 7;",
            "if r0 == 0 goto l0_7;",
            "r3 = 1;",
            "l0_7:",
            "w3 /= 0;",
            "*(u32*)(r10 - 4) = r6;",
            "*(u32*)(r10 - 8) = r7;",
            "r8 = *(u64*)(r10 - 8);",
            "if r8 != 0xffffffff goto l1_7;",
            "r3 = 1;",
            "l1_7:",
            "if r8 == 0xffffffff goto l2_7;",
            "w3 /= 0;",
            "l2_7:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: allocated_stack
extern "C" fn allocated_stack() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "call 7;",
            "r7 = r0;",
            "if r0 == 0 goto l0_8;",
            "r0 = 0;",
            "*(u64*)(r10 - 8) = r6;",
            "r6 = *(u64*)(r10 - 8);",
            "*(u8*)(r10 - 9) = r7;",
            "r7 = *(u8*)(r10 - 9);",
            "l0_8:",
            "if r0 != 0 goto l1_8;",
            "l1_8:",
            "if r0 != 0 goto l2_8;",
            "l2_8:",
            "if r0 != 0 goto l3_8;",
            "l3_8:",
            "if r0 != 0 goto l4_8;",
            "l4_8:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: and_register_parent_chain_bug
extern "C" fn and_register_parent_chain_bug() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "r6 = r0;",
            "call 5;",
            "if r0 > r6 goto l0_9;",
            "r0 = 0xdeadbeef;",
            "*(u64*)(r10 - 8) = r0;",
            "l0_9:",
            "r1 = 42;",
            "*(u8*)(r10 - 8) = r1;",
            "r2 = *(u64*)(r10 - 8);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "kprobe"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: short_loop1
extern "C" fn short_loop1() {
    unsafe {
        core::arch::asm!(
            "r7 = *(u16 *)(r1 +0);",
            "1:",
            "r7 += 0x1ab064b9;",
            ".8byte 31560386058520389;",
            "r7 &= 0x1ee60e;",
            "r7 += r1;",
            "if r7 s> 0x37d2 goto +0;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
