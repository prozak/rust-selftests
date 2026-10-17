// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_value_or_null.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_value_or_null` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: share_map_lookup_elem_result map_value_or_null_1 map_value_or_null_2 map_value_or_null_3 multiple_map_lookup_elem_calls with_2nd_lookup_in_branch map_access_from_else_condition lookup_and_null_branch_prediction null_check_ids_in_regsafe

use bpf_rs_core::{bpf_map, bpf_object, test_tags};

test_tags! {
    share_map_lookup_elem_result:
        __description("multiple registers share map_lookup_elem result"),
        __success,
        __retval("0");
    map_value_or_null_1:
        __description("alu ops on ptr_to_map_value_or_null, 1"),
        __failure,
        __msg("R4 pointer arithmetic on map_value_or_null");
    map_value_or_null_2:
        __description("alu ops on ptr_to_map_value_or_null, 2"),
        __failure,
        __msg("R4 pointer arithmetic on map_value_or_null");
    map_value_or_null_3:
        __description("alu ops on ptr_to_map_value_or_null, 3"),
        __failure,
        __msg("R4 pointer arithmetic on map_value_or_null");
    multiple_map_lookup_elem_calls:
        __description("invalid memory access with multiple map_lookup_elem calls"),
        __failure,
        __msg("R4 !read_ok");
    with_2nd_lookup_in_branch:
        __description("valid indirect map_lookup_elem access with 2nd lookup in branch"),
        __success,
        __retval("0");
    map_access_from_else_condition:
        __description("invalid map access from else condition"),
        __failure,
        __msg("R0 unbounded memory access"),
        __failure_unpriv,
        __msg_unpriv("R0 leaks addr"),
        __flag("BPF_F_ANY_ALIGNMENT");
    lookup_and_null_branch_prediction:
        __description("map lookup and null branch prediction"),
        __success,
        __retval("0");
    null_check_ids_in_regsafe:
        __description("MAP_VALUE_OR_NULL check_ids() in regsafe()"),
        __failure,
        __msg("R8 invalid mem access 'map_value_or_null'"),
        __failure_unpriv,
        __msg_unpriv(""),
        __flag("BPF_F_TEST_STATE_FREQ");
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

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: share_map_lookup_elem_result
extern "C" fn share_map_lookup_elem_result() {
    unsafe {
        core::arch::asm!(
            "r1 = 10;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "r4 = r0;",
            "if r0 == 0 goto l0_0;",
            "r1 = 0;",
            "*(u64*)(r4 + 0) = r1;",
            "l0_0:",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: map_value_or_null_1
extern "C" fn map_value_or_null_1() {
    unsafe {
        core::arch::asm!(
            "r1 = 10;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "r4 = r0;",
            "r4 += -2;",
            "r4 += 2;",
            "if r0 == 0 goto l0_1;",
            "r1 = 0;",
            "*(u64*)(r4 + 0) = r1;",
            "l0_1:",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: map_value_or_null_2
extern "C" fn map_value_or_null_2() {
    unsafe {
        core::arch::asm!(
            "r1 = 10;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "r4 = r0;",
            "r4 &= -1;",
            "if r0 == 0 goto l0_2;",
            "r1 = 0;",
            "*(u64*)(r4 + 0) = r1;",
            "l0_2:",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: map_value_or_null_3
extern "C" fn map_value_or_null_3() {
    unsafe {
        core::arch::asm!(
            "r1 = 10;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "r4 = r0;",
            "r4 <<= 1;",
            "if r0 == 0 goto l0_3;",
            "r1 = 0;",
            "*(u64*)(r4 + 0) = r1;",
            "l0_3:",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: multiple_map_lookup_elem_calls
extern "C" fn multiple_map_lookup_elem_calls() {
    unsafe {
        core::arch::asm!(
            "r1 = 10;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "r8 = r1;",
            "r7 = r2;",
            "call 1;",
            "r4 = r0;",
            "r1 = r8;",
            "r2 = r7;",
            "call 1;",
            "if r0 == 0 goto l0_4;",
            "r1 = 0;",
            "*(u64*)(r4 + 0) = r1;",
            "l0_4:",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: with_2nd_lookup_in_branch
extern "C" fn with_2nd_lookup_in_branch() {
    unsafe {
        core::arch::asm!(
            "r1 = 10;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "r8 = r1;",
            "r7 = r2;",
            "call 1;",
            "r2 = 10;",
            "if r2 != 0 goto l0_5;",
            "r1 = r8;",
            "r2 = r7;",
            "call 1;",
            "l0_5:",
            "r4 = r0;",
            "if r0 == 0 goto l1_5;",
            "r1 = 0;",
            "*(u64*)(r4 + 0) = r1;",
            "l1_5:",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: map_access_from_else_condition
extern "C" fn map_access_from_else_condition() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_6;",
            "r1 = *(u32*)(r0 + 0);",
            "if r1 >= 10 goto l1_6;",
            "r1 += 1;",
            "l1_6:",
            "r1 <<= 2;",
            "r0 += r1;",
            "r1 = 4;",
            "*(u64*)(r0 + 0) = r1;",
            "l0_6:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: lookup_and_null_branch_prediction
extern "C" fn lookup_and_null_branch_prediction() {
    unsafe {
        core::arch::asm!(
            "r1 = 10;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "r6 = r0;",
            "if r6 == 0 goto l0_7;",
            "if r6 != 0 goto l0_7;",
            "r10 += 10;",
            "l0_7:",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: null_check_ids_in_regsafe
extern "C" fn null_check_ids_in_regsafe() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "r9 = r0;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "r8 = r0;",
            "call 5;",
            "r7 = r0;",
            "call 5;",
            "r6 = r0;",
            "if r6 > r7 goto l0_8;",
            "r9 = r8;",
            "l0_8:",
            "if r9 == 0 goto l1_8;",
            "r0 = *(u64*)(r8 + 0);",
            "l1_8:",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

bpf_object!("GPL");
