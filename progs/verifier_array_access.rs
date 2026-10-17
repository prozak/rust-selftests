// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_array_access.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_array_access.rs
// (include!d below): an_array_with_a_constant_no_nullness, multiple_array_with_a_constant_no_nullness, an_array_with_a_32bit_constant_0_no_nullness, a_pcpu_array_with_a_constant_no_nullness, an_array_with_a_constant_no_nullness_out_of_bounds, an_array_with_a_constant_too_small, an_array_with_a_constant_too_big, mixed_const_and_non_const_key_lookup, non_stack_key_lookup, doesnt_reject_irrelevant_maps.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_array_access` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: an_array_with_a_constant_1 an_array_with_a_register_1 an_array_with_a_variable_1 array_with_a_signed_variable an_array_with_a_constant_2 an_array_with_a_register_2 an_array_with_a_variable_2 array_with_no_floor_check with_a_invalid_max_check_1 with_a_invalid_max_check_2 a_read_only_array_1_1 a_read_only_array_2_1 a_read_only_array_1_2 a_read_only_array_2_2 a_write_only_array_1_1 a_write_only_array_2_1 a_write_only_array_1_2 a_write_only_array_2_2 an_array_with_a_constant_no_nullness multiple_array_with_a_constant_no_nullness an_array_with_a_32bit_constant_0_no_nullness a_pcpu_array_with_a_constant_no_nullness an_array_with_a_constant_no_nullness_out_of_bounds an_array_with_a_constant_too_small an_array_with_a_constant_too_big mixed_const_and_non_const_key_lookup key_lookup_at_invalid_fp non_stack_key_lookup doesnt_reject_irrelevant_maps

use bpf_rs_core::{bpf_map, bpf_object, test_tags};
#[allow(unused_imports)]
use core::ffi::c_void;

test_tags! {
    an_array_with_a_constant_1:
        __description("valid map access into an array with a constant"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R0 leaks addr"),
        __retval("0");
    an_array_with_a_register_1:
        __description("valid map access into an array with a register"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R0 leaks addr"),
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    an_array_with_a_variable_1:
        __description("valid map access into an array with a variable"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R0 leaks addr"),
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    array_with_a_signed_variable:
        __description("valid map access into an array with a signed variable"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R0 leaks addr"),
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    an_array_with_a_constant_2:
        __description("invalid map access into an array with a constant"),
        __failure,
        __msg("invalid access to map value, value_size=48 off=48 size=8"),
        __failure_unpriv;
    an_array_with_a_register_2:
        __description("invalid map access into an array with a register"),
        __failure,
        __msg("R0 min value is outside of the allowed memory range"),
        __failure_unpriv,
        __flag("BPF_F_ANY_ALIGNMENT");
    an_array_with_a_variable_2:
        __description("invalid map access into an array with a variable"),
        __failure,
        __msg("R0 unbounded memory access, make sure to bounds check any such access"),
        __failure_unpriv,
        __flag("BPF_F_ANY_ALIGNMENT");
    array_with_no_floor_check:
        __description("invalid map access into an array with no floor check"),
        __failure,
        __msg("R0 unbounded memory access"),
        __failure_unpriv,
        __msg_unpriv("R0 leaks addr"),
        __flag("BPF_F_ANY_ALIGNMENT");
    with_a_invalid_max_check_1:
        __description("invalid map access into an array with a invalid max check"),
        __failure,
        __msg("invalid access to map value, value_size=48 off=44 size=8"),
        __failure_unpriv,
        __msg_unpriv("R0 leaks addr"),
        __flag("BPF_F_ANY_ALIGNMENT");
    with_a_invalid_max_check_2:
        __description("invalid map access into an array with a invalid max check"),
        __failure,
        __msg("R0 pointer += pointer"),
        __failure_unpriv,
        __flag("BPF_F_ANY_ALIGNMENT");
    a_read_only_array_1_1:
        __description("valid read map access into a read-only array 1"),
        __success,
        __success_unpriv,
        __retval("28");
    a_read_only_array_2_1:
        __description("valid read map access into a read-only array 2"),
        __success,
        __retval("65507");
    a_read_only_array_1_2:
        __description("invalid write map access into a read-only array 1"),
        __failure,
        __msg("write into map forbidden"),
        __failure_unpriv;
    a_read_only_array_2_2:
        __description("invalid write map access into a read-only array 2"),
        __failure,
        __msg("write into map forbidden");
    a_write_only_array_1_1:
        __description("valid write map access into a write-only array 1"),
        __success,
        __success_unpriv,
        __retval("1");
    a_write_only_array_2_1:
        __description("valid write map access into a write-only array 2"),
        __success,
        __retval("0");
    a_write_only_array_1_2:
        __description("invalid read map access into a write-only array 1"),
        __failure,
        __msg("read from map forbidden"),
        __failure_unpriv;
    a_write_only_array_2_2:
        __description("invalid read map access into a write-only array 2"),
        __failure,
        __msg("read from map forbidden");
    an_array_with_a_constant_no_nullness:
        __description("valid map access into an array using constant without nullness"),
        __success,
        __retval("4"),
        __log_level("2"),
        __msg("mark_precise: frame0: regs= stack=-8 before {{[0-9]}}: ({{[a-f0-9]+}}) *(u32 *)(r10 -8) = {{(1|r[0-9])}}");
    multiple_array_with_a_constant_no_nullness:
        __description("valid multiple map access into an array using constant without nullness"),
        __success,
        __retval("8"),
        __log_level("2"),
        __msg("mark_precise: frame0: regs= stack=-8 before {{[0-9]}}: ({{[a-f0-9]+}}) *(u32 *)(r10 -16) = {{(0|r[0-9])}}"),
        __msg("mark_precise: frame0: regs= stack=-8 before {{[0-9]}}: ({{[a-f0-9]+}}) *(u32 *)(r10 -8) = {{(1|r[0-9])}}");
    an_array_with_a_32bit_constant_0_no_nullness:
        __description("valid map access into an array using natural aligned 32-bit constant 0 without nullness"),
        __success,
        __retval("4");
    a_pcpu_array_with_a_constant_no_nullness:
        __description("valid map access into a pcpu array using constant without nullness"),
        __success,
        __retval("4"),
        __log_level("2"),
        __msg("mark_precise: frame0: regs= stack=-8 before {{[0-9]}}: ({{[a-f0-9]+}}) *(u32 *)(r10 -8) = {{(1|r[0-9])}}");
    an_array_with_a_constant_no_nullness_out_of_bounds:
        __description("invalid map access into an array using constant without nullness"),
        __failure,
        __msg("R0 invalid mem access 'map_value_or_null'");
    an_array_with_a_constant_too_small:
        __description("invalid map access into an array using constant smaller than key_size"),
        __failure,
        __msg("R0 invalid mem access 'map_value_or_null'");
    an_array_with_a_constant_too_big:
        __description("invalid map access into an array using constant larger than key_size"),
        __failure,
        __msg("R0 invalid mem access 'map_value_or_null'");
    mixed_const_and_non_const_key_lookup:
        __description("invalid elided lookup using const and non-const key"),
        __failure,
        __msg("R0 invalid mem access 'map_value_or_null'");
    key_lookup_at_invalid_fp:
        __failure,
        __msg("invalid read from stack R2 off=4096 size=4");
    non_stack_key_lookup:
        __description("invalid elided lookup using non-stack key"),
        __failure,
        __msg("R0 invalid mem access 'map_value_or_null'");
    doesnt_reject_irrelevant_maps:
        __description("doesn't reject UINT64_MAX as s64 for irrelevant maps"),
        __success,
        __retval("42");
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

bpf_map! {
    map_array_ro {
        r#type: *const [i32; 2],
        max_entries: *const [i32; 1],
        key: *const i32,
        value: *const test_val,
        map_flags: *const [i32; 128],
    }
}

bpf_map! {
    map_array_wo {
        r#type: *const [i32; 2],
        max_entries: *const [i32; 1],
        key: *const i32,
        value: *const test_val,
        map_flags: *const [i32; 256],
    }
}

bpf_map! {
    map_array {
        r#type: *const [i32; 2],
        max_entries: *const [i32; 2],
        key: *const u32,
        value: *const test_val,
    }
}

bpf_map! {
    map_array_pcpu {
        r#type: *const [i32; 6],
        max_entries: *const [i32; 2],
        key: *const u32,
        value: *const test_val,
    }
}

#[no_mangle]
static mut global_key: u32 = 0;

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: an_array_with_a_constant_1
extern "C" fn an_array_with_a_constant_1() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_0;",
            "r1 = 4;",
            "*(u64*)(r0 + 0) = r1;",
            "l0_0:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: an_array_with_a_register_1
extern "C" fn an_array_with_a_register_1() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_1;",
            "r1 = 4;",
            "r1 <<= 2;",
            "r0 += r1;",
            "r1 = 4;",
            "*(u64*)(r0 + 0) = r1;",
            "l0_1:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: an_array_with_a_variable_1
extern "C" fn an_array_with_a_variable_1() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_2;",
            "r1 = *(u32*)(r0 + 0);",
            "if r1 >= 11 goto l0_2;",
            "r1 <<= 2;",
            "r0 += r1;",
            "r1 = 4;",
            "*(u64*)(r0 + 0) = r1;",
            "l0_2:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: array_with_a_signed_variable
extern "C" fn array_with_a_signed_variable() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_3;",
            "r1 = *(u32*)(r0 + 0);",
            "if w1 s> 0xffffffff goto l1_3;",
            "w1 = 0;",
            "l1_3:",
            "w2 = 11;",
            "if r2 s> r1 goto l2_3;",
            "w1 = 0;",
            "l2_3:",
            "w1 <<= 2;",
            "r0 += r1;",
            "r1 = 4;",
            "*(u64*)(r0 + 0) = r1;",
            "l0_3:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: an_array_with_a_constant_2
extern "C" fn an_array_with_a_constant_2() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_4;",
            "r1 = 4;",
            "*(u64*)(r0 + 48) = r1;",
            "l0_4:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: an_array_with_a_register_2
extern "C" fn an_array_with_a_register_2() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_5;",
            "r1 = 12;",
            "r1 <<= 2;",
            "r0 += r1;",
            "r1 = 4;",
            "*(u64*)(r0 + 0) = r1;",
            "l0_5:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: an_array_with_a_variable_2
extern "C" fn an_array_with_a_variable_2() {
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

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: array_with_no_floor_check
extern "C" fn array_with_no_floor_check() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_7;",
            "r1 = *(u64*)(r0 + 0);",
            "w2 = 11;",
            "if r2 s> r1 goto l1_7;",
            "w1 = 0;",
            "l1_7:",
            "w1 <<= 2;",
            "r0 += r1;",
            "r1 = 4;",
            "*(u64*)(r0 + 0) = r1;",
            "l0_7:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: with_a_invalid_max_check_1
extern "C" fn with_a_invalid_max_check_1() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_8;",
            "r1 = *(u32*)(r0 + 0);",
            "w2 = 12;",
            "if r2 > r1 goto l1_8;",
            "w1 = 0;",
            "l1_8:",
            "w1 <<= 2;",
            "r0 += r1;",
            "r1 = 4;",
            "*(u64*)(r0 + 0) = r1;",
            "l0_8:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: with_a_invalid_max_check_2
extern "C" fn with_a_invalid_max_check_2() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_9;",
            "r8 = r0;",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_9;",
            "r0 += r8;",
            "r0 = *(u32*)(r0 + 4);",
            "l0_9:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: a_read_only_array_1_1
extern "C" fn a_read_only_array_1_1() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_array_ro} ll;",
            "call 1;",
            "if r0 == 0 goto l0_10;",
            "r0 = *(u32*)(r0 + 0);",
            "l0_10:",
            "exit;",
            map_array_ro = sym map_array_ro,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: a_read_only_array_2_1
extern "C" fn a_read_only_array_2_1() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_array_ro} ll;",
            "call 1;",
            "if r0 == 0 goto l0_11;",
            "r1 = r0;",
            "r2 = 4;",
            "r3 = 0;",
            "r4 = 0;",
            "r5 = 0;",
            "call 28;",
            "l0_11:",
            "exit;",
            map_array_ro = sym map_array_ro,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: a_read_only_array_1_2
extern "C" fn a_read_only_array_1_2() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_array_ro} ll;",
            "call 1;",
            "if r0 == 0 goto l0_12;",
            "r1 = 42;",
            "*(u64*)(r0 + 0) = r1;",
            "l0_12:",
            "exit;",
            map_array_ro = sym map_array_ro,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: a_read_only_array_2_2
extern "C" fn a_read_only_array_2_2() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_array_ro} ll;",
            "call 1;",
            "if r0 == 0 goto l0_13;",
            "r1 = r6;",
            "r2 = 0;",
            "r3 = r0;",
            "r4 = 8;",
            "call 26;",
            "l0_13:",
            "exit;",
            map_array_ro = sym map_array_ro,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: a_write_only_array_1_1
extern "C" fn a_write_only_array_1_1() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_array_wo} ll;",
            "call 1;",
            "if r0 == 0 goto l0_14;",
            "r1 = 42;",
            "*(u64*)(r0 + 0) = r1;",
            "l0_14:",
            "r0 = 1;",
            "exit;",
            map_array_wo = sym map_array_wo,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: a_write_only_array_2_1
extern "C" fn a_write_only_array_2_1() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_array_wo} ll;",
            "call 1;",
            "if r0 == 0 goto l0_15;",
            "r1 = r6;",
            "r2 = 0;",
            "r3 = r0;",
            "r4 = 8;",
            "call 26;",
            "l0_15:",
            "exit;",
            map_array_wo = sym map_array_wo,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: a_write_only_array_1_2
extern "C" fn a_write_only_array_1_2() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_array_wo} ll;",
            "call 1;",
            "if r0 == 0 goto l0_16;",
            "r0 = *(u64*)(r0 + 0);",
            "l0_16:",
            "exit;",
            map_array_wo = sym map_array_wo,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: a_write_only_array_2_2
extern "C" fn a_write_only_array_2_2() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_array_wo} ll;",
            "call 1;",
            "if r0 == 0 goto l0_17;",
            "r1 = r0;",
            "r2 = 4;",
            "r3 = 0;",
            "r4 = 0;",
            "r5 = 0;",
            "call 28;",
            "l0_17:",
            "exit;",
            map_array_wo = sym map_array_wo,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: key_lookup_at_invalid_fp
extern "C" fn key_lookup_at_invalid_fp() {
    unsafe {
        core::arch::asm!(
            "r1 = {map_array} ll;",
            "r2 = r10;",
            "r2 += 4096;",
            "call 1;",
            "r0 = *(u64*)(r0 + 0);",
            "exit;",
            map_array = sym map_array,
            options(nostack)
        );
    }
}

include!("hand/verifier_array_access.rs");

bpf_object!("GPL");
