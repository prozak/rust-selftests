// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_value_ptr_arith.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_value_ptr_arith` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: value_ptr_unknown_vs_const value_ptr_const_vs_unknown ptr_const_vs_const_ne ptr_const_vs_const_eq ptr_unknown_vs_unknown_eq ptr_unknown_vs_unknown_lt ptr_unknown_vs_unknown_gt value_ptr_from_different_maps known_scalar_from_different_maps maps_but_same_value_properties value_pointer_and_scalar_1 value_pointer_and_scalar_2 alu_with_different_scalars_1 alu_with_different_scalars_2 alu_with_different_scalars_3 upper_oob_arith_test_1 upper_oob_arith_test_2 upper_oob_arith_test_3 lower_oob_arith_test_1 lower_oob_arith_test_2 lower_oob_arith_test_3 access_known_scalar_value_ptr_1 value_ptr_known_scalar_1 value_ptr_known_scalar_2_1 value_ptr_known_scalar_3 value_ptr_known_scalar_4 value_ptr_known_scalar_5 value_ptr_known_scalar_6 value_ptr_n_known_scalar unknown_scalar_value_ptr_1 unknown_scalar_value_ptr_2 unknown_scalar_value_ptr_3 unknown_scalar_value_ptr_4 value_ptr_unknown_scalar_1 value_ptr_unknown_scalar_2_1 value_ptr_unknown_scalar_3 access_value_ptr_value_ptr_1 access_known_scalar_value_ptr_2 access_value_ptr_known_scalar value_ptr_known_scalar_2_2 access_unknown_scalar_value_ptr access_value_ptr_unknown_scalar value_ptr_unknown_scalar_2_2 access_value_ptr_value_ptr_2 to_leak_tainted_dst_reg _32bit_pkt_ptr_scalar _32bit_scalar_pkt_ptr

use bpf_rs_core::{bpf_map, bpf_object, test_tags};

test_tags! {
    value_ptr_unknown_vs_const:
        __description("map access: known scalar += value_ptr unknown vs const"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R1 tried to add from different maps, paths or scalars"),
        __retval("1");
    value_ptr_const_vs_unknown:
        __description("map access: known scalar += value_ptr const vs unknown"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R1 tried to add from different maps, paths or scalars"),
        __retval("1");
    ptr_const_vs_const_ne:
        __description("map access: known scalar += value_ptr const vs const (ne)"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R1 tried to add from different maps, paths or scalars"),
        __retval("1");
    ptr_const_vs_const_eq:
        __description("map access: known scalar += value_ptr const vs const (eq)"),
        __success,
        __success_unpriv,
        __retval("1");
    ptr_unknown_vs_unknown_eq:
        __description("map access: known scalar += value_ptr unknown vs unknown (eq)"),
        __success,
        __success_unpriv,
        __retval("1");
    ptr_unknown_vs_unknown_lt:
        __description("map access: known scalar += value_ptr unknown vs unknown (lt)"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R1 tried to add from different maps, paths or scalars"),
        __retval("1");
    ptr_unknown_vs_unknown_gt:
        __description("map access: known scalar += value_ptr unknown vs unknown (gt)"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R1 tried to add from different maps, paths or scalars"),
        __retval("1");
    value_ptr_from_different_maps:
        __description("map access: known scalar += value_ptr from different maps"),
        __success,
        __success_unpriv,
        __retval("1");
    known_scalar_from_different_maps:
        __description("map access: value_ptr -= known scalar from different maps"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R0 min value is negative"),
        __retval("1");
    maps_but_same_value_properties:
        __description("map access: known scalar += value_ptr from different maps, but same value properties"),
        __success,
        __success_unpriv,
        __retval("1");
    value_pointer_and_scalar_1:
        __description("map access: mixing value pointer and scalar, 1"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R2 tried to add from different maps, paths or scalars, pointer arithmetic with it prohibited for !root"),
        __retval("0");
    value_pointer_and_scalar_2:
        __description("map access: mixing value pointer and scalar, 2"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R2 tried to add from different maps, paths or scalars, pointer arithmetic with it prohibited for !root"),
        __retval("0");
    alu_with_different_scalars_1:
        __description("sanitation: alu with different scalars 1"),
        __success,
        __success_unpriv,
        __retval("0x100000");
    alu_with_different_scalars_2:
        __description("sanitation: alu with different scalars 2"),
        __success,
        __success_unpriv,
        __retval("0");
    alu_with_different_scalars_3:
        __description("sanitation: alu with different scalars 3"),
        __success,
        __success_unpriv,
        __retval("0");
    upper_oob_arith_test_1:
        __description("map access: value_ptr += known scalar, upper oob arith, test 1"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R0 pointer arithmetic of map value goes out of range"),
        __retval("1");
    upper_oob_arith_test_2:
        __description("map access: value_ptr += known scalar, upper oob arith, test 2"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R0 pointer arithmetic of map value goes out of range"),
        __retval("1");
    upper_oob_arith_test_3:
        __description("map access: value_ptr += known scalar, upper oob arith, test 3"),
        __success,
        __success_unpriv,
        __retval("1");
    lower_oob_arith_test_1:
        __description("map access: value_ptr -= known scalar, lower oob arith, test 1"),
        __failure,
        __msg("R0 min value is negative");
    lower_oob_arith_test_2:
        __description("map access: value_ptr -= known scalar, lower oob arith, test 2"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R0 pointer arithmetic of map value goes out of range"),
        __retval("1");
    lower_oob_arith_test_3:
        __description("map access: value_ptr -= known scalar, lower oob arith, test 3"),
        __success,
        __success_unpriv,
        __retval("1");
    access_known_scalar_value_ptr_1:
        __description("map access: known scalar += value_ptr"),
        __success,
        __success_unpriv,
        __retval("1");
    value_ptr_known_scalar_1:
        __description("map access: value_ptr += known scalar, 1"),
        __success,
        __success_unpriv,
        __retval("1");
    value_ptr_known_scalar_2_1:
        __description("map access: value_ptr += known scalar, 2"),
        __failure,
        __msg("invalid access to map value"),
        __failure_unpriv;
    value_ptr_known_scalar_3:
        __description("map access: value_ptr += known scalar, 3"),
        __failure,
        __msg("R0 min value is negative"),
        __failure_unpriv;
    value_ptr_known_scalar_4:
        __description("map access: value_ptr += known scalar, 4"),
        __success,
        __success_unpriv,
        __retval("1");
    value_ptr_known_scalar_5:
        __description("map access: value_ptr += known scalar, 5"),
        __success,
        __success_unpriv,
        __retval("0xabcdef12");
    value_ptr_known_scalar_6:
        __description("map access: value_ptr += known scalar, 6"),
        __success,
        __success_unpriv,
        __retval("0xabcdef12");
    value_ptr_n_known_scalar:
        __description("map access: value_ptr += N, value_ptr -= N known scalar"),
        __success,
        __success_unpriv,
        __retval("0x12345678");
    unknown_scalar_value_ptr_1:
        __description("map access: unknown scalar += value_ptr, 1"),
        __success,
        __success_unpriv,
        __retval("1");
    unknown_scalar_value_ptr_2:
        __description("map access: unknown scalar += value_ptr, 2"),
        __success,
        __success_unpriv,
        __retval("0xabcdef12"),
        __flag("BPF_F_ANY_ALIGNMENT");
    unknown_scalar_value_ptr_3:
        __description("map access: unknown scalar += value_ptr, 3"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R0 pointer arithmetic of map value goes out of range"),
        __retval("0xabcdef12"),
        __flag("BPF_F_ANY_ALIGNMENT");
    unknown_scalar_value_ptr_4:
        __description("map access: unknown scalar += value_ptr, 4"),
        __failure,
        __msg("R1 max value is outside of the allowed memory range"),
        __msg_unpriv("R1 pointer arithmetic of map value goes out of range"),
        __flag("BPF_F_ANY_ALIGNMENT");
    value_ptr_unknown_scalar_1:
        __description("map access: value_ptr += unknown scalar, 1"),
        __success,
        __success_unpriv,
        __retval("1");
    value_ptr_unknown_scalar_2_1:
        __description("map access: value_ptr += unknown scalar, 2"),
        __success,
        __success_unpriv,
        __retval("0xabcdef12"),
        __flag("BPF_F_ANY_ALIGNMENT");
    value_ptr_unknown_scalar_3:
        __description("map access: value_ptr += unknown scalar, 3"),
        __success,
        __success_unpriv,
        __retval("1");
    access_value_ptr_value_ptr_1:
        __description("map access: value_ptr += value_ptr"),
        __failure,
        __msg("R0 pointer += pointer prohibited"),
        __failure_unpriv;
    access_known_scalar_value_ptr_2:
        __description("map access: known scalar -= value_ptr"),
        __failure,
        __msg("R1 tried to subtract pointer from scalar"),
        __failure_unpriv;
    access_value_ptr_known_scalar:
        __description("map access: value_ptr -= known scalar"),
        __failure,
        __msg("R0 min value is negative"),
        __failure_unpriv;
    value_ptr_known_scalar_2_2:
        __description("map access: value_ptr -= known scalar, 2"),
        __success,
        __success_unpriv,
        __retval("1");
    access_unknown_scalar_value_ptr:
        __description("map access: unknown scalar -= value_ptr"),
        __failure,
        __msg("R1 tried to subtract pointer from scalar"),
        __failure_unpriv;
    access_value_ptr_unknown_scalar:
        __description("map access: value_ptr -= unknown scalar"),
        __failure,
        __msg("R0 min value is negative"),
        __failure_unpriv;
    value_ptr_unknown_scalar_2_2:
        __description("map access: value_ptr -= unknown scalar, 2"),
        __success,
        __success_unpriv,
        __retval("1"),
        __xlated_unpriv("r1 &= 7"),
        __xlated_unpriv("nospec"),
        __xlated_unpriv("r0 -= r1");
    access_value_ptr_value_ptr_2:
        __description("map access: value_ptr -= value_ptr"),
        __failure,
        __msg("R0 invalid mem access 'scalar'"),
        __msg_unpriv("R0 pointer -= pointer prohibited");
    to_leak_tainted_dst_reg:
        __description("map access: trying to leak tainted dst reg"),
        __failure,
        __msg("math between map_value pointer and 4294967295 is not allowed"),
        __failure_unpriv;
    _32bit_pkt_ptr_scalar:
        __description("32bit pkt_ptr -= scalar"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    _32bit_scalar_pkt_ptr:
        __description("32bit scalar -= pkt_ptr"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
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

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct other_val {
    foo: i64,
    bar: i64,
}

bpf_map! {
    map_array_48b {
        r#type: *const [i32; 2],
        max_entries: *const [i32; 1],
        key: *const i32,
        value: *const test_val,
    }
}

bpf_map! {
    map_hash_16b {
        r#type: *const [i32; 1],
        max_entries: *const [i32; 1],
        key: *const i64,
        value: *const other_val,
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
// BPF_NAKED: value_ptr_unknown_vs_const
extern "C" fn value_ptr_unknown_vs_const() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u32*)(r1 + 0);",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "if r0 == 1 goto l0_0;",
            "r1 = {map_hash_16b} ll;",
            "if r0 != 1 goto l1_0;",
            "l0_0:",
            "r1 = {map_array_48b} ll;",
            "l1_0:",
            "call 1;",
            "if r0 == 0 goto l2_0;",
            "r4 = *(u8*)(r0 + 0);",
            "if r4 == 1 goto l3_0;",
            "r1 = 6;",
            "r1 = -r1;",
            "r1 &= 0x7;",
            "goto l4_0;",
            "l3_0:",
            "r1 = 3;",
            "l4_0:",
            "r1 += r0;",
            "r0 = *(u8*)(r1 + 0);",
            "l2_0:",
            "r0 = 1;",
            "exit;",
            map_array_48b = sym map_array_48b,
            map_hash_16b = sym map_hash_16b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: value_ptr_const_vs_unknown
extern "C" fn value_ptr_const_vs_unknown() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u32*)(r1 + 0);",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "if r0 == 1 goto l0_1;",
            "r1 = {map_hash_16b} ll;",
            "if r0 != 1 goto l1_1;",
            "l0_1:",
            "r1 = {map_array_48b} ll;",
            "l1_1:",
            "call 1;",
            "if r0 == 0 goto l2_1;",
            "r4 = *(u8*)(r0 + 0);",
            "if r4 == 1 goto l3_1;",
            "r1 = 3;",
            "goto l4_1;",
            "l3_1:",
            "r1 = 6;",
            "r1 = -r1;",
            "r1 &= 0x7;",
            "l4_1:",
            "r1 += r0;",
            "r0 = *(u8*)(r1 + 0);",
            "l2_1:",
            "r0 = 1;",
            "exit;",
            map_array_48b = sym map_array_48b,
            map_hash_16b = sym map_hash_16b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_const_vs_const_ne
extern "C" fn ptr_const_vs_const_ne() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u32*)(r1 + 0);",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "if r0 == 1 goto l0_2;",
            "r1 = {map_hash_16b} ll;",
            "if r0 != 1 goto l1_2;",
            "l0_2:",
            "r1 = {map_array_48b} ll;",
            "l1_2:",
            "call 1;",
            "if r0 == 0 goto l2_2;",
            "r4 = *(u8*)(r0 + 0);",
            "if r4 == 1 goto l3_2;",
            "r1 = 3;",
            "goto l4_2;",
            "l3_2:",
            "r1 = 5;",
            "l4_2:",
            "r1 += r0;",
            "r0 = *(u8*)(r1 + 0);",
            "l2_2:",
            "r0 = 1;",
            "exit;",
            map_array_48b = sym map_array_48b,
            map_hash_16b = sym map_hash_16b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_const_vs_const_eq
extern "C" fn ptr_const_vs_const_eq() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u32*)(r1 + 0);",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "if r0 == 1 goto l0_3;",
            "r1 = {map_hash_16b} ll;",
            "if r0 != 1 goto l1_3;",
            "l0_3:",
            "r1 = {map_array_48b} ll;",
            "l1_3:",
            "call 1;",
            "if r0 == 0 goto l2_3;",
            "r4 = *(u8*)(r0 + 0);",
            "if r4 == 1 goto l3_3;",
            "r1 = 5;",
            "goto l4_3;",
            "l3_3:",
            "r1 = 5;",
            "l4_3:",
            "r1 += r0;",
            "r0 = *(u8*)(r1 + 0);",
            "l2_3:",
            "r0 = 1;",
            "exit;",
            map_array_48b = sym map_array_48b,
            map_hash_16b = sym map_hash_16b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_unknown_vs_unknown_eq
extern "C" fn ptr_unknown_vs_unknown_eq() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u32*)(r1 + 0);",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "if r0 == 1 goto l0_4;",
            "r1 = {map_hash_16b} ll;",
            "if r0 != 1 goto l1_4;",
            "l0_4:",
            "r1 = {map_array_48b} ll;",
            "l1_4:",
            "call 1;",
            "if r0 == 0 goto l2_4;",
            "r4 = *(u8*)(r0 + 0);",
            "if r4 == 1 goto l3_4;",
            "r1 = 6;",
            "r1 = -r1;",
            "r1 &= 0x7;",
            "goto l4_4;",
            "l3_4:",
            "r1 = 6;",
            "r1 = -r1;",
            "r1 &= 0x7;",
            "l4_4:",
            "r1 += r0;",
            "r0 = *(u8*)(r1 + 0);",
            "l2_4:",
            "r0 = 1;",
            "exit;",
            map_array_48b = sym map_array_48b,
            map_hash_16b = sym map_hash_16b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_unknown_vs_unknown_lt
extern "C" fn ptr_unknown_vs_unknown_lt() {
    unsafe {
        core::arch::asm!(
            "r8 = r1;",
            "call 7;",
            "r9 = r0;",
            "r1 = r8;",
            "r0 = *(u32*)(r1 + 0);",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "if r0 == 1 goto l0_5;",
            "r1 = {map_hash_16b} ll;",
            "if r0 != 1 goto l1_5;",
            "l0_5:",
            "r1 = {map_array_48b} ll;",
            "l1_5:",
            "call 1;",
            "if r0 == 0 goto l2_5;",
            "r4 = *(u8*)(r0 + 0);",
            "if r4 == 1 goto l3_5;",
            "r1 = 6;",
            "r1 = r9;",
            "r1 &= 0x3;",
            "goto l4_5;",
            "l3_5:",
            "r1 = 6;",
            "r1 = r9;",
            "r1 &= 0x7;",
            "l4_5:",
            "r1 += r0;",
            "r0 = *(u8*)(r1 + 0);",
            "l2_5:",
            "r0 = 1;",
            "exit;",
            map_array_48b = sym map_array_48b,
            map_hash_16b = sym map_hash_16b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_unknown_vs_unknown_gt
extern "C" fn ptr_unknown_vs_unknown_gt() {
    unsafe {
        core::arch::asm!(
            "r8 = r1;",
            "call 7;",
            "r9 = r0;",
            "r1 = r8;",
            "r0 = *(u32*)(r1 + 0);",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "if r0 == 1 goto l0_6;",
            "r1 = {map_hash_16b} ll;",
            "if r0 != 1 goto l1_6;",
            "l0_6:",
            "r1 = {map_array_48b} ll;",
            "l1_6:",
            "call 1;",
            "if r0 == 0 goto l2_6;",
            "r4 = *(u8*)(r0 + 0);",
            "if r4 == 1 goto l3_6;",
            "r1 = 6;",
            "r1 = r9;",
            "r1 &= 0x7;",
            "goto l4_6;",
            "l3_6:",
            "r1 = 6;",
            "r1 = r9;",
            "r1 &= 0x3;",
            "l4_6:",
            "r1 += r0;",
            "r0 = *(u8*)(r1 + 0);",
            "l2_6:",
            "r0 = 1;",
            "exit;",
            map_array_48b = sym map_array_48b,
            map_hash_16b = sym map_hash_16b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: value_ptr_from_different_maps
extern "C" fn value_ptr_from_different_maps() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u32*)(r1 + 0);",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "if r0 == 1 goto l0_7;",
            "r1 = {map_hash_16b} ll;",
            "if r0 != 1 goto l1_7;",
            "l0_7:",
            "r1 = {map_array_48b} ll;",
            "l1_7:",
            "call 1;",
            "if r0 == 0 goto l2_7;",
            "r1 = 4;",
            "r1 += r0;",
            "r0 = *(u8*)(r1 + 0);",
            "l2_7:",
            "r0 = 1;",
            "exit;",
            map_array_48b = sym map_array_48b,
            map_hash_16b = sym map_hash_16b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: known_scalar_from_different_maps
extern "C" fn known_scalar_from_different_maps() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u32*)(r1 + 0);",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "if r0 == 1 goto l0_8;",
            "r1 = {map_hash_16b} ll;",
            "if r0 != 1 goto l1_8;",
            "l0_8:",
            "r1 = {map_array_48b} ll;",
            "l1_8:",
            "call 1;",
            "if r0 == 0 goto l2_8;",
            "r1 = 4;",
            "r0 -= r1;",
            "r0 += r1;",
            "r0 = *(u8*)(r0 + 0);",
            "l2_8:",
            "r0 = 1;",
            "exit;",
            map_array_48b = sym map_array_48b,
            map_hash_16b = sym map_hash_16b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: maps_but_same_value_properties
extern "C" fn maps_but_same_value_properties() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u32*)(r1 + 0);",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "if r0 == 1 goto l0_9;",
            "r1 = {map_hash_48b} ll;",
            "if r0 != 1 goto l1_9;",
            "l0_9:",
            "r1 = {map_array_48b} ll;",
            "l1_9:",
            "call 1;",
            "if r0 == 0 goto l2_9;",
            "r1 = 4;",
            "r1 += r0;",
            "r0 = *(u8*)(r1 + 0);",
            "l2_9:",
            "r0 = 1;",
            "exit;",
            map_array_48b = sym map_array_48b,
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: value_pointer_and_scalar_1
extern "C" fn value_pointer_and_scalar_1() {
    unsafe {
        core::arch::asm!(
            "r0 = 1;",
            "r1 = {map_array_48b} ll;",
            "r2 = r10;",
            "r2 += -16;",
            "r6 = 0;",
            "*(u64*)(r10 - 16) = r6;",
            "call 1;",
            "if r0 != 0 goto l0_10;",
            "exit;",
            "l0_10:",
            "r1 = *(u8*)(r0 + 0);",
            "if r1 != 0 goto l1_10;",
            "r2 = r0;",
            "r3 = 0;",
            "goto l2_10;",
            "l1_10:",
            "r2 = 0;",
            "r3 = 0x100000;",
            "l2_10:",
            "r2 += r3;",
            "if r1 != 0 goto l3_10;",
            "goto l4_10;",
            "l3_10:",
            "r0 = 0x13371337;",
            "if r2 != 0x100000 goto l4_10;",
            "r0 = 0;",
            "exit;",
            "l4_10:",
            "r0 = *(u8*)(r0 + 0);",
            "r0 = 0;",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: value_pointer_and_scalar_2
extern "C" fn value_pointer_and_scalar_2() {
    unsafe {
        core::arch::asm!(
            "r0 = 1;",
            "r1 = {map_array_48b} ll;",
            "r2 = r10;",
            "r2 += -16;",
            "r6 = 0;",
            "*(u64*)(r10 - 16) = r6;",
            "call 1;",
            "if r0 != 0 goto l0_11;",
            "exit;",
            "l0_11:",
            "r1 = *(u8*)(r0 + 0);",
            "if r1 == 0 goto l1_11;",
            "r2 = 0;",
            "r3 = 0x100000;",
            "goto l2_11;",
            "l1_11:",
            "r2 = r0;",
            "r3 = 0;",
            "l2_11:",
            "r2 += r3;",
            "if r1 != 0 goto l3_11;",
            "goto l4_11;",
            "l3_11:",
            "r0 = 0x13371337;",
            "if r2 != 0x100000 goto l4_11;",
            "r0 = 0;",
            "exit;",
            "l4_11:",
            "r0 = *(u8*)(r0 + 0);",
            "r0 = 0;",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: alu_with_different_scalars_1
extern "C" fn alu_with_different_scalars_1() {
    unsafe {
        core::arch::asm!(
            "r0 = 1;",
            "r1 = {map_array_48b} ll;",
            "r2 = r10;",
            "r2 += -16;",
            "r6 = 0;",
            "*(u64*)(r10 - 16) = r6;",
            "call 1;",
            "if r0 != 0 goto l0_12;",
            "exit;",
            "l0_12:",
            "r1 = *(u32*)(r0 + 0);",
            "if r1 == 0 goto l1_12;",
            "r2 = 0;",
            "r3 = 0x100000;",
            "goto l2_12;",
            "l1_12:",
            "r2 = 42;",
            "r3 = 0x100001;",
            "l2_12:",
            "r2 += r3;",
            "r0 = r2;",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: alu_with_different_scalars_2
extern "C" fn alu_with_different_scalars_2() {
    unsafe {
        core::arch::asm!(
            "r0 = 1;",
            "r1 = {map_array_48b} ll;",
            "r6 = r1;",
            "r2 = r10;",
            "r2 += -16;",
            "r7 = 0;",
            "*(u64*)(r10 - 16) = r7;",
            "call 3;",
            "r7 = r0;",
            "r1 = r6;",
            "r2 = r10;",
            "r2 += -16;",
            "call 3;",
            "r6 = r0;",
            "r8 = r6;",
            "r8 += r7;",
            "r0 = r8;",
            "r0 += 22;",
            "r0 += 22;",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: alu_with_different_scalars_3
extern "C" fn alu_with_different_scalars_3() {
    unsafe {
        core::arch::asm!(
            "r0 = 22;",
            "r0 *= -1;",
            "r7 = r0;",
            "r0 = 22;",
            "r0 *= -1;",
            "r6 = r0;",
            "r8 = r6;",
            "r8 += r7;",
            "r0 = r8;",
            "r0 += 22;",
            "r0 += 22;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: upper_oob_arith_test_1
extern "C" fn upper_oob_arith_test_1() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_array_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_13;",
            "r1 = 48;",
            "r0 += r1;",
            "r0 -= r1;",
            "r0 = *(u8*)(r0 + 0);",
            "l0_13:",
            "r0 = 1;",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: upper_oob_arith_test_2
extern "C" fn upper_oob_arith_test_2() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_array_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_14;",
            "r1 = 49;",
            "r0 += r1;",
            "r0 -= r1;",
            "r0 = *(u8*)(r0 + 0);",
            "l0_14:",
            "r0 = 1;",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: upper_oob_arith_test_3
extern "C" fn upper_oob_arith_test_3() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_array_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_15;",
            "r1 = 47;",
            "r0 += r1;",
            "r0 -= r1;",
            "r0 = *(u8*)(r0 + 0);",
            "l0_15:",
            "r0 = 1;",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: lower_oob_arith_test_1
extern "C" fn lower_oob_arith_test_1() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_array_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_16;",
            "r1 = 47;",
            "r0 += r1;",
            "r1 = 48;",
            "r0 -= r1;",
            "r0 = *(u8*)(r0 + 0);",
            "l0_16:",
            "r0 = 1;",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: lower_oob_arith_test_2
extern "C" fn lower_oob_arith_test_2() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_array_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_17;",
            "r1 = 47;",
            "r0 += r1;",
            "r1 = 48;",
            "r0 -= r1;",
            "r1 = 1;",
            "r0 += r1;",
            "r0 = *(u8*)(r0 + 0);",
            "l0_17:",
            "r0 = 1;",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: lower_oob_arith_test_3
extern "C" fn lower_oob_arith_test_3() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_array_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_18;",
            "r1 = 47;",
            "r0 += r1;",
            "r1 = 47;",
            "r0 -= r1;",
            "r0 = *(u8*)(r0 + 0);",
            "l0_18:",
            "r0 = 1;",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: access_known_scalar_value_ptr_1
extern "C" fn access_known_scalar_value_ptr_1() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_array_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_19;",
            "r1 = 4;",
            "r1 += r0;",
            "r0 = *(u8*)(r1 + 0);",
            "l0_19:",
            "r0 = 1;",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: value_ptr_known_scalar_1
extern "C" fn value_ptr_known_scalar_1() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_array_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_20;",
            "r1 = 4;",
            "r0 += r1;",
            "r1 = *(u8*)(r0 + 0);",
            "l0_20:",
            "r0 = 1;",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: value_ptr_known_scalar_2_1
extern "C" fn value_ptr_known_scalar_2_1() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_array_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_21;",
            "r1 = 49;",
            "r0 += r1;",
            "r1 = *(u8*)(r0 + 0);",
            "l0_21:",
            "r0 = 1;",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: value_ptr_known_scalar_3
extern "C" fn value_ptr_known_scalar_3() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_array_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_22;",
            "r1 = -1;",
            "r0 += r1;",
            "r1 = *(u8*)(r0 + 0);",
            "l0_22:",
            "r0 = 1;",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: value_ptr_known_scalar_4
extern "C" fn value_ptr_known_scalar_4() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_array_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_23;",
            "r1 = 5;",
            "r0 += r1;",
            "r1 = -2;",
            "r0 += r1;",
            "r1 = -1;",
            "r0 += r1;",
            "r1 = *(u8*)(r0 + 0);",
            "l0_23:",
            "r0 = 1;",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: value_ptr_known_scalar_5
extern "C" fn value_ptr_known_scalar_5() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_array_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_24;",
            "r1 = 28;",
            "r1 += r0;",
            "r0 = *(u32*)(r1 + 0);",
            "l0_24:",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: value_ptr_known_scalar_6
extern "C" fn value_ptr_known_scalar_6() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_array_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_25;",
            "r1 = 16;",
            "r0 += r1;",
            "r1 = 12;",
            "r0 += r1;",
            "r0 = *(u32*)(r0 + 0);",
            "l0_25:",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: value_ptr_n_known_scalar
extern "C" fn value_ptr_n_known_scalar() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_array_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_26;",
            "w1 = 0x12345678;",
            "*(u32*)(r0 + 0) = r1;",
            "r0 += 2;",
            "r1 = 2;",
            "r0 -= r1;",
            "r0 = *(u32*)(r0 + 0);",
            "l0_26:",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: unknown_scalar_value_ptr_1
extern "C" fn unknown_scalar_value_ptr_1() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_array_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_27;",
            "r1 = *(u8*)(r0 + 0);",
            "r1 &= 0xf;",
            "r1 += r0;",
            "r0 = *(u8*)(r1 + 0);",
            "l0_27:",
            "r0 = 1;",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: unknown_scalar_value_ptr_2
extern "C" fn unknown_scalar_value_ptr_2() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_array_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_28;",
            "r1 = *(u32*)(r0 + 0);",
            "r1 &= 31;",
            "r1 += r0;",
            "r0 = *(u32*)(r1 + 0);",
            "l0_28:",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: unknown_scalar_value_ptr_3
extern "C" fn unknown_scalar_value_ptr_3() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_array_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_29;",
            "r1 = -1;",
            "r0 += r1;",
            "r1 = 1;",
            "r0 += r1;",
            "r1 = *(u32*)(r0 + 0);",
            "r1 &= 31;",
            "r1 += r0;",
            "r0 = *(u32*)(r1 + 0);",
            "l0_29:",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: unknown_scalar_value_ptr_4
extern "C" fn unknown_scalar_value_ptr_4() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_array_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_30;",
            "r1 = 19;",
            "r0 += r1;",
            "r1 = *(u32*)(r0 + 0);",
            "r1 &= 31;",
            "r1 += r0;",
            "r0 = *(u32*)(r1 + 0);",
            "l0_30:",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: value_ptr_unknown_scalar_1
extern "C" fn value_ptr_unknown_scalar_1() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_array_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_31;",
            "r1 = *(u8*)(r0 + 0);",
            "r1 &= 0xf;",
            "r0 += r1;",
            "r1 = *(u8*)(r0 + 0);",
            "l0_31:",
            "r0 = 1;",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: value_ptr_unknown_scalar_2_1
extern "C" fn value_ptr_unknown_scalar_2_1() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_array_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_32;",
            "r1 = *(u32*)(r0 + 0);",
            "r1 &= 31;",
            "r0 += r1;",
            "r0 = *(u32*)(r0 + 0);",
            "l0_32:",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: value_ptr_unknown_scalar_3
extern "C" fn value_ptr_unknown_scalar_3() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_array_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_33;",
            "r1 = *(u64*)(r0 + 0);",
            "r2 = *(u64*)(r0 + 8);",
            "r3 = *(u64*)(r0 + 16);",
            "r1 &= 0xf;",
            "r3 &= 1;",
            "r3 |= 1;",
            "if r2 > r3 goto l0_33;",
            "r0 += r3;",
            "r0 = *(u8*)(r0 + 0);",
            "r0 = 1;",
            "l1_33:",
            "exit;",
            "l0_33:",
            "r0 = 2;",
            "goto l1_33;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: access_value_ptr_value_ptr_1
extern "C" fn access_value_ptr_value_ptr_1() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_array_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_34;",
            "r0 += r0;",
            "r1 = *(u8*)(r0 + 0);",
            "l0_34:",
            "r0 = 1;",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: access_known_scalar_value_ptr_2
extern "C" fn access_known_scalar_value_ptr_2() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_array_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_35;",
            "r1 = 4;",
            "r1 -= r0;",
            "r0 = *(u8*)(r1 + 0);",
            "l0_35:",
            "r0 = 1;",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: access_value_ptr_known_scalar
extern "C" fn access_value_ptr_known_scalar() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_array_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_36;",
            "r1 = 4;",
            "r0 -= r1;",
            "r1 = *(u8*)(r0 + 0);",
            "l0_36:",
            "r0 = 1;",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: value_ptr_known_scalar_2_2
extern "C" fn value_ptr_known_scalar_2_2() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_array_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_37;",
            "r1 = 6;",
            "r2 = 4;",
            "r0 += r1;",
            "r0 -= r2;",
            "r1 = *(u8*)(r0 + 0);",
            "l0_37:",
            "r0 = 1;",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: access_unknown_scalar_value_ptr
extern "C" fn access_unknown_scalar_value_ptr() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_array_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_38;",
            "r1 = *(u8*)(r0 + 0);",
            "r1 &= 0xf;",
            "r1 -= r0;",
            "r0 = *(u8*)(r1 + 0);",
            "l0_38:",
            "r0 = 1;",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: access_value_ptr_unknown_scalar
extern "C" fn access_value_ptr_unknown_scalar() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_array_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_39;",
            "r1 = *(u8*)(r0 + 0);",
            "r1 &= 0xf;",
            "r0 -= r1;",
            "r1 = *(u8*)(r0 + 0);",
            "l0_39:",
            "r0 = 1;",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: value_ptr_unknown_scalar_2_2
extern "C" fn value_ptr_unknown_scalar_2_2() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_array_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_40;",
            "r1 = *(u8*)(r0 + 0);",
            "r1 &= 0xf;",
            "r1 |= 0x7;",
            "r0 += r1;",
            "r1 = *(u8*)(r0 + 0);",
            "r1 &= 0x7;",
            "r0 -= r1;",
            "r1 = *(u8*)(r0 + 0);",
            "l0_40:",
            "r0 = 1;",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: access_value_ptr_value_ptr_2
extern "C" fn access_value_ptr_value_ptr_2() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_array_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_41;",
            "r0 -= r0;",
            "r1 = *(u8*)(r0 + 0);",
            "l0_41:",
            "r0 = 1;",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: to_leak_tainted_dst_reg
extern "C" fn to_leak_tainted_dst_reg() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_array_48b} ll;",
            "call 1;",
            "if r0 != 0 goto l0_42;",
            "exit;",
            "l0_42:",
            "r2 = r0;",
            "w1 = 0xFFFFFFFF;",
            "w1 = w1;",
            "r2 -= r1;",
            "*(u64*)(r0 + 0) = r2;",
            "r0 = 0;",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: _32bit_pkt_ptr_scalar
extern "C" fn _32bit_pkt_ptr_scalar() {
    unsafe {
        core::arch::asm!(
            "r8 = *(u32*)(r1 + 80);",
            "r7 = *(u32*)(r1 + 76);",
            "r6 = r7;",
            "r6 += 40;",
            "if r6 > r8 goto l0_43;",
            "w4 = w7;",
            "w6 -= w4;",
            "l0_43:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: _32bit_scalar_pkt_ptr
extern "C" fn _32bit_scalar_pkt_ptr() {
    unsafe {
        core::arch::asm!(
            "r8 = *(u32*)(r1 + 80);",
            "r7 = *(u32*)(r1 + 76);",
            "r6 = r7;",
            "r6 += 40;",
            "if r6 > r8 goto l0_44;",
            "w4 = w6;",
            "w4 -= w7;",
            "l0_44:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
