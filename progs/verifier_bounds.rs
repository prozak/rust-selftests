// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_bounds.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_bounds` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: bounds_map_value_variant_1 bounds_map_value_variant_2 subtraction_on_pointers_for_unpriv based_on_zero_extended_mov on_sign_extended_mov_test1 on_sign_extended_mov_test2 var_off_insn_off_test1 var_off_insn_off_test2 of_non_boundary_crossing_range of_boundary_crossing_range_1 of_boundary_crossing_range_2 after_wrapping_32_bit_addition shift_with_oversized_count_operand shift_of_maybe_negative_number shift_with_64_bit_input size_signed_32bit_overflow_test1 size_signed_32bit_overflow_test2 size_signed_32bit_overflow_test3 size_signed_32bit_overflow_test4 _32bit_and_64bit_arithmetic_test1 _32bit_and_64bit_arithmetic_test2 for_wa_0_wb_wa reg_0_reg_xor_1 reg32_0_reg32_xor_1 reg_2_reg_xor_3 reg_any_reg_xor_3 reg32_any_reg32_xor_3 reg_0_reg_xor_3 reg32_0_reg32_xor_3 non_const_xor_src_dst non_const_or_src_dst non_const_mul_regs _32_bit_truncation_test_1 _32_bit_truncation_test_2 crossing_64_bit_signed_boundary_1 crossing_64_bit_signed_boundary_2 bound_greater_than_u32_max crossing_32_bit_signed_boundary_1 crossing_32_bit_signed_boundary_2 reg_not_equal_const reg_equal_const mult_mixed0_sign mult_mixed1_sign mult_sign_bounds mult_no_sign_crossing mult_unsign_ovf mult_sign_ovf add64_full_overflow add64_partial_overflow add32_full_overflow add32_partial_overflow sub64_full_overflow sub64_partial_overflow sub32_full_overflow sub32_partial_overflow jset_range_analysis bounds_deduct_negative_overlap bounds_deduct_positive_overlap bounds_deduct_two_overlaps jne_disagreeing_tnums jeq_disagreeing_tnums condition_jump_on_same_register jset_on_same_register_1 jset_on_same_register_2 jset_on_same_register_3 jset_on_same_register_4 jset_on_same_register_5 bounds_refinement_tnum_umax bounds_refinement_tnum_umin bounds_refinement_tnum_middle bounds_refinement_several_overlaps bounds_refinement_multiple_overlaps signed_unsigned_intersection32_case1 signed_unsigned_intersection32_case2 refinement_32bounds_not_overwriting_64bounds or_scalar_fork_rejects_oob and_scalar_fork_still_works or_scalar_fork_allows_inbounds tnums_equal_impossible_constant deduce64_from_32_before_block_start deduce64_from_32_wrapping_32bit spec_ptr_alu_const_offset range_within_cnum_cross_both_boundaries

use bpf_rs_core::{bpf_map, bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    bounds_map_value_variant_1:
        __description("subtraction bounds (map value) variant 1"),
        __failure,
        __msg("R0 max value is outside of the allowed memory range"),
        __failure_unpriv;
    bounds_map_value_variant_2:
        __description("subtraction bounds (map value) variant 2"),
        __failure,
        __msg("R0 min value is negative, either use unsigned index or do a if (index >=0) check."),
        __msg_unpriv("R1 has unknown scalar with mixed signed bounds");
    subtraction_on_pointers_for_unpriv:
        __description("check subtraction on pointers for unpriv"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R9 pointer -= pointer prohibited"),
        __retval("0");
    based_on_zero_extended_mov:
        __description("bounds check based on zero-extended MOV"),
        __success,
        __success_unpriv,
        __retval("0");
    on_sign_extended_mov_test1:
        __description("bounds check based on sign-extended MOV. test1"),
        __failure,
        __msg("map_value pointer and 4294967295"),
        __failure_unpriv;
    on_sign_extended_mov_test2:
        __description("bounds check based on sign-extended MOV. test2"),
        __failure,
        __msg("R0 min value is outside of the allowed memory range"),
        __failure_unpriv;
    var_off_insn_off_test1:
        __description("bounds check based on reg_off + var_off + insn_off. test1"),
        __failure,
        __msg("map_value pointer offset 1073741822 is not allowed");
    var_off_insn_off_test2:
        __description("bounds check based on reg_off + var_off + insn_off. test2"),
        __failure,
        __msg("value 1073741823");
    of_non_boundary_crossing_range:
        __description("bounds check after truncation of non-boundary-crossing range"),
        __success,
        __success_unpriv,
        __retval("0");
    of_boundary_crossing_range_1:
        __description("bounds check after truncation of boundary-crossing range (1)"),
        __failure,
        __msg("value -4294967168 makes map_value pointer be out of bounds"),
        __failure_unpriv;
    of_boundary_crossing_range_2:
        __description("bounds check after truncation of boundary-crossing range (2)"),
        __failure,
        __msg("value -4294967168 makes map_value pointer be out of bounds"),
        __failure_unpriv;
    after_wrapping_32_bit_addition:
        __description("bounds check after wrapping 32-bit addition"),
        __success,
        __success_unpriv,
        __retval("0");
    shift_with_oversized_count_operand:
        __description("bounds check after shift with oversized count operand"),
        __failure,
        __msg("R0 max value is outside of the allowed memory range"),
        __failure_unpriv;
    shift_of_maybe_negative_number:
        __description("bounds check after right shift of maybe-negative number"),
        __failure,
        __msg("R0 unbounded memory access"),
        __failure_unpriv;
    shift_with_64_bit_input:
        __description("bounds check after 32-bit right shift with 64-bit input"),
        __failure,
        __msg("math between map_value pointer and 4294967294 is not allowed"),
        __failure_unpriv;
    size_signed_32bit_overflow_test1:
        __description("bounds check map access with off+size signed 32bit overflow. test1"),
        __failure,
        __msg("map_value pointer and 2147483646"),
        __failure_unpriv;
    size_signed_32bit_overflow_test2:
        __description("bounds check map access with off+size signed 32bit overflow. test2"),
        __failure,
        __msg("pointer offset 1073741822"),
        __msg_unpriv("R0 pointer arithmetic of map value goes out of range");
    size_signed_32bit_overflow_test3:
        __description("bounds check map access with off+size signed 32bit overflow. test3"),
        __failure,
        __msg("pointer offset -1073741822"),
        __msg_unpriv("R0 pointer arithmetic of map value goes out of range");
    size_signed_32bit_overflow_test4:
        __description("bounds check map access with off+size signed 32bit overflow. test4"),
        __failure,
        __msg("map_value pointer and 1000000000000"),
        __failure_unpriv;
    _32bit_and_64bit_arithmetic_test1:
        __description("bounds check mixed 32bit and 64bit arithmetic. test1"),
        __success,
        __success_unpriv,
        __retval("0"),
        __xlated_unpriv("goto pc+2"),
        __xlated_unpriv("nospec"),
        __xlated_unpriv("goto pc-1"),
        __xlated_unpriv("exit");
    _32bit_and_64bit_arithmetic_test2:
        __description("bounds check mixed 32bit and 64bit arithmetic. test2"),
        __success,
        __success_unpriv,
        __retval("0"),
        __xlated_unpriv("goto pc+2"),
        __xlated_unpriv("nospec"),
        __xlated_unpriv("goto pc-1"),
        __xlated_unpriv("exit");
    for_wa_0_wb_wa:
        __description("assigning 32bit bounds to 64bit for wA = 0, wB = wA"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    reg_0_reg_xor_1:
        __description("bounds check for reg = 0, reg xor 1"),
        __success,
        __success_unpriv,
        __retval("0"),
        __xlated_unpriv("if r1 != 0x0 goto pc+2"),
        __xlated_unpriv("nospec"),
        __xlated_unpriv("goto pc-1"),
        __xlated_unpriv("r0 = 0");
    reg32_0_reg32_xor_1:
        __description("bounds check for reg32 = 0, reg32 xor 1"),
        __success,
        __success_unpriv,
        __retval("0"),
        __xlated_unpriv("if w1 != 0x0 goto pc+2"),
        __xlated_unpriv("nospec"),
        __xlated_unpriv("goto pc-1"),
        __xlated_unpriv("r0 = 0");
    reg_2_reg_xor_3:
        __description("bounds check for reg = 2, reg xor 3"),
        __success,
        __success_unpriv,
        __retval("0"),
        __xlated_unpriv("if r1 > 0x0 goto pc+2"),
        __xlated_unpriv("nospec"),
        __xlated_unpriv("goto pc-1"),
        __xlated_unpriv("r0 = 0");
    reg_any_reg_xor_3:
        __description("bounds check for reg = any, reg xor 3"),
        __failure,
        __msg("invalid access to map value"),
        __msg_unpriv("invalid access to map value");
    reg32_any_reg32_xor_3:
        __description("bounds check for reg32 = any, reg32 xor 3"),
        __failure,
        __msg("invalid access to map value"),
        __msg_unpriv("invalid access to map value");
    reg_0_reg_xor_3:
        __description("bounds check for reg > 0, reg xor 3"),
        __success,
        __success_unpriv,
        __retval("0"),
        __xlated_unpriv("if r1 >= 0x0 goto pc+2"),
        __xlated_unpriv("nospec"),
        __xlated_unpriv("goto pc-1"),
        __xlated_unpriv("r0 = 0");
    reg32_0_reg32_xor_3:
        __description("bounds check for reg32 > 0, reg32 xor 3"),
        __success,
        __success_unpriv,
        __retval("0"),
        __xlated_unpriv("if w1 >= 0x0 goto pc+2"),
        __xlated_unpriv("nospec"),
        __xlated_unpriv("goto pc-1"),
        __xlated_unpriv("r0 = 0");
    non_const_xor_src_dst:
        __description("bounds check for non const xor src dst"),
        __success,
        __log_level("2"),
        __msg("5: (af) r0 ^= r6                      ; R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=431,var_off=(0x0; 0x1af))");
    non_const_or_src_dst:
        __description("bounds check for non const or src dst"),
        __success,
        __log_level("2"),
        __msg("5: (4f) r0 |= r6                      ; R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=431,var_off=(0x0; 0x1af))");
    non_const_mul_regs:
        __description("bounds check for non const mul regs"),
        __success,
        __log_level("2"),
        __msg("5: (2f) r0 *= r6                      ; R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=3825,var_off=(0x0; 0xfff))");
    _32_bit_truncation_test_1:
        __description("bounds checks after 32-bit truncation. test 1"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R0 leaks addr"),
        __retval("0");
    _32_bit_truncation_test_2:
        __description("bounds checks after 32-bit truncation. test 2"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R0 leaks addr"),
        __retval("0");
    crossing_64_bit_signed_boundary_1:
        __description("bound check with JMP_JLT for crossing 64-bit signed boundary"),
        __success,
        __retval("0");
    crossing_64_bit_signed_boundary_2:
        __description("bound check with JMP_JSLT for crossing 64-bit signed boundary"),
        __success,
        __retval("0");
    bound_greater_than_u32_max:
        __description("bound check for loop upper bound greater than U32_MAX"),
        __success,
        __retval("0");
    crossing_32_bit_signed_boundary_1:
        __description("bound check with JMP32_JLT for crossing 32-bit signed boundary"),
        __success,
        __retval("0");
    crossing_32_bit_signed_boundary_2:
        __description("bound check with JMP32_JSLT for crossing 32-bit signed boundary"),
        __success,
        __retval("0");
    reg_not_equal_const:
        __description("bounds check with JMP_NE for reg edge"),
        __success,
        __retval("0");
    reg_equal_const:
        __description("bounds check with JMP_EQ for reg edge"),
        __success,
        __retval("0");
    mult_mixed0_sign:
        __description("multiply mixed sign bounds. test 1"),
        __success,
        __log_level("2"),
        __msg("r6 *= r7 {{.*}}; R6=scalar(smin=umin=0x1bc16d5cd4927ee1,smax=umax=0x1bc16d674ec80000,smax32=0x7ffffeff,var_off=(0x1bc16d4000000000; 0x3ffffffeff))");
    mult_mixed1_sign:
        __description("multiply mixed sign bounds. test 2"),
        __success,
        __log_level("2"),
        __msg("r6 *= r7 {{.*}}; R6=scalar(smin=smin32=-100,smax=smax32=200)");
    mult_sign_bounds:
        __description("multiply negative bounds"),
        __success,
        __log_level("2"),
        __msg("r6 *= r7 {{.*}}; R6=scalar(smin=umin=smin32=umin32=0x3ff280b0,smax=umax=smax32=umax32=0x3fff0001,var_off=(0x3ff00000; 0xf81ff))");
    mult_no_sign_crossing:
        __description("multiply bounds that don't cross signed boundary"),
        __success,
        __log_level("2"),
        __msg("r8 *= r6 {{.*}}; R6=scalar(smin=smin32=0,smax=umax=smax32=umax32=11,var_off=(0x0; 0xb)) R8=scalar(smin=0,smax=umax=0x7b96bb0a94a3a7cd,var_off=(0x0; 0x7fffffffffffffff))");
    mult_unsign_ovf:
        __description("multiplication overflow, result in unbounded reg. test 1"),
        __success,
        __log_level("2"),
        __msg("r6 *= r7 {{.*}}; R6=scalar()");
    mult_sign_ovf:
        __description("multiplication overflow, result in unbounded reg. test 2"),
        __success,
        __log_level("2"),
        __msg("r6 *= r7 {{.*}}; R6=scalar()");
    add64_full_overflow:
        __description("64-bit addition, all outcomes overflow"),
        __success,
        __log_level("2"),
        __msg("5: (0f) r3 += r3 {{.*}} R3=scalar(umin=0x4000000000000000,umax=0xfffffffffffffffe)"),
        __retval("0");
    add64_partial_overflow:
        __description("64-bit addition, partial overflow, result in unbounded reg"),
        __success,
        __log_level("2"),
        __msg("4: (0f) r3 += r3 {{.*}} R3=scalar()"),
        __retval("0");
    add32_full_overflow:
        __description("32-bit addition overflow, all outcomes overflow"),
        __success,
        __log_level("2"),
        __msg("4: (0c) w3 += w3 {{.*}} R3=scalar(smin=umin=umin32=0x40000000,smax=umax=umax32=0xfffffffe,var_off=(0x0; 0xffffffff))"),
        __retval("0");
    add32_partial_overflow:
        __description("32-bit addition, partial overflow, result in unbounded u32 bounds"),
        __success,
        __log_level("2"),
        __msg("4: (0c) w3 += w3 {{.*}} R3=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))"),
        __retval("0");
    sub64_full_overflow:
        __description("64-bit subtraction, all outcomes underflow"),
        __success,
        __log_level("2"),
        __msg("6: (1f) r3 -= r1 {{.*}} R3=scalar(umin=1,umax=0x8000000000000000)"),
        __retval("0");
    sub64_partial_overflow:
        __description("64-bit subtraction, partial overflow, result in unbounded reg"),
        __success,
        __log_level("2"),
        __msg("3: (1f) r3 -= r2 {{.*}} R3=scalar(id=1-1)"),
        __retval("0");
    sub32_full_overflow:
        __description("32-bit subtraction overflow, all outcomes underflow"),
        __success,
        __log_level("2"),
        __msg("5: (1c) w3 -= w1 {{.*}} R3=scalar(smin=umin=umin32=1,smax=umax=umax32=0x80000000,var_off=(0x0; 0xffffffff))"),
        __retval("0");
    sub32_partial_overflow:
        __description("32-bit subtraction, partial overflow, result in unbounded u32 bounds"),
        __success,
        __log_level("2"),
        __msg("3: (1c) w3 -= w2 {{.*}} R3=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))"),
        __retval("0");
    jset_range_analysis:
        __description("dead branch on jset, does not result in invariants violation error"),
        __success,
        __log_level("2"),
        __retval("0");
    bounds_deduct_negative_overlap:
        __description("bounds deduction cross sign boundary, negative overlap"),
        __success,
        __log_level("2"),
        __msg("7: (1f) r0 -= r6 {{.*}} R0=scalar(smin=smin32=-655,smax=smax32=-146,umin=0xfffffffffffffd71,umax=0xffffffffffffff6e,umin32=0xfffffd71,umax32=0xffffff6e,var_off=(0xfffffffffffffc00; 0x3ff))"),
        __retval("0");
    bounds_deduct_positive_overlap:
        __description("bounds deduction cross sign boundary, positive overlap"),
        __success,
        __log_level("2"),
        __msg("3: (2d) if r0 > r1 {{.*}} R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=127,var_off=(0x0; 0x7f))"),
        __retval("0");
    bounds_deduct_two_overlaps:
        __description("bounds deduction cross sign boundary, two overlaps"),
        __failure,
        __msg("3: (2d) if r0 > r1 {{.*}} R0=scalar(smin=smin32=-128,smax=smax32=127)"),
        __msg("frame pointer is read only");
    jne_disagreeing_tnums:
        __description("dead jne branch due to disagreeing tnums"),
        __success,
        __log_level("2");
    jeq_disagreeing_tnums:
        __description("dead jeq branch due to disagreeing tnums"),
        __success,
        __log_level("2");
    condition_jump_on_same_register:
        __description("conditional jump on same register, branch taken"),
        __not_msg("20: (b7) r0 = 1 {{.*}} R0=1"),
        __success,
        __log_level("2"),
        __retval("0");
    jset_on_same_register_1:
        __description("jset on same register, constant value branch taken"),
        __not_msg("7: (b7) r0 = 1 {{.*}} R0=1"),
        __success,
        __log_level("2"),
        __retval("0");
    jset_on_same_register_2:
        __description("jset on same register, scalar value branch taken"),
        __not_msg("12: (b7) r0 = 1 {{.*}} R0=1"),
        __success,
        __log_level("2"),
        __retval("0");
    jset_on_same_register_3:
        __description("jset on same register, scalar value unknown branch 1"),
        __msg("3: (b7) r0 = 0 {{.*}} R0=0"),
        __msg("5: (b7) r0 = 1 {{.*}} R0=1"),
        __success,
        __log_level("2");
    jset_on_same_register_4:
        __description("jset on same register, scalar value unknown branch 2"),
        __msg("4: (b7) r0 = 0 {{.*}} R0=0"),
        __msg("6: (b7) r0 = 1 {{.*}} R0=1"),
        __success,
        __log_level("2");
    jset_on_same_register_5:
        __description("jset on same register, scalar value unknown branch 3"),
        __msg("4: (b7) r0 = 0 {{.*}} R0=0"),
        __msg("6: (b7) r0 = 1 {{.*}} R0=1"),
        __success,
        __log_level("2");
    bounds_refinement_tnum_umax:
        __description("bounds refinement with single-value tnum on umax"),
        __msg("3: (15) if r0 == 0xe0 {{.*}} R0=240"),
        __success,
        __log_level("2");
    bounds_refinement_tnum_umin:
        __description("bounds refinement with single-value tnum on umin"),
        __msg("3: (15) if r0 == 0xf1 {{.*}} R0=225"),
        __success,
        __log_level("2");
    bounds_refinement_tnum_middle:
        __description("bounds refinement with single-value tnum in middle of range"),
        __msg("3: (a5) if r0 < 0x7cf {{.*}} R0=2000"),
        __success,
        __log_level("2");
    bounds_refinement_several_overlaps:
        __description("bounds refinement: several overlaps between tnum and u64"),
        __msg("2: (25) if r0 > 0x1 {{.*}} R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=1,var_off=(0x0; 0x1))"),
        __failure,
        __log_level("2");
    bounds_refinement_multiple_overlaps:
        __description("bounds refinement: multiple overlaps between tnum and u64"),
        __msg("2: (25) if r0 > 0x10 {{.*}} R0=scalar(smin=umin=smin32=umin32=15,smax=umax=smax32=umax32=16,var_off=(0x0; 0x1f))"),
        __failure,
        __log_level("2");
    signed_unsigned_intersection32_case1:
        __success;
    signed_unsigned_intersection32_case2:
        __success;
    refinement_32bounds_not_overwriting_64bounds:
        __description("bounds refinement: 64bits ranges not overwritten by 32bits ranges"),
        __msg("3: (65) if r0 s> 0x2 {{.*}} R0=scalar(smin=0x8000000000000002,smax=2,smin32=umin32=2,smax32=umax32=3,var_off{{.*}}))"),
        __msg("4: (25) if r0 > 0x13 {{.*}} R0=2"),
        __success,
        __log_level("2");
    or_scalar_fork_rejects_oob:
        __description("maybe_fork_scalars: OR with constant rejects OOB"),
        __failure,
        __msg("invalid access to map value");
    and_scalar_fork_still_works:
        __description("maybe_fork_scalars: AND with constant still works"),
        __success,
        __retval("0");
    or_scalar_fork_allows_inbounds:
        __description("maybe_fork_scalars: OR with constant allows in-bounds"),
        __success,
        __retval("0");
    tnums_equal_impossible_constant:
        __description("dead branch: tnums give impossible constant if equal"),
        __success;
    deduce64_from_32_before_block_start:
        __success,
        __flag("BPF_F_TEST_REG_INVARIANTS");
    deduce64_from_32_wrapping_32bit:
        __success,
        __flag("BPF_F_TEST_REG_INVARIANTS");
    spec_ptr_alu_const_offset:
        __success,
        __success_unpriv,
        __flag("BPF_F_TEST_REG_INVARIANTS");
    range_within_cnum_cross_both_boundaries:
        __failure,
        __msg("div by zero"),
        __flag("BPF_F_TEST_STATE_FREQ");
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
// BPF_NAKED: bounds_map_value_variant_1
extern "C" fn bounds_map_value_variant_1() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_0;",
            "r1 = *(u8*)(r0 + 0);",
            "if r1 > 0xff goto l0_0;",
            "r3 = *(u8*)(r0 + 1);",
            "if r3 > 0xff goto l0_0;",
            "r1 -= r3;",
            "r1 >>= 56;",
            "r0 += r1;",
            "r0 = *(u8*)(r0 + 0);",
            "exit;",
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
// BPF_NAKED: bounds_map_value_variant_2
extern "C" fn bounds_map_value_variant_2() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_1;",
            "r1 = *(u8*)(r0 + 0);",
            "if r1 > 0xff goto l0_1;",
            "r3 = *(u8*)(r0 + 1);",
            "if r3 > 0xff goto l0_1;",
            "r1 -= r3;",
            "r0 += r1;",
            "r0 = *(u8*)(r0 + 0);",
            "exit;",
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
// BPF_NAKED: subtraction_on_pointers_for_unpriv
extern "C" fn subtraction_on_pointers_for_unpriv() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "r1 = {map_hash_8b} ll;",
            "r2 = r10;",
            "r2 += -8;",
            "r6 = 9;",
            "*(u64*)(r2 + 0) = r6;",
            "call 1;",
            "r9 = r10;",
            "r9 -= r0;",
            "r1 = {map_hash_8b} ll;",
            "r2 = r10;",
            "r2 += -8;",
            "r6 = 0;",
            "*(u64*)(r2 + 0) = r6;",
            "call 1;",
            "if r0 != 0 goto l0_2;",
            "exit;",
            "l0_2:",
            "*(u64*)(r0 + 0) = r9;",
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
// BPF_NAKED: based_on_zero_extended_mov
extern "C" fn based_on_zero_extended_mov() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_3;",
            "w2 = 0xffffffff;",
            "r2 >>= 32;",
            "r0 += r2;",
            "r0 = *(u8*)(r0 + 0);",
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
// BPF_NAKED: on_sign_extended_mov_test1
extern "C" fn on_sign_extended_mov_test1() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_4;",
            "r2 = 0xffffffff;",
            "r2 >>= 32;",
            "r0 += r2;",
            "r0 = *(u8*)(r0 + 0);",
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
// BPF_NAKED: on_sign_extended_mov_test2
extern "C" fn on_sign_extended_mov_test2() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_5;",
            "r2 = 0xffffffff;",
            "r2 >>= 36;",
            "r0 += r2;",
            "r0 = *(u8*)(r0 + 0);",
            "l0_5:",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: var_off_insn_off_test1
extern "C" fn var_off_insn_off_test1() {
    unsafe {
        core::arch::asm!(
            "r6 = *(u32*)(r1 + 8);",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_6;",
            "r6 &= 1;",
            "r6 += 536870911;",
            "r0 += r6;",
            "r0 += 536870911;",
            "l0_6:",
            "r0 = *(u8*)(r0 + 3);",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: var_off_insn_off_test2
extern "C" fn var_off_insn_off_test2() {
    unsafe {
        core::arch::asm!(
            "r6 = *(u32*)(r1 + 8);",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_7;",
            "r6 &= 1;",
            "r6 += 1073741823;",
            "r0 += r6;",
            "r0 += 536870911;",
            "l0_7:",
            "r0 = *(u8*)(r0 + 3);",
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
// BPF_NAKED: of_non_boundary_crossing_range
extern "C" fn of_non_boundary_crossing_range() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_8;",
            "r1 = *(u8*)(r0 + 0);",
            "r2 = 1;",
            "r2 <<= 36;",
            "r1 += r2;",
            "r1 += 0x7fffffff;",
            "w1 -= 0x7fffffff;",
            "r1 >>= 8;",
            "r0 += r1;",
            "r0 = *(u8*)(r0 + 0);",
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
// BPF_NAKED: of_boundary_crossing_range_1
extern "C" fn of_boundary_crossing_range_1() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_9;",
            "r1 = *(u8*)(r0 + 0);",
            "r1 += 2147483584;",
            "r1 += 2147483584;",
            "w1 += 0;",
            "r1 -= 2147483584;",
            "r1 -= 2147483584;",
            "r0 += r1;",
            "r0 = 0;",
            "l0_9:",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: of_boundary_crossing_range_2
extern "C" fn of_boundary_crossing_range_2() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_10;",
            "r1 = *(u8*)(r0 + 0);",
            "r1 += 2147483584;",
            "r1 += 2147483584;",
            "w1 = w1;",
            "r1 -= 2147483584;",
            "r1 -= 2147483584;",
            "r0 += r1;",
            "r0 = 0;",
            "l0_10:",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: after_wrapping_32_bit_addition
extern "C" fn after_wrapping_32_bit_addition() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_11;",
            "r1 = 0x7fffffff;",
            "r1 += 0x7fffffff;",
            "w1 += 2;",
            "r0 += r1;",
            "r0 = *(u8*)(r0 + 0);",
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
// BPF_NAKED: shift_with_oversized_count_operand
extern "C" fn shift_with_oversized_count_operand() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_12;",
            "r2 = 32;",
            "r1 = 1;",
            "w1 <<= w2;",
            "r1 &= 0xffff;",
            "r0 += r1;",
            "r0 = *(u8*)(r0 + 0);",
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
// BPF_NAKED: shift_of_maybe_negative_number
extern "C" fn shift_of_maybe_negative_number() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_13;",
            "r1 = *(u8*)(r0 + 0);",
            "r1 -= 1;",
            "r1 >>= 8;",
            "r1 >>= 8;",
            "r0 += r1;",
            "r0 = *(u8*)(r0 + 0);",
            "l0_13:",
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
// BPF_NAKED: shift_with_64_bit_input
extern "C" fn shift_with_64_bit_input() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_14;",
            "r1 = 2;",
            "r1 <<= 31;",
            "w1 >>= 31;",
            "w1 -= 2;",
            "r0 += r1;",
            "r0 = 0;",
            "l0_14:",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: size_signed_32bit_overflow_test1
extern "C" fn size_signed_32bit_overflow_test1() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 != 0 goto l0_15;",
            "exit;",
            "l0_15:",
            "r0 += 0x7ffffffe;",
            "r0 = *(u64*)(r0 + 0);",
            "goto l1_15;",
            "l1_15:",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: size_signed_32bit_overflow_test2
extern "C" fn size_signed_32bit_overflow_test2() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 != 0 goto l0_16;",
            "exit;",
            "l0_16:",
            "r0 += 0x1fffffff;",
            "r0 += 0x1fffffff;",
            "r0 += 0x1fffffff;",
            "r0 = *(u64*)(r0 + 0);",
            "goto l1_16;",
            "l1_16:",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: size_signed_32bit_overflow_test3
extern "C" fn size_signed_32bit_overflow_test3() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 != 0 goto l0_17;",
            "exit;",
            "l0_17:",
            "r0 -= 0x1fffffff;",
            "r0 -= 0x1fffffff;",
            "r0 = *(u64*)(r0 + 2);",
            "goto l1_17;",
            "l1_17:",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: size_signed_32bit_overflow_test4
extern "C" fn size_signed_32bit_overflow_test4() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 != 0 goto l0_18;",
            "exit;",
            "l0_18:",
            "r1 = 1000000;",
            "r1 *= 1000000;",
            "r0 += r1;",
            "r0 = *(u64*)(r0 + 2);",
            "goto l1_18;",
            "l1_18:",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: _32bit_and_64bit_arithmetic_test1
extern "C" fn _32bit_and_64bit_arithmetic_test1() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "r1 = -1;",
            "r1 <<= 32;",
            "r1 += 1;",
            "if w1 > 1 goto l0_19;",
            "r1 += 1;",
            "if w1 > 2 goto l0_19;",
            "goto l1_19;",
            "l0_19:",
            "r0 = *(u64*)(r0 - 1);",
            "l1_19:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: _32bit_and_64bit_arithmetic_test2
extern "C" fn _32bit_and_64bit_arithmetic_test2() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "r1 = -1;",
            "r1 <<= 32;",
            "r1 += 1;",
            "r2 = 3;",
            "w1 += 1;",
            "if r1 > r2 goto l0_20;",
            "goto l1_20;",
            "l0_20:",
            "r0 = *(u64*)(r0 - 1);",
            "l1_20:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: for_wa_0_wb_wa
extern "C" fn for_wa_0_wb_wa() {
    unsafe {
        core::arch::asm!(
            "r8 = *(u32*)(r1 + 80);",
            "r7 = *(u32*)(r1 + 76);",
            "w9 = 0;",
            "w2 = w9;",
            "r6 = r7;",
            "r6 += r2;",
            "r3 = r6;",
            "r3 += 8;",
            "if r3 > r8 goto l0_21;",
            "r5 = *(u32*)(r6 + 0);",
            "l0_21:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: reg_0_reg_xor_1
extern "C" fn reg_0_reg_xor_1() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 != 0 goto l0_22;",
            "exit;",
            "l0_22:",
            "r1 = 0;",
            "r1 ^= 1;",
            "if r1 != 0 goto l1_22;",
            "r0 = *(u64*)(r0 + 8);",
            "l1_22:",
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
// BPF_NAKED: reg32_0_reg32_xor_1
extern "C" fn reg32_0_reg32_xor_1() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 != 0 goto l0_23;",
            "exit;",
            "l0_23:",
            "w1 = 0;",
            "w1 ^= 1;",
            "if w1 != 0 goto l1_23;",
            "r0 = *(u64*)(r0 + 8);",
            "l1_23:",
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
// BPF_NAKED: reg_2_reg_xor_3
extern "C" fn reg_2_reg_xor_3() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 != 0 goto l0_24;",
            "exit;",
            "l0_24:",
            "r1 = 2;",
            "r1 ^= 3;",
            "if r1 > 0 goto l1_24;",
            "r0 = *(u64*)(r0 + 8);",
            "l1_24:",
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
// BPF_NAKED: reg_any_reg_xor_3
extern "C" fn reg_any_reg_xor_3() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 != 0 goto l0_25;",
            "exit;",
            "l0_25:",
            "r1 = *(u64*)(r0 + 0);",
            "r1 ^= 3;",
            "if r1 != 0 goto l1_25;",
            "r0 = *(u64*)(r0 + 8);",
            "l1_25:",
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
// BPF_NAKED: reg32_any_reg32_xor_3
extern "C" fn reg32_any_reg32_xor_3() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 != 0 goto l0_26;",
            "exit;",
            "l0_26:",
            "r1 = *(u64*)(r0 + 0);",
            "w1 ^= 3;",
            "if w1 != 0 goto l1_26;",
            "r0 = *(u64*)(r0 + 8);",
            "l1_26:",
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
// BPF_NAKED: reg_0_reg_xor_3
extern "C" fn reg_0_reg_xor_3() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 != 0 goto l0_27;",
            "exit;",
            "l0_27:",
            "r1 = *(u64*)(r0 + 0);",
            "if r1 <= 0 goto l1_27;",
            "r1 ^= 3;",
            "if r1 >= 0 goto l1_27;",
            "r0 = *(u64*)(r0 + 8);",
            "l1_27:",
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
// BPF_NAKED: reg32_0_reg32_xor_3
extern "C" fn reg32_0_reg32_xor_3() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 != 0 goto l0_28;",
            "exit;",
            "l0_28:",
            "r1 = *(u64*)(r0 + 0);",
            "if w1 <= 0 goto l1_28;",
            "w1 ^= 3;",
            "if w1 >= 0 goto l1_28;",
            "r0 = *(u64*)(r0 + 8);",
            "l1_28:",
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
// BPF_NAKED: non_const_xor_src_dst
extern "C" fn non_const_xor_src_dst() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r6 = r0;",
            "call 7;",
            "r6 &= 0xaf;",
            "r0 &= 0x1a0;",
            "r0 ^= r6;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: non_const_or_src_dst
extern "C" fn non_const_or_src_dst() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r6 = r0;",
            "call 7;",
            "r6 &= 0xaf;",
            "r0 &= 0x1a0;",
            "r0 |= r6;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: non_const_mul_regs
extern "C" fn non_const_mul_regs() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r6 = r0;",
            "call 7;",
            "r6 &= 0xff;",
            "r0 &= 0x0f;",
            "r0 *= r6;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: _32_bit_truncation_test_1
extern "C" fn _32_bit_truncation_test_1() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_29;",
            "r1 = *(u32*)(r0 + 0);",
            "if r1 == 0 goto l1_29;",
            "if r1 > 0x7fffffff goto l0_29;",
            "l1_29:",
            "r0 = 0;",
            "l0_29:",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: _32_bit_truncation_test_2
extern "C" fn _32_bit_truncation_test_2() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_30;",
            "r1 = *(u32*)(r0 + 0);",
            "if r1 s< 1 goto l1_30;",
            "if w1 s< 0 goto l0_30;",
            "l1_30:",
            "r0 = 0;",
            "l0_30:",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: crossing_64_bit_signed_boundary_1
extern "C" fn crossing_64_bit_signed_boundary_1() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 1;",
            "if r1 > r3 goto l0_31;",
            "r1 = *(u8*)(r2 + 0);",
            "r0 = 0x7fffffffffffff10 ll;",
            "r1 += r0;",
            "r0 = 0x8000000000000000 ll;",
            "l1_31:",
            "r0 += 1;",
            "if r0 < r1 goto l1_31;",
            "l0_31:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: crossing_64_bit_signed_boundary_2
extern "C" fn crossing_64_bit_signed_boundary_2() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 1;",
            "if r1 > r3 goto l0_32;",
            "r1 = *(u8*)(r2 + 0);",
            "r0 = 0x7fffffffffffff10 ll;",
            "r1 += r0;",
            "r2 = 0x8000000000000fff ll;",
            "r0 = 0x8000000000000000 ll;",
            "l1_32:",
            "r0 += 1;",
            "if r0 s> r2 goto l0_32;",
            "if r0 s< r1 goto l1_32;",
            "r0 = 1;",
            "exit;",
            "l0_32:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bound_greater_than_u32_max
extern "C" fn bound_greater_than_u32_max() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 1;",
            "if r1 > r3 goto l0_33;",
            "r1 = *(u8*)(r2 + 0);",
            "r0 = 0x100000000 ll;",
            "r1 += r0;",
            "r0 = 0x100000000 ll;",
            "l1_33:",
            "r0 += 1;",
            "if r0 < r1 goto l1_33;",
            "l0_33:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: crossing_32_bit_signed_boundary_1
extern "C" fn crossing_32_bit_signed_boundary_1() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 1;",
            "if r1 > r3 goto l0_34;",
            "r1 = *(u8*)(r2 + 0);",
            "w0 = 0x7fffff10;",
            "w1 += w0;",
            "w0 = 0x80000000;",
            "l1_34:",
            "w0 += 1;",
            "if w0 < w1 goto l1_34;",
            "l0_34:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: crossing_32_bit_signed_boundary_2
extern "C" fn crossing_32_bit_signed_boundary_2() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 1;",
            "if r1 > r3 goto l0_35;",
            "r1 = *(u8*)(r2 + 0);",
            "w0 = 0x7fffff10;",
            "w1 += w0;",
            "w2 = 0x80000fff;",
            "w0 = 0x80000000;",
            "l1_35:",
            "w0 += 1;",
            "if w0 s> w2 goto l0_35;",
            "if w0 s< w1 goto l1_35;",
            "r0 = 1;",
            "exit;",
            "l0_35:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: reg_not_equal_const
extern "C" fn reg_not_equal_const() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "call 7;",
            "r4 = r0;",
            "r4 &= 7;",
            "if r4 != 0 goto l0_36;",
            "r0 = 0;",
            "exit;",
            "l0_36:",
            "r1 = r6;",
            "r2 = 0;",
            "r3 = r10;",
            "r3 += -8;",
            "r5 = 0;",
            "call 9;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: reg_equal_const
extern "C" fn reg_equal_const() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "call 7;",
            "r4 = r0;",
            "r4 &= 7;",
            "if r4 == 0 goto l0_37;",
            "r1 = r6;",
            "r2 = 0;",
            "r3 = r10;",
            "r3 += -8;",
            "r5 = 0;",
            "call 9;",
            "l0_37:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mult_mixed0_sign
extern "C" fn mult_mixed0_sign() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r6 = r0;",
            "call 7;",
            "r7 = r0;",
            "r6 &= 0xf;",
            "r6 -= 1000000000;",
            "r7 &= 0xf;",
            "r7 -= 2000000000;",
            "r6 *= r7;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mult_mixed1_sign
extern "C" fn mult_mixed1_sign() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r6 = r0;",
            "call 7;",
            "r7 = r0;",
            "r6 &= 0xf;",
            "r6 -= 0xa;",
            "r7 &= 0xf;",
            "r7 -= 0x14;",
            "r6 *= r7;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mult_sign_bounds
extern "C" fn mult_sign_bounds() {
    unsafe {
        core::arch::asm!(
            "r8 = 0x7fff;",
            "call 7;",
            "r6 = r0;",
            "call 7;",
            "r7 = r0;",
            "r6 &= 0xa;",
            "r6 -= r8;",
            "r7 &= 0xf;",
            "r7 -= r8;",
            "r6 *= r7;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mult_no_sign_crossing
extern "C" fn mult_no_sign_crossing() {
    unsafe {
        core::arch::asm!(
            "r6 = 0xb;",
            "r8 = 0xb3c3f8c99262687 ll;",
            "call 7;",
            "r7 = r0;",
            "r6 &= r7;",
            "r8 *= r6;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mult_unsign_ovf
extern "C" fn mult_unsign_ovf() {
    unsafe {
        core::arch::asm!(
            "r8 = 0x7ffffffffff ll;",
            "call 7;",
            "r6 = r0;",
            "call 7;",
            "r7 = r0;",
            "r6 &= 0x7fffffff;",
            "r7 &= r8;",
            "r6 *= r7;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mult_sign_ovf
extern "C" fn mult_sign_ovf() {
    unsafe {
        core::arch::asm!(
            "r8 = 0x7ffffffff ll;",
            "call 7;",
            "r6 = r0;",
            "call 7;",
            "r7 = r0;",
            "r6 &= 0xa;",
            "r6 -= r8;",
            "r7 &= 0x7fffffff;",
            "r6 *= r7;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: add64_full_overflow
extern "C" fn add64_full_overflow() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r4 = r0;",
            "r3 = 0xa000000000000000 ll;",
            "r3 |= r4;",
            "r3 += r3;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: add64_partial_overflow
extern "C" fn add64_partial_overflow() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r4 = r0;",
            "r3 = 2;",
            "r3 |= r4;",
            "r3 += r3;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: add32_full_overflow
extern "C" fn add32_full_overflow() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w4 = w0;",
            "w3 = 0xa0000000;",
            "w3 |= w4;",
            "w3 += w3;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: add32_partial_overflow
extern "C" fn add32_partial_overflow() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w4 = w0;",
            "w3 = 2;",
            "w3 |= w4;",
            "w3 += w3;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sub64_full_overflow
extern "C" fn sub64_full_overflow() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = r0;",
            "r2 = 0x8000000000000000 ll;",
            "r1 |= r2;",
            "r3 = 0;",
            "r3 -= r1;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sub64_partial_overflow
extern "C" fn sub64_partial_overflow() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r3 = r0;",
            "r2 = 1;",
            "r3 -= r2;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sub32_full_overflow
extern "C" fn sub32_full_overflow() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w1 = w0;",
            "w2 = 0x80000000;",
            "w1 |= w2;",
            "w3 = 0;",
            "w3 -= w1;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sub32_partial_overflow
extern "C" fn sub32_partial_overflow() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w3 = w0;",
            "w2 = 1;",
            "w3 -= w2;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jset_range_analysis
extern "C" fn jset_range_analysis() {
    unsafe {
        core::arch::asm!(
            "call 122;",
            "if r0 == 0 goto l0_38;",
            "if r0 & 0xffffffff goto +0;",
            "l0_38:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bounds_deduct_negative_overlap
extern "C" fn bounds_deduct_negative_overlap() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w3 = w0;",
            "w6 = (s8)w0;",
            "r0 = (s8)r0;",
            "if w6 >= 0xf0000000 goto l0_39;",
            "r0 += r6;",
            "r6 += 400;",
            "r0 -= r6;",
            "if r3 < r0 goto l0_39;",
            "l0_39:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bounds_deduct_positive_overlap
extern "C" fn bounds_deduct_positive_overlap() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 = (s8)r0;",
            "r1 = 0xffffffffffffff00;",
            "if r0 > r1 goto l0_40;",
            "if r0 < 128 goto l0_40;",
            "r10 = 0;",
            "l0_40:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bounds_deduct_two_overlaps
extern "C" fn bounds_deduct_two_overlaps() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 = (s8)r0;",
            "r1 = 0xffffffffffffff80;",
            "if r0 > r1 goto l0_41;",
            "if r0 < 128 goto l0_41;",
            "r10 = 0;",
            "l0_41:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jne_disagreeing_tnums
extern "C" fn jne_disagreeing_tnums(_ctx: *mut c_void) {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w0 = w0;",
            "r0 >>= 30;",
            "r0 <<= 30;",
            "r1 = r0;",
            "r1 += 1024;",
            "if r1 != r0 goto +1;",
            "r10 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jeq_disagreeing_tnums
extern "C" fn jeq_disagreeing_tnums(_ctx: *mut c_void) {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w0 = w0;",
            "r0 >>= 30;",
            "r0 <<= 30;",
            "r1 = r0;",
            "r1 += 1024;",
            "if r1 == r0 goto +1;",
            "exit;",
            "r10 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: condition_jump_on_same_register
extern "C" fn condition_jump_on_same_register(_ctx: *mut c_void) {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w8 = 0x80000000;",
            "r0 &= r8;",
            "if r0 == r0 goto +1;",
            "goto l1_42;",
            "if r0 >= r0 goto +1;",
            "goto l1_42;",
            "if r0 s>= r0 goto +1;",
            "goto l1_42;",
            "if r0 <= r0 goto +1;",
            "goto l1_42;",
            "if r0 s<= r0 goto +1;",
            "goto l1_42;",
            "if r0 != r0 goto l1_42;",
            "if r0 > r0 goto l1_42;",
            "if r0 s> r0 goto l1_42;",
            "if r0 < r0 goto l1_42;",
            "if r0 s< r0 goto l1_42;",
            "l0_42:",
            "r0 = 0;",
            "exit;",
            "l1_42:",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jset_on_same_register_1
extern "C" fn jset_on_same_register_1(_ctx: *mut c_void) {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "if r0 & r0 goto l1_43;",
            "r0 = 1;",
            "if r0 & r0 goto +1;",
            "goto l1_43;",
            "l0_43:",
            "r0 = 0;",
            "exit;",
            "l1_43:",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jset_on_same_register_2
extern "C" fn jset_on_same_register_2(_ctx: *mut c_void) {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 0x1;",
            "r0 += 1;",
            "if r0 & r0 goto +1;",
            "goto l1_44;",
            "call 7;",
            "r0 &= 0x1;",
            "r0 -= 2;",
            "if r0 & r0 goto +1;",
            "goto l1_44;",
            "l0_44:",
            "r0 = 0;",
            "exit;",
            "l1_44:",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jset_on_same_register_3
extern "C" fn jset_on_same_register_3(_ctx: *mut c_void) {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 0x1;",
            "if r0 & r0 goto l1_45;",
            "l0_45:",
            "r0 = 0;",
            "exit;",
            "l1_45:",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jset_on_same_register_4
extern "C" fn jset_on_same_register_4(_ctx: *mut c_void) {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 0x1;",
            "r0 -= 1;",
            "if r0 & r0 goto l1_46;",
            "l0_46:",
            "r0 = 0;",
            "exit;",
            "l1_46:",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jset_on_same_register_5
extern "C" fn jset_on_same_register_5(_ctx: *mut c_void) {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 0x2;",
            "r0 -= 1;",
            "if r0 & r0 goto l1_47;",
            "l0_47:",
            "r0 = 0;",
            "exit;",
            "l1_47:",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bounds_refinement_tnum_umax
extern "C" fn bounds_refinement_tnum_umax(_ctx: *mut c_void) {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 |= 0xe0;",
            "r0 &= 0xf0;",
            "if r0 == 0xe0 goto +2;",
            "if r0 == 0xf0 goto +1;",
            "r10 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bounds_refinement_tnum_umin
extern "C" fn bounds_refinement_tnum_umin(_ctx: *mut c_void) {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 |= 0xe1;",
            "r0 &= 0xf1;",
            "if r0 == 0xf1 goto +2;",
            "if r0 == 0xe1 goto +1;",
            "r10 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bounds_refinement_tnum_middle
extern "C" fn bounds_refinement_tnum_middle(_ctx: *mut c_void) {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "if r0 & 0x0f goto +4;",
            "if r0 > 0x7df goto +3;",
            "if r0 < 0x7cf goto +2;",
            "if r0 == 0x7d0 goto +1;",
            "r10 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bounds_refinement_several_overlaps
extern "C" fn bounds_refinement_several_overlaps(_ctx: *mut c_void) {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "if r0 < 0 goto +3;",
            "if r0 > 1 goto +2;",
            "if r0 == 1 goto +1;",
            "r10 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bounds_refinement_multiple_overlaps
extern "C" fn bounds_refinement_multiple_overlaps(_ctx: *mut c_void) {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "if r0 < 0xf goto +3;",
            "if r0 > 0x10 goto +2;",
            "if r0 == 0x10 goto +1;",
            "r10 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: signed_unsigned_intersection32_case1
extern "C" fn signed_unsigned_intersection32_case1(_ctx: *mut c_void) {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w0 &= 0xffffffff;",
            "if w0 < 0x3 goto 1f;",
            "if w0 s> 0x1 goto 1f;",
            "if w0 s< 0x0 goto 1f;",
            "r10 = 0;",
            "1:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: signed_unsigned_intersection32_case2
extern "C" fn signed_unsigned_intersection32_case2(_ctx: *mut c_void) {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w0 &= 0xffffffff;",
            "if w0 > 0x80000003 goto 1f;",
            "if w0 s< -3 goto 1f;",
            "if w0 s> 5 goto 1f;",
            "if w0 <= 5 goto 1f;",
            "r10 = 0;",
            "1:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: refinement_32bounds_not_overwriting_64bounds
extern "C" fn refinement_32bounds_not_overwriting_64bounds(_ctx: *mut c_void) {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "if w0 < 2 goto +5;",
            "if w0 > 3 goto +4;",
            "if r0 s> 2 goto +3;",
            "if r0 > 19 goto +2;",
            "if r0 == 2 goto +1;",
            "r10 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: or_scalar_fork_rejects_oob
extern "C" fn or_scalar_fork_rejects_oob() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_48;",
            "r9 = r0;",
            "r6 = *(u64*)(r9 + 0);",
            "r6 s>>= 63;",
            "r6 |= 8;",
            "if r6 s< 0 goto l0_48;",
            "r9 += r6;",
            "r0 = *(u8*)(r9 + 0);",
            "l0_48:",
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
// BPF_NAKED: and_scalar_fork_still_works
extern "C" fn and_scalar_fork_still_works() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_49;",
            "r9 = r0;",
            "r6 = *(u64*)(r9 + 0);",
            "r6 s>>= 63;",
            "r6 &= 4;",
            "if r6 s< 0 goto l0_49;",
            "r9 += r6;",
            "r0 = *(u8*)(r9 + 0);",
            "l0_49:",
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
// BPF_NAKED: or_scalar_fork_allows_inbounds
extern "C" fn or_scalar_fork_allows_inbounds() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_50;",
            "r9 = r0;",
            "r6 = *(u64*)(r9 + 0);",
            "r6 s>>= 63;",
            "r6 |= 4;",
            "if r6 s< 0 goto l0_50;",
            "r9 += r6;",
            "r0 = *(u8*)(r9 + 0);",
            "l0_50:",
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
// BPF_NAKED: tnums_equal_impossible_constant
extern "C" fn tnums_equal_impossible_constant(_ctx: *mut c_void) {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r5 = r0;",
            "r5 &= 0xfffffffffffffffc;",
            "r7 = r0;",
            "r7 &= 0x1;",
            "r7 += -43;",
            "if w5 != w7 goto +1;",
            "r10 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deduce64_from_32_before_block_start
extern "C" fn deduce64_from_32_before_block_start() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = 0x100000008 ll;",
            "if r0 < r1 goto 2f;",
            "r1 = 0x300000001 ll;",
            "if r0 > r1 goto 2f;",
            "if w0 < 2 goto 2f;",
            "if w0 > 5 goto 2f;",
            "r2 = 0x200000002 ll;",
            "r3 = 0x200000005 ll;",
            "if r0 >= r2 goto 1f;",
            "r10 = 0;",
            "1:",
            "if r0 <= r3 goto 2f;",
            "r10 = 0;",
            "2:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deduce64_from_32_wrapping_32bit
extern "C" fn deduce64_from_32_wrapping_32bit() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = 0x100000006 ll;",
            "if r0 < r1 goto 2f;",
            "r1 = 0x2ffffffef ll;",
            "if r0 > r1 goto 2f;",
            "if w0 s< -16 goto 2f;",
            "if w0 s> 5 goto 2f;",
            "r1 = 0x1fffffff0 ll;",
            "r2 = 0x200000005 ll;",
            "if r0 >= r1 goto 1f;",
            "r10 = 0;",
            "1:",
            "if r0 <= r2 goto 2f;",
            "r10 = 0;",
            "2:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: spec_ptr_alu_const_offset
extern "C" fn spec_ptr_alu_const_offset() {
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
            "if r0 == 0 goto l0_51;",
            "r1 = *(u64*)(r10 - 16);",
            "r2 = 0x40000000;",
            "if r1 > r2 goto l0_51;",
            "if r1 s> 1 goto l0_51;",
            "r0 += r1;",
            "r9 = r0;",
            "*(u8*)(r0 + 0) = r1;",
            "l0_51:",
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
// BPF_NAKED: range_within_cnum_cross_both_boundaries
extern "C" fn range_within_cnum_cross_both_boundaries() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = 0x80000020;",
            "if r0 > r1 goto 1f;",
            "r0 += 0x7FFFFFF0;",
            "goto 2f;",
            "1:",
            "call 7;",
            "if r0 < 0x100 goto 3f;",
            "if r0 > 0x200 goto 3f;",
            "2:",
            "if r0 != 0x100 goto 3f;",
            "r0 /= 0;",
            "3:",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
