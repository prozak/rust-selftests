// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_sdiv.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_sdiv` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: sdiv32_non_zero_imm_1 sdiv32_non_zero_imm_2 sdiv32_non_zero_imm_3 sdiv32_non_zero_imm_4 sdiv32_non_zero_imm_5 sdiv32_non_zero_imm_6 sdiv32_non_zero_imm_7 sdiv32_non_zero_imm_8 sdiv32_non_zero_reg_1 sdiv32_non_zero_reg_2 sdiv32_non_zero_reg_3 sdiv32_non_zero_reg_4 sdiv32_non_zero_reg_5 sdiv32_non_zero_reg_6 sdiv32_non_zero_reg_7 sdiv32_non_zero_reg_8 sdiv64_non_zero_imm_1 sdiv64_non_zero_imm_2 sdiv64_non_zero_imm_3 sdiv64_non_zero_imm_4 sdiv64_non_zero_imm_5 sdiv64_non_zero_imm_6 sdiv64_non_zero_reg_1 sdiv64_non_zero_reg_2 sdiv64_non_zero_reg_3 sdiv64_non_zero_reg_4 sdiv64_non_zero_reg_5 sdiv64_non_zero_reg_6 smod32_non_zero_imm_1 smod32_non_zero_imm_2 smod32_non_zero_imm_3 smod32_non_zero_imm_4 smod32_non_zero_imm_5 smod32_non_zero_imm_6 smod32_non_zero_reg_1 smod32_non_zero_reg_2 smod32_non_zero_reg_3 smod32_non_zero_reg_4 smod32_non_zero_reg_5 smod32_non_zero_reg_6 smod64_non_zero_imm_1 smod64_non_zero_imm_2 smod64_non_zero_imm_3 smod64_non_zero_imm_4 smod64_non_zero_imm_5 smod64_non_zero_imm_6 smod64_non_zero_imm_7 smod64_non_zero_imm_8 smod64_non_zero_reg_1 smod64_non_zero_reg_2 smod64_non_zero_reg_3 smod64_non_zero_reg_4 smod64_non_zero_reg_5 smod64_non_zero_reg_6 smod64_non_zero_reg_7 smod64_non_zero_reg_8 sdiv32_zero_divisor sdiv64_zero_divisor smod32_zero_divisor smod64_zero_divisor sdiv64_overflow_rr sdiv64_rr_divisor_neg_1 sdiv64_overflow_ri sdiv64_ri_divisor_neg_1 sdiv32_overflow_rr sdiv32_rr_divisor_neg_1 sdiv32_overflow_ri sdiv32_ri_divisor_neg_1 smod64_overflow_rr smod64_rr_divisor_neg_1 smod64_overflow_ri smod64_ri_divisor_neg_1 smod32_overflow_rr smod32_rr_divisor_neg_1 smod32_overflow_ri smod32_ri_divisor_neg_1 sdiv32_int_min_div_2_imm sdiv32_int_min_div_2_reg smod32_int_min_mod_2_imm smod32_int_min_mod_neg2_imm

use bpf_rs_core::{bpf_object, test_tags};

test_tags! {
    sdiv32_non_zero_imm_1:
        __description("SDIV32, non-zero imm divisor, check 1"),
        __success,
        __success_unpriv,
        __retval("-20");
    sdiv32_non_zero_imm_2:
        __description("SDIV32, non-zero imm divisor, check 2"),
        __success,
        __success_unpriv,
        __retval("-20");
    sdiv32_non_zero_imm_3:
        __description("SDIV32, non-zero imm divisor, check 3"),
        __success,
        __success_unpriv,
        __retval("20");
    sdiv32_non_zero_imm_4:
        __description("SDIV32, non-zero imm divisor, check 4"),
        __success,
        __success_unpriv,
        __retval("-21");
    sdiv32_non_zero_imm_5:
        __description("SDIV32, non-zero imm divisor, check 5"),
        __success,
        __success_unpriv,
        __retval("-21");
    sdiv32_non_zero_imm_6:
        __description("SDIV32, non-zero imm divisor, check 6"),
        __success,
        __success_unpriv,
        __retval("21");
    sdiv32_non_zero_imm_7:
        __description("SDIV32, non-zero imm divisor, check 7"),
        __success,
        __success_unpriv,
        __retval("21");
    sdiv32_non_zero_imm_8:
        __description("SDIV32, non-zero imm divisor, check 8"),
        __success,
        __success_unpriv,
        __retval("20");
    sdiv32_non_zero_reg_1:
        __description("SDIV32, non-zero reg divisor, check 1"),
        __success,
        __success_unpriv,
        __retval("-20");
    sdiv32_non_zero_reg_2:
        __description("SDIV32, non-zero reg divisor, check 2"),
        __success,
        __success_unpriv,
        __retval("-20");
    sdiv32_non_zero_reg_3:
        __description("SDIV32, non-zero reg divisor, check 3"),
        __success,
        __success_unpriv,
        __retval("20");
    sdiv32_non_zero_reg_4:
        __description("SDIV32, non-zero reg divisor, check 4"),
        __success,
        __success_unpriv,
        __retval("-21");
    sdiv32_non_zero_reg_5:
        __description("SDIV32, non-zero reg divisor, check 5"),
        __success,
        __success_unpriv,
        __retval("-21");
    sdiv32_non_zero_reg_6:
        __description("SDIV32, non-zero reg divisor, check 6"),
        __success,
        __success_unpriv,
        __retval("21");
    sdiv32_non_zero_reg_7:
        __description("SDIV32, non-zero reg divisor, check 7"),
        __success,
        __success_unpriv,
        __retval("21");
    sdiv32_non_zero_reg_8:
        __description("SDIV32, non-zero reg divisor, check 8"),
        __success,
        __success_unpriv,
        __retval("20");
    sdiv64_non_zero_imm_1:
        __description("SDIV64, non-zero imm divisor, check 1"),
        __success,
        __success_unpriv,
        __retval("-20");
    sdiv64_non_zero_imm_2:
        __description("SDIV64, non-zero imm divisor, check 2"),
        __success,
        __success_unpriv,
        __retval("-20");
    sdiv64_non_zero_imm_3:
        __description("SDIV64, non-zero imm divisor, check 3"),
        __success,
        __success_unpriv,
        __retval("20");
    sdiv64_non_zero_imm_4:
        __description("SDIV64, non-zero imm divisor, check 4"),
        __success,
        __success_unpriv,
        __retval("-21");
    sdiv64_non_zero_imm_5:
        __description("SDIV64, non-zero imm divisor, check 5"),
        __success,
        __success_unpriv,
        __retval("-21");
    sdiv64_non_zero_imm_6:
        __description("SDIV64, non-zero imm divisor, check 6"),
        __success,
        __success_unpriv,
        __retval("21");
    sdiv64_non_zero_reg_1:
        __description("SDIV64, non-zero reg divisor, check 1"),
        __success,
        __success_unpriv,
        __retval("-20");
    sdiv64_non_zero_reg_2:
        __description("SDIV64, non-zero reg divisor, check 2"),
        __success,
        __success_unpriv,
        __retval("-20");
    sdiv64_non_zero_reg_3:
        __description("SDIV64, non-zero reg divisor, check 3"),
        __success,
        __success_unpriv,
        __retval("20");
    sdiv64_non_zero_reg_4:
        __description("SDIV64, non-zero reg divisor, check 4"),
        __success,
        __success_unpriv,
        __retval("-21");
    sdiv64_non_zero_reg_5:
        __description("SDIV64, non-zero reg divisor, check 5"),
        __success,
        __success_unpriv,
        __retval("-21");
    sdiv64_non_zero_reg_6:
        __description("SDIV64, non-zero reg divisor, check 6"),
        __success,
        __success_unpriv,
        __retval("21");
    smod32_non_zero_imm_1:
        __description("SMOD32, non-zero imm divisor, check 1"),
        __success,
        __success_unpriv,
        __retval("-1");
    smod32_non_zero_imm_2:
        __description("SMOD32, non-zero imm divisor, check 2"),
        __success,
        __success_unpriv,
        __retval("1");
    smod32_non_zero_imm_3:
        __description("SMOD32, non-zero imm divisor, check 3"),
        __success,
        __success_unpriv,
        __retval("-1");
    smod32_non_zero_imm_4:
        __description("SMOD32, non-zero imm divisor, check 4"),
        __success,
        __success_unpriv,
        __retval("0");
    smod32_non_zero_imm_5:
        __description("SMOD32, non-zero imm divisor, check 5"),
        __success,
        __success_unpriv,
        __retval("0");
    smod32_non_zero_imm_6:
        __description("SMOD32, non-zero imm divisor, check 6"),
        __success,
        __success_unpriv,
        __retval("0");
    smod32_non_zero_reg_1:
        __description("SMOD32, non-zero reg divisor, check 1"),
        __success,
        __success_unpriv,
        __retval("-1");
    smod32_non_zero_reg_2:
        __description("SMOD32, non-zero reg divisor, check 2"),
        __success,
        __success_unpriv,
        __retval("1");
    smod32_non_zero_reg_3:
        __description("SMOD32, non-zero reg divisor, check 3"),
        __success,
        __success_unpriv,
        __retval("-1");
    smod32_non_zero_reg_4:
        __description("SMOD32, non-zero reg divisor, check 4"),
        __success,
        __success_unpriv,
        __retval("0");
    smod32_non_zero_reg_5:
        __description("SMOD32, non-zero reg divisor, check 5"),
        __success,
        __success_unpriv,
        __retval("0");
    smod32_non_zero_reg_6:
        __description("SMOD32, non-zero reg divisor, check 6"),
        __success,
        __success_unpriv,
        __retval("0");
    smod64_non_zero_imm_1:
        __description("SMOD64, non-zero imm divisor, check 1"),
        __success,
        __success_unpriv,
        __retval("-1");
    smod64_non_zero_imm_2:
        __description("SMOD64, non-zero imm divisor, check 2"),
        __success,
        __success_unpriv,
        __retval("1");
    smod64_non_zero_imm_3:
        __description("SMOD64, non-zero imm divisor, check 3"),
        __success,
        __success_unpriv,
        __retval("-1");
    smod64_non_zero_imm_4:
        __description("SMOD64, non-zero imm divisor, check 4"),
        __success,
        __success_unpriv,
        __retval("0");
    smod64_non_zero_imm_5:
        __description("SMOD64, non-zero imm divisor, check 5"),
        __success,
        __success_unpriv,
        __retval("-0");
    smod64_non_zero_imm_6:
        __description("SMOD64, non-zero imm divisor, check 6"),
        __success,
        __success_unpriv,
        __retval("0");
    smod64_non_zero_imm_7:
        __description("SMOD64, non-zero imm divisor, check 7"),
        __success,
        __success_unpriv,
        __retval("0");
    smod64_non_zero_imm_8:
        __description("SMOD64, non-zero imm divisor, check 8"),
        __success,
        __success_unpriv,
        __retval("1");
    smod64_non_zero_reg_1:
        __description("SMOD64, non-zero reg divisor, check 1"),
        __success,
        __success_unpriv,
        __retval("-1");
    smod64_non_zero_reg_2:
        __description("SMOD64, non-zero reg divisor, check 2"),
        __success,
        __success_unpriv,
        __retval("1");
    smod64_non_zero_reg_3:
        __description("SMOD64, non-zero reg divisor, check 3"),
        __success,
        __success_unpriv,
        __retval("-1");
    smod64_non_zero_reg_4:
        __description("SMOD64, non-zero reg divisor, check 4"),
        __success,
        __success_unpriv,
        __retval("0");
    smod64_non_zero_reg_5:
        __description("SMOD64, non-zero reg divisor, check 5"),
        __success,
        __success_unpriv,
        __retval("0");
    smod64_non_zero_reg_6:
        __description("SMOD64, non-zero reg divisor, check 6"),
        __success,
        __success_unpriv,
        __retval("0");
    smod64_non_zero_reg_7:
        __description("SMOD64, non-zero reg divisor, check 7"),
        __success,
        __success_unpriv,
        __retval("0");
    smod64_non_zero_reg_8:
        __description("SMOD64, non-zero reg divisor, check 8"),
        __success,
        __success_unpriv,
        __retval("1");
    sdiv32_zero_divisor:
        __description("SDIV32, zero divisor"),
        __success,
        __success_unpriv,
        __retval("0");
    sdiv64_zero_divisor:
        __description("SDIV64, zero divisor"),
        __success,
        __success_unpriv,
        __retval("0");
    smod32_zero_divisor:
        __description("SMOD32, zero divisor"),
        __success,
        __success_unpriv,
        __retval("-1");
    smod64_zero_divisor:
        __description("SMOD64, zero divisor"),
        __success,
        __success_unpriv,
        __retval("-1");
    sdiv64_overflow_rr:
        __description("SDIV64, overflow r/r, LLONG_MIN/-1"),
        __success,
        __retval("1"),
        __arch_x86_64,
        __xlated("0: r2 = 0x8000000000000000"),
        __xlated("2: r3 = -1"),
        __xlated("3: r4 = r2"),
        __xlated("4: r12 = r3"),
        __xlated("5: r12 += 1"),
        __xlated("6: if r12 > 0x1 goto pc+4"),
        __xlated("7: if r12 == 0x0 goto pc+1"),
        __xlated("8: r2 = 0"),
        __xlated("9: r2 = -r2"),
        __xlated("10: goto pc+1"),
        __xlated("11: r2 s/= r3"),
        __xlated("12: r0 = 0"),
        __xlated("13: if r2 != r4 goto pc+1"),
        __xlated("14: r0 = 1"),
        __xlated("15: exit");
    sdiv64_rr_divisor_neg_1:
        __description("SDIV64, r/r, small_val/-1"),
        __success,
        __retval("-5"),
        __arch_x86_64,
        __xlated("0: r2 = 5"),
        __xlated("1: r3 = -1"),
        __xlated("2: r12 = r3"),
        __xlated("3: r12 += 1"),
        __xlated("4: if r12 > 0x1 goto pc+4"),
        __xlated("5: if r12 == 0x0 goto pc+1"),
        __xlated("6: r2 = 0"),
        __xlated("7: r2 = -r2"),
        __xlated("8: goto pc+1"),
        __xlated("9: r2 s/= r3"),
        __xlated("10: r0 = r2"),
        __xlated("11: exit");
    sdiv64_overflow_ri:
        __description("SDIV64, overflow r/i, LLONG_MIN/-1"),
        __success,
        __retval("1"),
        __arch_x86_64,
        __xlated("0: r2 = 0x8000000000000000"),
        __xlated("2: r4 = r2"),
        __xlated("3: r2 = -r2"),
        __xlated("4: r0 = 0"),
        __xlated("5: if r2 != r4 goto pc+1"),
        __xlated("6: r0 = 1"),
        __xlated("7: exit");
    sdiv64_ri_divisor_neg_1:
        __description("SDIV64, r/i, small_val/-1"),
        __success,
        __retval("-5"),
        __arch_x86_64,
        __xlated("0: r2 = 5"),
        __xlated("1: r4 = r2"),
        __xlated("2: r2 = -r2"),
        __xlated("3: r0 = r2"),
        __xlated("4: exit");
    sdiv32_overflow_rr:
        __description("SDIV32, overflow r/r, INT_MIN/-1"),
        __success,
        __retval("1"),
        __arch_x86_64,
        __xlated("0: w2 = -2147483648"),
        __xlated("1: w3 = -1"),
        __xlated("2: w4 = w2"),
        __xlated("3: r12 = r3"),
        __xlated("4: w12 += 1"),
        __xlated("5: if w12 > 0x1 goto pc+4"),
        __xlated("6: if w12 == 0x0 goto pc+1"),
        __xlated("7: w2 = 0"),
        __xlated("8: w2 = -w2"),
        __xlated("9: goto pc+1"),
        __xlated("10: w2 s/= w3"),
        __xlated("11: r0 = 0"),
        __xlated("12: if w2 != w4 goto pc+1"),
        __xlated("13: r0 = 1"),
        __xlated("14: exit");
    sdiv32_rr_divisor_neg_1:
        __description("SDIV32, r/r, small_val/-1"),
        __success,
        __retval("5"),
        __arch_x86_64,
        __xlated("0: w2 = -5"),
        __xlated("1: w3 = -1"),
        __xlated("2: w4 = w2"),
        __xlated("3: r12 = r3"),
        __xlated("4: w12 += 1"),
        __xlated("5: if w12 > 0x1 goto pc+4"),
        __xlated("6: if w12 == 0x0 goto pc+1"),
        __xlated("7: w2 = 0"),
        __xlated("8: w2 = -w2"),
        __xlated("9: goto pc+1"),
        __xlated("10: w2 s/= w3"),
        __xlated("11: w0 = w2"),
        __xlated("12: exit");
    sdiv32_overflow_ri:
        __description("SDIV32, overflow r/i, INT_MIN/-1"),
        __success,
        __retval("1"),
        __arch_x86_64,
        __xlated("0: w2 = -2147483648"),
        __xlated("1: w4 = w2"),
        __xlated("2: w2 = -w2"),
        __xlated("3: r0 = 0"),
        __xlated("4: if w2 != w4 goto pc+1"),
        __xlated("5: r0 = 1"),
        __xlated("6: exit");
    sdiv32_ri_divisor_neg_1:
        __description("SDIV32, r/i, small_val/-1"),
        __success,
        __retval("-5"),
        __arch_x86_64,
        __xlated("0: w2 = 5"),
        __xlated("1: w4 = w2"),
        __xlated("2: w2 = -w2"),
        __xlated("3: w0 = w2"),
        __xlated("4: exit");
    smod64_overflow_rr:
        __description("SMOD64, overflow r/r, LLONG_MIN/-1"),
        __success,
        __retval("0"),
        __arch_x86_64,
        __xlated("0: r2 = 0x8000000000000000"),
        __xlated("2: r3 = -1"),
        __xlated("3: r4 = r2"),
        __xlated("4: r12 = r3"),
        __xlated("5: r12 += 1"),
        __xlated("6: if r12 > 0x1 goto pc+3"),
        __xlated("7: if r12 == 0x1 goto pc+3"),
        __xlated("8: w2 = 0"),
        __xlated("9: goto pc+1"),
        __xlated("10: r2 s%= r3"),
        __xlated("11: r0 = r2"),
        __xlated("12: exit");
    smod64_rr_divisor_neg_1:
        __description("SMOD64, r/r, small_val/-1"),
        __success,
        __retval("0"),
        __arch_x86_64,
        __xlated("0: r2 = 5"),
        __xlated("1: r3 = -1"),
        __xlated("2: r4 = r2"),
        __xlated("3: r12 = r3"),
        __xlated("4: r12 += 1"),
        __xlated("5: if r12 > 0x1 goto pc+3"),
        __xlated("6: if r12 == 0x1 goto pc+3"),
        __xlated("7: w2 = 0"),
        __xlated("8: goto pc+1"),
        __xlated("9: r2 s%= r3"),
        __xlated("10: r0 = r2"),
        __xlated("11: exit");
    smod64_overflow_ri:
        __description("SMOD64, overflow r/i, LLONG_MIN/-1"),
        __success,
        __retval("0"),
        __arch_x86_64,
        __xlated("0: r2 = 0x8000000000000000"),
        __xlated("2: r4 = r2"),
        __xlated("3: w2 = 0"),
        __xlated("4: r0 = r2"),
        __xlated("5: exit");
    smod64_ri_divisor_neg_1:
        __description("SMOD64, r/i, small_val/-1"),
        __success,
        __retval("0"),
        __arch_x86_64,
        __xlated("0: r2 = 5"),
        __xlated("1: r4 = r2"),
        __xlated("2: w2 = 0"),
        __xlated("3: r0 = r2"),
        __xlated("4: exit");
    smod32_overflow_rr:
        __description("SMOD32, overflow r/r, INT_MIN/-1"),
        __success,
        __retval("0"),
        __arch_x86_64,
        __xlated("0: w2 = -2147483648"),
        __xlated("1: w3 = -1"),
        __xlated("2: w4 = w2"),
        __xlated("3: r12 = r3"),
        __xlated("4: w12 += 1"),
        __xlated("5: if w12 > 0x1 goto pc+3"),
        __xlated("6: if w12 == 0x1 goto pc+4"),
        __xlated("7: w2 = 0"),
        __xlated("8: goto pc+1"),
        __xlated("9: w2 s%= w3"),
        __xlated("10: goto pc+1"),
        __xlated("11: w2 = w2"),
        __xlated("12: r0 = r2"),
        __xlated("13: exit");
    smod32_rr_divisor_neg_1:
        __description("SMOD32, r/r, small_val/-1"),
        __success,
        __retval("0"),
        __arch_x86_64,
        __xlated("0: w2 = -5"),
        __xlated("1: w3 = -1"),
        __xlated("2: w4 = w2"),
        __xlated("3: r12 = r3"),
        __xlated("4: w12 += 1"),
        __xlated("5: if w12 > 0x1 goto pc+3"),
        __xlated("6: if w12 == 0x1 goto pc+4"),
        __xlated("7: w2 = 0"),
        __xlated("8: goto pc+1"),
        __xlated("9: w2 s%= w3"),
        __xlated("10: goto pc+1"),
        __xlated("11: w2 = w2"),
        __xlated("12: r0 = r2"),
        __xlated("13: exit");
    smod32_overflow_ri:
        __description("SMOD32, overflow r/i, INT_MIN/-1"),
        __success,
        __retval("0"),
        __arch_x86_64,
        __xlated("0: w2 = -2147483648"),
        __xlated("1: w4 = w2"),
        __xlated("2: w2 = 0"),
        __xlated("3: r0 = r2"),
        __xlated("4: exit");
    smod32_ri_divisor_neg_1:
        __description("SMOD32, r/i, small_val/-1"),
        __success,
        __retval("0"),
        __arch_x86_64,
        __xlated("0: w2 = 5"),
        __xlated("1: w4 = w2"),
        __xlated("2: w2 = 0"),
        __xlated("3: w0 = w2"),
        __xlated("4: exit");
    sdiv32_int_min_div_2_imm:
        __description("SDIV32, INT_MIN divided by 2, imm"),
        __success,
        __success_unpriv,
        __retval("-1073741824");
    sdiv32_int_min_div_2_reg:
        __description("SDIV32, INT_MIN divided by 2, reg"),
        __success,
        __success_unpriv,
        __retval("-1073741824");
    smod32_int_min_mod_2_imm:
        __description("SMOD32, INT_MIN modulo 2, imm"),
        __success,
        __success_unpriv,
        __retval("0");
    smod32_int_min_mod_neg2_imm:
        __description("SMOD32, INT_MIN modulo -2, imm"),
        __success,
        __success_unpriv,
        __retval("0");
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv32_non_zero_imm_1
extern "C" fn sdiv32_non_zero_imm_1() {
    unsafe {
        core::arch::asm!(
            "w0 = -41;",
            "w0 s/= 2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv32_non_zero_imm_2
extern "C" fn sdiv32_non_zero_imm_2() {
    unsafe {
        core::arch::asm!(
            "w0 = 41;",
            "w0 s/= -2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv32_non_zero_imm_3
extern "C" fn sdiv32_non_zero_imm_3() {
    unsafe {
        core::arch::asm!(
            "w0 = -41;",
            "w0 s/= -2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv32_non_zero_imm_4
extern "C" fn sdiv32_non_zero_imm_4() {
    unsafe {
        core::arch::asm!(
            "w0 = -42;",
            "w0 s/= 2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv32_non_zero_imm_5
extern "C" fn sdiv32_non_zero_imm_5() {
    unsafe {
        core::arch::asm!(
            "w0 = 42;",
            "w0 s/= -2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv32_non_zero_imm_6
extern "C" fn sdiv32_non_zero_imm_6() {
    unsafe {
        core::arch::asm!(
            "w0 = -42;",
            "w0 s/= -2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv32_non_zero_imm_7
extern "C" fn sdiv32_non_zero_imm_7() {
    unsafe {
        core::arch::asm!(
            "w0 = 42;",
            "w0 s/= 2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv32_non_zero_imm_8
extern "C" fn sdiv32_non_zero_imm_8() {
    unsafe {
        core::arch::asm!(
            "w0 = 41;",
            "w0 s/= 2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv32_non_zero_reg_1
extern "C" fn sdiv32_non_zero_reg_1() {
    unsafe {
        core::arch::asm!(
            "w0 = -41;",
            "w1 = 2;",
            "w0 s/= w1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv32_non_zero_reg_2
extern "C" fn sdiv32_non_zero_reg_2() {
    unsafe {
        core::arch::asm!(
            "w0 = 41;",
            "w1 = -2;",
            "w0 s/= w1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv32_non_zero_reg_3
extern "C" fn sdiv32_non_zero_reg_3() {
    unsafe {
        core::arch::asm!(
            "w0 = -41;",
            "w1 = -2;",
            "w0 s/= w1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv32_non_zero_reg_4
extern "C" fn sdiv32_non_zero_reg_4() {
    unsafe {
        core::arch::asm!(
            "w0 = -42;",
            "w1 = 2;",
            "w0 s/= w1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv32_non_zero_reg_5
extern "C" fn sdiv32_non_zero_reg_5() {
    unsafe {
        core::arch::asm!(
            "w0 = 42;",
            "w1 = -2;",
            "w0 s/= w1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv32_non_zero_reg_6
extern "C" fn sdiv32_non_zero_reg_6() {
    unsafe {
        core::arch::asm!(
            "w0 = -42;",
            "w1 = -2;",
            "w0 s/= w1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv32_non_zero_reg_7
extern "C" fn sdiv32_non_zero_reg_7() {
    unsafe {
        core::arch::asm!(
            "w0 = 42;",
            "w1 = 2;",
            "w0 s/= w1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv32_non_zero_reg_8
extern "C" fn sdiv32_non_zero_reg_8() {
    unsafe {
        core::arch::asm!(
            "w0 = 41;",
            "w1 = 2;",
            "w0 s/= w1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv64_non_zero_imm_1
extern "C" fn sdiv64_non_zero_imm_1() {
    unsafe {
        core::arch::asm!(
            "r0 = -41;",
            "r0 s/= 2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv64_non_zero_imm_2
extern "C" fn sdiv64_non_zero_imm_2() {
    unsafe {
        core::arch::asm!(
            "r0 = 41;",
            "r0 s/= -2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv64_non_zero_imm_3
extern "C" fn sdiv64_non_zero_imm_3() {
    unsafe {
        core::arch::asm!(
            "r0 = -41;",
            "r0 s/= -2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv64_non_zero_imm_4
extern "C" fn sdiv64_non_zero_imm_4() {
    unsafe {
        core::arch::asm!(
            "r0 = -42;",
            "r0 s/= 2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv64_non_zero_imm_5
extern "C" fn sdiv64_non_zero_imm_5() {
    unsafe {
        core::arch::asm!(
            "r0 = 42;",
            "r0 s/= -2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv64_non_zero_imm_6
extern "C" fn sdiv64_non_zero_imm_6() {
    unsafe {
        core::arch::asm!(
            "r0 = -42;",
            "r0 s/= -2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv64_non_zero_reg_1
extern "C" fn sdiv64_non_zero_reg_1() {
    unsafe {
        core::arch::asm!(
            "r0 = -41;",
            "r1 = 2;",
            "r0 s/= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv64_non_zero_reg_2
extern "C" fn sdiv64_non_zero_reg_2() {
    unsafe {
        core::arch::asm!(
            "r0 = 41;",
            "r1 = -2;",
            "r0 s/= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv64_non_zero_reg_3
extern "C" fn sdiv64_non_zero_reg_3() {
    unsafe {
        core::arch::asm!(
            "r0 = -41;",
            "r1 = -2;",
            "r0 s/= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv64_non_zero_reg_4
extern "C" fn sdiv64_non_zero_reg_4() {
    unsafe {
        core::arch::asm!(
            "r0 = -42;",
            "r1 = 2;",
            "r0 s/= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv64_non_zero_reg_5
extern "C" fn sdiv64_non_zero_reg_5() {
    unsafe {
        core::arch::asm!(
            "r0 = 42;",
            "r1 = -2;",
            "r0 s/= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv64_non_zero_reg_6
extern "C" fn sdiv64_non_zero_reg_6() {
    unsafe {
        core::arch::asm!(
            "r0 = -42;",
            "r1 = -2;",
            "r0 s/= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod32_non_zero_imm_1
extern "C" fn smod32_non_zero_imm_1() {
    unsafe {
        core::arch::asm!(
            "w0 = -41;",
            "w0 s%= 2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod32_non_zero_imm_2
extern "C" fn smod32_non_zero_imm_2() {
    unsafe {
        core::arch::asm!(
            "w0 = 41;",
            "w0 s%= -2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod32_non_zero_imm_3
extern "C" fn smod32_non_zero_imm_3() {
    unsafe {
        core::arch::asm!(
            "w0 = -41;",
            "w0 s%= -2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod32_non_zero_imm_4
extern "C" fn smod32_non_zero_imm_4() {
    unsafe {
        core::arch::asm!(
            "w0 = -42;",
            "w0 s%= 2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod32_non_zero_imm_5
extern "C" fn smod32_non_zero_imm_5() {
    unsafe {
        core::arch::asm!(
            "w0 = 42;",
            "w0 s%= -2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod32_non_zero_imm_6
extern "C" fn smod32_non_zero_imm_6() {
    unsafe {
        core::arch::asm!(
            "w0 = -42;",
            "w0 s%= -2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod32_non_zero_reg_1
extern "C" fn smod32_non_zero_reg_1() {
    unsafe {
        core::arch::asm!(
            "w0 = -41;",
            "w1 = 2;",
            "w0 s%= w1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod32_non_zero_reg_2
extern "C" fn smod32_non_zero_reg_2() {
    unsafe {
        core::arch::asm!(
            "w0 = 41;",
            "w1 = -2;",
            "w0 s%= w1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod32_non_zero_reg_3
extern "C" fn smod32_non_zero_reg_3() {
    unsafe {
        core::arch::asm!(
            "w0 = -41;",
            "w1 = -2;",
            "w0 s%= w1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod32_non_zero_reg_4
extern "C" fn smod32_non_zero_reg_4() {
    unsafe {
        core::arch::asm!(
            "w0 = -42;",
            "w1 = 2;",
            "w0 s%= w1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod32_non_zero_reg_5
extern "C" fn smod32_non_zero_reg_5() {
    unsafe {
        core::arch::asm!(
            "w0 = 42;",
            "w1 = -2;",
            "w0 s%= w1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod32_non_zero_reg_6
extern "C" fn smod32_non_zero_reg_6() {
    unsafe {
        core::arch::asm!(
            "w0 = -42;",
            "w1 = -2;",
            "w0 s%= w1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod64_non_zero_imm_1
extern "C" fn smod64_non_zero_imm_1() {
    unsafe {
        core::arch::asm!(
            "r0 = -41;",
            "r0 s%= 2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod64_non_zero_imm_2
extern "C" fn smod64_non_zero_imm_2() {
    unsafe {
        core::arch::asm!(
            "r0 = 41;",
            "r0 s%= -2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod64_non_zero_imm_3
extern "C" fn smod64_non_zero_imm_3() {
    unsafe {
        core::arch::asm!(
            "r0 = -41;",
            "r0 s%= -2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod64_non_zero_imm_4
extern "C" fn smod64_non_zero_imm_4() {
    unsafe {
        core::arch::asm!(
            "r0 = -42;",
            "r0 s%= 2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod64_non_zero_imm_5
extern "C" fn smod64_non_zero_imm_5() {
    unsafe {
        core::arch::asm!(
            "r0 = 42;",
            "r0 s%= -2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod64_non_zero_imm_6
extern "C" fn smod64_non_zero_imm_6() {
    unsafe {
        core::arch::asm!(
            "r0 = -42;",
            "r0 s%= -2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod64_non_zero_imm_7
extern "C" fn smod64_non_zero_imm_7() {
    unsafe {
        core::arch::asm!(
            "r0 = 42;",
            "r0 s%= 2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod64_non_zero_imm_8
extern "C" fn smod64_non_zero_imm_8() {
    unsafe {
        core::arch::asm!(
            "r0 = 41;",
            "r0 s%= 2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod64_non_zero_reg_1
extern "C" fn smod64_non_zero_reg_1() {
    unsafe {
        core::arch::asm!(
            "r0 = -41;",
            "r1 = 2;",
            "r0 s%= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod64_non_zero_reg_2
extern "C" fn smod64_non_zero_reg_2() {
    unsafe {
        core::arch::asm!(
            "r0 = 41;",
            "r1 = -2;",
            "r0 s%= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod64_non_zero_reg_3
extern "C" fn smod64_non_zero_reg_3() {
    unsafe {
        core::arch::asm!(
            "r0 = -41;",
            "r1 = -2;",
            "r0 s%= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod64_non_zero_reg_4
extern "C" fn smod64_non_zero_reg_4() {
    unsafe {
        core::arch::asm!(
            "r0 = -42;",
            "r1 = 2;",
            "r0 s%= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod64_non_zero_reg_5
extern "C" fn smod64_non_zero_reg_5() {
    unsafe {
        core::arch::asm!(
            "r0 = 42;",
            "r1 = -2;",
            "r0 s%= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod64_non_zero_reg_6
extern "C" fn smod64_non_zero_reg_6() {
    unsafe {
        core::arch::asm!(
            "r0 = -42;",
            "r1 = -2;",
            "r0 s%= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod64_non_zero_reg_7
extern "C" fn smod64_non_zero_reg_7() {
    unsafe {
        core::arch::asm!(
            "r0 = 42;",
            "r1 = 2;",
            "r0 s%= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod64_non_zero_reg_8
extern "C" fn smod64_non_zero_reg_8() {
    unsafe {
        core::arch::asm!(
            "r0 = 41;",
            "r1 = 2;",
            "r0 s%= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv32_zero_divisor
extern "C" fn sdiv32_zero_divisor() {
    unsafe {
        core::arch::asm!(
            "w0 = 42;",
            "w1 = 0;",
            "w2 = -1;",
            "w2 s/= w1;",
            "w0 = w2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv64_zero_divisor
extern "C" fn sdiv64_zero_divisor() {
    unsafe {
        core::arch::asm!(
            "r0 = 42;",
            "r1 = 0;",
            "r2 = -1;",
            "r2 s/= r1;",
            "r0 = r2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod32_zero_divisor
extern "C" fn smod32_zero_divisor() {
    unsafe {
        core::arch::asm!(
            "w0 = 42;",
            "w1 = 0;",
            "w2 = -1;",
            "w2 s%= w1;",
            "w0 = w2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod64_zero_divisor
extern "C" fn smod64_zero_divisor() {
    unsafe {
        core::arch::asm!(
            "r0 = 42;",
            "r1 = 0;",
            "r2 = -1;",
            "r2 s%= r1;",
            "r0 = r2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv64_overflow_rr
extern "C" fn sdiv64_overflow_rr() {
    unsafe {
        core::arch::asm!(
            "r2 = -9223372036854775808 ll;",
            "r3 = -1;",
            "r4 = r2;",
            "r2 s/= r3;",
            "r0 = 0;",
            "if r2 != r4 goto +1;",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv64_rr_divisor_neg_1
extern "C" fn sdiv64_rr_divisor_neg_1() {
    unsafe {
        core::arch::asm!(
            "r2 = 5;",
            "r3 = -1;",
            "r2 s/= r3;",
            "r0 = r2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv64_overflow_ri
extern "C" fn sdiv64_overflow_ri() {
    unsafe {
        core::arch::asm!(
            "r2 = -9223372036854775808 ll;",
            "r4 = r2;",
            "r2 s/= -1;",
            "r0 = 0;",
            "if r2 != r4 goto +1;",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv64_ri_divisor_neg_1
extern "C" fn sdiv64_ri_divisor_neg_1() {
    unsafe {
        core::arch::asm!(
            "r2 = 5;",
            "r4 = r2;",
            "r2 s/= -1;",
            "r0 = r2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv32_overflow_rr
extern "C" fn sdiv32_overflow_rr() {
    unsafe {
        core::arch::asm!(
            "w2 = -2147483648;",
            "w3 = -1;",
            "w4 = w2;",
            "w2 s/= w3;",
            "r0 = 0;",
            "if w2 != w4 goto +1;",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv32_rr_divisor_neg_1
extern "C" fn sdiv32_rr_divisor_neg_1() {
    unsafe {
        core::arch::asm!(
            "w2 = -5;",
            "w3 = -1;",
            "w4 = w2;",
            "w2 s/= w3;",
            "w0 = w2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv32_overflow_ri
extern "C" fn sdiv32_overflow_ri() {
    unsafe {
        core::arch::asm!(
            "w2 = -2147483648;",
            "w4 = w2;",
            "w2 s/= -1;",
            "r0 = 0;",
            "if w2 != w4 goto +1;",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv32_ri_divisor_neg_1
extern "C" fn sdiv32_ri_divisor_neg_1() {
    unsafe {
        core::arch::asm!(
            "w2 = 5;",
            "w4 = w2;",
            "w2 s/= -1;",
            "w0 = w2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod64_overflow_rr
extern "C" fn smod64_overflow_rr() {
    unsafe {
        core::arch::asm!(
            "r2 = -9223372036854775808 ll;",
            "r3 = -1;",
            "r4 = r2;",
            "r2 s%= r3;",
            "r0 = r2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod64_rr_divisor_neg_1
extern "C" fn smod64_rr_divisor_neg_1() {
    unsafe {
        core::arch::asm!(
            "r2 = 5;",
            "r3 = -1;",
            "r4 = r2;",
            "r2 s%= r3;",
            "r0 = r2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod64_overflow_ri
extern "C" fn smod64_overflow_ri() {
    unsafe {
        core::arch::asm!(
            "r2 = -9223372036854775808 ll;",
            "r4 = r2;",
            "r2 s%= -1;",
            "r0 = r2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod64_ri_divisor_neg_1
extern "C" fn smod64_ri_divisor_neg_1() {
    unsafe {
        core::arch::asm!(
            "r2 = 5;",
            "r4 = r2;",
            "r2 s%= -1;",
            "r0 = r2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod32_overflow_rr
extern "C" fn smod32_overflow_rr() {
    unsafe {
        core::arch::asm!(
            "w2 = -2147483648;",
            "w3 = -1;",
            "w4 = w2;",
            "w2 s%= w3;",
            "r0 = r2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod32_rr_divisor_neg_1
extern "C" fn smod32_rr_divisor_neg_1() {
    unsafe {
        core::arch::asm!(
            "w2 = -5;",
            "w3 = -1;",
            "w4 = w2;",
            "w2 s%= w3;",
            "r0 = r2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod32_overflow_ri
extern "C" fn smod32_overflow_ri() {
    unsafe {
        core::arch::asm!(
            "w2 = -2147483648;",
            "w4 = w2;",
            "w2 s%= -1;",
            "r0 = r2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod32_ri_divisor_neg_1
extern "C" fn smod32_ri_divisor_neg_1() {
    unsafe {
        core::arch::asm!(
            "w2 = 5;",
            "w4 = w2;",
            "w2 s%= -1;",
            "w0 = w2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv32_int_min_div_2_imm
extern "C" fn sdiv32_int_min_div_2_imm() {
    unsafe {
        core::arch::asm!(
            "w0 = -2147483648;",
            "w0 s/= 2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sdiv32_int_min_div_2_reg
extern "C" fn sdiv32_int_min_div_2_reg() {
    unsafe {
        core::arch::asm!(
            "w0 = -2147483648;",
            "w1 = 2;",
            "w0 s/= w1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod32_int_min_mod_2_imm
extern "C" fn smod32_int_min_mod_2_imm() {
    unsafe {
        core::arch::asm!(
            "w0 = -2147483648;",
            "w0 s%= 2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: smod32_int_min_mod_neg2_imm
extern "C" fn smod32_int_min_mod_neg2_imm() {
    unsafe {
        core::arch::asm!(
            "w0 = -2147483648;",
            "w0 s%= -2;",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
