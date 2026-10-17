// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_direct_packet_access.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_direct_packet_access` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: end_pkt_start_is_allowed direct_packet_access_test1 direct_packet_access_test2 direct_packet_access_test3 direct_packet_access_test4_write pkt_end_reg_good_access pkt_end_reg_bad_access pkt_end_reg_both_accesses test8_double_test_variant_1 test9_double_test_variant_2 packet_access_test10_write_invalid access_test11_shift_good_access access_test12_and_good_access access_test13_branches_good_access _0_const_imm_good_access access_test15_spill_with_xadd test16_arith_on_data_end packet_access_test17_pruning_alignment test18_imm_pkt_ptr_1 test19_imm_pkt_ptr_2 test20_x_pkt_ptr_1 test21_x_pkt_ptr_2 test22_x_pkt_ptr_3 test23_x_pkt_ptr_4 test24_x_pkt_ptr_5 test25_marking_on_good_access test26_marking_on_bad_access test27_marking_on_good_access test28_marking_on_bad_access reg_pkt_end_in_subprog reg_pkt_end_in_subprog__1 id_in_regsafe_bad_access access_non_linear_test31 access_non_linear_test32 access_non_linear_test33 access_non_linear_test34 access_non_linear_test35 access_non_linear_test36 access_non_linear_linearized pkt_range_clear_after_sub pkt_range_clear_after_add pkt_same_id_check_copy_load_base pkt_same_id_check_base_load_via_copy pkt_same_id_check_base_4_load_via_copy pkt_sub_unknown_keeps_range pkt_same_id_pruning pkt_spilled_copy_gets_range

use bpf_rs_core::{bpf_object, test_tags};

test_tags! {
    end_pkt_start_is_allowed:
        __description("pkt_end - pkt_start is allowed"),
        __success,
        __retval("64");
    direct_packet_access_test1:
        __description("direct packet access: test1"),
        __success,
        __retval("0");
    direct_packet_access_test2:
        __description("direct packet access: test2"),
        __success,
        __retval("0");
    direct_packet_access_test3:
        __description("direct packet access: test3"),
        __failure,
        __msg("invalid bpf_context access off=76"),
        __failure_unpriv;
    direct_packet_access_test4_write:
        __description("direct packet access: test4 (write)"),
        __success,
        __retval("0");
    pkt_end_reg_good_access:
        __description("direct packet access: test5 (pkt_end >= reg, good access)"),
        __success,
        __retval("0");
    pkt_end_reg_bad_access:
        __description("direct packet access: test6 (pkt_end >= reg, bad access)"),
        __failure,
        __msg("invalid access to packet");
    pkt_end_reg_both_accesses:
        __description("direct packet access: test7 (pkt_end >= reg, both accesses)"),
        __failure,
        __msg("invalid access to packet");
    test8_double_test_variant_1:
        __description("direct packet access: test8 (double test, variant 1)"),
        __success,
        __retval("0");
    test9_double_test_variant_2:
        __description("direct packet access: test9 (double test, variant 2)"),
        __success,
        __retval("0");
    packet_access_test10_write_invalid:
        __description("direct packet access: test10 (write invalid)"),
        __failure,
        __msg("invalid access to packet");
    access_test11_shift_good_access:
        __description("direct packet access: test11 (shift, good access)"),
        __success,
        __retval("1");
    access_test12_and_good_access:
        __description("direct packet access: test12 (and, good access)"),
        __success,
        __retval("1");
    access_test13_branches_good_access:
        __description("direct packet access: test13 (branches, good access)"),
        __success,
        __retval("1");
    _0_const_imm_good_access:
        __description("direct packet access: test14 (pkt_ptr += 0, CONST_IMM, good access)"),
        __success,
        __retval("1");
    access_test15_spill_with_xadd:
        __description("direct packet access: test15 (spill with xadd)"),
        __failure,
        __msg("R2 invalid mem access 'scalar'"),
        __flag("BPF_F_ANY_ALIGNMENT");
    test16_arith_on_data_end:
        __description("direct packet access: test16 (arith on data_end)"),
        __failure,
        __msg("R3 pointer arithmetic on pkt_end");
    packet_access_test17_pruning_alignment:
        __description("direct packet access: test17 (pruning, alignment)"),
        __failure,
        __msg("misaligned packet access off 2+15+-4 size 4"),
        __flag("BPF_F_STRICT_ALIGNMENT");
    test18_imm_pkt_ptr_1:
        __description("direct packet access: test18 (imm += pkt_ptr, 1)"),
        __success,
        __retval("0");
    test19_imm_pkt_ptr_2:
        __description("direct packet access: test19 (imm += pkt_ptr, 2)"),
        __success,
        __retval("0");
    test20_x_pkt_ptr_1:
        __description("direct packet access: test20 (x += pkt_ptr, 1)"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    test21_x_pkt_ptr_2:
        __description("direct packet access: test21 (x += pkt_ptr, 2)"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    test22_x_pkt_ptr_3:
        __description("direct packet access: test22 (x += pkt_ptr, 3)"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    test23_x_pkt_ptr_4:
        __description("direct packet access: test23 (x += pkt_ptr, 4)"),
        __failure,
        __msg("invalid access to packet, off=31 size=8, R5(id=3,off=31,r=0)"),
        __flag("BPF_F_ANY_ALIGNMENT");
    test24_x_pkt_ptr_5:
        __description("direct packet access: test24 (x += pkt_ptr, 5)"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    test25_marking_on_good_access:
        __description("direct packet access: test25 (marking on <, good access)"),
        __success,
        __retval("0");
    test26_marking_on_bad_access:
        __description("direct packet access: test26 (marking on <, bad access)"),
        __failure,
        __msg("invalid access to packet");
    test27_marking_on_good_access:
        __description("direct packet access: test27 (marking on <=, good access)"),
        __success,
        __retval("1");
    test28_marking_on_bad_access:
        __description("direct packet access: test28 (marking on <=, bad access)"),
        __failure,
        __msg("invalid access to packet");
    reg_pkt_end_in_subprog:
        __description("direct packet access: test29 (reg > pkt_end in subprog)"),
        __success,
        __retval("0");
    id_in_regsafe_bad_access:
        __description("direct packet access: test30 (check_id() in regsafe(), bad access)"),
        __failure,
        __msg("invalid access to packet, off=0 size=1, R2"),
        __flag("BPF_F_TEST_STATE_FREQ");
    access_non_linear_test31:
        __description("direct packet access: test31 (non-linear, tc, too short eth)"),
        __success,
        __retval("1"),
        __linear_size("14");
    access_non_linear_test32:
        __description("direct packet access: test32 (non-linear, tc, too short 1)"),
        __success,
        __retval("1"),
        __linear_size("1");
    access_non_linear_test33:
        __description("direct packet access: test33 (non-linear, tc, long enough)"),
        __success,
        __retval("0"),
        __linear_size("22");
    access_non_linear_test34:
        __description("direct packet access: test34 (non-linear, cgroup_skb/ingress, too short eth)"),
        __success,
        __retval("1"),
        __linear_size("14");
    access_non_linear_test35:
        __description("direct packet access: test35 (non-linear, cgroup_skb/ingress, too short 1)"),
        __success,
        __retval("1"),
        __linear_size("1");
    access_non_linear_test36:
        __description("direct packet access: test36 (non-linear, cgroup_skb/ingress, long enough)"),
        __success,
        __retval("0"),
        __linear_size("22");
    access_non_linear_linearized:
        __description("direct packet access: test37 (non-linear, linearized)"),
        __success,
        __retval("0"),
        __linear_size("14");
    pkt_range_clear_after_sub:
        __description("direct packet access: pkt_range cleared after sub with known scalar"),
        __failure,
        __msg("invalid access to packet");
    pkt_range_clear_after_add:
        __description("direct packet access: pkt_range cleared after add with known scalar"),
        __failure,
        __msg("invalid access to packet");
    pkt_same_id_check_copy_load_base:
        __description("direct packet access: 8-aligned offset, check p + 8, load 8 bytes at p"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    pkt_same_id_check_base_load_via_copy:
        __description("direct packet access: 8-aligned offset, check p, load past it via p + 8"),
        __failure,
        __msg("invalid access to packet, off=51 size=1");
    pkt_same_id_check_base_4_load_via_copy:
        __description("direct packet access: 8-aligned offset, check p + 4, 4-byte load at p + 2"),
        __failure,
        __msg("invalid access to packet, off=52 size=4");
    pkt_sub_unknown_keeps_range:
        __description("direct packet access: checked pointer minus non-negative unknown keeps range"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    pkt_same_id_pruning:
        __description("direct packet access: no pruning of a path whose checks prove fewer bytes"),
        __failure,
        __msg("invalid access to packet, off=255 size=8"),
        __flag("BPF_F_ANY_ALIGNMENT"),
        __flag("BPF_F_TEST_STATE_FREQ");
    pkt_spilled_copy_gets_range:
        __description("direct packet access: spilled copy of checked pointer, load past range"),
        __failure,
        __msg("invalid access to packet, off=262 size=1, R7(id={{[0-9]+}},off=262,r=262)");
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: end_pkt_start_is_allowed
extern "C" fn end_pkt_start_is_allowed() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u32*)(r1 + 80);",
            "r2 = *(u32*)(r1 + 76);",
            "r0 -= r2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: direct_packet_access_test1
extern "C" fn direct_packet_access_test1() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 8;",
            "if r0 > r3 goto l0_0;",
            "r0 = *(u8*)(r2 + 0);",
            "l0_0:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: direct_packet_access_test2
extern "C" fn direct_packet_access_test2() {
    unsafe {
        core::arch::asm!(
            "r0 = 1;",
            "r4 = *(u32*)(r1 + 80);",
            "r3 = *(u32*)(r1 + 76);",
            "r5 = r3;",
            "r5 += 14;",
            "if r5 > r4 goto l0_1;",
            "r0 = *(u8*)(r3 + 7);",
            "r4 = *(u8*)(r3 + 12);",
            "r4 *= 14;",
            "r3 = *(u32*)(r1 + 76);",
            "r3 += r4;",
            "r2 = *(u32*)(r1 + 0);",
            "r2 <<= 49;",
            "r2 >>= 49;",
            "r3 += r2;",
            "r2 = r3;",
            "r2 += 8;",
            "r1 = *(u32*)(r1 + 80);",
            "if r2 > r1 goto l1_1;",
            "r1 = *(u8*)(r3 + 4);",
            "l1_1:",
            "r0 = 0;",
            "l0_1:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: direct_packet_access_test3
extern "C" fn direct_packet_access_test3() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: direct_packet_access_test4_write
extern "C" fn direct_packet_access_test4_write() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 8;",
            "if r0 > r3 goto l0_2;",
            "*(u8*)(r2 + 0) = r2;",
            "l0_2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pkt_end_reg_good_access
extern "C" fn pkt_end_reg_good_access() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 8;",
            "if r3 >= r0 goto l0_3;",
            "r0 = 1;",
            "exit;",
            "l0_3:",
            "r0 = *(u8*)(r2 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pkt_end_reg_bad_access
extern "C" fn pkt_end_reg_bad_access() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 8;",
            "if r3 >= r0 goto l0_4;",
            "r0 = *(u8*)(r2 + 0);",
            "r0 = 1;",
            "exit;",
            "l0_4:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pkt_end_reg_both_accesses
extern "C" fn pkt_end_reg_both_accesses() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 8;",
            "if r3 >= r0 goto l0_5;",
            "r0 = *(u8*)(r2 + 0);",
            "r0 = 1;",
            "exit;",
            "l0_5:",
            "r0 = *(u8*)(r2 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: test8_double_test_variant_1
extern "C" fn test8_double_test_variant_1() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 8;",
            "if r3 >= r0 goto l0_6;",
            "if r0 > r3 goto l1_6;",
            "r0 = *(u8*)(r2 + 0);",
            "l1_6:",
            "r0 = 1;",
            "exit;",
            "l0_6:",
            "r0 = *(u8*)(r2 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: test9_double_test_variant_2
extern "C" fn test9_double_test_variant_2() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 8;",
            "if r3 >= r0 goto l0_7;",
            "r0 = 1;",
            "exit;",
            "l0_7:",
            "if r0 > r3 goto l1_7;",
            "r0 = *(u8*)(r2 + 0);",
            "l1_7:",
            "r0 = *(u8*)(r2 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: packet_access_test10_write_invalid
extern "C" fn packet_access_test10_write_invalid() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 8;",
            "if r0 > r3 goto l0_8;",
            "r0 = 0;",
            "exit;",
            "l0_8:",
            "*(u8*)(r2 + 0) = r2;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: access_test11_shift_good_access
extern "C" fn access_test11_shift_good_access() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 22;",
            "if r0 > r3 goto l0_9;",
            "r3 = 144;",
            "r5 = r3;",
            "r5 += 23;",
            "r5 >>= 3;",
            "r6 = r2;",
            "r6 += r5;",
            "r0 = 1;",
            "exit;",
            "l0_9:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: access_test12_and_good_access
extern "C" fn access_test12_and_good_access() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 22;",
            "if r0 > r3 goto l0_10;",
            "r3 = 144;",
            "r5 = r3;",
            "r5 += 23;",
            "r5 &= 15;",
            "r6 = r2;",
            "r6 += r5;",
            "r0 = 1;",
            "exit;",
            "l0_10:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: access_test13_branches_good_access
extern "C" fn access_test13_branches_good_access() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 22;",
            "if r0 > r3 goto l0_11;",
            "r3 = *(u32*)(r1 + 8);",
            "r4 = 1;",
            "if r3 > r4 goto l1_11;",
            "r3 = 14;",
            "goto l2_11;",
            "l1_11:",
            "r3 = 24;",
            "l2_11:",
            "r5 = r3;",
            "r5 += 23;",
            "r5 &= 15;",
            "r6 = r2;",
            "r6 += r5;",
            "r0 = 1;",
            "exit;",
            "l0_11:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: _0_const_imm_good_access
extern "C" fn _0_const_imm_good_access() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 22;",
            "if r0 > r3 goto l0_12;",
            "r5 = 12;",
            "r5 >>= 4;",
            "r6 = r2;",
            "r6 += r5;",
            "r0 = *(u8*)(r6 + 0);",
            "r0 = 1;",
            "exit;",
            "l0_12:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: access_test15_spill_with_xadd
extern "C" fn access_test15_spill_with_xadd() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 8;",
            "if r0 > r3 goto l0_13;",
            "r5 = 4096;",
            "r4 = r10;",
            "r4 += -8;",
            "*(u64*)(r4 + 0) = r2;",
            "lock *(u64 *)(r4 + 0) += r5;",
            "r2 = *(u64*)(r4 + 0);",
            "*(u32*)(r2 + 0) = r5;",
            "r0 = 0;",
            "l0_13:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: test16_arith_on_data_end
extern "C" fn test16_arith_on_data_end() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 8;",
            "r3 += 16;",
            "if r0 > r3 goto l0_14;",
            "*(u8*)(r2 + 0) = r2;",
            "l0_14:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: packet_access_test17_pruning_alignment
extern "C" fn packet_access_test17_pruning_alignment() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r7 = *(u32*)(r1 + 8);",
            "r0 = r2;",
            "r0 += 14;",
            "if r7 > 1 goto l0_15;",
            "l2_15:",
            "if r0 > r3 goto l1_15;",
            "*(u32*)(r0 - 4) = r0;",
            "l1_15:",
            "r0 = 0;",
            "exit;",
            "l0_15:",
            "r0 += 1;",
            "goto l2_15;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: test18_imm_pkt_ptr_1
extern "C" fn test18_imm_pkt_ptr_1() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = 8;",
            "r0 += r2;",
            "if r0 > r3 goto l0_16;",
            "*(u8*)(r2 + 0) = r2;",
            "l0_16:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: test19_imm_pkt_ptr_2
extern "C" fn test19_imm_pkt_ptr_2() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 8;",
            "if r0 > r3 goto l0_17;",
            "r4 = 4;",
            "r4 += r2;",
            "*(u8*)(r4 + 0) = r4;",
            "l0_17:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: test20_x_pkt_ptr_1
extern "C" fn test20_x_pkt_ptr_1() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = 0xffffffff;",
            "*(u64*)(r10 - 8) = r0;",
            "r0 = *(u64*)(r10 - 8);",
            "r0 &= 0x7fff;",
            "r4 = r0;",
            "r4 += r2;",
            "r5 = r4;",
            "r4 += 32766;",
            "if r4 > r3 goto l0_18;",
            "*(u64*)(r5 + 0) = r4;",
            "l0_18:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: test21_x_pkt_ptr_2
extern "C" fn test21_x_pkt_ptr_2() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 8;",
            "if r0 > r3 goto l0_19;",
            "r4 = 0xffffffff;",
            "*(u64*)(r10 - 8) = r4;",
            "r4 = *(u64*)(r10 - 8);",
            "r4 &= 0x7fff;",
            "r4 += r2;",
            "r5 = r4;",
            "r4 += 32766;",
            "if r4 > r3 goto l0_19;",
            "*(u64*)(r5 + 0) = r4;",
            "l0_19:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: test22_x_pkt_ptr_3
extern "C" fn test22_x_pkt_ptr_3() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 8;",
            "*(u64*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r3;",
            "r3 = *(u64*)(r10 - 16);",
            "if r0 > r3 goto l0_20;",
            "r2 = *(u64*)(r10 - 8);",
            "r4 = 0xffffffff;",
            "lock *(u64 *)(r10 - 8) += r4;",
            "r4 = *(u64*)(r10 - 8);",
            "r4 >>= 49;",
            "r4 += r2;",
            "r0 = r4;",
            "r0 += 2;",
            "if r0 > r3 goto l0_20;",
            "r2 = 1;",
            "*(u16*)(r4 + 0) = r2;",
            "l0_20:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: test23_x_pkt_ptr_4
extern "C" fn test23_x_pkt_ptr_4() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = *(u32*)(r1 + 8);",
            "*(u64*)(r10 - 8) = r0;",
            "r0 = *(u64*)(r10 - 8);",
            "r0 &= 0xffff;",
            "r4 = r0;",
            "r0 = 31;",
            "r0 += r4;",
            "r0 += r2;",
            "r5 = r0;",
            "r0 += 65534;",
            "if r0 > r3 goto l0_21;",
            "*(u64*)(r5 + 0) = r0;",
            "l0_21:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: test24_x_pkt_ptr_5
extern "C" fn test24_x_pkt_ptr_5() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = 0xffffffff;",
            "*(u64*)(r10 - 8) = r0;",
            "r0 = *(u64*)(r10 - 8);",
            "r0 &= 0xff;",
            "r4 = r0;",
            "r0 = 64;",
            "r0 += r4;",
            "r0 += r2;",
            "r5 = r0;",
            "r0 += 32766;",
            "if r0 > r3 goto l0_22;",
            "*(u64*)(r5 + 0) = r0;",
            "l0_22:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: test25_marking_on_good_access
extern "C" fn test25_marking_on_good_access() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 8;",
            "if r0 < r3 goto l0_23;",
            "l1_23:",
            "r0 = 0;",
            "exit;",
            "l0_23:",
            "r0 = *(u8*)(r2 + 0);",
            "goto l1_23;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: test26_marking_on_bad_access
extern "C" fn test26_marking_on_bad_access() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 8;",
            "if r0 < r3 goto l0_24;",
            "r0 = *(u8*)(r2 + 0);",
            "l1_24:",
            "r0 = 0;",
            "exit;",
            "l0_24:",
            "goto l1_24;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: test27_marking_on_good_access
extern "C" fn test27_marking_on_good_access() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 8;",
            "if r3 <= r0 goto l0_25;",
            "r0 = *(u8*)(r2 + 0);",
            "l0_25:",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: test28_marking_on_bad_access
extern "C" fn test28_marking_on_bad_access() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 8;",
            "if r3 <= r0 goto l0_26;",
            "l1_26:",
            "r0 = 1;",
            "exit;",
            "l0_26:",
            "r0 = *(u8*)(r2 + 0);",
            "goto l1_26;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: reg_pkt_end_in_subprog
extern "C" fn reg_pkt_end_in_subprog() {
    unsafe {
        core::arch::asm!(
            "r6 = *(u32*)(r1 + 76);",
            "r2 = *(u32*)(r1 + 80);",
            "r3 = r6;",
            "r3 += 8;",
            "call {reg_pkt_end_in_subprog__1};",
            "if r0 == 0 goto l0_27;",
            "r0 = *(u8*)(r6 + 0);",
            "l0_27:",
            "r0 = 0;",
            "exit;",
            reg_pkt_end_in_subprog__1 = sym reg_pkt_end_in_subprog__1,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: reg_pkt_end_in_subprog__1
extern "C" fn reg_pkt_end_in_subprog__1() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "if r3 > r2 goto l0_28;",
            "r0 = 1;",
            "l0_28:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: id_in_regsafe_bad_access
extern "C" fn id_in_regsafe_bad_access() {
    unsafe {
        core::arch::asm!(
            "r9 = r1;",
            "call 5;",
            "r7 = r0;",
            "call 5;",
            "r6 = r0;",
            "r2 = *(u32*)(r9 + 76);",
            "r3 = *(u32*)(r9 + 76);",
            "r4 = *(u32*)(r9 + 80);",
            "if r6 > 100 goto l0_29;",
            "if r7 > 100 goto l0_29;",
            "r2 += r6;",
            "r2 += 1;",
            "r3 += r7;",
            "r3 += 1;",
            "if r6 != r7 goto l1_29;",
            "r2 = r3;",
            "l1_29:",
            "if r3 > r4 goto l0_29;",
            "r5 = *(u8*)(r2 - 1);",
            "l0_29:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: access_non_linear_test31
extern "C" fn access_non_linear_test31() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 22;",
            "if r0 > r3 goto l0_30;",
            "r0 = *(u8*)(r0 - 1);",
            "r0 = 0;",
            "exit;",
            "l0_30:",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: access_non_linear_test32
extern "C" fn access_non_linear_test32() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 22;",
            "if r0 > r3 goto l0_31;",
            "r0 = *(u8*)(r0 - 1);",
            "r0 = 0;",
            "exit;",
            "l0_31:",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: access_non_linear_test33
extern "C" fn access_non_linear_test33() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 22;",
            "if r0 > r3 goto l0_32;",
            "r0 = *(u8*)(r0 - 1);",
            "r0 = 0;",
            "exit;",
            "l0_32:",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup_skb/ingress"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: access_non_linear_test34
extern "C" fn access_non_linear_test34() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 8;",
            "if r0 > r3 goto l0_33;",
            "r0 = *(u8*)(r0 - 1);",
            "r0 = 0;",
            "exit;",
            "l0_33:",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup_skb/ingress"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: access_non_linear_test35
extern "C" fn access_non_linear_test35() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 8;",
            "if r0 > r3 goto l0_34;",
            "r0 = *(u8*)(r0 - 1);",
            "r0 = 0;",
            "exit;",
            "l0_34:",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup_skb/ingress"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: access_non_linear_test36
extern "C" fn access_non_linear_test36() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 8;",
            "if r0 > r3 goto l0_35;",
            "r0 = *(u8*)(r0 - 1);",
            "r0 = 0;",
            "exit;",
            "l0_35:",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: access_non_linear_linearized
extern "C" fn access_non_linear_linearized() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r2 = 22;",
            "call 39;",
            "r2 = *(u32*)(r6 + 76);",
            "r3 = *(u32*)(r6 + 80);",
            "r0 = r2;",
            "r0 += 22;",
            "if r0 > r3 goto l0_36;",
            "r0 = *(u8*)(r0 - 1);",
            "exit;",
            "l0_36:",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pkt_range_clear_after_sub
extern "C" fn pkt_range_clear_after_sub() {
    unsafe {
        core::arch::asm!(
            "r9 = *(u32*)(r1 + 76);",
            "r8 = *(u32*)(r1 + 80);",
            "r9 += 256;",
            "if r9 >= r8 goto l0_37;",
            "r0 = 0;",
            "exit;",
            "l0_37:",
            "r9 -= 256;",
            "if r9 < r8 goto l1_37;",
            "r0 = 0;",
            "exit;",
            "l1_37:",
            "r0 = *(u8*)(r9 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pkt_range_clear_after_add
extern "C" fn pkt_range_clear_after_add() {
    unsafe {
        core::arch::asm!(
            "r9 = *(u32*)(r1 + 76);",
            "r8 = *(u32*)(r1 + 80);",
            "r9 += 256;",
            "if r9 >= r8 goto l0_38;",
            "r0 = 0;",
            "exit;",
            "l0_38:",
            "r9 += -256;",
            "if r9 < r8 goto l1_38;",
            "r0 = 0;",
            "exit;",
            "l1_38:",
            "r0 = *(u8*)(r9 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pkt_same_id_check_copy_load_base
extern "C" fn pkt_same_id_check_copy_load_base() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r4 = *(u32*)(r1 + 8);",
            "r4 &= 0x38;",
            "if r4 > 50 goto l0_39;",
            "r5 = r2;",
            "r5 += r4;",
            "r6 = r5;",
            "r6 += 8;",
            "if r6 > r3 goto l0_39;",
            "r0 = *(u64*)(r5 + 0);",
            "l0_39:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pkt_same_id_check_base_load_via_copy
extern "C" fn pkt_same_id_check_base_load_via_copy() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r4 = *(u32*)(r1 + 8);",
            "r4 &= 0x38;",
            "if r4 > 50 goto l0_40;",
            "r5 = r2;",
            "r5 += r4;",
            "r6 = r5;",
            "r6 += 8;",
            "if r5 > r3 goto l0_40;",
            "r0 = *(u8*)(r6 - 7);",
            "l0_40:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pkt_same_id_check_base_4_load_via_copy
extern "C" fn pkt_same_id_check_base_4_load_via_copy() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r4 = *(u32*)(r1 + 8);",
            "r4 &= 0x38;",
            "if r4 > 50 goto l0_41;",
            "r5 = r2;",
            "r5 += r4;",
            "r6 = r5;",
            "r6 += 8;",
            "r7 = r5;",
            "r7 += 4;",
            "if r7 > r3 goto l0_41;",
            "r0 = *(u32*)(r6 - 6);",
            "l0_41:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pkt_sub_unknown_keeps_range
extern "C" fn pkt_sub_unknown_keeps_range() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r4 = *(u32*)(r1 + 8);",
            "r4 &= 0x1f;",
            "r4 += 8;",
            "r5 = r2;",
            "r5 += 40;",
            "if r5 > r3 goto l0_42;",
            "r5 -= r4;",
            "r0 = *(u64*)(r5 + 0);",
            "l0_42:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pkt_same_id_pruning
extern "C" fn pkt_same_id_pruning() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r4 = *(u32*)(r1 + 8);",
            "r0 = *(u32*)(r1 + 32);",
            "r4 &= 0xff;",
            "r5 = r2;",
            "r5 += r4;",
            "if r0 != 0 goto l1_43;",
            "r6 = r5;",
            "r6 += 8;",
            "if r6 > r3 goto l0_43;",
            "goto l2_43;",
            "l1_43:",
            "if r5 > r3 goto l0_43;",
            "r6 = r5;",
            "r6 += 7;",
            "if r6 > r3 goto l0_43;",
            "l2_43:",
            "r0 = *(u64*)(r5 + 0);",
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
// BPF_NAKED: pkt_spilled_copy_gets_range
extern "C" fn pkt_spilled_copy_gets_range() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r4 = *(u32*)(r1 + 8);",
            "r4 &= 0xff;",
            "r5 = r2;",
            "r5 += r4;",
            "*(u64*)(r10 - 8) = r5;",
            "if r5 > r3 goto l0_44;",
            "r6 = r5;",
            "r6 += 7;",
            "if r6 > r3 goto l0_44;",
            "r7 = *(u64*)(r10 - 8);",
            "r0 = *(u8*)(r7 + 7);",
            "l0_44:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
