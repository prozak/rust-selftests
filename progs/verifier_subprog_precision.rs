// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]
#![allow(function_casts_as_integer)]

// Translation of tools/testing/selftests/bpf/progs/verifier_subprog_precision.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_subprog_precision.rs
// (include!d below): global_identity_subprog, subprog_with_precise_arg.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_subprog_precision` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: identity_subprog global_identity_subprog callback_subprog subprog_result_precise fp_leaking_subprog sneaky_fp_leaking_subprog fp_precise_subprog_result sneaky_fp_precise_subprog_result global_subprog_result_precise loop_callback_bad callback_precise_return_fail callback_result_precise parent_callee_saved_reg_precise parent_callee_saved_reg_precise_global parent_callee_saved_reg_precise_with_callback parent_stack_slot_precise parent_stack_slot_precise_global parent_stack_slot_precise_with_callback subprog_with_precise_arg subprog_arg_precise subprog_spill_reg_precise subprog_spill_into_parent_stack_slot_precise stack_slot_aliases_precision identity_tail_call subprog_result_tail_call ld_abs_subprog ld_abs_backtrack_both_paths

use bpf_rs_core::{bpf_map, bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    subprog_result_precise:
        __success,
        __log_level("2"),
        __msg("7: (0f) r1 += r0"),
        __msg("mark_precise: frame0: regs=r0 stack= before 6: (bf) r1 = r7"),
        __msg("mark_precise: frame0: regs=r0 stack= before 5: (27) r0 *= 4"),
        __msg("mark_precise: frame0: regs=r0 stack= before 11: (95) exit"),
        __msg("mark_precise: frame1: regs=r0 stack= before 10: (bf) r0 = r1"),
        __msg("mark_precise: frame1: regs=r1 stack= before 4: (85) call pc+5"),
        __msg("mark_precise: frame0: regs=r1 stack= before 3: (bf) r1 = r6"),
        __msg("mark_precise: frame0: regs=r6 stack= before 2: (b7) r6 = 3");
    fp_precise_subprog_result:
        __success,
        __log_level("2"),
        __msg("6: (0f) r1 += r0"),
        __msg("mark_precise: frame0: last_idx 6 first_idx 0 subseq_idx -1"),
        __msg("mark_precise: frame0: regs=r0 stack= before 5: (bf) r1 = r6"),
        __msg("mark_precise: frame0: regs=r0 stack= before 4: (27) r0 *= 4"),
        __msg("mark_precise: frame0: regs=r0 stack= before 3: (57) r0 &= 3"),
        __msg("mark_precise: frame0: regs=r0 stack= before 10: (95) exit"),
        __msg("mark_precise: frame1: regs=r0 stack= before 9: (bf) r0 = (s8)r10"),
        __msg("7: R0=scalar");
    sneaky_fp_precise_subprog_result:
        __success,
        __log_level("2"),
        __msg("6: (0f) r1 += r0"),
        __msg("mark_precise: frame0: last_idx 6 first_idx 0 subseq_idx -1"),
        __msg("mark_precise: frame0: regs=r0 stack= before 5: (bf) r1 = r6"),
        __msg("mark_precise: frame0: regs=r0 stack= before 4: (27) r0 *= 4"),
        __msg("mark_precise: frame0: regs=r0 stack= before 3: (57) r0 &= 3"),
        __msg("mark_precise: frame0: regs=r0 stack= before 11: (95) exit"),
        __msg("mark_precise: frame1: regs=r0 stack= before 10: (bf) r0 = (s8)r1"),
        __msg("mark_precise: frame1: regs=r1 stack= before 9: (bf) r1 = r10"),
        __msg("7: R0=scalar");
    global_subprog_result_precise:
        __success,
        __log_level("2"),
        __msg("9: (0f) r1 += r0"),
        __msg("mark_precise: frame0: last_idx 9 first_idx 0"),
        __msg("mark_precise: frame0: regs=r0 stack= before 8: (bf) r1 = r7"),
        __msg("mark_precise: frame0: regs=r0 stack= before 7: (27) r0 *= 4"),
        __msg("mark_precise: frame0: regs=r0 stack= before 5: (a5) if r0 < 0x4 goto pc+1"),
        __msg("mark_precise: frame0: regs=r0 stack= before 4: (85) call pc+7");
    callback_precise_return_fail:
        __failure,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("mark_precise: frame1: regs=r0 stack= before 11: (b7) r0 = 0"),
        __msg("from 10 to 12: frame1: R0=scalar(smin=umin=1001"),
        __msg("mark_precise: frame1: regs=r0 stack= before 9: (85) call bpf_get_prandom_u32#7"),
        __msg("At callback return the register R0 has smin=1001 should have been in [0, 1]");
    callback_result_precise:
        __success,
        __log_level("2"),
        __msg("9: (85) call bpf_loop#181"),
        __msg("mark_precise: frame0: last_idx 9 first_idx 9 subseq_idx -1"),
        __msg("mark_precise: frame0: parent state regs=r4 stack=:"),
        __msg("mark_precise: frame0: last_idx 8 first_idx 0 subseq_idx 9"),
        __msg("mark_precise: frame0: regs=r4 stack= before 8: (b7) r4 = 0"),
        __msg("mark_precise: frame0: last_idx 9 first_idx 9 subseq_idx -1"),
        __msg("mark_precise: frame0: parent state regs=r1 stack=:"),
        __msg("mark_precise: frame0: last_idx 8 first_idx 0 subseq_idx 9"),
        __msg("mark_precise: frame0: regs=r1 stack= before 8: (b7) r4 = 0"),
        __msg("mark_precise: frame0: regs=r1 stack= before 7: (b7) r3 = 0"),
        __msg("mark_precise: frame0: regs=r1 stack= before 6: (bf) r2 = r8"),
        __msg("mark_precise: frame0: regs=r1 stack= before 5: (bf) r1 = r6"),
        __msg("mark_precise: frame0: regs=r6 stack= before 4: (b7) r6 = 3"),
        __msg("14: (0f) r1 += r6"),
        __msg("mark_precise: frame0: last_idx 14 first_idx 9"),
        __msg("mark_precise: frame0: regs=r6 stack= before 13: (bf) r1 = r7"),
        __msg("mark_precise: frame0: regs=r6 stack= before 12: (27) r6 *= 4"),
        __msg("mark_precise: frame0: regs=r6 stack= before 11: (25) if r6 > 0x3 goto pc+4"),
        __msg("mark_precise: frame0: regs=r0,r6 stack= before 10: (bf) r6 = r0"),
        __msg("mark_precise: frame0: regs=r0 stack= before 9: (85) call bpf_loop"),
        __msg("from 9 to 17: frame1:"),
        __msg("17: frame1: R10=fp0 cb"),
        __msg("17: (b7) r0 = 0"),
        __msg("18: (95) exit"),
        __msg("returning from callee:"),
        __msg("to caller at 9:"),
        __msg("frame 0: propagating r1,r3,r4"),
        __msg("mark_precise: frame0: last_idx 9 first_idx 9 subseq_idx -1"),
        __msg("mark_precise: frame0: regs=r1,r3,r4 stack= before 18: (95) exit"),
        __msg("from 18 to 9: safe");
    parent_callee_saved_reg_precise:
        __success,
        __log_level("2"),
        __msg("7: (0f) r1 += r6"),
        __msg("mark_precise: frame0: last_idx 7 first_idx 0"),
        __msg("mark_precise: frame0: regs=r6 stack= before 6: (bf) r1 = r7"),
        __msg("mark_precise: frame0: regs=r6 stack= before 5: (27) r6 *= 4"),
        __msg("mark_precise: frame0: regs=r6 stack= before 11: (95) exit"),
        __msg("mark_precise: frame1: regs= stack= before 10: (bf) r0 = r1"),
        __msg("mark_precise: frame1: regs= stack= before 4: (85) call pc+5"),
        __msg("mark_precise: frame0: regs=r6 stack= before 3: (b7) r1 = 0"),
        __msg("mark_precise: frame0: regs=r6 stack= before 2: (b7) r6 = 3");
    parent_callee_saved_reg_precise_global:
        __success,
        __log_level("2"),
        __msg("7: (0f) r1 += r6"),
        __msg("mark_precise: frame0: last_idx 7 first_idx 0"),
        __msg("mark_precise: frame0: regs=r6 stack= before 6: (bf) r1 = r7"),
        __msg("mark_precise: frame0: regs=r6 stack= before 5: (27) r6 *= 4"),
        __msg("mark_precise: frame0: regs=r6 stack= before 4: (85) call pc+5"),
        __msg("mark_precise: frame0: regs=r6 stack= before 3: (b7) r1 = 0"),
        __msg("mark_precise: frame0: regs=r6 stack= before 2: (b7) r6 = 3");
    parent_callee_saved_reg_precise_with_callback:
        __success,
        __log_level("2"),
        __msg("12: (0f) r1 += r6"),
        __msg("mark_precise: frame0: last_idx 12 first_idx 9"),
        __msg("mark_precise: frame0: regs=r6 stack= before 11: (bf) r1 = r7"),
        __msg("mark_precise: frame0: regs=r6 stack= before 10: (27) r6 *= 4"),
        __msg("mark_precise: frame0: regs=r6 stack= before 9: (85) call bpf_loop"),
        __msg("mark_precise: frame0: parent state regs=r6 stack=:"),
        __msg("mark_precise: frame0: last_idx 8 first_idx 0 subseq_idx 9"),
        __msg("mark_precise: frame0: regs=r6 stack= before 8: (b7) r4 = 0"),
        __msg("mark_precise: frame0: regs=r6 stack= before 7: (b7) r3 = 0"),
        __msg("mark_precise: frame0: regs=r6 stack= before 6: (bf) r2 = r8"),
        __msg("mark_precise: frame0: regs=r6 stack= before 5: (b7) r1 = 1"),
        __msg("mark_precise: frame0: regs=r6 stack= before 4: (b7) r6 = 3"),
        __msg("from 9 to 15: frame1:"),
        __msg("15: frame1: R10=fp0 cb"),
        __msg("15: (b7) r0 = 0"),
        __msg("16: (95) exit"),
        __msg("returning from callee:"),
        __msg("to caller at 9:"),
        __msg("frame 0: propagating r1,r3,r4,r6"),
        __msg("mark_precise: frame0: last_idx 9 first_idx 9 subseq_idx -1"),
        __msg("mark_precise: frame0: regs=r1,r3,r4,r6 stack= before 16: (95) exit"),
        __msg("mark_precise: frame1: regs= stack= before 15: (b7) r0 = 0"),
        __msg("mark_precise: frame1: regs= stack= before 9: (85) call bpf_loop"),
        __msg("mark_precise: frame0: parent state regs= stack=:"),
        __msg("from 16 to 9: safe");
    parent_stack_slot_precise:
        __success,
        __log_level("2"),
        __msg("9: (0f) r1 += r6"),
        __msg("mark_precise: frame0: last_idx 9 first_idx 6"),
        __msg("mark_precise: frame0: regs=r6 stack= before 8: (bf) r1 = r7"),
        __msg("mark_precise: frame0: regs=r6 stack= before 7: (27) r6 *= 4"),
        __msg("mark_precise: frame0: regs=r6 stack= before 6: (79) r6 = *(u64 *)(r10 -8)"),
        __msg("mark_precise: frame0: parent state regs= stack=-8:"),
        __msg("mark_precise: frame0: last_idx 13 first_idx 0"),
        __msg("mark_precise: frame0: regs= stack=-8 before 13: (95) exit"),
        __msg("mark_precise: frame1: regs= stack= before 12: (bf) r0 = r1"),
        __msg("mark_precise: frame1: regs= stack= before 5: (85) call pc+6"),
        __msg("mark_precise: frame0: regs= stack=-8 before 4: (b7) r1 = 0"),
        __msg("mark_precise: frame0: regs= stack=-8 before 3: (7b) *(u64 *)(r10 -8) = r6"),
        __msg("mark_precise: frame0: regs=r6 stack= before 2: (b7) r6 = 3");
    parent_stack_slot_precise_global:
        __success,
        __log_level("2"),
        __msg("9: (0f) r1 += r6"),
        __msg("mark_precise: frame0: last_idx 9 first_idx 0"),
        __msg("mark_precise: frame0: regs=r6 stack= before 8: (bf) r1 = r7"),
        __msg("mark_precise: frame0: regs=r6 stack= before 7: (27) r6 *= 4"),
        __msg("mark_precise: frame0: regs=r6 stack= before 6: (79) r6 = *(u64 *)(r10 -8)"),
        __msg("mark_precise: frame0: regs= stack=-8 before 5: (85) call pc+6"),
        __msg("mark_precise: frame0: regs= stack=-8 before 4: (b7) r1 = 0"),
        __msg("mark_precise: frame0: regs= stack=-8 before 3: (7b) *(u64 *)(r10 -8) = r6"),
        __msg("mark_precise: frame0: regs=r6 stack= before 2: (b7) r6 = 3");
    parent_stack_slot_precise_with_callback:
        __success,
        __log_level("2"),
        __msg("14: (0f) r1 += r6"),
        __msg("mark_precise: frame0: last_idx 14 first_idx 10"),
        __msg("mark_precise: frame0: regs=r6 stack= before 13: (bf) r1 = r7"),
        __msg("mark_precise: frame0: regs=r6 stack= before 12: (27) r6 *= 4"),
        __msg("mark_precise: frame0: regs=r6 stack= before 11: (79) r6 = *(u64 *)(r10 -8)"),
        __msg("mark_precise: frame0: regs= stack=-8 before 10: (85) call bpf_loop"),
        __msg("mark_precise: frame0: parent state regs= stack=-8:"),
        __msg("mark_precise: frame0: last_idx 9 first_idx 0 subseq_idx 10"),
        __msg("mark_precise: frame0: regs= stack=-8 before 9: (b7) r4 = 0"),
        __msg("mark_precise: frame0: regs= stack=-8 before 8: (b7) r3 = 0"),
        __msg("mark_precise: frame0: regs= stack=-8 before 7: (bf) r2 = r8"),
        __msg("mark_precise: frame0: regs= stack=-8 before 6: (bf) r1 = r6"),
        __msg("mark_precise: frame0: regs= stack=-8 before 5: (7b) *(u64 *)(r10 -8) = r6"),
        __msg("mark_precise: frame0: regs=r6 stack= before 4: (b7) r6 = 3"),
        __msg("from 10 to 17: frame1:"),
        __msg("17: frame1: R10=fp0 cb"),
        __msg("17: (b7) r0 = 0"),
        __msg("18: (95) exit"),
        __msg("returning from callee:"),
        __msg("to caller at 10:"),
        __msg("frame 0: propagating r1,r3,r4,fp-8"),
        __msg("mark_precise: frame0: last_idx 10 first_idx 10 subseq_idx -1"),
        __msg("mark_precise: frame0: regs=r1,r3,r4 stack=-8 before 18: (95) exit"),
        __msg("mark_precise: frame1: regs= stack= before 17: (b7) r0 = 0"),
        __msg("mark_precise: frame1: regs= stack= before 10: (85) call bpf_loop#181"),
        __msg("mark_precise: frame0: parent state regs= stack=:"),
        __msg("from 18 to 10: safe");
    subprog_arg_precise:
        __success,
        __log_level("2"),
        __msg("8: (0f) r2 += r1"),
        __msg("mark_precise: frame1: last_idx 8 first_idx 0"),
        __msg("mark_precise: frame1: regs=r1 stack= before 6: (18) r2 = "),
        __msg("mark_precise: frame1: regs=r1 stack= before 5: (67) r1 <<= 2"),
        __msg("mark_precise: frame1: regs=r1 stack= before 2: (85) call pc+2"),
        __msg("mark_precise: frame0: regs=r1 stack= before 1: (bf) r1 = r6"),
        __msg("mark_precise: frame0: regs=r6 stack= before 0: (b7) r6 = 3");
    subprog_spill_into_parent_stack_slot_precise:
        __success,
        __log_level("2"),
        __msg("10: (0f) r1 += r7"),
        __msg("mark_precise: frame0: last_idx 10 first_idx 7 subseq_idx -1"),
        __msg("mark_precise: frame0: regs=r7 stack= before 9: (bf) r1 = r8"),
        __msg("mark_precise: frame0: regs=r7 stack= before 8: (27) r7 *= 4"),
        __msg("mark_precise: frame0: regs=r7 stack= before 7: (79) r7 = *(u64 *)(r10 -8)"),
        __msg("mark_precise: frame0: parent state regs= stack=-8:  R8=map_value(map=.data.vals,ks=4,vs=16) R10=fp0 fp-8=P1"),
        __msg("mark_precise: frame0: last_idx 18 first_idx 0 subseq_idx 7"),
        __msg("mark_precise: frame0: regs= stack=-8 before 18: (95) exit"),
        __msg("mark_precise: frame1: regs= stack= before 17: (0f) r0 += r2"),
        __msg("mark_precise: frame1: regs= stack= before 16: (79) r2 = *(u64 *)(r1 +0)"),
        __msg("mark_precise: frame1: regs= stack= before 15: (79) r0 = *(u64 *)(r10 -16)"),
        __msg("mark_precise: frame1: regs= stack= before 14: (7b) *(u64 *)(r10 -16) = r2"),
        __msg("mark_precise: frame1: regs= stack= before 13: (7b) *(u64 *)(r1 +0) = r2"),
        __msg("mark_precise: frame1: regs=r2 stack= before 6: (85) call pc+6"),
        __msg("mark_precise: frame0: regs=r2 stack= before 5: (bf) r2 = r6"),
        __msg("mark_precise: frame0: regs=r6 stack= before 4: (07) r1 += -8"),
        __msg("mark_precise: frame0: regs=r6 stack= before 3: (bf) r1 = r10"),
        __msg("mark_precise: frame0: regs=r6 stack= before 2: (b7) r6 = 1");
    stack_slot_aliases_precision:
        __success,
        __log_level("2"),
        __msg("17: (0f) r1 += r0"),
        __msg("mark_precise: frame0: last_idx 17 first_idx 0 subseq_idx -1"),
        __msg("mark_precise: frame0: regs=r0 stack= before 16: (bf) r1 = r7"),
        __msg("mark_precise: frame0: regs=r0 stack= before 15: (27) r0 *= 4"),
        __msg("mark_precise: frame0: regs=r0 stack= before 14: (79) r0 = *(u64 *)(r10 -16)"),
        __msg("mark_precise: frame0: regs= stack=-16 before 13: (7b) *(u64 *)(r7 -8) = r0"),
        __msg("mark_precise: frame0: regs=r0 stack= before 12: (79) r0 = *(u64 *)(r8 +16)"),
        __msg("mark_precise: frame0: regs= stack=-16 before 11: (7b) *(u64 *)(r8 +16) = r0"),
        __msg("mark_precise: frame0: regs=r0 stack= before 10: (79) r0 = *(u64 *)(r7 -8)"),
        __msg("mark_precise: frame0: regs= stack=-16 before 9: (7b) *(u64 *)(r10 -16) = r0"),
        __msg("mark_precise: frame0: regs=r0 stack= before 8: (07) r8 += -32"),
        __msg("mark_precise: frame0: regs=r0 stack= before 7: (bf) r8 = r10"),
        __msg("mark_precise: frame0: regs=r0 stack= before 6: (07) r7 += -8"),
        __msg("mark_precise: frame0: regs=r0 stack= before 5: (bf) r7 = r10"),
        __msg("mark_precise: frame0: regs=r0 stack= before 21: (95) exit"),
        __msg("mark_precise: frame1: regs=r0 stack= before 20: (bf) r0 = r1"),
        __msg("mark_precise: frame1: regs=r1 stack= before 4: (85) call pc+15"),
        __msg("mark_precise: frame0: regs=r1 stack= before 3: (bf) r1 = r6"),
        __msg("mark_precise: frame0: regs=r6 stack= before 2: (b7) r6 = 1");
    subprog_result_tail_call:
        __failure,
        __log_level("2"),
        __msg("13: (85) call bpf_tail_call#12"),
        __msg("mark_precise: frame1: last_idx 13 first_idx 0 subseq_idx -1 "),
        __msg("returning from callee:"),
        __msg("frame1: R0=scalar() R6=3 R10=fp0"),
        __msg("to caller at 4:"),
        __msg("R0=scalar() R6=map_value(map=.data.vals,ks=4,vs=16) R10=fp0"),
        __msg("6: (0f) r1 += r0"),
        __msg("mark_precise: frame0: regs=r0 stack= before 5: (bf) r1 = r6"),
        __msg("mark_precise: frame0: regs=r0 stack= before 4: (27) r0 *= 4"),
        __msg("mark_precise: frame0: parent state regs=r0 stack=:  R0=Pscalar() R6=map_value(map=.data.vals,ks=4,vs=16) R10=fp0"),
        __msg("math between map_value pointer and register with unbounded min value is not allowed");
    ld_abs_backtrack_both_paths:
        __success,
        __log_level("2"),
        __msg("3: (0f) r1 += r7"),
        __msg("mark_precise: frame0: regs=r7 stack= before 2: (bf) r1 = r10"),
        __msg("mark_precise: frame0: regs=r7 stack= before 9: (20) r0 = *(u32 *)skb[0]"),
        __msg("mark_precise: frame1: regs= stack= before 8: (bf) r7 = r1"),
        __msg("mark_precise: frame1: regs= stack= before 7: (bf) r6 = r1"),
        __msg("mark_precise: frame1: regs= stack= before 1: (85) call pc+5"),
        __msg("mark_precise: frame0: regs=r7 stack= before 0: (b7) r7 = -8"),
        __msg("3: (0f) r1 += r7"),
        __msg("mark_precise: frame0: regs=r7 stack= before 2: (bf) r1 = r10"),
        __msg("mark_precise: frame0: regs=r7 stack= before 10: (95) exit"),
        __msg("mark_precise: frame1: regs= stack= before 9: (20) r0 = *(u32 *)skb[0]"),
        __msg("mark_precise: frame1: regs= stack= before 8: (bf) r7 = r1"),
        __msg("mark_precise: frame1: regs= stack= before 7: (bf) r6 = r1"),
        __msg("mark_precise: frame1: regs= stack= before 1: (85) call pc+5"),
        __msg("mark_precise: frame0: regs=r7 stack= before 0: (b7) r7 = -8");
}

bpf_map! {
    map_array {
        r#type: *const [i32; 3],
        max_entries: *const [i32; 1],
        key: *const u32,
        value: *const u32,
    }
}

#[link_section = ".data.vals"]
#[no_mangle]
static mut vals: [i32; 4] = [1, 2, 3, 4];

#[no_mangle]
#[inline(never)]
// BPF_NAKED: identity_subprog
extern "C" fn identity_subprog() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "r0 = r1;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: callback_subprog
extern "C" fn callback_subprog() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: subprog_result_precise
extern "C" fn subprog_result_precise() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r6 = 3;",
            "r1 = r6;",
            "call {identity_subprog};",
            "r0 *= 4;",
            "r1 = {vals};",
            "r1 += r0;",
            "r0 = *(u32 *)(r1 + 0);",
            "exit;",
            vals = in(reg) core::ptr::addr_of!(vals),
            identity_subprog = sym identity_subprog,
            out("r0") ret,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
            out("r6") _,
            options(nostack)
        );
    }
    ret
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: fp_leaking_subprog
extern "C" fn fp_leaking_subprog() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            ".8byte 565439;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: sneaky_fp_leaking_subprog
extern "C" fn sneaky_fp_leaking_subprog() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            ".8byte 528575;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: fp_precise_subprog_result
extern "C" fn fp_precise_subprog_result() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "call {fp_leaking_subprog};",
            "r0 &= 3;",
            "r0 *= 4;",
            "r1 = {vals};",
            "r1 += r0;",
            "r0 = *(u32 *)(r1 + 0);",
            "exit;",
            vals = in(reg) core::ptr::addr_of!(vals),
            fp_leaking_subprog = sym fp_leaking_subprog,
            out("r0") ret,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
            options(nostack)
        );
    }
    ret
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sneaky_fp_precise_subprog_result
extern "C" fn sneaky_fp_precise_subprog_result() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "call {sneaky_fp_leaking_subprog};",
            "r0 &= 3;",
            "r0 *= 4;",
            "r1 = {vals};",
            "r1 += r0;",
            "r0 = *(u32 *)(r1 + 0);",
            "exit;",
            vals = in(reg) core::ptr::addr_of!(vals),
            sneaky_fp_leaking_subprog = sym sneaky_fp_leaking_subprog,
            out("r0") ret,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
            options(nostack)
        );
    }
    ret
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: global_subprog_result_precise
extern "C" fn global_subprog_result_precise() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r6 = 3;",
            "r1 = r6;",
            "call {global_identity_subprog};",
            "if r0 < 4 goto 1f;",
            "r0 = 4 - 1;",
            "1:r0 *= 4;",
            "r1 = {vals};",
            "r1 += r0;",
            "r0 = *(u32 *)(r1 + 0);",
            "exit;",
            vals = in(reg) core::ptr::addr_of!(vals),
            global_identity_subprog = sym global_identity_subprog,
            out("r0") ret,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
            out("r6") _,
            options(nostack)
        );
    }
    ret
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: loop_callback_bad
extern "C" fn loop_callback_bad() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "call 7;",
            "if r0 s> 1000 goto 1f;",
            "r0 = 0;",
            "1:goto +0;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callback_precise_return_fail
extern "C" fn callback_precise_return_fail() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "r2 = {loop_callback_bad};",
            "r3 = 0;",
            "r4 = 0;",
            "call 181;",
            "r0 = 0;",
            "exit;",
            loop_callback_bad = in(reg) loop_callback_bad as usize,
            out("r0") ret,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
            options(nostack)
        );
    }
    ret
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callback_result_precise
extern "C" fn callback_result_precise() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r6 = 3;",
            "r1 = r6;",
            "r2 = {callback_subprog};",
            "r3 = 0;",
            "r4 = 0;",
            "call 181;",
            "r6 = r0;",
            "if r6 > 3 goto 1f;",
            "r6 *= 4;",
            "r1 = {vals};",
            "r1 += r6;",
            "r0 = *(u32 *)(r1 + 0);",
            "1:exit;",
            vals = in(reg) core::ptr::addr_of!(vals),
            callback_subprog = in(reg) callback_subprog as usize,
            out("r0") ret,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
            out("r6") _,
            options(nostack)
        );
    }
    ret
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: parent_callee_saved_reg_precise
extern "C" fn parent_callee_saved_reg_precise() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r6 = 3;",
            "r1 = 0;",
            "call {identity_subprog};",
            "r6 *= 4;",
            "r1 = {vals};",
            "r1 += r6;",
            "r0 = *(u32 *)(r1 + 0);",
            "exit;",
            vals = in(reg) core::ptr::addr_of!(vals),
            identity_subprog = sym identity_subprog,
            out("r0") ret,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
            out("r6") _,
            options(nostack)
        );
    }
    ret
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: parent_callee_saved_reg_precise_global
extern "C" fn parent_callee_saved_reg_precise_global() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r6 = 3;",
            "r1 = 0;",
            "call {global_identity_subprog};",
            "r6 *= 4;",
            "r1 = {vals};",
            "r1 += r6;",
            "r0 = *(u32 *)(r1 + 0);",
            "exit;",
            vals = in(reg) core::ptr::addr_of!(vals),
            global_identity_subprog = sym global_identity_subprog,
            out("r0") ret,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
            out("r6") _,
            options(nostack)
        );
    }
    ret
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: parent_callee_saved_reg_precise_with_callback
extern "C" fn parent_callee_saved_reg_precise_with_callback() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r6 = 3;",
            "r1 = 1;",
            "r2 = {callback_subprog};",
            "r3 = 0;",
            "r4 = 0;",
            "call 181;",
            "r6 *= 4;",
            "r1 = {vals};",
            "r1 += r6;",
            "r0 = *(u32 *)(r1 + 0);",
            "exit;",
            vals = in(reg) core::ptr::addr_of!(vals),
            callback_subprog = in(reg) callback_subprog as usize,
            out("r0") ret,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
            out("r6") _,
            options(nostack)
        );
    }
    ret
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: parent_stack_slot_precise
extern "C" fn parent_stack_slot_precise() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r6 = 3;",
            "*(u64 *)(r10 - 8) = r6;",
            "r1 = 0;",
            "call {identity_subprog};",
            "r6 = *(u64 *)(r10 - 8);",
            "r6 *= 4;",
            "r1 = {vals};",
            "r1 += r6;",
            "r0 = *(u32 *)(r1 + 0);",
            "exit;",
            vals = in(reg) core::ptr::addr_of!(vals),
            identity_subprog = sym identity_subprog,
            out("r0") ret,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
            out("r6") _,
            options(nostack)
        );
    }
    ret
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: parent_stack_slot_precise_global
extern "C" fn parent_stack_slot_precise_global() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r6 = 3;",
            "*(u64 *)(r10 - 8) = r6;",
            "r1 = 0;",
            "call {global_identity_subprog};",
            "r6 = *(u64 *)(r10 - 8);",
            "r6 *= 4;",
            "r1 = {vals};",
            "r1 += r6;",
            "r0 = *(u32 *)(r1 + 0);",
            "exit;",
            vals = in(reg) core::ptr::addr_of!(vals),
            global_identity_subprog = sym global_identity_subprog,
            out("r0") ret,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
            out("r6") _,
            options(nostack)
        );
    }
    ret
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: parent_stack_slot_precise_with_callback
extern "C" fn parent_stack_slot_precise_with_callback() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r6 = 3;",
            "*(u64 *)(r10 - 8) = r6;",
            "r1 = r6;",
            "r2 = {callback_subprog};",
            "r3 = 0;",
            "r4 = 0;",
            "call 181;",
            "r6 = *(u64 *)(r10 - 8);",
            "r6 *= 4;",
            "r1 = {vals};",
            "r1 += r6;",
            "r0 = *(u32 *)(r1 + 0);",
            "exit;",
            vals = in(reg) core::ptr::addr_of!(vals),
            callback_subprog = in(reg) callback_subprog as usize,
            out("r0") ret,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
            out("r6") _,
            options(nostack)
        );
    }
    ret
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: subprog_arg_precise
extern "C" fn subprog_arg_precise() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r6 = 3;",
            "r1 = r6;",
            "call {subprog_with_precise_arg};",
            "r0 += r6;",
            "exit;",
            subprog_with_precise_arg = sym subprog_with_precise_arg,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: subprog_spill_reg_precise
extern "C" fn subprog_spill_reg_precise() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r1 + 0) = r2;",
            "*(u64 *)(r10 - 16) = r2;",
            "r0 = *(u64 *)(r10 - 16);",
            "r2 = *(u64 *)(r1 + 0);",
            "r0 += r2;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: subprog_spill_into_parent_stack_slot_precise
extern "C" fn subprog_spill_into_parent_stack_slot_precise() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r6 = 1;",
            "r1 = r10;",
            "r1 += -8;",
            "r2 = r6;",
            "call {subprog_spill_reg_precise};",
            "r7 = *(u64 *)(r10 - 8);",
            "r7 *= 4;",
            "r1 = {vals};",
            "r1 += r7;",
            "r0 = *(u32 *)(r1 + 0);",
            "exit;",
            vals = in(reg) core::ptr::addr_of!(vals),
            subprog_spill_reg_precise = sym subprog_spill_reg_precise,
            out("r0") ret,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
            out("r6") _,
            out("r7") _,
            options(nostack)
        );
    }
    ret
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_slot_aliases_precision
extern "C" fn stack_slot_aliases_precision() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r6 = 1;",
            "r1 = r6;",
            "call {identity_subprog};",
            "r7 = r10;",
            "r7 += -8;",
            "r8 = r10;",
            "r8 += -32;",
            "*(u64 *)(r10 - 16) = r0;",
            "r0 = *(u64 *)(r7 - 8);",
            "*(u64 *)(r8 + 16) = r0;",
            "r0 = *(u64 *)(r8 + 16);",
            "*(u64 *)(r7 - 8) = r0;",
            "r0 = *(u64 *)(r10 - 16);",
            "r0 *= 4;",
            "r1 = {vals};",
            "r1 += r0;",
            "r0 = *(u32 *)(r1 + 0);",
            "exit;",
            vals = in(reg) core::ptr::addr_of!(vals),
            identity_subprog = sym identity_subprog,
            out("r0") ret,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
            out("r6") _,
            options(nostack)
        );
    }
    ret
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: identity_tail_call
extern "C" fn identity_tail_call() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "r6 = r2;",
            "r2 = {map_array} ll;",
            "r3 = 0;",
            "call 12;",
            "r0 = r6;",
            "exit;",
            map_array = sym map_array,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: subprog_result_tail_call
extern "C" fn subprog_result_tail_call() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r2 = 3;",
            "call {identity_tail_call};",
            "r0 *= 4;",
            "r1 = {vals};",
            "r1 += r0;",
            "r0 = *(u32 *)(r1 + 0);",
            "exit;",
            vals = in(reg) core::ptr::addr_of!(vals),
            identity_tail_call = sym identity_tail_call,
            out("r0") ret,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
            options(nostack)
        );
    }
    ret
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: ld_abs_subprog
extern "C" fn ld_abs_subprog() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r7 = r1;",
            ".8byte 32;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ld_abs_backtrack_both_paths
extern "C" fn ld_abs_backtrack_both_paths() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r7 = -8;",
            "call {ld_abs_subprog};",
            "r1 = r10;",
            "r1 += r7;",
            "*(u64 *)(r1 + 0) = 0;",
            "r0 = 0;",
            "exit;",
            ld_abs_subprog = sym ld_abs_subprog,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

include!("hand/verifier_subprog_precision.rs");

bpf_object!("GPL");
