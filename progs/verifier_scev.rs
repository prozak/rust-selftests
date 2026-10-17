// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_scev.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_scev.rs
// (include!d below): global_noop_counter, no_widen_dynptr_kfunc_arg.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_scev` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: simple_loop1 indirect_write_invalidates_scev global_noop_counter global_call_invalidates_scev simple_loop2 meet_agrees meet_disagrees entry_state_join expr_chain alu_ops_exprs store_load_exprs nested_loop1 nested_loop_hdr_backedge1 nested_loop_hdr_backedge2 nested_loops_shared_header nested_loops_outer_latch_true_branch_to_inner pre_lt post_lt pre_le post_le pre_gt post_gt pre_ge post_ge pre_slt post_slt pre_sle post_sle pre_sgt post_sgt pre_sge post_sge pre_ne post_ne pre_ne_down post_ne_down pre_lt_round pre_le_round pre_gt_round pre_ge_round pre_slt_round pre_sle_round pre_sgt_round pre_sge_round pre_le_eq pre_ge_eq pre_sle_eq pre_sge_eq pre_lt_sign pre_gt_sign pre_lt_false pre_le_false pre_gt_false pre_ge_false pre_slt_false pre_sle_false pre_sgt_false pre_sge_false pre_ne_false pre_lt_dir pre_le_dir pre_gt_dir pre_ge_dir pre_slt_dir pre_sle_dir pre_sgt_dir pre_sge_dir pre_lt_wrap pre_le_wrap pre_gt_wrap pre_ge_wrap pre_slt_wrap pre_sle_wrap pre_sgt_wrap pre_sge_wrap pre_le_count_ovf pre_ge_count_ovf pre_sle_count_ovf pre_sge_count_ovf pre_ne_rem pre_ne_rem_down pre_ne_wrap_up pre_ne_wrap_down pre_lt_max_hdrs pre_lt_sentinel pre_lt_hdr_ovf pre_lt_step_max pre_gt_step_min pre_ne_step_min pre_lt_zero_step post_cond_jlt mark_bound_precise mark_base_precise eval_expr_small_spill_bound eval_expr_small_spill_bound_fits no_widen_small_spill_counter widen_full_spill_counter widen_acquire_release_counter widen_any_small_spill_leaf widen_any_unallocated_slot widen_any_zero_spill widen_any_misc_slot probe_read_stack widen_subprog_probe_read widen_overflowing_range eval_expr_unallocated_stack_bound post_cond_jlt_with_base latch_base_differs_from_step post_cond_jle post_cond_jge pre_cond_jge post_cond_jne post_cond_jne_neg_step pre_cond_je1 one_backedge_two_exits correlated_regs nested_loops_precise_var1 nested_loop_with_two_exits exit_loop_into_loop_header enter_nested_loop_from_side nested_irreducible_loop nested_irreducible_loop2 widen_nonconst_base widen_nonconst_base_refined sibling_inner_loops uninit_slot_counter conditional_assignment_on_second_iteration no_widen_changing_latch_bound conditional_stack_pointer_assignment no_widen_any_map_origin any_stack_origin_callee no_widen_any_stack_origin conditional_scalar_assignment_gcd break_pkt_pointers_id no_widen_stack_spill no_widen_stack_spill_nested nested_loop_exit_clobbers_reg nested_loop_exit_preserves_reg widen_byte_stack_store no_widen_stack_fill no_widen_stack_fill_any no_widen_dynptr_kfunc_arg ptr_stack ptr_stack_callee ptr_stack_other_frame ptr_packet_meta_other_origin ptr_map_value_two_lookups ptr_map_value_two_lookups_inner_map ptr_map_value ptr_map_value_other_map ptr_mem ptr_mem_other_reservation ptr_buf ptr_buf_other_load ptr_vs_scalar_no_widen no_widen_maybe_null nested_terminating_prune nested_loop_backedge_to_outer_header post_cond_ivar_src dominating_exit_bounds_count

use bpf_rs_core::{bpf_map, bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    simple_loop1:
        __success,
        __log_level("2"),
        __msg_next("scev at header 1:"),
        __msg_next("  r0=(+ r0 1) / (linear r0 1)");
    indirect_write_invalidates_scev:
        __success,
        __log_level("2"),
        __msg("8: (7b) *(u64 *)(r1 +0) = r0     ; *fp-8 (+ *fp-8 1) -> ?");
    global_call_invalidates_scev:
        __success,
        __log_level("2"),
        __msg("8: (85) call pc+{{[0-9]+}} {{.*}}; *fp-8 (+ *fp-8 1) -> ?");
    simple_loop2:
        __success,
        __log_level("2"),
        __msg_next("scev at header 2:"),
        __msg_next("  *fp-8=(+ *fp-8 1) / (linear *fp-8 1)"),
        __msg_next(" scev at latch 3:"),
        __msg_next("  r0=*fp-8 / (linear *fp-8 1)"),
        __msg_next("  *fp-8=*fp-8 / (linear *fp-8 1)");
    meet_agrees:
        __success,
        __log_level("2"),
        __msg_next("scev at header 2:"),
        __msg_next("  r1=(+ r1 1) / (linear r1 1)");
    meet_disagrees:
        __failure,
        __log_level("2"),
        __msg_next("scev at header 1:"),
        __msg_next("  r6=(any r6 (+ r6 1)) / ?");
    entry_state_join:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("scev at header 2:"),
        __msg_next("  r0=(+ r0 1) / (linear r0 1)"),
        __msg_next("  r1=42 / (any r1 42)"),
        __msg_next(" scev at latch 2:"),
        __msg_next("  r0=(+ r0 1) / (linear r0 1)"),
        __msg_next("  r1=42 / (any r1 42)"),
        __msg("loop header at 2, widening r0 to 0..10 step 1"),
        __msg_next("loop header at 2, widening r1 to 7..42 step 1");
    expr_chain:
        __log_level("2"),
        __msg_next("scev at header 1:"),
        __msg_next("  r6=(bswap32 (bswap32 (zext32 (- (- (zext32 (+ (>>...) 1))))))) / ?");
    alu_ops_exprs:
        __success,
        __log_level("2"),
        __msg("r1 += 2 {{.*}}; r1 r6 -> (+ r6 2)"),
        __msg("r1 += r7 {{.*}}; r1 r6 -> (+ r6 r7)"),
        __msg("w1 += 2 {{.*}}; r1 r6 -> (zext32 (+ r6 2))"),
        __msg("w1 += w7 {{.*}}; r1 r6 -> (zext32 (+ r6 r7))"),
        __msg("r1 -= 2 {{.*}}; r1 r6 -> (- r6 2)"),
        __msg("r1 -= r7 {{.*}}; r1 r6 -> (- r6 r7)"),
        __msg("w1 -= 2 {{.*}}; r1 r6 -> (zext32 (- r6 2))"),
        __msg("w1 -= w7 {{.*}}; r1 r6 -> (zext32 (- r6 r7))"),
        __msg("r1 *= 2 {{.*}}; r1 r6 -> (* r6 2)"),
        __msg("r1 *= r7 {{.*}}; r1 r6 -> (* r6 r7)"),
        __msg("w1 *= 2 {{.*}}; r1 r6 -> (zext32 (* r6 2))"),
        __msg("w1 *= w7 {{.*}}; r1 r6 -> (zext32 (* r6 r7))"),
        __msg("r1 /= 2 {{.*}}; r1 r6 -> (/ r6 2)"),
        __msg("r1 /= r7 {{.*}}; r1 r6 -> (/ r6 r7)"),
        __msg("w1 /= 2 {{.*}}; r1 r6 -> (zext32 (/ r6 2))"),
        __msg("w1 /= w7 {{.*}}; r1 r6 -> (zext32 (/ r6 r7))"),
        __msg("r1 s/= 2 {{.*}}; r1 r6 -> (s/ r6 2)"),
        __msg("r1 s/= r7 {{.*}}; r1 r6 -> (s/ r6 r7)"),
        __msg("w1 s/= 2 {{.*}}; r1 r6 -> (zext32 (s/ r6 2))"),
        __msg("w1 s/= w7 {{.*}}; r1 r6 -> (zext32 (s/ r6 r7))"),
        __msg("r1 %= 2 {{.*}}; r1 r6 -> (% r6 2)"),
        __msg("r1 %= r7 {{.*}}; r1 r6 -> (% r6 r7)"),
        __msg("w1 %= 2 {{.*}}; r1 r6 -> (zext32 (% r6 2))"),
        __msg("w1 %= w7 {{.*}}; r1 r6 -> (zext32 (% r6 r7))"),
        __msg("r1 s%= 2 {{.*}}; r1 r6 -> (s% r6 2)"),
        __msg("r1 s%= r7 {{.*}}; r1 r6 -> (s% r6 r7)"),
        __msg("w1 s%= 2 {{.*}}; r1 r6 -> (zext32 (s% r6 2))"),
        __msg("w1 s%= w7 {{.*}}; r1 r6 -> (zext32 (s% r6 r7))"),
        __msg("r1 |= 2 {{.*}}; r1 r6 -> (| r6 2)"),
        __msg("r1 |= r7 {{.*}}; r1 r6 -> (| r6 r7)"),
        __msg("w1 |= 2 {{.*}}; r1 r6 -> (zext32 (| r6 2))"),
        __msg("w1 |= w7 {{.*}}; r1 r6 -> (zext32 (| r6 r7))"),
        __msg("r1 &= 2 {{.*}}; r1 r6 -> (& r6 2)"),
        __msg("r1 &= r7 {{.*}}; r1 r6 -> (& r6 r7)"),
        __msg("w1 &= 2 {{.*}}; r1 r6 -> (zext32 (& r6 2))"),
        __msg("w1 &= w7 {{.*}}; r1 r6 -> (zext32 (& r6 r7))"),
        __msg("r1 ^= 2 {{.*}}; r1 r6 -> (^ r6 2)"),
        __msg("r1 ^= r7 {{.*}}; r1 r6 -> (^ r6 r7)"),
        __msg("w1 ^= 2 {{.*}}; r1 r6 -> (zext32 (^ r6 2))"),
        __msg("w1 ^= w7 {{.*}}; r1 r6 -> (zext32 (^ r6 r7))"),
        __msg("r1 <<= 2 {{.*}}; r1 r6 -> (<< r6 2)"),
        __msg("r1 <<= r7 {{.*}}; r1 r6 -> (<< r6 r7)"),
        __msg("w1 <<= 2 {{.*}}; r1 r6 -> (zext32 (<< r6 2))"),
        __msg("w1 <<= w7 {{.*}}; r1 r6 -> (zext32 (<< r6 r7))"),
        __msg("r1 >>= 2 {{.*}}; r1 r6 -> (>> r6 2)"),
        __msg("r1 >>= r7 {{.*}}; r1 r6 -> (>> r6 r7)"),
        __msg("w1 >>= 2 {{.*}}; r1 r6 -> (zext32 (>> r6 2))"),
        __msg("w1 >>= w7 {{.*}}; r1 r6 -> (zext32 (>> r6 r7))"),
        __msg("r1 s>>= 2 {{.*}}; r1 r6 -> (s>> r6 2)"),
        __msg("r1 s>>= r7 {{.*}}; r1 r6 -> (s>> r6 r7)"),
        __msg("w1 s>>= 2 {{.*}}; r1 r6 -> (zext32 (s>> r6 2))"),
        __msg("w1 s>>= w7 {{.*}}; r1 r6 -> (zext32 (s>> r6 r7))"),
        __msg("r1 = -r1 {{.*}}; r1 r6 -> (- r6)"),
        __msg("w1 = -w1 {{.*}}; r1 r6 -> (zext32 (- r6))"),
        __msg("r1 = 42 {{.*}}; r1 r6 -> 42"),
        __msg("w1 = 42 {{.*}}; r1 r6 -> (zext32 42)"),
        __msg("r1 = r7 {{.*}}; r1 r6 -> r7"),
        __msg("w1 = w7 {{.*}}; r1 r6 -> (zext32 r7)"),
        __msg("r1 = (s8)r6 {{.*}}; r1 r6 -> (sext8 r6)"),
        __msg("r1 = (s16)r6 {{.*}}; r1 r6 -> (sext16 r6)"),
        __msg("r1 = (s32)r6 {{.*}}; r1 r6 -> (sext32 r6)"),
        __msg("w1 = (s8)w6 {{.*}}; r1 r6 -> (zext32 (sext8 r6))"),
        __msg("w1 = (s16)w6 {{.*}}; r1 r6 -> (zext32 (sext16 r6))"),
        __msg("r1 = bswap16 r1 {{.*}}; r1 r6 -> (bswap16 r6)"),
        __msg("r1 = bswap32 r1 {{.*}}; r1 r6 -> (bswap32 r6)"),
        __msg("r1 = bswap64 r1 {{.*}}; r1 r6 -> (bswap64 r6)"),
        __msg("r1 = le16 r1 {{.*}}; r1 r6 -> (zext16 r6)"),
        __msg("r1 = le32 r1 {{.*}}; r1 r6 -> (zext32 r6)"),
        __msg("r1 += 1 {{.*}}; r1 r6 -> (+ r6 1)"),
        __msg("r1 = be16 r1 {{.*}}; r1 r6 -> (bswap16 r6)"),
        __msg("r1 = be32 r1 {{.*}}; r1 r6 -> (bswap32 r6)"),
        __msg("r1 = be64 r1 {{.*}}; r1 r6 -> (bswap64 r6)");
    store_load_exprs:
        __success,
        __log_level("2"),
        __msg("*(u64 *)(r10 -8) = r1 {{.*}}; *fp-8 -8 -> 1"),
        __msg("*(u32 *)(r10 -8) = r1 {{.*}}; *fp-8 -8 -> (spill32 1)"),
        __msg("*(u16 *)(r10 -8) = r1 {{.*}}; *fp-8 -8 -> (spill16 1)"),
        __msg("*(u8 *)(r10 -8) = r1 {{.*}}; *fp-8 -8 -> (spill8 1)"),
        __msg("r1 = *(u64 *)(r10 -8) {{.*}}; r1 1 -> -8"),
        __msg("r1 = *(u32 *)(r10 -8) {{.*}}; r1 1 -> (zext32 -8)"),
        __msg("r1 = *(u16 *)(r10 -8) {{.*}}; r1 1 -> (zext16 -8)"),
        __msg("r1 = *(u8 *)(r10 -8) {{.*}}; r1 1 -> (zext8 -8)"),
        __msg("r1 = *(s32 *)(r10 -8) {{.*}}; r1 1 -> (sext32 -8)"),
        __msg("r1 = *(s16 *)(r10 -8) {{.*}}; r1 1 -> (sext16 -8)"),
        __msg("r1 = *(s8 *)(r10 -8) {{.*}}; r1 1 -> (sext8 -8)"),
        __msg("r1 = load_acquire((u8 *)(r10 -8)) {{.*}}; r1 1 -> (zext8 -8)"),
        __msg("r1 = load_acquire((u16 *)(r10 -8)) {{.*}}; r1 1 -> (zext16 -8)"),
        __msg("r1 = load_acquire((u32 *)(r10 -8)) {{.*}}; r1 1 -> (zext32 -8)"),
        __msg("r2 = load_acquire((u64 *)(r10 -8)) {{.*}}; r2 2 -> -8"),
        __msg("store_release((u8 *)(r10 -8), r1) {{.*}}; *fp-8 -8 -> (spill8 1)"),
        __msg("store_release((u16 *)(r10 -8), r1) {{.*}}; *fp-8 -8 -> (spill16 1)"),
        __msg("store_release((u32 *)(r10 -8), r1) {{.*}}; *fp-8 -8 -> (spill32 1)"),
        __msg("store_release((u64 *)(r10 -8), r1) {{.*}}; *fp-8 -8 -> 1"),
        __msg("lock *(u64 *)(r10 -8) += r1 {{.*}}; *fp-8 -8 -> _"),
        __msg("r1 = atomic64_fetch_add((u64 *)(r10 -8), r1) {{.*}}; r1 1 -> _, *fp-8 -8 -> _"),
        __msg("r1 = atomic_fetch_add((u32 *)(r10 -8), r1) {{.*}}; r1 1 -> _, *fp-8 -8 -> _"),
        __msg("r1 = atomic64_xchg((u64 *)(r10 -8), r1) {{.*}}; r1 1 -> _, *fp-8 -8 -> _"),
        __msg("r0 = atomic64_cmpxchg((u64 *)(r10 -8), r0, r2) {{.*}}; r0 0 -> _, *fp-8 -8 -> _"),
        __msg("*(u64 *)(r10 -8) = 42 {{.*}}; *fp-8 -8 -> 42"),
        __msg("*(u8 *)(r10 -7) = r0 {{.*}}; *fp-8 -8 -> _");
    nested_loop1:
        __success,
        __log_level("2"),
        __msg_next("scev at header 1:"),
        __msg_next("  r6=(+ r6 1) / (linear r6 1)"),
        __msg_next("  r7=?"),
        __msg_next(" scev at latch 1:"),
        __msg_next("  r6=(+ r6 1) / (linear r6 1)"),
        __msg_next("  r7=?"),
        __msg_next("scev at header 4:"),
        __msg_next("  r7=(+ r7 1) / (linear r7 1)"),
        __msg_next(" scev at latch 4:"),
        __msg_next("  r7=(+ r7 1) / (linear r7 1)");
    nested_loop_hdr_backedge1:
        __success,
        __msg("loop at 1"),
        __msg_next("  backedge from 4{{$}}"),
        __msg_next("  exit from 1 to 7"),
        __msg_next("loop at 4, nested in 1"),
        __msg_next("  backedge from 6, latch at 4"),
        __msg_next("  exit from 4 to 1"),
        __msg("scev at header 1:"),
        __msg_next("  r6=(+ r6 1) / (linear r6 1)"),
        __msg_next("  r7=?"),
        __msg_next("scev at header 4:"),
        __msg_next("  r7=(+ r7 1) / (linear r7 1)"),
        __msg_next(" scev at latch 4:"),
        __msg_next("  r7=(+ r7 1) / (linear r7 1)"),
        __msg("loop header at 1, latch not identified"),
        __msg("loop header at 4, widening r7 to 0..2 step 1"),
        __log_level("2");
    nested_loop_hdr_backedge2:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop at 2{{$}}"),
        __msg_next("  backedge from 4{{$}}"),
        __msg_next("  exit from 5 to 6"),
        __msg_next("loop at 3, nested in 2"),
        __msg_next("  backedge from 5, latch at 5"),
        __msg_next("  exit from 4 to 2"),
        __msg_next("  exit from 5 to 6"),
        __msg("scev at header 2:"),
        __msg_next("  r6=?"),
        __msg_next("  r7=(+ r7 1) / (linear r7 1)"),
        __msg_next("scev at header 3:"),
        __msg_next("  r6=(+ r6 1) / (linear r6 1)"),
        __msg_next(" scev at latch 5:"),
        __msg_next("  r6=(+ r6 1) / (linear (+ r6 1) 1)"),
        __msg("loop header at 2, latch not identified"),
        __msg("loop header at 3, header_count is [0..2] ");
    nested_loops_shared_header:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop at 3{{$}}"),
        __msg("scev at header 3:"),
        __msg_next("  r6=(any r6 (+ r6 1)) / ?"),
        __msg_next("  r7=(any (+ r7 1) 0) / ?"),
        __msg_next("  r8=(+ r8 1) / (linear r8 1)"),
        __msg("loop header at 3, unsupported loop: multiple backedges");
    nested_loops_outer_latch_true_branch_to_inner:
        __success,
        __log_level("2"),
        __msg("loop header at 1, header_count is 10"),
        __msg("loop header at 5, header_count is 5"),
        __flag("BPF_F_TEST_STATE_FREQ");
    pre_lt:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, header_count is 4 ");
    post_lt:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, header_count is 3 ");
    pre_le:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, header_count is 5 ");
    post_le:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, header_count is 4 ");
    pre_gt:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, header_count is 4 ");
    post_gt:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, header_count is 3 ");
    pre_ge:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, header_count is 5 ");
    post_ge:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, header_count is 4 ");
    pre_slt:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, header_count is 4 ");
    post_slt:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, header_count is 3 ");
    pre_sle:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, header_count is 5 ");
    post_sle:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, header_count is 4 ");
    pre_sgt:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, header_count is 4 ");
    post_sgt:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, header_count is 3 ");
    pre_sge:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, header_count is 5 ");
    post_sge:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, header_count is 4 ");
    pre_ne:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, header_count is 4 ");
    post_ne:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, header_count is 3 ");
    pre_ne_down:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, header_count is 4 ");
    post_ne_down:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, header_count is 3 ");
    pre_lt_round:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, header_count is 5 ");
    pre_le_round:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, header_count is 5 ");
    pre_gt_round:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, header_count is 5 ");
    pre_ge_round:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, header_count is 5 ");
    pre_slt_round:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, header_count is 5 ");
    pre_sle_round:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, header_count is 5 ");
    pre_sgt_round:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, header_count is 5 ");
    pre_sge_round:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, header_count is 5 ");
    pre_le_eq:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, header_count is 2 ");
    pre_ge_eq:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, header_count is 2 ");
    pre_sle_eq:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, header_count is 2 ");
    pre_sge_eq:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, header_count is 2 ");
    pre_lt_sign:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, header_count is 4 ");
    pre_gt_sign:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, header_count is 4 ");
    pre_lt_false:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, can't compute iterations count");
    pre_le_false:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, can't compute iterations count");
    pre_gt_false:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, can't compute iterations count");
    pre_ge_false:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, can't compute iterations count");
    pre_slt_false:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, can't compute iterations count");
    pre_sle_false:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, can't compute iterations count");
    pre_sgt_false:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, can't compute iterations count");
    pre_sge_false:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, can't compute iterations count");
    pre_ne_false:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, can't compute iterations count");
    pre_lt_dir:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, can't compute iterations count");
    pre_le_dir:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, can't compute iterations count");
    pre_gt_dir:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, can't compute iterations count");
    pre_ge_dir:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, can't compute iterations count");
    pre_slt_dir:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, can't compute iterations count");
    pre_sle_dir:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, can't compute iterations count");
    pre_sgt_dir:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, can't compute iterations count");
    pre_sge_dir:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, can't compute iterations count");
    pre_lt_wrap:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, can't compute iterations count");
    pre_le_wrap:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, can't compute iterations count");
    pre_gt_wrap:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, can't compute iterations count");
    pre_ge_wrap:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, can't compute iterations count");
    pre_slt_wrap:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, can't compute iterations count");
    pre_sle_wrap:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, can't compute iterations count");
    pre_sgt_wrap:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, can't compute iterations count");
    pre_sge_wrap:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, can't compute iterations count");
    pre_le_count_ovf:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, can't compute iterations count");
    pre_ge_count_ovf:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, can't compute iterations count");
    pre_sle_count_ovf:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, can't compute iterations count");
    pre_sge_count_ovf:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, can't compute iterations count");
    pre_ne_rem:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, can't compute iterations count");
    pre_ne_rem_down:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, can't compute iterations count");
    pre_ne_wrap_up:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, header_count is 2 ");
    pre_ne_wrap_down:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, header_count is 2 ");
    pre_lt_max_hdrs:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, header_count is [0..4294967294] ");
    pre_lt_sentinel:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, can't compute iterations count");
    pre_lt_hdr_ovf:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, can't compute iterations count");
    pre_lt_step_max:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, header_count is 2 ");
    pre_gt_step_min:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, header_count is 2 ");
    pre_ne_step_min:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, header_count is 2 ");
    pre_lt_zero_step:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at {{[0-9]+}}, can't compute iterations count");
    post_cond_jlt:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at 1, header_count is 10 "),
        __msg("loop header at 1, widening r0 to 0..9 step 1"),
        __msg("processed 5 insns");
    mark_bound_precise:
        __failure,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at 6, header_count is 10 "),
        __msg("mark_precise: frame0: parent state regs=r6,r7 stack=:"),
        __msg("loop header at 6, widening r0 to 0..9 step 1"),
        __msg("loop header at 6, header_count is 4096 "),
        __msg("loop header at 6, widening r0 to 0..4095 step 1"),
        __msg("invalid variable-offset read from stack R2");
    mark_base_precise:
        __failure,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at 5, header_count is 10 "),
        __msg("mark_precise: frame0: parent state regs=r6 stack=:"),
        __msg("loop header at 5, widening r0 to 0..9 step 1"),
        __msg("loop header at 5, header_count is 4096 "),
        __msg("loop header at 5, widening r0 to 0..4095 step 1"),
        __msg("invalid variable-offset read from stack R2");
    eval_expr_small_spill_bound:
        __success,
        __log_level("2"),
        __msg("scev at header 3:"),
        __msg_next("  r0=(+ r0 1) / (linear r0 1)"),
        __msg("loop header at 3, can't compute iterations count");
    eval_expr_small_spill_bound_fits:
        __success,
        __log_level("2"),
        __msg("scev at header 3:"),
        __msg_next("  r0=(+ r0 1) / (linear r0 1)"),
        __msg("loop header at 3, can't compute iterations count");
    no_widen_small_spill_counter:
        __success,
        __log_level("2"),
        __msg("scev at header 2:"),
        __msg_next("  *fp-8=(+ *fp-8 1) / (linear *fp-8 1)"),
        __msg("loop header at 2, can't compute iterations count"),
        __not_msg("widening");
    widen_full_spill_counter:
        __success,
        __log_level("2"),
        __msg("scev at header 2:"),
        __msg_next("  *fp-8=(+ *fp-8 1) / (linear *fp-8 1)"),
        __msg("loop header at 2, widening *fp-8 to 5..14 step 1");
    widen_acquire_release_counter:
        __success,
        __log_level("2"),
        __msg("scev at header 2:"),
        __msg_next("  *fp-8=(+ *fp-8 1) / (linear *fp-8 1)"),
        __msg("loop header at 2, widening *fp-8 to 5..14 step 1");
    widen_any_small_spill_leaf:
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("scev at header 6:"),
        __msg_next("  r6=*fp-8 / (any r6 *fp-8)"),
        __msg_next("  r7=(+ r7 1) / (linear r7 1)"),
        __msg("loop header at 6, widening r6 to 0x8000000000000000..0x7fffffffffffffff step 1");
    widen_any_unallocated_slot:
        __success,
        __retval("7"),
        __log_level("2"),
        __msg("scev at header 1:"),
        __msg_next("r6=(+ r6 1) / (linear r6 1)"),
        __msg_next("*fp-8=(any *fp-8 7) / (any *fp-8 7)"),
        __msg("loop header at 1, widening r6 to 0..2 step 1"),
        __msg("2: (7a) *(u64 *)(r10 -8) = 7          ; R10=fp0 fp-8=7 loop_stack=1");
    widen_any_zero_spill:
        __success,
        __retval("7"),
        __log_level("2"),
        __msg("loop header at 2, widening *fp-8 to 0..7 step 1");
    widen_any_misc_slot:
        __success,
        __retval("7"),
        __log_level("2"),
        __msg("scev at header 2:"),
        __msg_next("r6=(+ r6 1) / (linear r6 1)"),
        __msg_next("*fp-8=(any *fp-8 7) / (any *fp-8 7)"),
        __msg("loop header at 2, widening r6 to 0..2 step 1"),
        __msg("3: (79) r1 = *(u64 *)(r10 -8)         ; R1=scalar() R10=fp0 fp-8=m???????");
    widen_subprog_probe_read:
        __success,
        __log_level("2"),
        __msg("scev at header 4:"),
        __msg_next("  r6=(+ r6 1) / (linear r6 1)"),
        __msg_next("  *fp-8=?"),
        __msg("loop header at 4, widening r6 to 0..9 step 1");
    widen_overflowing_range:
        __success,
        __log_level("2"),
        __msg("loop header at 4, header_count is 10"),
        __msg("loop header at 4, widening r1 to 0..9 step 1"),
        __msg("loop header at 4, widening r6 to 0x8000000000000000..0x7fffffffffffffff step 1"),
        __flag("BPF_F_TEST_STATE_FREQ");
    eval_expr_unallocated_stack_bound:
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("scev at header 1:"),
        __msg_next("  r0=(+ r0 1) / (linear r0 1)"),
        __msg("loop header at 1, can't compute iterations count"),
        __not_msg("widening");
    post_cond_jlt_with_base:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at 3, header_count is 8"),
        __msg("loop header at 3, widening r0 to 2..9 step 1"),
        __msg("3: R0=scalar(smin=umin=smin32=umin32=2,smax=umax=smax32=umax32=9,{{.*}})"),
        __msg("processed 6 insns");
    latch_base_differs_from_step:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at 1, header_count is 4 ");
    post_cond_jle:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at 1, header_count is 11"),
        __msg("loop header at 1, widening r0 to 0..10 step 1"),
        __msg("1: R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=10,{{.*}})"),
        __msg("processed 5 insns");
    post_cond_jge:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at 1, header_count is 10"),
        __msg("loop header at 1, widening r0 to 0..9 step 1"),
        __msg("1: R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=9,{{.*}})"),
        __msg("processed 6 insns");
    pre_cond_jge:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at 1, header_count is 11"),
        __msg("loop header at 1, widening r0 to 0..10 step 1"),
        __msg("1: R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=10,{{.*}})"),
        __msg("processed 6 insns");
    post_cond_jne:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg_next("scev at header 1:"),
        __msg_next("  r0=(+ r0 1) / (linear r0 1)"),
        __msg_next(" scev at latch 2:"),
        __msg_next("  r0=(+ r0 1) / (linear (+ r0 1) 1)"),
        __msg("loop header at 1, widening r0"),
        __msg("1: R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=2,{{.*}})"),
        __msg("1: (07) r0 += 1                       ; R0=scalar(smin=umin=smin32=umin32=1,smax=umax=smax32=umax32=3,{{.*}})"),
        __msg("2: (55) if r0 != 0x3 goto pc-2"),
        __msg("3: (95) exit"),
        __msg("loop header at 1, clamping r0"),
        __msg("from 2 to 1: safe"),
        __msg("processed 5 insns");
    post_cond_jne_neg_step:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg_next("scev at header 1:"),
        __msg_next("  r0=(+ r0 -1) / (linear r0 -1)"),
        __msg_next(" scev at latch 2:"),
        __msg_next("  r0=(+ r0 -1) / (linear (+ r0 -1) -1)"),
        __msg("loop header at 1, header_count is 3 "),
        __msg("loop header at 1, widening r0 to 1..3 step 1"),
        __msg("1: R0=scalar(smin=umin=smin32=umin32=1,smax=umax=smax32=umax32=3,var_off=(0x0; 0x3)) loop_stack=1"),
        __msg("loop header at 1, clamping r0 to 1..2 step 1"),
        __msg("processed 5 insns");
    pre_cond_je1:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg_next("scev at header 1:"),
        __msg_next("  r0=(+ r0 1) / (linear r0 1)"),
        __msg_next(" scev at latch 1:"),
        __msg_next("  r0=(+ r0 1) / (linear r0 1)"),
        __msg("loop header at 1, widening r0"),
        __msg("1: R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=3,{{.*}})"),
        __msg("1: (15) if r0 == 0x3 goto pc+2        ; R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=2,{{.*}})"),
        __msg("2: (07) r0 += 1                       ; R0=scalar(smin=umin=smin32=umin32=1,smax=umax=smax32=umax32=3,{{.*}})"),
        __msg("3: (05) goto pc-3"),
        __msg("loop header at 1, clamping r0"),
        __msg("1: safe"),
        __msg("from 1 to 4: R0=3"),
        __msg("4: R0=3"),
        __msg("4: (95) exit"),
        __msg("processed 6 insns");
    one_backedge_two_exits:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at 1, header_count is [0..3] ");
    correlated_regs:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg_next("scev at header 11:"),
        __msg_next("  r0=(+ r0 1) / (linear r0 1)"),
        __msg_next("  r1=(+ r1 2) / (linear r1 2)"),
        __msg_next(" scev at latch 16:"),
        __msg_next("  r0=(+ r0 1) / (linear (+ r0 1) 1)"),
        __msg_next("  r1=(+ r1 2) / (linear (+ r1 2) 2)"),
        __msg("loop header at 11, widening r0"),
        __msg("loop header at 11, widening r1"),
        __msg("11: R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=7,var_off=(0x0; 0x7)) R1=scalar(smin=smin32=0,smax=umax=smax32=umax32=14,var_off=(0x0; 0xe),step=0+2)"),
        __msg("16: (a5) if r0 < 0x8 goto pc-6"),
        __msg("exiting loop 11"),
        __msg("17: (95) exit"),
        __msg("loop header at 11, clamping r0"),
        __msg("loop header at 11, clamping r1"),
        __msg("from 16 to 11: safe"),
        __not_msg("{{^}}11:"),
        __msg("from 7 to 17: safe");
    nested_loops_precise_var1:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("19: (72) *(u8 *)(r4 +0) = 1           ; R4=map_value(id={{.*}},map=map,ks=4,vs=1024,imm=16)"),
        __not_msg("19: "),
        __msg("processed 106 insns");
    nested_loop_with_two_exits:
        __success,
        __log_level("2"),
        __msg("loop header at 2, header_count is 100 "),
        __msg("loop header at 4, header_count is [0..100] "),
        __msg("loop header at 6, header_count is [0..100] "),
        __msg("processed 20 insns"),
        __flag("BPF_F_TEST_STATE_FREQ");
    exit_loop_into_loop_header:
        __success,
        __log_level("2");
    enter_nested_loop_from_side:
        __log_level("2"),
        __msg("loop at 5"),
        __msg("loop at 6, nested in 5"),
        __msg("loop at 11, irreducible"),
        __msg("loop at 12, nested in 11"),
        __msg("loop header at 12, header_count is 3 "),
        __msg("loop header at 12, widening r9 to 0..2 step 1"),
        __msg("12: R8=1 R9=scalar(smin=smin32=0,smax=umax=smax32=umax32=2,var_off=(0x0; 0x3)) loop_stack=11,12"),
        __msg("loop header at 12, header_count is 3 "),
        __msg("loop header at 12, widening r9 to 0..2 step 1"),
        __msg("from 8 to 12: R8=0 R9=scalar(smin=smin32=0,smax=umax=smax32=umax32=2,var_off=(0x0; 0x3)) R10=fp0 loop_stack=11,12");
    nested_irreducible_loop:
        __success,
        __log_level("2"),
        __msg("loop at 1{{$}}"),
        __msg("loop at 5, nested in 1, irreducible"),
        __msg("loop at 11, nested in 5"),
        __msg("scev at header 1:"),
        __msg_next("  r6=?"),
        __msg("scev at header 11:"),
        __msg_next("  r9=(+ r9 1) / (linear r9 1)"),
        __msg("loop header at 11, widening r9 to 0..2 step 1"),
        __not_msg("loop header at 1, widening r6");
    nested_irreducible_loop2:
        __success,
        __log_level("2");
    widen_nonconst_base:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at 4, widening r7 to 0..18 step 2"),
        __msg("R7=scalar(smin=smin32=0,smax=umax=smax32=umax32=18,var_off=(0x0; 0x1e),step=0+2)");
    widen_nonconst_base_refined:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at 5, header_count is 3 "),
        __msg("5: R7=scalar({{.*}}smax=umax=smax32=umax32=20,{{.*}}step=0+4)");
    sibling_inner_loops:
        __success,
        __log_level("2"),
        __msg("loop header at 1, widening r6 to 0..3 step 1"),
        __msg("loop header at 2, widening r7 to 0..2 step 1"),
        __msg("exiting loop 2"),
        __msg("entering loop 4"),
        __msg("loop header at 4, widening r7 to 1..3 step 1");
    uninit_slot_counter:
        __success,
        __log_level("2"),
        __msg("loop header at 0, can't compute iterations count");
    conditional_assignment_on_second_iteration:
        __failure,
        __log_level("2"),
        __msg("2: {{.*}}R7=scalar(smin=umin=smin32=umin32=5,smax=umax=smax32=umax32=10,var_off=(0x0; 0xf))"),
        __msg("7: R7=scalar(smin=umin=smin32=umin32=5,smax=umax=smax32=umax32=10,var_off=(0x0; 0xf))"),
        __msg("invalid read from stack R10 off=0 size=8");
    no_widen_changing_latch_bound:
        __success,
        __log_level("2"),
        __msg("scev at header 2:"),
        __msg_next("  r6=(+ r6 1) / (linear r6 1)"),
        __msg_next("  r7=(any r7 100) / (any r7 100)"),
        __msg_next(" scev at latch 3:"),
        __msg_next("  r6=(+ r6 1) / (linear (+ r6 1) 1)"),
        __msg_next("  r7=r7 / (any r7 100)");
    conditional_stack_pointer_assignment:
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("loop header at 7, widening r7 to -16..-8 step 1"),
        __msg("7: {{.*}}R7=fp(smin=smin32=-16,smax=smax32=-8,"),
        __msg("12: R7=fp(smin=smin32=-16,smax=smax32=-8,");
    no_widen_any_map_origin:
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("loop header at {{[0-9]+}}, can't widen r6, expr is"),
        __not_msg("widening");
    no_widen_any_stack_origin:
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("loop header at {{[0-9]+}}, can't widen r6, expr is"),
        __not_msg("widening");
    conditional_scalar_assignment_gcd:
        __success,
        __retval("1"),
        __log_level("2"),
        __msg("r7 += 1 {{.*}}step=1+6)"),
        __msg("r8 += 1 {{.*}}step=1+9)"),
        __msg("loop header at 9, widening r7 to 1..28 step 3"),
        __msg("9: {{.*}}R7=scalar({{.*}},step=1+3)"),
        __msg("14: R7=scalar({{.*}},step=1+3)");
    break_pkt_pointers_id:
        __failure,
        __msg("R8 min value is outside of the allowed memory range");
    no_widen_stack_spill:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at 2, can't widen r2, expr is (+ r2 8), requires exact stack-offset tracking");
    no_widen_stack_spill_nested:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at 2, can't widen r2, expr is (+ r2 8), requires exact stack-offset tracking"),
        __msg("loop header at 3, widening r1 to 0..1 step 1");
    nested_loop_exit_clobbers_reg:
        __failure,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("scev at header 9:"),
        __msg_next("  r6=(+ ? 1) / ?"),
        __msg_next(" scev at latch 20:"),
        __msg_next("  r6=(+ ? 1) / (+ ? 1)"),
        __msg_next("scev at header 13:"),
        __msg_next("  r9=(+ r9 1) / (linear r9 1)"),
        __msg_next(" scev at latch 16:"),
        __msg_next("  r6=-1000 / -1000"),
        __msg_next("  r8=r6 / r6"),
        __msg_next("  r9=(+ r9 1) / (linear (+ r9 1) 1)"),
        __msg("R6=-999"),
        __msg("R1 min value is negative");
    nested_loop_exit_preserves_reg:
        __success,
        __retval("3"),
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("r6 = *(u64 *)(r10 -8) {{.*}}; r6 ? -> r6"),
        __msg("scev at header 1:"),
        __msg_next("  r6=(+ r6 1) / (linear r6 1)"),
        __msg_next(" scev at latch 16:"),
        __msg_next("  r6=(+ r6 1) / (linear (+ r6 1) 1)"),
        __msg("scev at header 2:"),
        __msg_next("  r7=(+ r7 1) / (linear r7 1)"),
        __msg("scev at header 4:"),
        __msg_next("  r9=(+ r9 1) / (linear r9 1)"),
        __msg(" scev at latch 9:"),
        __msg_next("  r8=r6 / r6"),
        __msg_next("  r9=(+ r9 1) / (linear (+ r9 1) 1)");
    widen_byte_stack_store:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("widening r2 to 0..24 step 8");
    no_widen_stack_fill:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at 6, can't widen r2, expr is (+ r2 8), requires exact stack-offset tracking");
    no_widen_stack_fill_any:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("scev at header 4:"),
        __msg_next("r7=(any r7 8) / (any r7 8)"),
        __msg("loop header at 4, can't widen r7, expr is {{.*}}, requires exact stack-offset tracking");
    no_widen_dynptr_kfunc_arg:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("can't widen {{.*}}, requires exact stack-offset tracking");
    ptr_stack:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("header_count is 4 "),
        __msg("widening r6 to -16..-13 step 1");
    ptr_stack_other_frame:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("scev: incompatible latch operands r6 (fp), r7 (fp)"),
        __not_msg("widening r6");
    ptr_packet_meta_other_origin:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("scev: incompatible latch operands r6 (pkt_meta), r7 (pkt)"),
        __not_msg("widening r6");
    ptr_map_value_two_lookups:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("header_count is 4 "),
        __msg("widening r6 to 0..3 step 1");
    ptr_map_value_two_lookups_inner_map:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("scev: incompatible latch operands r6 (map_value), r7 (map_value)"),
        __not_msg("widening r6");
    ptr_map_value:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("header_count is 4 "),
        __msg("widening r6 to 0..3 step 1");
    ptr_map_value_other_map:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("scev: incompatible latch operands r6 (map_value), r7 (map_value)"),
        __not_msg("widening r6");
    ptr_mem:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("header_count is 4 "),
        __msg("widening r6 to 0..3 step 1");
    ptr_mem_other_reservation:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("scev: incompatible latch operands r6 (ringbuf_mem), r7 (ringbuf_mem)"),
        __not_msg("widening r6");
    ptr_buf:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("header_count is 4 "),
        __msg("widening r6 to 0..3 step 1");
    ptr_buf_other_load:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("scev: incompatible latch operands r6 (buf), r7 (buf)"),
        __not_msg("widening r6");
    ptr_vs_scalar_no_widen:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("scev: incompatible latch operands r1 (map_value), scalar 4"),
        __not_msg("widening r1");
    no_widen_maybe_null:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at 9, can't widen r1, expr is (+ r1 8)");
    nested_terminating_prune:
        __failure,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("infinite loop detected at insn 6");
    nested_loop_backedge_to_outer_header:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop at 1{{$}}"),
        __msg("loop at 4, nested in 1"),
        __msg("entering loop 1"),
        __msg("entering loop 4"),
        __msg("exiting loop 4"),
        __not_msg("entering loop 1"),
        __msg("from 4 to 1:"),
        __msg("loop_stack=1{{$}}");
    post_cond_ivar_src:
        __success,
        __log_level("2"),
        __msg("loop header at 2, header_count is 10"),
        __msg("loop header at 2, widening r1 to 0..9 step 1"),
        __flag("BPF_F_TEST_STATE_FREQ");
    dominating_exit_bounds_count:
        __success,
        __log_level("2"),
        __msg("  backedge from 4, latch at 4, dominating exits at 2"),
        __msg("loop header at 2, header_count is [0..15]"),
        __msg("loop header at 2, widening r1 to 0..14 step 1"),
        __flag("BPF_F_TEST_STATE_FREQ");
}

// Map key/value types, shaped like the C object's BTF (the kernel
// checks some of them member by member, so no explicit padding).
// translint: allow(padding)
#[allow(non_camel_case_types)]
#[repr(C)]
struct xdp_md {
    data: u32,
    data_end: u32,
    data_meta: u32,
    ingress_ifindex: u32,
    rx_queue_index: u32,
    egress_ifindex: u32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct map_val {
    foo: [i8; 1024],
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct outer_map__inner {
    r#type: *const [i32; 2],
    map_flags: *const [i32; 4096],
    max_entries: *const [i32; 1],
    key: *const i32,
    value: *const map_val,
}

bpf_map! {
    map {
        r#type: *const [i32; 1],
        max_entries: *const [i32; 1],
        key: *const i32,
        value: *const map_val,
    }
}

bpf_map! {
    small_map {
        r#type: *const [i32; 2],
        max_entries: *const [i32; 1],
        key: *const i32,
        value: *const u64,
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct outer_map {
    r#type: *const [i32; 12],
    max_entries: *const [i32; 1],
    key: *const i32,
    value: *const i32,
    values: [*const outer_map__inner; 0],
}
unsafe impl Sync for outer_map {}

#[link_section = ".maps"]
#[no_mangle]
static outer_map: outer_map = outer_map {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
    values: [],
};

bpf_map! {
    other_map {
        r#type: *const [i32; 1],
        max_entries: *const [i32; 1],
        key: *const i32,
        value: *const map_val,
    }
}

bpf_map! {
    ringbuf {
        r#type: *const [i32; 27],
        max_entries: *const [i32; 4096],
    }
}

extern "C" {
    fn bpf_dynptr_from_xdp(a0: *mut c_void, a1: u64, a2: *mut c_void) -> i32;
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: simple_loop1
extern "C" fn simple_loop1() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "loop_0:",
            "if r0 == 10 goto exit_0;",
            "r0 += 1;",
            "goto loop_0;",
            "exit_0:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: indirect_write_invalidates_scev
extern "C" fn indirect_write_invalidates_scev() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "*(u64 *)(r10 - 8) = r0;",
            "loop_1:",
            "r0 = *(u64 *)(r10 - 8);",
            "if r0 == 10 goto exit_1;",
            "r0 += 1;",
            "*(u64 *)(r10 - 8) = r0;",
            "r1 = r10;",
            "r1 += -8;",
            "*(u64 *)(r1 + 0) = r0;",
            "goto loop_1;",
            "exit_1:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: global_call_invalidates_scev
extern "C" fn global_call_invalidates_scev() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "*(u64 *)(r10 - 8) = r0;",
            "r6 = 0;",
            "1:",
            "r0 = *(u64 *)(r10 - 8);",
            "r0 += 1;",
            "*(u64 *)(r10 - 8) = r0;",
            "r1 = r10;",
            "r1 += -8;",
            "call {global_noop_counter};",
            "r6 += 1;",
            "if r6 < 3 goto 1b;",
            "r0 = 0;",
            "exit;",
            global_noop_counter = sym global_noop_counter,
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: simple_loop2
extern "C" fn simple_loop2() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "*(u64 *)(r10 - 8) = r0;",
            "loop_2:",
            "r0 = *(u64 *)(r10 - 8);",
            "if r0 == 10 goto exit_2;",
            "r0 = *(u64 *)(r10 - 8);",
            "r0 += 1;",
            "*(u64 *)(r10 - 8) = r0;",
            "goto loop_2;",
            "exit_2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: meet_agrees
extern "C" fn meet_agrees() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = 0;",
            "1:",
            "if r1 == 2 goto 3f;",
            "if r0 == 7 goto 2f;",
            "r1 += 1;",
            "goto 1b;",
            "2:",
            "r1 += 1;",
            "goto 1b;",
            "3:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: meet_disagrees
extern "C" fn meet_disagrees() {
    unsafe {
        core::arch::asm!(
            "r6 = 0;",
            "1:",
            "if r6 == 2 goto 3f;",
            "call 7;",
            "if r0 == 7 goto 1b;",
            "r6 += 1;",
            "goto 1b;",
            "3:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: entry_state_join
extern "C" fn entry_state_join() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "r1 = 7;",
            "1:",
            "if r0 == 10 goto 2f;",
            "r0 += 1;",
            "r1 = 42;",
            "goto 1b;",
            "2:",
            "r0 = r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: expr_chain
extern "C" fn expr_chain() {
    unsafe {
        core::arch::asm!(
            "r6 = 0;",
            "1:",
            "if r6 == 2 goto 2f;",
            "r6 += 1;",
            "r6 <<= 32;",
            "r6 >>= 32;",
            "w6 += 1;",
            "r6 = -r6;",
            "w6 = -w6;",
            "r6 = bswap32 r6;",
            "r6 = bswap32 r6;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: alu_ops_exprs
extern "C" fn alu_ops_exprs() {
    unsafe {
        core::arch::asm!(
            "r6 = 7;",
            "r7 = 2;",
            "r8 = 0;",
            "1:",
            "r0 = 0;",
            "r1 = r6;",
            "r1 += 2;",
            "r0 += r1;",
            "r1 = r6;",
            "r1 += r7;",
            "r0 += r1;",
            "r1 = r6;",
            "w1 += 2;",
            "r0 += r1;",
            "r1 = r6;",
            "w1 += w7;",
            "r0 += r1;",
            "r1 = r6;",
            "r1 -= 2;",
            "r0 += r1;",
            "r1 = r6;",
            "r1 -= r7;",
            "r0 += r1;",
            "r1 = r6;",
            "w1 -= 2;",
            "r0 += r1;",
            "r1 = r6;",
            "w1 -= w7;",
            "r0 += r1;",
            "r1 = r6;",
            "r1 *= 2;",
            "r0 += r1;",
            "r1 = r6;",
            "r1 *= r7;",
            "r0 += r1;",
            "r1 = r6;",
            "w1 *= 2;",
            "r0 += r1;",
            "r1 = r6;",
            "w1 *= w7;",
            "r0 += r1;",
            "r1 = r6;",
            "r1 /= 2;",
            "r0 += r1;",
            "r1 = r6;",
            "r1 /= r7;",
            "r0 += r1;",
            "r1 = r6;",
            "w1 /= 2;",
            "r0 += r1;",
            "r1 = r6;",
            "w1 /= w7;",
            "r0 += r1;",
            "r1 = r6;",
            "r1 s/= 2;",
            "r0 += r1;",
            "r1 = r6;",
            "r1 s/= r7;",
            "r0 += r1;",
            "r1 = r6;",
            "w1 s/= 2;",
            "r0 += r1;",
            "r1 = r6;",
            "w1 s/= w7;",
            "r0 += r1;",
            "r1 = r6;",
            "r1 %= 2;",
            "r0 += r1;",
            "r1 = r6;",
            "r1 %= r7;",
            "r0 += r1;",
            "r1 = r6;",
            "w1 %= 2;",
            "r0 += r1;",
            "r1 = r6;",
            "w1 %= w7;",
            "r0 += r1;",
            "r1 = r6;",
            "r1 s%= 2;",
            "r0 += r1;",
            "r1 = r6;",
            "r1 s%= r7;",
            "r0 += r1;",
            "r1 = r6;",
            "w1 s%= 2;",
            "r0 += r1;",
            "r1 = r6;",
            "w1 s%= w7;",
            "r0 += r1;",
            "r1 = r6;",
            "r1 |= 2;",
            "r0 += r1;",
            "r1 = r6;",
            "r1 |= r7;",
            "r0 += r1;",
            "r1 = r6;",
            "w1 |= 2;",
            "r0 += r1;",
            "r1 = r6;",
            "w1 |= w7;",
            "r0 += r1;",
            "r1 = r6;",
            "r1 &= 2;",
            "r0 += r1;",
            "r1 = r6;",
            "r1 &= r7;",
            "r0 += r1;",
            "r1 = r6;",
            "w1 &= 2;",
            "r0 += r1;",
            "r1 = r6;",
            "w1 &= w7;",
            "r0 += r1;",
            "r1 = r6;",
            "r1 ^= 2;",
            "r0 += r1;",
            "r1 = r6;",
            "r1 ^= r7;",
            "r0 += r1;",
            "r1 = r6;",
            "w1 ^= 2;",
            "r0 += r1;",
            "r1 = r6;",
            "w1 ^= w7;",
            "r0 += r1;",
            "r1 = r6;",
            "r1 <<= 2;",
            "r0 += r1;",
            "r1 = r6;",
            "r1 <<= r7;",
            "r0 += r1;",
            "r1 = r6;",
            "w1 <<= 2;",
            "r0 += r1;",
            "r1 = r6;",
            "w1 <<= w7;",
            "r0 += r1;",
            "r1 = r6;",
            "r1 >>= 2;",
            "r0 += r1;",
            "r1 = r6;",
            "r1 >>= r7;",
            "r0 += r1;",
            "r1 = r6;",
            "w1 >>= 2;",
            "r0 += r1;",
            "r1 = r6;",
            "w1 >>= w7;",
            "r0 += r1;",
            "r1 = r6;",
            "r1 s>>= 2;",
            "r0 += r1;",
            "r1 = r6;",
            "r1 s>>= r7;",
            "r0 += r1;",
            "r1 = r6;",
            "w1 s>>= 2;",
            "r0 += r1;",
            "r1 = r6;",
            "w1 s>>= w7;",
            "r0 += r1;",
            "r1 = r6;",
            "r1 = -r1;",
            "r0 += r1;",
            "r1 = r6;",
            "w1 = -w1;",
            "r0 += r1;",
            "r1 = r6;",
            "r1 = 42;",
            "r0 += r1;",
            "r1 = r6;",
            "w1 = 42;",
            "r0 += r1;",
            "r1 = r6;",
            "r1 = r7;",
            "r0 += r1;",
            "r1 = r6;",
            "w1 = w7;",
            "r0 += r1;",
            "r1 = r6;",
            "r1 = (s8)r6;",
            "r0 += r1;",
            "r1 = r6;",
            "r1 = (s16)r6;",
            "r0 += r1;",
            "r1 = r6;",
            "r1 = (s32)r6;",
            "r0 += r1;",
            "r1 = r6;",
            "w1 = (s8)w6;",
            "r0 += r1;",
            "r1 = r6;",
            "w1 = (s16)w6;",
            "r0 += r1;",
            "r1 = r6;",
            "r1 = bswap16 r1;",
            "r0 += r1;",
            "r1 = r6;",
            "r1 = bswap32 r1;",
            "r0 += r1;",
            "r1 = r6;",
            "r1 = bswap64 r1;",
            "r0 += r1;",
            "r1 = r6;",
            "r1 = le16 r1;",
            "r0 += r1;",
            "r1 = r6;",
            "r1 = le32 r1;",
            "r0 += r1;",
            "r1 = r6;",
            "r1 = le64 r1;",
            "r1 += 1;",
            "r0 += r1;",
            "r1 = r6;",
            "r1 = be16 r1;",
            "r0 += r1;",
            "r1 = r6;",
            "r1 = be32 r1;",
            "r0 += r1;",
            "r1 = r6;",
            "r1 = be64 r1;",
            "r1 += 1;",
            "r0 += r1;",
            "r8 += 1;",
            "if r8 < 2 goto 1b;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: store_load_exprs
extern "C" fn store_load_exprs() {
    unsafe {
        core::arch::asm!(
            "r7 = 0;",
            "1:",
            "r0 = 0;",
            "r1 = 1;",
            "r2 = 2;",
            "*(u64 *)(r10 - 8) = -8;",
            "*(u64 *)(r10 - 8) = r1;",
            "r0 += r1;",
            "r0 += r2;",
            "r3 = *(u64 *)(r10 - 8);",
            "r0 += r3;",
            "r0 = 0;",
            "r1 = 1;",
            "r2 = 2;",
            "*(u64 *)(r10 - 8) = -8;",
            "*(u32 *)(r10 - 8) = r1;",
            "r0 += r1;",
            "r0 += r2;",
            "r3 = *(u64 *)(r10 - 8);",
            "r0 += r3;",
            "r0 = 0;",
            "r1 = 1;",
            "r2 = 2;",
            "*(u64 *)(r10 - 8) = -8;",
            "*(u16 *)(r10 - 8) = r1;",
            "r0 += r1;",
            "r0 += r2;",
            "r3 = *(u64 *)(r10 - 8);",
            "r0 += r3;",
            "r0 = 0;",
            "r1 = 1;",
            "r2 = 2;",
            "*(u64 *)(r10 - 8) = -8;",
            "*(u8 *)(r10 - 8) = r1;",
            "r0 += r1;",
            "r0 += r2;",
            "r3 = *(u64 *)(r10 - 8);",
            "r0 += r3;",
            "r0 = 0;",
            "r1 = 1;",
            "r2 = 2;",
            "*(u64 *)(r10 - 8) = -8;",
            "r1 = *(u64 *)(r10 - 8);",
            "r0 += r1;",
            "r0 += r2;",
            "r3 = *(u64 *)(r10 - 8);",
            "r0 += r3;",
            "r0 = 0;",
            "r1 = 1;",
            "r2 = 2;",
            "*(u64 *)(r10 - 8) = -8;",
            "r1 = *(u32 *)(r10 - 8);",
            "r0 += r1;",
            "r0 += r2;",
            "r3 = *(u64 *)(r10 - 8);",
            "r0 += r3;",
            "r0 = 0;",
            "r1 = 1;",
            "r2 = 2;",
            "*(u64 *)(r10 - 8) = -8;",
            "r1 = *(u16 *)(r10 - 8);",
            "r0 += r1;",
            "r0 += r2;",
            "r3 = *(u64 *)(r10 - 8);",
            "r0 += r3;",
            "r0 = 0;",
            "r1 = 1;",
            "r2 = 2;",
            "*(u64 *)(r10 - 8) = -8;",
            "r1 = *(u8 *)(r10 - 8);",
            "r0 += r1;",
            "r0 += r2;",
            "r3 = *(u64 *)(r10 - 8);",
            "r0 += r3;",
            "r0 = 0;",
            "r1 = 1;",
            "r2 = 2;",
            "*(u64 *)(r10 - 8) = -8;",
            "r1 = *(s32 *)(r10 - 8);",
            "r0 += r1;",
            "r0 += r2;",
            "r3 = *(u64 *)(r10 - 8);",
            "r0 += r3;",
            "r0 = 0;",
            "r1 = 1;",
            "r2 = 2;",
            "*(u64 *)(r10 - 8) = -8;",
            "r1 = *(s16 *)(r10 - 8);",
            "r0 += r1;",
            "r0 += r2;",
            "r3 = *(u64 *)(r10 - 8);",
            "r0 += r3;",
            "r0 = 0;",
            "r1 = 1;",
            "r2 = 2;",
            "*(u64 *)(r10 - 8) = -8;",
            "r1 = *(s8 *)(r10 - 8);",
            "r0 += r1;",
            "r0 += r2;",
            "r3 = *(u64 *)(r10 - 8);",
            "r0 += r3;",
            "r0 = 0;",
            "r1 = 1;",
            "r2 = 2;",
            "*(u64 *)(r10 - 8) = -8;",
            ".8byte 1103806112211;",
            "r0 += r1;",
            "r0 += r2;",
            "r3 = *(u64 *)(r10 - 8);",
            "r0 += r3;",
            "r0 = 0;",
            "r1 = 1;",
            "r2 = 2;",
            "*(u64 *)(r10 - 8) = -8;",
            ".8byte 1103806112203;",
            "r0 += r1;",
            "r0 += r2;",
            "r3 = *(u64 *)(r10 - 8);",
            "r0 += r3;",
            "r0 = 0;",
            "r1 = 1;",
            "r2 = 2;",
            "*(u64 *)(r10 - 8) = -8;",
            ".8byte 1103806112195;",
            "r0 += r1;",
            "r0 += r2;",
            "r3 = *(u64 *)(r10 - 8);",
            "r0 += r3;",
            "r0 = 0;",
            "r1 = 1;",
            "r2 = 2;",
            "*(u64 *)(r10 - 8) = -8;",
            ".8byte 1103806112475;",
            "r0 += r1;",
            "r0 += r2;",
            "r3 = *(u64 *)(r10 - 8);",
            "r0 += r3;",
            "r0 = 0;",
            "r1 = 1;",
            "r2 = 2;",
            "*(u64 *)(r10 - 8) = -8;",
            ".8byte 1172525554387;",
            "r0 += r1;",
            "r0 += r2;",
            "r3 = *(u64 *)(r10 - 8);",
            "r0 += r3;",
            "r0 = 0;",
            "r1 = 1;",
            "r2 = 2;",
            "*(u64 *)(r10 - 8) = -8;",
            ".8byte 1172525554379;",
            "r0 += r1;",
            "r0 += r2;",
            "r3 = *(u64 *)(r10 - 8);",
            "r0 += r3;",
            "r0 = 0;",
            "r1 = 1;",
            "r2 = 2;",
            "*(u64 *)(r10 - 8) = -8;",
            ".8byte 1172525554371;",
            "r0 += r1;",
            "r0 += r2;",
            "r3 = *(u64 *)(r10 - 8);",
            "r0 += r3;",
            "r0 = 0;",
            "r1 = 1;",
            "r2 = 2;",
            "*(u64 *)(r10 - 8) = -8;",
            ".8byte 1172525554395;",
            "r0 += r1;",
            "r0 += r2;",
            "r3 = *(u64 *)(r10 - 8);",
            "r0 += r3;",
            "r0 = 0;",
            "r1 = 1;",
            "r2 = 2;",
            "*(u64 *)(r10 - 8) = -8;",
            ".8byte 4294449883;",
            "r0 += r1;",
            "r0 += r2;",
            "r3 = *(u64 *)(r10 - 8);",
            "r0 += r3;",
            "r0 = 0;",
            "r1 = 1;",
            "r2 = 2;",
            "*(u64 *)(r10 - 8) = -8;",
            ".8byte 8589417179;",
            "r0 += r1;",
            "r0 += r2;",
            "r3 = *(u64 *)(r10 - 8);",
            "r0 += r3;",
            "r0 = 0;",
            "r1 = 1;",
            "r2 = 2;",
            "*(u64 *)(r10 - 8) = -8;",
            ".8byte 8589417155;",
            "r0 += r1;",
            "r0 += r2;",
            "r3 = *(u64 *)(r10 - 8);",
            "r0 += r3;",
            "r0 = 0;",
            "r1 = 1;",
            "r2 = 2;",
            "*(u64 *)(r10 - 8) = -8;",
            ".8byte 970662091483;",
            "r0 += r1;",
            "r0 += r2;",
            "r3 = *(u64 *)(r10 - 8);",
            "r0 += r3;",
            "r0 = 0;",
            "r1 = 1;",
            "r2 = 2;",
            "*(u64 *)(r10 - 8) = -8;",
            ".8byte 1039381572315;",
            "r0 += r1;",
            "r0 += r2;",
            "r3 = *(u64 *)(r10 - 8);",
            "r0 += r3;",
            "r0 = 0;",
            "r1 = 1;",
            "r2 = 2;",
            "*(u64 *)(r10 - 8) = -8;",
            "*(u64 *)(r10 - 8) = 42;",
            "r0 += r1;",
            "r0 += r2;",
            "r3 = *(u64 *)(r10 - 8);",
            "r0 += r3;",
            "r0 = 0;",
            "r1 = 1;",
            "r2 = 2;",
            "*(u64 *)(r10 - 8) = -8;",
            "*(u8 *)(r10 - 7) = r0;",
            "r0 += r1;",
            "r0 += r2;",
            "r3 = *(u64 *)(r10 - 8);",
            "r0 += r3;",
            "r7 += 1;",
            "if r7 < 2 goto 1b;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: nested_loop1
extern "C" fn nested_loop1() {
    unsafe {
        core::arch::asm!(
            "r6 = 0;",
            "1:",
            "if r6 == 2 goto 2f;",
            "r6 += 1;",
            "r7 = 0;",
            "3:",
            "if r7 == 2 goto 4f;",
            "r7 += 1;",
            "goto 3b;",
            "4:",
            "goto 1b;",
            "2:",
            "r0 = r7;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: nested_loop_hdr_backedge1
extern "C" fn nested_loop_hdr_backedge1() {
    unsafe {
        core::arch::asm!(
            "r6 = 0;",
            "1:",
            "if r6 == 2 goto 3f;",
            "r6 += 1;",
            "r7 = 0;",
            "2:",
            "if r7 == 2 goto 1b;",
            "r7 += 1;",
            "goto 2b;",
            "3:",
            "r0 = r7;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: nested_loop_hdr_backedge2
extern "C" fn nested_loop_hdr_backedge2() {
    unsafe {
        core::arch::asm!(
            "r6 = 0;",
            "r7 = 0;",
            "1:",
            "r7 += 1;",
            "2:",
            "r6 += 1;",
            "if r7 == 2 goto 1b;",
            "if r6 < 2 goto 2b;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: nested_loops_shared_header
extern "C" fn nested_loops_shared_header() {
    unsafe {
        core::arch::asm!(
            "r6 = 0;",
            "r7 = 0;",
            "r8 = 0;",
            "1:",
            "r8 += 1;",
            "r7 += 1;",
            "if r7 < 4 goto 1b;",
            "r7 = 0;",
            "r6 += 1;",
            "if r6 < 3 goto 1b;",
            "r0 = r8;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: nested_loops_outer_latch_true_branch_to_inner
extern "C" fn nested_loops_outer_latch_true_branch_to_inner() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "1:",
            "r0 += 1;",
            "r1 = 0;",
            "if r0 < 10 goto 2f;",
            "goto 3f;",
            "2:",
            "r1 += 1;",
            "if r1 < 5 goto 2b;",
            "goto 1b;",
            "3:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_lt
extern "C" fn pre_lt() {
    unsafe {
        core::arch::asm!(
            "r6 = 1 ll;",
            "r7 = 7 ll;",
            "r9 = 0;",
            "1:",
            "r8 = 2 ll;",
            "if r6 >= r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: post_lt
extern "C" fn post_lt() {
    unsafe {
        core::arch::asm!(
            "r6 = 1 ll;",
            "r7 = 7 ll;",
            "r9 = 0;",
            "1:",
            "r8 = 2 ll;",
            "r6 += r8;",
            "if r6 < r7 goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_le
extern "C" fn pre_le() {
    unsafe {
        core::arch::asm!(
            "r6 = 1 ll;",
            "r7 = 7 ll;",
            "r9 = 0;",
            "1:",
            "r8 = 2 ll;",
            "if r6 > r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: post_le
extern "C" fn post_le() {
    unsafe {
        core::arch::asm!(
            "r6 = 1 ll;",
            "r7 = 7 ll;",
            "r9 = 0;",
            "1:",
            "r8 = 2 ll;",
            "r6 += r8;",
            "if r6 <= r7 goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_gt
extern "C" fn pre_gt() {
    unsafe {
        core::arch::asm!(
            "r6 = 9 ll;",
            "r7 = 3 ll;",
            "r9 = 0;",
            "1:",
            "r8 = -2 ll;",
            "if r6 <= r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: post_gt
extern "C" fn post_gt() {
    unsafe {
        core::arch::asm!(
            "r6 = 9 ll;",
            "r7 = 3 ll;",
            "r9 = 0;",
            "1:",
            "r8 = -2 ll;",
            "r6 += r8;",
            "if r6 > r7 goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_ge
extern "C" fn pre_ge() {
    unsafe {
        core::arch::asm!(
            "r6 = 9 ll;",
            "r7 = 3 ll;",
            "r9 = 0;",
            "1:",
            "r8 = -2 ll;",
            "if r6 < r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: post_ge
extern "C" fn post_ge() {
    unsafe {
        core::arch::asm!(
            "r6 = 9 ll;",
            "r7 = 3 ll;",
            "r9 = 0;",
            "1:",
            "r8 = -2 ll;",
            "r6 += r8;",
            "if r6 >= r7 goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_slt
extern "C" fn pre_slt() {
    unsafe {
        core::arch::asm!(
            "r6 = -5 ll;",
            "r7 = 1 ll;",
            "r9 = 0;",
            "1:",
            "r8 = 2 ll;",
            "if r6 s>= r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: post_slt
extern "C" fn post_slt() {
    unsafe {
        core::arch::asm!(
            "r6 = -5 ll;",
            "r7 = 1 ll;",
            "r9 = 0;",
            "1:",
            "r8 = 2 ll;",
            "r6 += r8;",
            "if r6 s< r7 goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_sle
extern "C" fn pre_sle() {
    unsafe {
        core::arch::asm!(
            "r6 = -5 ll;",
            "r7 = 1 ll;",
            "r9 = 0;",
            "1:",
            "r8 = 2 ll;",
            "if r6 s> r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: post_sle
extern "C" fn post_sle() {
    unsafe {
        core::arch::asm!(
            "r6 = -5 ll;",
            "r7 = 1 ll;",
            "r9 = 0;",
            "1:",
            "r8 = 2 ll;",
            "r6 += r8;",
            "if r6 s<= r7 goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_sgt
extern "C" fn pre_sgt() {
    unsafe {
        core::arch::asm!(
            "r6 = 5 ll;",
            "r7 = -1 ll;",
            "r9 = 0;",
            "1:",
            "r8 = -2 ll;",
            "if r6 s<= r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: post_sgt
extern "C" fn post_sgt() {
    unsafe {
        core::arch::asm!(
            "r6 = 5 ll;",
            "r7 = -1 ll;",
            "r9 = 0;",
            "1:",
            "r8 = -2 ll;",
            "r6 += r8;",
            "if r6 s> r7 goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_sge
extern "C" fn pre_sge() {
    unsafe {
        core::arch::asm!(
            "r6 = 5 ll;",
            "r7 = -1 ll;",
            "r9 = 0;",
            "1:",
            "r8 = -2 ll;",
            "if r6 s< r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: post_sge
extern "C" fn post_sge() {
    unsafe {
        core::arch::asm!(
            "r6 = 5 ll;",
            "r7 = -1 ll;",
            "r9 = 0;",
            "1:",
            "r8 = -2 ll;",
            "r6 += r8;",
            "if r6 s>= r7 goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_ne
extern "C" fn pre_ne() {
    unsafe {
        core::arch::asm!(
            "r6 = 1 ll;",
            "r7 = 7 ll;",
            "r9 = 0;",
            "1:",
            "r8 = 2 ll;",
            "if r6 == r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: post_ne
extern "C" fn post_ne() {
    unsafe {
        core::arch::asm!(
            "r6 = 1 ll;",
            "r7 = 7 ll;",
            "r9 = 0;",
            "1:",
            "r8 = 2 ll;",
            "r6 += r8;",
            "if r6 != r7 goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_ne_down
extern "C" fn pre_ne_down() {
    unsafe {
        core::arch::asm!(
            "r6 = 9 ll;",
            "r7 = 3 ll;",
            "r9 = 0;",
            "1:",
            "r8 = -2 ll;",
            "if r6 == r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: post_ne_down
extern "C" fn post_ne_down() {
    unsafe {
        core::arch::asm!(
            "r6 = 9 ll;",
            "r7 = 3 ll;",
            "r9 = 0;",
            "1:",
            "r8 = -2 ll;",
            "r6 += r8;",
            "if r6 != r7 goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_lt_round
extern "C" fn pre_lt_round() {
    unsafe {
        core::arch::asm!(
            "r6 = 1 ll;",
            "r7 = 8 ll;",
            "r9 = 0;",
            "1:",
            "r8 = 2 ll;",
            "if r6 >= r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_le_round
extern "C" fn pre_le_round() {
    unsafe {
        core::arch::asm!(
            "r6 = 1 ll;",
            "r7 = 8 ll;",
            "r9 = 0;",
            "1:",
            "r8 = 2 ll;",
            "if r6 > r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_gt_round
extern "C" fn pre_gt_round() {
    unsafe {
        core::arch::asm!(
            "r6 = 9 ll;",
            "r7 = 2 ll;",
            "r9 = 0;",
            "1:",
            "r8 = -2 ll;",
            "if r6 <= r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_ge_round
extern "C" fn pre_ge_round() {
    unsafe {
        core::arch::asm!(
            "r6 = 9 ll;",
            "r7 = 2 ll;",
            "r9 = 0;",
            "1:",
            "r8 = -2 ll;",
            "if r6 < r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_slt_round
extern "C" fn pre_slt_round() {
    unsafe {
        core::arch::asm!(
            "r6 = -5 ll;",
            "r7 = 2 ll;",
            "r9 = 0;",
            "1:",
            "r8 = 2 ll;",
            "if r6 s>= r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_sle_round
extern "C" fn pre_sle_round() {
    unsafe {
        core::arch::asm!(
            "r6 = -5 ll;",
            "r7 = 2 ll;",
            "r9 = 0;",
            "1:",
            "r8 = 2 ll;",
            "if r6 s> r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_sgt_round
extern "C" fn pre_sgt_round() {
    unsafe {
        core::arch::asm!(
            "r6 = 5 ll;",
            "r7 = -2 ll;",
            "r9 = 0;",
            "1:",
            "r8 = -2 ll;",
            "if r6 s<= r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_sge_round
extern "C" fn pre_sge_round() {
    unsafe {
        core::arch::asm!(
            "r6 = 5 ll;",
            "r7 = -2 ll;",
            "r9 = 0;",
            "1:",
            "r8 = -2 ll;",
            "if r6 s< r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_le_eq
extern "C" fn pre_le_eq() {
    unsafe {
        core::arch::asm!(
            "r6 = 7 ll;",
            "r7 = 7 ll;",
            "r9 = 0;",
            "1:",
            "r8 = 2 ll;",
            "if r6 > r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_ge_eq
extern "C" fn pre_ge_eq() {
    unsafe {
        core::arch::asm!(
            "r6 = 3 ll;",
            "r7 = 3 ll;",
            "r9 = 0;",
            "1:",
            "r8 = -2 ll;",
            "if r6 < r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_sle_eq
extern "C" fn pre_sle_eq() {
    unsafe {
        core::arch::asm!(
            "r6 = 1 ll;",
            "r7 = 1 ll;",
            "r9 = 0;",
            "1:",
            "r8 = 2 ll;",
            "if r6 s> r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_sge_eq
extern "C" fn pre_sge_eq() {
    unsafe {
        core::arch::asm!(
            "r6 = -1 ll;",
            "r7 = -1 ll;",
            "r9 = 0;",
            "1:",
            "r8 = -2 ll;",
            "if r6 s< r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_lt_sign
extern "C" fn pre_lt_sign() {
    unsafe {
        core::arch::asm!(
            "r6 = 9223372036854775806 ll;",
            "r7 = -9223372036854775807 ll;",
            "r9 = 0;",
            "1:",
            "r8 = 1 ll;",
            "if r6 >= r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_gt_sign
extern "C" fn pre_gt_sign() {
    unsafe {
        core::arch::asm!(
            "r6 = -9223372036854775807 ll;",
            "r7 = 9223372036854775806 ll;",
            "r9 = 0;",
            "1:",
            "r8 = -1 ll;",
            "if r6 <= r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_lt_false
extern "C" fn pre_lt_false() {
    unsafe {
        core::arch::asm!(
            "r6 = 7 ll;",
            "r7 = 7 ll;",
            "r9 = 0;",
            "1:",
            "r8 = 2 ll;",
            "if r6 >= r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_le_false
extern "C" fn pre_le_false() {
    unsafe {
        core::arch::asm!(
            "r6 = 8 ll;",
            "r7 = 7 ll;",
            "r9 = 0;",
            "1:",
            "r8 = 2 ll;",
            "if r6 > r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_gt_false
extern "C" fn pre_gt_false() {
    unsafe {
        core::arch::asm!(
            "r6 = 3 ll;",
            "r7 = 3 ll;",
            "r9 = 0;",
            "1:",
            "r8 = -2 ll;",
            "if r6 <= r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_ge_false
extern "C" fn pre_ge_false() {
    unsafe {
        core::arch::asm!(
            "r6 = 2 ll;",
            "r7 = 3 ll;",
            "r9 = 0;",
            "1:",
            "r8 = -2 ll;",
            "if r6 < r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_slt_false
extern "C" fn pre_slt_false() {
    unsafe {
        core::arch::asm!(
            "r6 = 1 ll;",
            "r7 = 1 ll;",
            "r9 = 0;",
            "1:",
            "r8 = 2 ll;",
            "if r6 s>= r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_sle_false
extern "C" fn pre_sle_false() {
    unsafe {
        core::arch::asm!(
            "r6 = 2 ll;",
            "r7 = 1 ll;",
            "r9 = 0;",
            "1:",
            "r8 = 2 ll;",
            "if r6 s> r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_sgt_false
extern "C" fn pre_sgt_false() {
    unsafe {
        core::arch::asm!(
            "r6 = -1 ll;",
            "r7 = -1 ll;",
            "r9 = 0;",
            "1:",
            "r8 = -2 ll;",
            "if r6 s<= r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_sge_false
extern "C" fn pre_sge_false() {
    unsafe {
        core::arch::asm!(
            "r6 = -2 ll;",
            "r7 = -1 ll;",
            "r9 = 0;",
            "1:",
            "r8 = -2 ll;",
            "if r6 s< r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_ne_false
extern "C" fn pre_ne_false() {
    unsafe {
        core::arch::asm!(
            "r6 = 7 ll;",
            "r7 = 7 ll;",
            "r9 = 0;",
            "1:",
            "r8 = 2 ll;",
            "if r6 == r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_lt_dir
extern "C" fn pre_lt_dir() {
    unsafe {
        core::arch::asm!(
            "r6 = 5 ll;",
            "r7 = 7 ll;",
            "r9 = 0;",
            "1:",
            "r8 = -2 ll;",
            "r9 += 1;",
            "if r9 & 8 goto 2f;",
            "if r6 >= r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_le_dir
extern "C" fn pre_le_dir() {
    unsafe {
        core::arch::asm!(
            "r6 = 5 ll;",
            "r7 = 7 ll;",
            "r9 = 0;",
            "1:",
            "r8 = -2 ll;",
            "r9 += 1;",
            "if r9 & 8 goto 2f;",
            "if r6 > r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_gt_dir
extern "C" fn pre_gt_dir() {
    unsafe {
        core::arch::asm!(
            "r6 = 5 ll;",
            "r7 = 3 ll;",
            "r9 = 0;",
            "1:",
            "r8 = 2 ll;",
            "r9 += 1;",
            "if r9 & 8 goto 2f;",
            "if r6 <= r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_ge_dir
extern "C" fn pre_ge_dir() {
    unsafe {
        core::arch::asm!(
            "r6 = 5 ll;",
            "r7 = 3 ll;",
            "r9 = 0;",
            "1:",
            "r8 = 2 ll;",
            "r9 += 1;",
            "if r9 & 8 goto 2f;",
            "if r6 < r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_slt_dir
extern "C" fn pre_slt_dir() {
    unsafe {
        core::arch::asm!(
            "r6 = -1 ll;",
            "r7 = 1 ll;",
            "r9 = 0;",
            "1:",
            "r8 = -2 ll;",
            "r9 += 1;",
            "if r9 & 8 goto 2f;",
            "if r6 s>= r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_sle_dir
extern "C" fn pre_sle_dir() {
    unsafe {
        core::arch::asm!(
            "r6 = -1 ll;",
            "r7 = 1 ll;",
            "r9 = 0;",
            "1:",
            "r8 = -2 ll;",
            "r9 += 1;",
            "if r9 & 8 goto 2f;",
            "if r6 s> r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_sgt_dir
extern "C" fn pre_sgt_dir() {
    unsafe {
        core::arch::asm!(
            "r6 = 1 ll;",
            "r7 = -1 ll;",
            "r9 = 0;",
            "1:",
            "r8 = 2 ll;",
            "r9 += 1;",
            "if r9 & 8 goto 2f;",
            "if r6 s<= r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_sge_dir
extern "C" fn pre_sge_dir() {
    unsafe {
        core::arch::asm!(
            "r6 = 1 ll;",
            "r7 = -1 ll;",
            "r9 = 0;",
            "1:",
            "r8 = 2 ll;",
            "r9 += 1;",
            "if r9 & 8 goto 2f;",
            "if r6 s< r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_lt_wrap
extern "C" fn pre_lt_wrap() {
    unsafe {
        core::arch::asm!(
            "r6 = -2 ll;",
            "r7 = -1 ll;",
            "r9 = 0;",
            "1:",
            "r8 = 2 ll;",
            "r9 += 1;",
            "if r9 & 8 goto 2f;",
            "if r6 >= r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_le_wrap
extern "C" fn pre_le_wrap() {
    unsafe {
        core::arch::asm!(
            "r6 = -1 ll;",
            "r7 = -1 ll;",
            "r9 = 0;",
            "1:",
            "r8 = 1 ll;",
            "r9 += 1;",
            "if r9 & 8 goto 2f;",
            "if r6 > r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_gt_wrap
extern "C" fn pre_gt_wrap() {
    unsafe {
        core::arch::asm!(
            "r6 = 1 ll;",
            "r7 = 0 ll;",
            "r9 = 0;",
            "1:",
            "r8 = -2 ll;",
            "r9 += 1;",
            "if r9 & 8 goto 2f;",
            "if r6 <= r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_ge_wrap
extern "C" fn pre_ge_wrap() {
    unsafe {
        core::arch::asm!(
            "r6 = 0 ll;",
            "r7 = 0 ll;",
            "r9 = 0;",
            "1:",
            "r8 = -1 ll;",
            "r9 += 1;",
            "if r9 & 8 goto 2f;",
            "if r6 < r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_slt_wrap
extern "C" fn pre_slt_wrap() {
    unsafe {
        core::arch::asm!(
            "r6 = 9223372036854775806 ll;",
            "r7 = 9223372036854775807 ll;",
            "r9 = 0;",
            "1:",
            "r8 = 2 ll;",
            "r9 += 1;",
            "if r9 & 8 goto 2f;",
            "if r6 s>= r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_sle_wrap
extern "C" fn pre_sle_wrap() {
    unsafe {
        core::arch::asm!(
            "r6 = 9223372036854775807 ll;",
            "r7 = 9223372036854775807 ll;",
            "r9 = 0;",
            "1:",
            "r8 = 1 ll;",
            "r9 += 1;",
            "if r9 & 8 goto 2f;",
            "if r6 s> r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_sgt_wrap
extern "C" fn pre_sgt_wrap() {
    unsafe {
        core::arch::asm!(
            "r6 = -9223372036854775807 ll;",
            "r7 = -9223372036854775808 ll;",
            "r9 = 0;",
            "1:",
            "r8 = -2 ll;",
            "r9 += 1;",
            "if r9 & 8 goto 2f;",
            "if r6 s<= r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_sge_wrap
extern "C" fn pre_sge_wrap() {
    unsafe {
        core::arch::asm!(
            "r6 = -9223372036854775808 ll;",
            "r7 = -9223372036854775808 ll;",
            "r9 = 0;",
            "1:",
            "r8 = -1 ll;",
            "r9 += 1;",
            "if r9 & 8 goto 2f;",
            "if r6 s< r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_le_count_ovf
extern "C" fn pre_le_count_ovf() {
    unsafe {
        core::arch::asm!(
            "r6 = 0 ll;",
            "r7 = -1 ll;",
            "r9 = 0;",
            "1:",
            "r8 = 1 ll;",
            "r9 += 1;",
            "if r9 & 8 goto 2f;",
            "if r6 > r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_ge_count_ovf
extern "C" fn pre_ge_count_ovf() {
    unsafe {
        core::arch::asm!(
            "r6 = -1 ll;",
            "r7 = 0 ll;",
            "r9 = 0;",
            "1:",
            "r8 = -1 ll;",
            "r9 += 1;",
            "if r9 & 8 goto 2f;",
            "if r6 < r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_sle_count_ovf
extern "C" fn pre_sle_count_ovf() {
    unsafe {
        core::arch::asm!(
            "r6 = -9223372036854775808 ll;",
            "r7 = 9223372036854775807 ll;",
            "r9 = 0;",
            "1:",
            "r8 = 1 ll;",
            "r9 += 1;",
            "if r9 & 8 goto 2f;",
            "if r6 s> r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_sge_count_ovf
extern "C" fn pre_sge_count_ovf() {
    unsafe {
        core::arch::asm!(
            "r6 = 9223372036854775807 ll;",
            "r7 = -9223372036854775808 ll;",
            "r9 = 0;",
            "1:",
            "r8 = -1 ll;",
            "r9 += 1;",
            "if r9 & 8 goto 2f;",
            "if r6 s< r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_ne_rem
extern "C" fn pre_ne_rem() {
    unsafe {
        core::arch::asm!(
            "r6 = 1 ll;",
            "r7 = 8 ll;",
            "r9 = 0;",
            "1:",
            "r8 = 2 ll;",
            "r9 += 1;",
            "if r9 & 8 goto 2f;",
            "if r6 == r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_ne_rem_down
extern "C" fn pre_ne_rem_down() {
    unsafe {
        core::arch::asm!(
            "r6 = 9 ll;",
            "r7 = 2 ll;",
            "r9 = 0;",
            "1:",
            "r8 = -2 ll;",
            "r9 += 1;",
            "if r9 & 8 goto 2f;",
            "if r6 == r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_ne_wrap_up
extern "C" fn pre_ne_wrap_up() {
    unsafe {
        core::arch::asm!(
            "r6 = -2 ll;",
            "r7 = 0 ll;",
            "r9 = 0;",
            "1:",
            "r8 = 2 ll;",
            "if r6 == r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_ne_wrap_down
extern "C" fn pre_ne_wrap_down() {
    unsafe {
        core::arch::asm!(
            "r6 = 1 ll;",
            "r7 = -1 ll;",
            "r9 = 0;",
            "1:",
            "r8 = -2 ll;",
            "if r6 == r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_lt_max_hdrs
extern "C" fn pre_lt_max_hdrs() {
    unsafe {
        core::arch::asm!(
            "r6 = 0 ll;",
            "r7 = 4294967293 ll;",
            "r9 = 0;",
            "1:",
            "r8 = 1 ll;",
            "r9 += 1;",
            "if r9 & 8 goto 2f;",
            "if r6 >= r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_lt_sentinel
extern "C" fn pre_lt_sentinel() {
    unsafe {
        core::arch::asm!(
            "r6 = 0 ll;",
            "r7 = 4294967294 ll;",
            "r9 = 0;",
            "1:",
            "r8 = 1 ll;",
            "r9 += 1;",
            "if r9 & 8 goto 2f;",
            "if r6 >= r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_lt_hdr_ovf
extern "C" fn pre_lt_hdr_ovf() {
    unsafe {
        core::arch::asm!(
            "r6 = 0 ll;",
            "r7 = 4294967295 ll;",
            "r9 = 0;",
            "1:",
            "r8 = 1 ll;",
            "r9 += 1;",
            "if r9 & 8 goto 2f;",
            "if r6 >= r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_lt_step_max
extern "C" fn pre_lt_step_max() {
    unsafe {
        core::arch::asm!(
            "r6 = 0 ll;",
            "r7 = 9223372036854775807 ll;",
            "r9 = 0;",
            "1:",
            "r8 = 9223372036854775807 ll;",
            "if r6 >= r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_gt_step_min
extern "C" fn pre_gt_step_min() {
    unsafe {
        core::arch::asm!(
            "r6 = -9223372036854775808 ll;",
            "r7 = 0 ll;",
            "r9 = 0;",
            "1:",
            "r8 = -9223372036854775808 ll;",
            "if r6 <= r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_ne_step_min
extern "C" fn pre_ne_step_min() {
    unsafe {
        core::arch::asm!(
            "r6 = 0 ll;",
            "r7 = -9223372036854775808 ll;",
            "r9 = 0;",
            "1:",
            "r8 = -9223372036854775808 ll;",
            "if r6 == r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_lt_zero_step
extern "C" fn pre_lt_zero_step() {
    unsafe {
        core::arch::asm!(
            "r6 = 1 ll;",
            "r7 = 7 ll;",
            "r9 = 0;",
            "1:",
            "r8 = 0 ll;",
            "r9 += 1;",
            "if r9 & 8 goto 2f;",
            "if r6 >= r7 goto 2f;",
            "r6 += r8;",
            "goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: post_cond_jlt
extern "C" fn post_cond_jlt() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "1:",
            "r0 += 1;",
            "if r0 < 10 goto 1b;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mark_bound_precise
extern "C" fn mark_bound_precise() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r7 = 4096;",
            "if r0 != 42 goto 1f;",
            "r7 = 10;",
            "1:",
            "r0 = 0;",
            "r6 = 0;",
            "2:",
            "r0 += 1;",
            "r6 += 1;",
            "r2 = r0;",
            "r2 = -r2;",
            "r2 += r10;",
            "r3 = *(u8 *)(r2 + 0);",
            "if r6 < r7 goto 2b;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mark_base_precise
extern "C" fn mark_base_precise() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r6 = 0;",
            "if r0 != 42 goto 1f;",
            "r6 = 4086;",
            "1:",
            "r0 = 0;",
            "2:",
            "r0 += 1;",
            "r6 += 1;",
            "r2 = r0;",
            "r2 = -r2;",
            "r2 += r10;",
            "r3 = *(u8 *)(r2 + 0);",
            "if r6 < 4096 goto 2b;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: eval_expr_small_spill_bound
extern "C" fn eval_expr_small_spill_bound() {
    unsafe {
        core::arch::asm!(
            "r0 = 256;",
            "*(u8 *)(r10 - 8) = r0;",
            "r0 = 0;",
            "1:",
            "r0 += 1;",
            "r1 = *(u64 *)(r10 - 8);",
            "if r0 & 0x200 goto 2f;",
            "if r0 < r1 goto 1b;",
            "2:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: eval_expr_small_spill_bound_fits
extern "C" fn eval_expr_small_spill_bound_fits() {
    unsafe {
        core::arch::asm!(
            "r0 = 10;",
            "*(u8 *)(r10 - 8) = r0;",
            "r0 = 0;",
            "1:",
            "r0 += 1;",
            "r1 = *(u64 *)(r10 - 8);",
            "if r0 & 0x80 goto 2f;",
            "if r0 < r1 goto 1b;",
            "2:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: no_widen_small_spill_counter
extern "C" fn no_widen_small_spill_counter() {
    unsafe {
        core::arch::asm!(
            "r0 = 255;",
            "*(u8 *)(r10 - 8) = r0;",
            "1:",
            "r0 = *(u64 *)(r10 - 8);",
            "r0 += 1;",
            "*(u64 *)(r10 - 8) = r0;",
            "if r0 < 265 goto 1b;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: widen_full_spill_counter
extern "C" fn widen_full_spill_counter() {
    unsafe {
        core::arch::asm!(
            "r0 = 5;",
            "*(u64 *)(r10 - 8) = r0;",
            "1:",
            "r0 = *(u64 *)(r10 - 8);",
            "r0 += 1;",
            "*(u64 *)(r10 - 8) = r0;",
            "if r0 < 15 goto 1b;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: widen_acquire_release_counter
extern "C" fn widen_acquire_release_counter() {
    unsafe {
        core::arch::asm!(
            "r0 = 5;",
            "*(u64 *)(r10 - 8) = r0;",
            "1:",
            ".8byte 1103806111963;",
            "r0 += 1;",
            ".8byte 1172525550299;",
            "if r0 < 15 goto 1b;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: widen_any_small_spill_leaf
extern "C" fn widen_any_small_spill_leaf() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "*(u64 *)(r10 - 8) = r0;",
            "r0 = 256;",
            "*(u8 *)(r10 - 8) = r0;",
            "r6 = 1;",
            "r7 = 0;",
            "1:",
            "r0 = r6;",
            "r6 = *(u64 *)(r10 - 8);",
            "r7 += 1;",
            "if r7 < 2 goto 1b;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: widen_any_unallocated_slot
extern "C" fn widen_any_unallocated_slot() {
    unsafe {
        core::arch::asm!(
            "r6 = 0;",
            "1:",
            "if r6 != 1 goto 2f;",
            "*(u64 *)(r10 - 8) = 7;",
            "2:",
            "r0 = *(u64 *)(r10 - 8);",
            "r6 += 1;",
            "if r6 < 3 goto 1b;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: widen_any_zero_spill
extern "C" fn widen_any_zero_spill() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 8) = 0;",
            "r6 = 0;",
            "1:",
            "if r6 != 1 goto 2f;",
            "*(u64 *)(r10 - 8) = 7;",
            "2:",
            "r0 = *(u64 *)(r10 - 8);",
            "r6 += 1;",
            "if r6 < 3 goto 1b;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: widen_any_misc_slot
extern "C" fn widen_any_misc_slot() {
    unsafe {
        core::arch::asm!(
            "*(u8 *)(r10 - 1) = 1;",
            "r6 = 0;",
            "1:",
            "if r6 != 1 goto 2f;",
            "r1 = *(u64 *)(r10 - 8);",
            "*(u64 *)(r10 - 8) = 7;",
            "2:",
            "r0 = *(u64 *)(r10 - 8);",
            "r6 += 1;",
            "if r6 < 3 goto 1b;",
            "exit;",
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: probe_read_stack
extern "C" fn probe_read_stack() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r2 = 8;",
            "r3 = 0;",
            "call 113;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: widen_subprog_probe_read
extern "C" fn widen_subprog_probe_read() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -8;",
            "call {probe_read_stack};",
            "r6 = 0;",
            "1:",
            "r0 = *(u64 *)(r10 - 8);",
            "r1 = r10;",
            "r1 += -8;",
            "call {probe_read_stack};",
            "r6 += 1;",
            "if r6 < 10 goto 1b;",
            "r0 = 0;",
            "exit;",
            probe_read_stack = sym probe_read_stack,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: widen_overflowing_range
extern "C" fn widen_overflowing_range() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r6 = r0;",
            "r6 |= 1;",
            "r1 = 0;",
            "1:",
            "r6 += 24;",
            "r1 += 1;",
            "if r1 < 10 goto 1b;",
            "r0 = r6;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: eval_expr_unallocated_stack_bound
extern "C" fn eval_expr_unallocated_stack_bound() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "1:",
            "r0 += 1;",
            "r1 = *(u64 *)(r10 - 8);",
            "if r0 & 0x80 goto 2f;",
            "if r0 < r1 goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: post_cond_jlt_with_base
extern "C" fn post_cond_jlt_with_base() {
    unsafe {
        core::arch::asm!(
            "r7 = 10 ll;",
            "r0 = 2;",
            "1:",
            "r0 += 1;",
            "if r0 < r7 goto 1b;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: latch_base_differs_from_step
extern "C" fn latch_base_differs_from_step() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "1:",
            "r1 = r0;",
            "r1 += 1;",
            "if r1 >= 10 goto 2f;",
            "r0 += 4;",
            "goto 1b;",
            "2:",
            "r0 = r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: post_cond_jle
extern "C" fn post_cond_jle() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "1:",
            "r0 += 1;",
            "if r0 <= 10 goto 1b;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: post_cond_jge
extern "C" fn post_cond_jge() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "1:",
            "r0 += 1;",
            "if r0 >= 10 goto 2f;",
            "goto 1b;",
            "2:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_cond_jge
extern "C" fn pre_cond_jge() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "1:",
            "if r0 >= 10 goto 2f;",
            "r0 += 1;",
            "goto 1b;",
            "2:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: post_cond_jne
extern "C" fn post_cond_jne() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "1:",
            "r0 += 1;",
            "if r0 != 3 goto 1b;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: post_cond_jne_neg_step
extern "C" fn post_cond_jne_neg_step() {
    unsafe {
        core::arch::asm!(
            "r0 = 3;",
            "1:",
            "r0 += -1;",
            "if r0 != 0 goto 1b;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pre_cond_je1
extern "C" fn pre_cond_je1() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "1:",
            "if r0 == 3 goto 2f;",
            "r0 += 1;",
            "goto 1b;",
            "2:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: one_backedge_two_exits
extern "C" fn one_backedge_two_exits() {
    unsafe {
        core::arch::asm!(
            "r6 = 0;",
            "1:",
            "call 7;",
            "if r0 == 0 goto 2f;",
            "r6 += 1;",
            "if r6 != 3 goto 1b;",
            "2:",
            "r0 = r6;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: correlated_regs
extern "C" fn correlated_regs() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map} ll;",
            "call 1;",
            "if r0 == 0 goto 2f;",
            "r6 = r0;",
            "r0 = 0;",
            "r1 = 0;",
            "1:",
            "r2 = r6;",
            "r2 += r1;",
            "*(u8 *)(r2 + 0) = 1;",
            "r0 += 1;",
            "r1 += 2;",
            "if r0 < 8 goto 1b;",
            "2:",
            "exit;",
            map = sym map,
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: nested_loops_precise_var1
extern "C" fn nested_loops_precise_var1() {
    unsafe {
        core::arch::asm!(
            "*(u64*)(r10 - 8) = 0;",
            "r1 = {map} ll;",
            "r2 = r10;",
            "r2 += -8;",
            "call 1;",
            "if r0 == 0 goto 3f;",
            "r1 = 0;",
            "r3 = 0;",
            "1:",
            "r2 = 0;",
            "2:",
            "r2 += 1;",
            "r3 += 1;",
            "r3 <<= 1;",
            "r3 >>= 1;",
            "if r2 < 4 goto 2b;",
            "r1 += 1;",
            "if r1 < 4 goto 1b;",
            "r4 = r0;",
            "r4 += r3;",
            "*(u8 *)(r4 + 0) = 1;",
            "r0 = 0;",
            "3:",
            "exit;",
            map = sym map,
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: nested_loop_with_two_exits
extern "C" fn nested_loop_with_two_exits() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r6 = 0;",
            "1:",
            "r6 += 1;",
            "r7 = 0;",
            "2:",
            "r7 += 1;",
            "r8 = 0;",
            "3:",
            "r8 += 1;",
            "call 7;",
            "if r0 == 42 goto +1;",
            "goto 4f;",
            "if r8 < 100 goto 3b;",
            "if r7 < 100 goto 2b;",
            "4:",
            "if r6 < 100 goto 1b;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: exit_loop_into_loop_header
extern "C" fn exit_loop_into_loop_header() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "r2 = 0;",
            "loop_a_4:",
            "r1 += 1;",
            "if r1 < 10 goto loop_a_4;",
            "loop_b_4:",
            "r2 += 1;",
            "if r2 < 10 goto loop_b_4;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: enter_nested_loop_from_side
extern "C" fn enter_nested_loop_from_side() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r6 = 0;",
            "r7 = 0;",
            "r8 = 0;",
            "r9 = 0;",
            "a_5:",
            "r6 += 1;",
            "b_5:",
            "r7 += 1;",
            "call 7;",
            "if r0 == 5 goto d_5;",
            "if r7 < 3 goto b_5;",
            "if r6 < 3 goto a_5;",
            "c_5:",
            "r8 += 1;",
            "d_5:",
            "r9 += 1;",
            "if r9 < 3 goto d_5;",
            "if r8 < 3 goto c_5;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: nested_irreducible_loop
extern "C" fn nested_irreducible_loop() {
    unsafe {
        core::arch::asm!(
            "r6 = 0;",
            "a_6:",
            "r6 += 1;",
            "call 7;",
            "r7 = 0;",
            "if r0 > 5 goto alternate_6;",
            "b_6:",
            "r8 = r6;",
            "goto body_6;",
            "alternate_6:",
            "r8 = r6;",
            "r8 += 1;",
            "body_6:",
            "r6 = r8;",
            "r9 = 0;",
            "c_6:",
            "r9 += 1;",
            "if r9 < 3 goto c_6;",
            "r7 += 1;",
            "if r7 < 4 goto b_6;",
            "if r6 < 4 goto a_6;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: nested_irreducible_loop2
extern "C" fn nested_irreducible_loop2() {
    unsafe {
        core::arch::asm!(
            "r6 = 0;",
            "a_7:",
            "r6 += 1;",
            "call 7;",
            "r7 = 0;",
            "if r0 > 5 goto alternate_7;",
            "b_7:",
            "r7 += 1;",
            "alternate_7:",
            "call 7;",
            "if r0 == 42 goto exit_7;",
            "r7 += 1;",
            "if r7 < 4 goto b_7;",
            "if r6 < 4 goto a_7;",
            "r0 = 0;",
            "exit_7:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: widen_nonconst_base
extern "C" fn widen_nonconst_base() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r7 = r0;",
            "r7 &= 0x6;",
            "r6 = 0;",
            "1:",
            "r7 += 6;",
            "r6 += 1;",
            "if r6 < 3 goto 1b;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: widen_nonconst_base_refined
extern "C" fn widen_nonconst_base_refined() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r7 = r0;",
            "r7 &= 0xc;",
            "if r7 < 1 goto 2f;",
            "r8 = 0;",
            "1:",
            "r7 += 4;",
            "r8 += 1;",
            "if r8 < 3 goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sibling_inner_loops
extern "C" fn sibling_inner_loops() {
    unsafe {
        core::arch::asm!(
            "r6 = 0;",
            "1:",
            "r7 = 0;",
            "2:",
            "r7 += 1;",
            "if r7 < 3 goto 2b;",
            "3:",
            "r7 += -1;",
            "if r7 != 0 goto 3b;",
            "r6 += 1;",
            "if r6 < 4 goto 1b;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: uninit_slot_counter
extern "C" fn uninit_slot_counter() {
    unsafe {
        core::arch::asm!(
            "1:",
            "r0 = *(u64 *)(r10 - 8);",
            "r0 += 1;",
            "*(u64 *)(r10 - 8) = r0;",
            "if r0 < 10 goto 1b;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: conditional_assignment_on_second_iteration
extern "C" fn conditional_assignment_on_second_iteration() {
    unsafe {
        core::arch::asm!(
            "r7 = 5;",
            "r6 = 0;",
            "1:",
            "if r6 >= 3 goto 3f;",
            "if r6 != 1 goto 2f;",
            "r7 = 10;",
            "2:",
            "r6 += 1;",
            "goto 1b;",
            "3:",
            "if r7 == 10 goto 4f;",
            "r0 = *(u64 *)(r10 + 0);",
            "4:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: no_widen_changing_latch_bound
extern "C" fn no_widen_changing_latch_bound() {
    unsafe {
        core::arch::asm!(
            "r6 = 0;",
            "r7 = 3;",
            "loop_8:",
            "r6 += 1;",
            "if r6 >= r7 goto exit_8;",
            "if r6 != 1 goto next_8;",
            "r7 = 100;",
            "next_8:",
            "goto loop_8;",
            "exit_8:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: conditional_stack_pointer_assignment
extern "C" fn conditional_stack_pointer_assignment() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 16) = 0;",
            "*(u64 *)(r10 - 8) = 0;",
            "r7 = r10;",
            "r7 += -16;",
            "r8 = r10;",
            "r8 += -8;",
            "r6 = 0;",
            "1:",
            "if r6 >= 3 goto 3f;",
            "if r6 != 1 goto 2f;",
            "r7 = r8;",
            "2:",
            "r6 += 1;",
            "goto 1b;",
            "3:",
            "r0 = *(u64 *)(r7 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: no_widen_any_map_origin
extern "C" fn no_widen_any_map_origin() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 8) = 0;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {small_map} ll;",
            "call 1;",
            "if r0 == 0 goto 3f;",
            "r6 = r0;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map} ll;",
            "call 1;",
            "if r0 == 0 goto 3f;",
            "r7 = r0;",
            "r7 += 32;",
            "r8 = 0;",
            "1:",
            "if r8 != 1 goto 2f;",
            "r6 = r7;",
            "2:",
            "r0 = *(u32 *)(r6 + 0);",
            "r8 += 1;",
            "if r8 < 3 goto 1b;",
            "3:",
            "r0 = 0;",
            "exit;",
            small_map = sym small_map,
            map = sym map,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: any_stack_origin_callee
extern "C" fn any_stack_origin_callee() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 8) = 0;",
            "r6 = r1;",
            "r7 = r10;",
            "r7 += -8;",
            "r8 = 0;",
            "1:",
            "if r8 != 1 goto 2f;",
            "r6 = r7;",
            "2:",
            "r8 += 1;",
            "if r8 < 3 goto 1b;",
            "r0 = *(u64 *)(r6 + 0);",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: no_widen_any_stack_origin
extern "C" fn no_widen_any_stack_origin() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 16) = 0;",
            "r1 = r10;",
            "r1 += -16;",
            "call {any_stack_origin_callee};",
            "exit;",
            any_stack_origin_callee = sym any_stack_origin_callee,
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: conditional_scalar_assignment_gcd
extern "C" fn conditional_scalar_assignment_gcd() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 3;",
            "r7 = r0;",
            "r7 *= 6;",
            "r7 += 1;",
            "r8 = r0;",
            "r8 *= 9;",
            "r8 += 1;",
            "r6 = 0;",
            "1:",
            "if r6 >= 3 goto 3f;",
            "if r6 != 1 goto 2f;",
            "r7 = r8;",
            "2:",
            "r6 += 1;",
            "goto 1b;",
            "3:",
            "r0 = r7;",
            "r0 %= 3;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: break_pkt_pointers_id
extern "C" fn break_pkt_pointers_id() {
    unsafe {
        core::arch::asm!(
            "r7 = *(u32*)(r1 + 76);",
            "r8 = r7;",
            "r9 = *(u32*)(r1 + 80);",
            "r6 = 0;",
            "1:",
            "call 7;",
            "if r0 == 42 goto 3f;",
            "r6 += 1;",
            "r7 += 1;",
            "if r6 < 10 goto 1b;",
            "3:",
            "if r7 >= r9 goto 2f;",
            "r0 = *(u8*)(r8 + 4);",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: no_widen_stack_spill
extern "C" fn no_widen_stack_spill() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "r2 = 0;",
            "1:",
            "r3 = r10;",
            "r3 += -64;",
            "r3 += r2;",
            "*(u64 *)(r3 + 0) = r0;",
            "r0 += 1;",
            "r2 += 8;",
            "if r0 < 4 goto 1b;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: no_widen_stack_spill_nested
extern "C" fn no_widen_stack_spill_nested() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "r2 = 0;",
            "1:",
            "r1 = 0;",
            "2:",
            "r3 = r10;",
            "r3 += -64;",
            "r3 += r2;",
            "*(u64 *)(r3 + 0) = r1;",
            "r1 += 1;",
            "if r1 < 2 goto 2b;",
            "r0 += 1;",
            "r2 += 8;",
            "if r0 < 4 goto 1b;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: nested_loop_exit_clobbers_reg
extern "C" fn nested_loop_exit_clobbers_reg() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 8) = 0;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map} ll;",
            "call 1;",
            "if r0 == 0 goto 4f;",
            "r7 = r0;",
            "r6 = 0;",
            "1:",
            "r9 = 0;",
            "r1 = r7;",
            "r1 += r6;",
            "r0 = *(u8 *)(r1 + 0);",
            "2:",
            "r8 = r6;",
            "r6 = -1000;",
            "r9 += 1;",
            "if r9 > 5 goto 3f;",
            "r6 = r8;",
            "goto 2b;",
            "3:",
            "r6 += 1;",
            "if r6 s< 3 goto 1b;",
            "4:",
            "r0 = 0;",
            "exit;",
            map = sym map,
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: nested_loop_exit_preserves_reg
extern "C" fn nested_loop_exit_preserves_reg() {
    unsafe {
        core::arch::asm!(
            "r6 = 0;",
            "1:",
            "r7 = 0;",
            "2:",
            "*(u64 *)(r10 - 8) = r6;",
            "r9 = 0;",
            "3:",
            "r8 = r6;",
            "call 7;",
            "if r0 & 1 goto 5f;",
            "r6 = -1000;",
            "r9 += 1;",
            "if r9 >= 2 goto 4f;",
            "r6 = r8;",
            "goto 3b;",
            "4:",
            "r6 = *(u64 *)(r10 - 8);",
            "r7 += 1;",
            "if r7 < 2 goto 2b;",
            "5:",
            "r6 += 1;",
            "if r6 < 3 goto 1b;",
            "r0 = r6;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: widen_byte_stack_store
extern "C" fn widen_byte_stack_store() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "r2 = 0;",
            "1:",
            "r3 = r10;",
            "r3 += -64;",
            "r3 += r2;",
            "*(u8 *)(r3 + 0) = r0;",
            "r0 += 1;",
            "r2 += 8;",
            "if r0 < 4 goto 1b;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: no_widen_stack_fill
extern "C" fn no_widen_stack_fill() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "*(u64 *)(r10 - 64) = r0;",
            "*(u64 *)(r10 - 56) = r0;",
            "*(u64 *)(r10 - 48) = r0;",
            "*(u64 *)(r10 - 40) = r0;",
            "r2 = 0;",
            "1:",
            "r3 = r10;",
            "r3 += -64;",
            "r3 += r2;",
            "r4 = *(u64 *)(r3 + 0);",
            "r0 += 1;",
            "r2 += 8;",
            "if r0 < 4 goto 1b;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: no_widen_stack_fill_any
extern "C" fn no_widen_stack_fill_any() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 16) = r1;",
            "*(u64 *)(r10 - 8) = r1;",
            "r7 = 0;",
            "r8 = 0;",
            "1:",
            "r2 = r10;",
            "r2 += -16;",
            "r2 += r7;",
            "r3 = *(u64 *)(r2 + 0);",
            "r0 = *(u32 *)(r3 + 0);",
            "if r8 != 0 goto 2f;",
            "r7 = 8;",
            "2:",
            "r8 += 1;",
            "if r8 < 2 goto 1b;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_stack
extern "C" fn ptr_stack() {
    unsafe {
        core::arch::asm!(
            "r6 = r10;",
            "r6 += -16;",
            "r7 = r6;",
            "r7 += 4;",
            "1:",
            "r6 += 1;",
            "if r6 < r7 goto 1b;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_stack_callee
extern "C" fn ptr_stack_callee() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r6 = r10;",
            "r6 += -16;",
            "r7 = r1;",
            "r0 = 0;",
            "1:",
            "r6 += 1;",
            "r0 += 1;",
            "if r0 & 8 goto 4f;",
            "if r6 < r7 goto 1b;",
            "4:",
            "r0 = 0;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_stack_other_frame
extern "C" fn ptr_stack_other_frame() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -12;",
            "call {ptr_stack_callee};",
            "exit;",
            ptr_stack_callee = sym ptr_stack_callee,
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_packet_meta_other_origin
extern "C" fn ptr_packet_meta_other_origin() {
    unsafe {
        core::arch::asm!(
            "r6 = *(u32 *)(r1 + 8);",
            "r7 = *(u32 *)(r1 + 0);",
            "r7 += 4;",
            "r0 = 0;",
            "1:",
            "r6 += 1;",
            "r0 += 1;",
            "if r0 & 8 goto 4f;",
            "if r6 < r7 goto 1b;",
            "4:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_map_value_two_lookups
extern "C" fn ptr_map_value_two_lookups() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 8) = 0;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {small_map} ll;",
            "call 1;",
            "if r0 == 0 goto 2f;",
            "r6 = r0;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {small_map} ll;",
            "call 1;",
            "if r0 == 0 goto 2f;",
            "r7 = r0;",
            "r7 += 4;",
            "1:",
            "r6 += 1;",
            "if r6 < r7 goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            small_map = sym small_map,
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_map_value_two_lookups_inner_map
extern "C" fn ptr_map_value_two_lookups_inner_map() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 8) = 0;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {outer_map} ll;",
            "call 1;",
            "if r0 == 0 goto 2f;",
            "r8 = r0;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = r8;",
            "call 1;",
            "if r0 == 0 goto 2f;",
            "r6 = r0;",
            "r1 = r8;",
            "r2 = r10;",
            "r2 += -8;",
            "call 1;",
            "if r0 == 0 goto 2f;",
            "r7 = r0;",
            "r7 += 4;",
            "r0 = 0;",
            "1:",
            "r6 += 1;",
            "r0 += 1;",
            "if r0 & 8 goto 2f;",
            "if r6 < r7 goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            outer_map = sym outer_map,
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_map_value
extern "C" fn ptr_map_value() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 8) = 0;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map} ll;",
            "call 1;",
            "if r0 == 0 goto 2f;",
            "r6 = r0;",
            "r7 = r6;",
            "r7 += 4;",
            "1:",
            "r6 += 1;",
            "if r6 < r7 goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            map = sym map,
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_map_value_other_map
extern "C" fn ptr_map_value_other_map() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 8) = 0;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map} ll;",
            "call 1;",
            "if r0 == 0 goto 2f;",
            "r6 = r0;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {other_map} ll;",
            "call 1;",
            "if r0 == 0 goto 2f;",
            "r7 = r0;",
            "r7 += 4;",
            "r0 = 0;",
            "1:",
            "r6 += 1;",
            "r0 += 1;",
            "if r0 & 8 goto 4f;",
            "if r6 < r7 goto 1b;",
            "4:",
            "2:",
            "r0 = 0;",
            "exit;",
            map = sym map,
            other_map = sym other_map,
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_mem
extern "C" fn ptr_mem() {
    unsafe {
        core::arch::asm!(
            "r1 = {ringbuf} ll;",
            "r2 = 8;",
            "r3 = 0;",
            "call 131;",
            "if r0 == 0 goto 2f;",
            "r8 = r0;",
            "r6 = r0;",
            "r7 = r6;",
            "r7 += 4;",
            "1:",
            "r6 += 1;",
            "if r6 < r7 goto 1b;",
            "r1 = r8;",
            "r2 = 0;",
            "call 133;",
            "2:",
            "r0 = 0;",
            "exit;",
            ringbuf = sym ringbuf,
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_mem_other_reservation
extern "C" fn ptr_mem_other_reservation() {
    unsafe {
        core::arch::asm!(
            "r1 = {ringbuf} ll;",
            "r2 = 8;",
            "r3 = 0;",
            "call 131;",
            "if r0 == 0 goto 3f;",
            "r8 = r0;",
            "r6 = r0;",
            "r1 = {ringbuf} ll;",
            "r2 = 8;",
            "r3 = 0;",
            "call 131;",
            "if r0 == 0 goto 2f;",
            "r9 = r0;",
            "r7 = r0;",
            "r7 += 4;",
            "r0 = 0;",
            "1:",
            "r6 += 1;",
            "r0 += 1;",
            "if r0 & 8 goto 4f;",
            "if r6 < r7 goto 1b;",
            "4:",
            "r1 = r9;",
            "r2 = 0;",
            "call 133;",
            "2:",
            "r1 = r8;",
            "r2 = 0;",
            "call 133;",
            "3:",
            "r0 = 0;",
            "exit;",
            ringbuf = sym ringbuf,
            options(nostack)
        );
    }
}

#[link_section = "iter/bpf_map_elem"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_buf
extern "C" fn ptr_buf() {
    unsafe {
        core::arch::asm!(
            "r6 = *(u64 *)(r1 + 24);",
            "if r6 == 0 goto 2f;",
            "r7 = r6;",
            "r7 += 4;",
            "1:",
            "r6 += 1;",
            "if r6 < r7 goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "iter/bpf_map_elem"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_buf_other_load
extern "C" fn ptr_buf_other_load() {
    unsafe {
        core::arch::asm!(
            "r6 = *(u64 *)(r1 + 24);",
            "if r6 == 0 goto 2f;",
            "r7 = *(u64 *)(r1 + 24);",
            "if r7 == 0 goto 2f;",
            "r7 += 4;",
            "r0 = 0;",
            "1:",
            "r6 += 1;",
            "r0 += 1;",
            "if r0 & 8 goto 4f;",
            "if r6 < r7 goto 1b;",
            "4:",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_vs_scalar_no_widen
extern "C" fn ptr_vs_scalar_no_widen() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 8) = 0;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map} ll;",
            "call 1;",
            "if r0 == 0 goto out_10;",
            "r1 = r0;",
            "r0 = 0;",
            "loop_10:",
            "r1 += 1;",
            "r0 += 1;",
            "if r0 & 8 goto out_10;",
            "if r1 < 4 goto loop_10;",
            "out_10:",
            "r0 = 0;",
            "exit;",
            map = sym map,
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: no_widen_maybe_null
extern "C" fn no_widen_maybe_null() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64 *)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map} ll;",
            "call 1;",
            "r1 = r0;",
            "r6 = 0;",
            "loop_11:",
            "if r1 == 0 goto exit_11;",
            "r1 += 8;",
            "r6 += 1;",
            "if r6 < 3 goto loop_11;",
            "exit_11:",
            "r0 = 0;",
            "exit;",
            map = sym map,
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: nested_terminating_prune
extern "C" fn nested_terminating_prune() {
    unsafe {
        core::arch::asm!(
            "r7 = 0;",
            "outer_12:",
            "r7 += 1;",
            "r7 &= 0xf;",
            "call 7;",
            "if r0 == 42 goto out_12;",
            "r8 = 0;",
            "inner_12:",
            "r8 += 1;",
            "if r8 < 3 goto inner_12;",
            "goto outer_12;",
            "out_12:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: nested_loop_backedge_to_outer_header
extern "C" fn nested_loop_backedge_to_outer_header() {
    unsafe {
        core::arch::asm!(
            "r6 = 0;",
            "outer_13:",
            "if r6 == 3 goto exit_13;",
            "r6 += 1;",
            "r7 = 0;",
            "inner_13:",
            "if r7 == 2 goto outer_13;",
            "r7 += 1;",
            "goto inner_13;",
            "exit_13:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: post_cond_ivar_src
extern "C" fn post_cond_ivar_src() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "r2 = 10;",
            "1:",
            "r1 += 1;",
            "if r2 != r1 goto 1b;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: dominating_exit_bounds_count
extern "C" fn dominating_exit_bounds_count() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "r2 = 14;",
            "1:",
            "if r2 == r1 goto 2f;",
            "r1 += 1;",
            "if r1 != 63 goto 1b;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

include!("hand/verifier_scev.rs");

bpf_object!("GPL");
