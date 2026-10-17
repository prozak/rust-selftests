// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_live_stack.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_live_stack.rs
// (include!d below): global_noop_arg, global_int_arg, global_noop_dynptr_arg, global_noop_btf_arg.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_live_stack` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: simple_read_simple_write read_write_join must_write_not_same_slot may_write_two_precise_offsets must_write_not_same_type caller_stack_write write_first_param global_noop_arg global_callee_arg global_int_arg global_noop_int_arg global_noop_dynptr_arg global_callee_dynptr_arg global_noop_btf_arg global_callee_btf_arg imprecise_frame_write imprecise_frame_writer caller_stack_read read_first_param arg_track_join_convergence arg_track_join_convergence_subprog caller_stack_pruning read_first_param2 caller_stack_pruning_callback loop_cb syzbot_postorder_bug1 caller_stack_write_tail_call write_tail_call subprog_precise_stack_access precise_read_two subprog_multilevel_conservative forward_to_inner inner_callee callee_consumed_caller_stack consume_and_call_inner do_nothing2 stack_zero_to_misc_unsound_array_lookup subprog_stack_zero_to_misc_unsound maybe_clobber_key spill_reload_inflates_stack_liveness modifier2 spill_reload_reader2 __kfunc_btf_root kfunc_iter_stack_liveness spill_ptr_liveness_type_confusion four_byte_write_kills_slot dead_half_spi_write four_byte_read_upper_half two_byte_write_no_kill one_byte_write_no_kill high_stack_second_bitmask_word two_four_byte_writes_kill_full_spi both_branches_kill_slot half_spi_clean_preserves_stack_zero dead_spill_at_merge_enables_pruning fp_add_loses_precision_kills_liveness fp_spill_loses_precision_kills_liveness conditional_stx_in_subprog cond_writer multiple_callsites_different_offsets nested_fp_passthrough outer_forwarder inner_reader callee_must_write_before_read write_then_read return_site_liveness_bleeding callback_conditional_read_beyond_ctx cb_cond_read callback_write_before_read_kills cb_write_read callback_conditional_write_preserves cb_cond_write_read callback_two_calls_different_ctx cb_read_ctx transitive_parent_stack_read_unsound mid_fwd grandchild_deref two_fp_clear_stack_threshold mid_two_fp_threshold inner_nop_fptest one_fp_clear_stack_threshold mid_one_fp_threshold helper_parent_stack_read_unsound fwd_parent_key_to_helper helper_arg_fallback_keeps_scanning helper_update_parent_after_local_fallback propagate_callee_ancestor_chain mid_seq_touch nop_callee deref_ancestor spilled_fp_cross_frame_deref mid_fwd_spilled_ptr load_ptr_deref_grandchild test_merge_nonlocal_live merge_wrapper_a merge_wrapper_b merge_shared_mid merge_leaf_read bpf_loop_two_callbacks dyn_wrapper_a dyn_wrapper_b mid_dynamic_cb dyn_cb_a dyn_cb_b stack_or_non_stack_write shared_instance_must_write_overwrite forwarding_rw write_first_read_second merge_preserves_may_write mvs_mid mvs_leaf stale_must_write_cross_callsite fwd_to_stale_wr stale_wr_leaf load_acquire_dont_clear_dst atomic_rmw load_acquire_fills_spilled_ptr store_release_spills_ptr atomic_rmw_fills_spilled_ptr atomic_rmw_fills_parent_spilled_ptr atomic_rmw_fills_parent_spilled_ptr_callee imprecise_fill_loses_cross_frame imprecise_fill_cross_frame spill_join_with_multi_off spill_join_with_imprecise_off st_imm_join_with_multi_off st_imm_join_with_single_off st_imm_join_with_imprecise_off imprecise_dst_spill_join imprecise_dst_spill_join_sub narrow_store_defines_nothing merge_keeps_whole_frame_read merge_read_all_mid merge_read_all_callee spill_below_512_stays_precise helper_output_unknown_size helper_map_output_known_size helper_map_output_merged_sizes helper_bloom_peek_input

use bpf_rs_core::{arg_tags, bpf_map, bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    simple_read_simple_write:
        __log_level("2"),
        __msg("0: (79) r1 = *(u64 *)(r10 -8)        ; use: fp0-8"),
        __msg("1: (79) r2 = *(u64 *)(r10 -24)       ; use: fp0-24"),
        __msg("2: (7b) *(u64 *)(r10 -8) = r1        ; def: fp0-8");
    read_write_join:
        __log_level("2"),
        __msg("2: (79) r0 = *(u64 *)(r10 -8)        ; use: fp0-8"),
        __msg("6: (79) r0 = *(u64 *)(r10 -16)       ; use: fp0-16");
    must_write_not_same_slot:
        __log_level("2"),
        __msg("stack use/def subprog#0 must_write_not_same_slot (d0,cs0):"),
        __msg("6: (7b) *(u64 *)(r2 +0) = r0         ; may_def: fp0-8..-{{(512|2048)}}"),
        __msg("Program dump");
    may_write_two_precise_offsets:
        __log_level("2"),
        __msg("stack use/def subprog#0 may_write_two_precise_offsets (d0,cs0):"),
        __msg("6: (7b) *(u64 *)(r1 +0) = r0         ; may_def: fp0-8 fp0-16");
    must_write_not_same_type:
        __log_level("2"),
        __msg("0: (7a) *(u64 *)(r10 -8) = 0         ; def: fp0-8"),
        __msg("5: (85) call bpf_map_lookup_elem#1   ; use: fp0-8h");
    caller_stack_write:
        __log_level("2"),
        __msg("stack use/def subprog#0 caller_stack_write (d0,cs0):"),
        __msg("2: (85) call pc+1                    ; may_def: fp0-8"),
        __msg("stack use/def subprog#1 write_first_param (d1,cs2):"),
        __msg("4: (7a) *(u64 *)(r1 +0) = 7          ; def: fp0-8 may_def: fp0-8");
    global_callee_arg:
        __log_level("2"),
        __msg("stack use/def subprog#0 global_callee_arg (d0,cs0):"),
        __msg("3: (85) call pc+{{.*}}; use: fp0-8 def: fp0-8 may_def: fp0-8");
    global_noop_int_arg:
        __success,
        __log_level("2"),
        __msg("stack use/def subprog#0 global_noop_int_arg (d0,cs0):"),
        __msg_next("  0: (bf) r1 = r10{{$}}"),
        __msg_next("  1: (07) r1 += -8{{$}}"),
        __msg_next("  2: (1f) r1 -= r10{{$}}"),
        __msg_next("  3: (85) call pc+1{{$}}"),
        __msg_next("  4: (95) exit");
    global_callee_dynptr_arg:
        __success,
        __log_level("2"),
        __msg("stack use/def subprog#0 global_callee_dynptr_arg (d0,cs0):"),
        __msg("  7: (bf) r1 = r10{{$}}"),
        __msg_next("  8: (07) r1 += -32{{$}}"),
        __msg_next("  9: (85) call pc+1{{ +}}; use: fp0-24 fp0-32 may_def: fp0-24 fp0-32{{$}}"),
        __msg_next(" 10: (95) exit{{$}}");
    global_callee_btf_arg:
        __success,
        __log_level("2"),
        __msg("stack use/def subprog#0 global_callee_btf_arg (d0,cs0):"),
        __msg_next("  0: (7a) *(u64 *)(r10 -8) = 0{{.*}}"),
        __msg_next("  1: (bf) r1 = r10{{$}}"),
        __msg_next("  2: (07) r1 += -8{{$}}"),
        __msg_next("  3: (85) call pc+1{{$}}"),
        __msg_next("  4: (95) exit{{$}}");
    imprecise_frame_write:
        __log_level("2"),
        __msg("stack use/def subprog#0 imprecise_frame_write (d0,cs0):"),
        __msg("2: (85) call pc+2                    ; may_def: fp0-8..-{{(512|2048)}}"),
        __msg("stack use/def subprog#1 imprecise_frame_writer (d1,cs2):"),
        __msg("12: (7b) *(u64 *)(r1 +0) = r2         ; may_def: fp1-8..-{{(512|2048)}} fp0-8..-{{(512|2048)}}");
    caller_stack_read:
        __log_level("2"),
        __msg("stack use/def subprog#0 caller_stack_read (d0,cs0):"),
        __msg("2: (85) call pc+{{.*}}                   ; use: fp0-8{{$}}"),
        __msg("5: (85) call pc+{{.*}}                   ; use: fp0-16{{$}}"),
        __msg("stack use/def subprog#1 read_first_param (d1,cs2):"),
        __msg("7: (79) r0 = *(u64 *)(r1 +0)         ; use: fp0-8{{$}}"),
        __msg("8: (95) exit"),
        __msg("stack use/def subprog#1 read_first_param (d1,cs5):"),
        __msg("7: (79) r0 = *(u64 *)(r1 +0)         ; use: fp0-16{{$}}"),
        __msg("8: (95) exit");
    arg_track_join_convergence:
        __success;
    caller_stack_pruning:
        __flag("BPF_F_TEST_STATE_FREQ"),
        __log_level("2"),
        __msg("4: (7b) *(u64 *)(r10 -8) = r0        ; def: fp0-8"),
        __msg("7: (85) call pc+{{.*}}               ; use: fp0-8"),
        __msg("9: (79) r0 = *(u64 *)(r1 +0)         ; use: fp0-8"),
        __msg("10: (b7) r0 = 0{{$}}"),
        __msg("11: (05) goto pc+0{{$}}"),
        __msg("12: (95) exit"),
        __msg("12: safe");
    caller_stack_pruning_callback:
        __flag("BPF_F_TEST_STATE_FREQ"),
        __failure,
        __msg("Possibly NULL pointer passed to trusted R1");
    caller_stack_write_tail_call:
        __failure,
        __msg("invalid read from stack R2 off=-4096 size=8"),
        __flag("BPF_F_TEST_STATE_FREQ");
    subprog_precise_stack_access:
        __log_level("2"),
        __msg("6: (85) call pc+{{.*}}                   ; use: fp0-24 fp0-32{{$}}");
    subprog_multilevel_conservative:
        __log_level("2"),
        __msg("6: (85) call pc+{{.*}}                   ; use: fp0-32{{$}}");
    callee_consumed_caller_stack:
        __flag("BPF_F_TEST_STATE_FREQ"),
        __log_level("2"),
        __success,
        __msg(" 7: (85) call pc+{{.*}}                   ; use: fp0-8"),
        __msg(" 8: {{.*}} (b7)");
    stack_zero_to_misc_unsound_array_lookup:
        __flag("BPF_F_TEST_STATE_FREQ"),
        __failure,
        __msg("R0 invalid mem access 'map_value_or_null'");
    subprog_stack_zero_to_misc_unsound:
        __flag("BPF_F_TEST_STATE_FREQ"),
        __failure,
        __msg("R0 invalid mem access 'map_value_or_null'");
    spill_reload_inflates_stack_liveness:
        __flag("BPF_F_TEST_STATE_FREQ"),
        __log_level("2"),
        __success,
        __msg("6: safe");
    kfunc_iter_stack_liveness:
        __success,
        __log_level("2"),
        __msg(" 6: (85) call bpf_iter_num_new{{.*}}          ; def: fp0-24 may_def: fp0-24{{$}}"),
        __msg(" 9: (85) call bpf_iter_num_next{{.*}}         ; use: fp0-24 may_def: fp0-24{{$}}"),
        __msg("14: (85) call bpf_iter_num_destroy{{.*}}      ; use: fp0-24 may_def: fp0-24{{$}}");
    spill_ptr_liveness_type_confusion:
        __flag("BPF_F_TEST_STATE_FREQ"),
        __failure,
        __msg("R0 invalid mem access 'scalar'");
    four_byte_write_kills_slot:
        __log_level("2"),
        __msg("1: (62) *(u32 *)(r10 -8) = 0         ; def: fp0-8h");
    dead_half_spi_write:
        __log_level("2"),
        __msg("0: (62) *(u32 *)(r10 -8) = 0         ; def: fp0-8h"),
        __msg("2: (61) r0 = *(u32 *)(r10 -4)        ; use: fp0-4h");
    four_byte_read_upper_half:
        __log_level("2"),
        __msg("1: (61) r0 = *(u32 *)(r10 -8)        ; use: fp0-8h");
    two_byte_write_no_kill:
        __log_level("2"),
        __msg("0: (7a) *(u64 *)(r10 -8) = 0         ; def: fp0-8 may_def: fp0-8"),
        __msg("1: (6a) *(u16 *)(r10 -4) = 0         ; may_def: fp0-4h"),
        __msg("2: (61) r0 = *(u32 *)(r10 -4)        ; use: fp0-4h");
    one_byte_write_no_kill:
        __log_level("2"),
        __msg("0: (7a) *(u64 *)(r10 -8) = 0         ; def: fp0-8"),
        __msg("1: (72) *(u8 *)(r10 -4) = 0"),
        __msg("2: (61) r0 = *(u32 *)(r10 -4)        ; use: fp0-4h");
    high_stack_second_bitmask_word:
        __log_level("2"),
        __msg("1: (79) r0 = *(u64 *)(r10 -264)      ; use: fp0-264");
    two_four_byte_writes_kill_full_spi:
        __log_level("2"),
        __msg("0: (62) *(u32 *)(r10 -8) = 0         ; def: fp0-8h"),
        __msg("1: (62) *(u32 *)(r10 -4) = 0         ; def: fp0-4h");
    both_branches_kill_slot:
        __log_level("2"),
        __msg("1: (55) if r0 != 0x0 goto pc+2"),
        __msg("2: (7a) *(u64 *)(r10 -8) = 0         ; def: fp0-8"),
        __msg("3: (05) goto pc+1"),
        __msg("4: (62) *(u32 *)(r10 -4) = 0         ; def: fp0-4h"),
        __msg("5: (61) r0 = *(u32 *)(r10 -4)        ; use: fp0-4h");
    half_spi_clean_preserves_stack_zero:
        __flag("BPF_F_TEST_STATE_FREQ"),
        __failure,
        __msg("R0 invalid mem access 'map_value_or_null'");
    dead_spill_at_merge_enables_pruning:
        __flag("BPF_F_TEST_STATE_FREQ"),
        __success,
        __log_level("2"),
        __msg("6: safe");
    fp_add_loses_precision_kills_liveness:
        __flag("BPF_F_TEST_STATE_FREQ"),
        __failure,
        __msg("R1 invalid mem access 'scalar'");
    fp_spill_loses_precision_kills_liveness:
        __flag("BPF_F_TEST_STATE_FREQ"),
        __failure,
        __msg("R1 invalid mem access 'scalar'");
    conditional_stx_in_subprog:
        __log_level("2"),
        __msg("1: (7b) *(u64 *)(r10 -8) = r1        ; def: fp0-8 may_def: fp0-8"),
        __msg("4: (85) call pc+2                    ; may_def: fp0-8"),
        __msg("5: (79) r0 = *(u64 *)(r10 -8)        ; use: fp0-8");
    multiple_callsites_different_offsets:
        __log_level("2"),
        __msg("4: (85) call pc+{{.*}}                   ; use: fp0-16"),
        __msg("7: (85) call pc+{{.*}}                   ; use: fp0-32");
    nested_fp_passthrough:
        __log_level("2"),
        __msg("6: (85) call pc+{{.*}}                   ; use: fp0-32");
    callee_must_write_before_read:
        __log_level("2"),
        __msg("2: .1........ (85) call pc+");
    return_site_liveness_bleeding:
        __log_level("2"),
        __msg("3: (85) call pc+{{.*}}                   ; use: fp0-8"),
        __msg("7: (85) call pc+{{.*}}                   ; use: fp0-8");
    callback_conditional_read_beyond_ctx:
        __log_level("2"),
        __msg("9: (85) call bpf_loop#181            ; use: fp0-16");
    callback_write_before_read_kills:
        __log_level("2"),
        __msg("14: (7b) *(u64 *)(r6 -8) = r7         ; def: fp0-16"),
        __msg("15: (79) r0 = *(u64 *)(r6 -8)         ; use: fp0-16");
    callback_conditional_write_preserves:
        __log_level("2"),
        __msg("9: (85) call bpf_loop#181            ; use: fp0-16");
    callback_two_calls_different_ctx:
        __log_level("2"),
        __msg(" 8: (85) call bpf_loop{{.*}}            ; use: fp0-8"),
        __msg("15: (85) call bpf_loop{{.*}}            ; use: fp0-24");
    transitive_parent_stack_read_unsound:
        __flag("BPF_F_TEST_STATE_FREQ"),
        __failure,
        __msg("R0 invalid mem access 'scalar'");
    two_fp_clear_stack_threshold:
        __log_level("2"),
        __success,
        __msg("14: (79) r1 = *(u64 *)(r10 -8) // r6=fp0-8 r7=fp1-16 fp-8=fp1-16 fp-16=fp0-8"),
        __msg("15: (79) r0 = *(u64 *)(r1 +0) // r1=fp1-16 r6=fp0-8 r7=fp1-16 fp-8=fp1-16 fp-16=fp0-8"),
        __msg("stack use/def subprog#1 mid_two_fp_threshold (d1,cs2):"),
        __msg("14: (79) r1 = *(u64 *)(r10 -8)        ; use: fp1-8"),
        __msg("15: (79) r0 = *(u64 *)(r1 +0)         ; use: fp1-16");
    one_fp_clear_stack_threshold:
        __log_level("2"),
        __success,
        __msg("13: (79) r1 = *(u64 *)(r10 -8) // r6=fp0-8 r7=fp1-16 fp-8=fp1-16 fp-16=fp0-8"),
        __msg("14: (79) r0 = *(u64 *)(r1 +0) // r1=fp1-16 r6=fp0-8 r7=fp1-16 fp-8=fp1-16 fp-16=fp0-8"),
        __msg("stack use/def subprog#1 mid_one_fp_threshold (d1,cs2):"),
        __msg("13: (79) r1 = *(u64 *)(r10 -8)        ; use: fp1-8"),
        __msg("14: (79) r0 = *(u64 *)(r1 +0)         ; use: fp1-16");
    helper_parent_stack_read_unsound:
        __flag("BPF_F_TEST_STATE_FREQ"),
        __failure,
        __msg("R0 invalid mem access 'map_value_or_null'");
    helper_arg_fallback_keeps_scanning:
        __log_level("2"),
        __success,
        __msg("call bpf_map_update_elem{{.*}}; use: fp1-8..-{{(512|2048)}} fp0-8");
    propagate_callee_ancestor_chain:
        __flag("BPF_F_TEST_STATE_FREQ"),
        __failure,
        __msg("R0 invalid mem access 'scalar'");
    spilled_fp_cross_frame_deref:
        __flag("BPF_F_TEST_STATE_FREQ"),
        __success;
    test_merge_nonlocal_live:
        __log_level("2"),
        __success,
        __msg("14: (85) call pc+2\tr1: fp0-16"),
        __msg("17: (79) r0 = *(u64 *)(r1 +0) // r1=fp0-16"),
        __msg("14: (85) call pc+2\tr1: fp0-8"),
        __msg("17: (79) r0 = *(u64 *)(r1 +0) // r1=fp0-8"),
        __msg("5: (85) call pc+{{.*}}                   ; use: fp0-8 fp0-16");
    bpf_loop_two_callbacks:
        __log_level("2"),
        __success,
        __msg("stack use/def subprog#0 bpf_loop_two_callbacks (d0,cs0):"),
        __msg("5: (85) call pc+{{.*}};{{.*}} may_def: fp0-8..-{{(512|2048)}}{{$}}"),
        __msg("8: (85) call pc+{{.*}};{{.*}} may_def: fp0-8..-{{(512|2048)}}{{$}}"),
        __msg("call bpf_loop#181            ; use: fp2-8..-{{(512|2048)}} fp1-8..-{{(512|2048)}} fp0-8..-{{(512|2048)}} may_def: fp2-8..-{{(512|2048)}} fp1-8..-{{(512|2048)}} fp0-8..-{{(512|2048)}}{{$}}");
    stack_or_non_stack_write:
        __log_level("2"),
        __msg("10: (79) r0 = *(u64 *)(r10 -8) // r0=fp0-8|fp0+0");
    shared_instance_must_write_overwrite:
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("subprog#2 write_first_read_second:"),
        __msg("17: (7a) *(u64 *)(r1 +0) = 42{{$}}"),
        __msg("18: (79) r0 = *(u64 *)(r2 +0) // r1=fp0-8 r2=fp0-16{{$}}"),
        __msg("stack use/def subprog#0 shared_instance_must_write_overwrite (d0,cs0):"),
        __msg("7: (85) call pc+7                    ; use: fp0-8 fp0-16 may_def: fp0-8 fp0-16"),
        __msg("12: (85) call pc+2                    ; use: fp0-8 may_def: fp0-16"),
        __msg("stack use/def subprog#1 forwarding_rw (d1,cs7):"),
        __msg("15: (85) call pc+1                    ; use: fp0-8 fp0-16 may_def: fp0-8 fp0-16"),
        __msg("stack use/def subprog#1 forwarding_rw (d1,cs12):"),
        __msg("15: (85) call pc+1                    ; use: fp0-8 may_def: fp0-16"),
        __msg("stack use/def subprog#2 write_first_read_second (d2,cs15):"),
        __msg("17: (7a) *(u64 *)(r1 +0) = 42         ; may_def: fp0-8 fp0-16"),
        __msg("18: (79) r0 = *(u64 *)(r2 +0)         ; use: fp0-8 fp0-16");
    merge_preserves_may_write:
        __success,
        __log_level("2"),
        __msg("stack use/def subprog#2 mvs_leaf (d2,cs19):"),
        __msg("21: (7a) *(u64 *)(r2 +0) = 42         ; may_def: fp0-8");
    stale_must_write_cross_callsite:
        __success;
    load_acquire_dont_clear_dst:
        __log_level("2"),
        __success,
        __msg("*(u64 *)(r0 +0) = 42         ; def: fp0-16");
    atomic_rmw:
        __log_level("2"),
        __success,
        __msg("lock *(u64 *)(r10 -8) += r1{{.*}}use: fp0-8{{.*}}may_def: fp0-8"),
        __msg("r1 = atomic64_fetch_add((u64 *)(r10 -8), r1){{.*}}use: fp0-8{{.*}}may_def: fp0-8"),
        __msg("r1 = atomic64_xchg((u64 *)(r10 -8), r1){{.*}}use: fp0-8{{.*}}may_def: fp0-8"),
        __msg("r0 = atomic64_cmpxchg((u64 *)(r10 -8), r0, r1){{.*}}use: fp0-8{{.*}}may_def: fp0-8");
    load_acquire_fills_spilled_ptr:
        __log_level("2"),
        __success,
        __msg("r2 = load_acquire((u64 *)(r10 -16)){{.*}}use: fp0-16"),
        __msg("*(u64 *)(r2 +0) = 42{{.*}}def: fp0-8 may_def: fp0-8");
    store_release_spills_ptr:
        __log_level("2"),
        __success,
        __msg("store_release((u64 *)(r10 -16), r1){{.*}}def: fp0-16"),
        __msg("*(u64 *)(r2 +0) = 42{{.*}}def: fp0-8 may_def: fp0-8");
    atomic_rmw_fills_spilled_ptr:
        __log_level("2"),
        __success,
        __msg("r2 = atomic64_xchg((u64 *)(r10 -16), r2){{.*}}use: fp0-16{{.*}}may_def: fp0-16"),
        __msg("*(u64 *)(r2 +0) = 42{{.*}}def: fp0-8 may_def: fp0-8"),
        __msg("r3 = atomic64_fetch_add((u64 *)(r10 -16), r3){{.*}}use: fp0-16{{.*}}may_def: fp0-16"),
        __msg("*(u64 *)(r3 +0) = 42{{.*}}def: fp0-8 may_def: fp0-8"),
        __msg("r0 = atomic64_cmpxchg((u64 *)(r10 -16), r0, r4){{.*}}use: fp0-16{{.*}}may_def: fp0-16"),
        __msg("*(u64 *)(r0 +0) = 42{{.*}}def: fp0-8 may_def: fp0-8");
    atomic_rmw_fills_parent_spilled_ptr:
        __log_level("2"),
        __success,
        __msg("r2 = atomic64_xchg((u64 *)(r1 +0), r2){{.*}}use: fp0-16{{.*}}may_def: fp0-16"),
        __msg("*(u64 *)(r2 +0) = 42{{.*}}; may_def: fp0-8");
    imprecise_fill_loses_cross_frame:
        __success;
    spill_join_with_multi_off:
        __log_level("2"),
        __success,
        __msg("20: (79) r0 = *(u64 *)(r10 -16)"),
        __msg("21: (79) r0 = *(u64 *)(r0 +0)         ; use: fp0-24 fp0-32");
    spill_join_with_imprecise_off:
        __log_level("2"),
        __success,
        __msg("15: (79) r0 = *(u64 *)(r0 +0)         ; use: fp0-24 fp0-32");
    st_imm_join_with_multi_off:
        __log_level("2"),
        __failure,
        __msg("15: (7a) *(u64 *)(r1 +0) = 0\tfp-8: fp0-24 -> fp0-24|fp0+0\tfp-16: fp0-32 -> fp0-32|fp0+0"),
        __msg("17: (79) r0 = *(u64 *)(r0 +0)         ; use: fp0-32");
    st_imm_join_with_single_off:
        __log_level("2"),
        __success,
        __msg("5: (7a) *(u64 *)(r1 +0) = 0\tfp-8: fp0-16 -> _{{$}}");
    st_imm_join_with_imprecise_off:
        __log_level("2"),
        __success,
        __msg("13: (79) r0 = *(u64 *)(r0 +0)         ; use: fp0-32");
    imprecise_dst_spill_join:
        __log_level("2"),
        __success,
        __msg("26: (79) r0 = *(u64 *)(r10 -8) // r1=IMP3 r6=fp0-24 r7=fp1-16 fp-8=fp1-16|fp1+0");
    narrow_store_defines_nothing:
        __log_level("2"),
        __msg("0: (79) r0 = *(u64 *)(r10 -8)        ; use: fp0-8"),
        __msg("1: (73) *(u8 *)(r10 -1) = r0         ; may_def: fp0-4h"),
        __msg("2: (6b) *(u16 *)(r10 -4) = r0        ; may_def: fp0-4h"),
        __msg("3: (79) r0 = *(u64 *)(r10 -8)        ; use: fp0-8");
    merge_keeps_whole_frame_read:
        __log_level("2"),
        __msg("stack use/def subprog#{{[0-9]+}} merge_read_all_callee (d2,cs{{[0-9]+}}):"),
        __msg("(79) r0 = *(u64 *)(r1 +0){{.*}}; use: fp0-8..-{{(512|2048)}}");
    spill_below_512_stays_precise:
        __log_level("2"),
        __load_if_large_stack,
        __msg("(79) r0 = *(u64 *)(r1 +0){{.*}}; use: fp0-8{{$}}");
    helper_output_unknown_size:
        __success,
        __log_level("2"),
        __msg("call bpf_probe_read_kernel{{.*}}; may_def: fp0-8{{$}}");
    helper_map_output_known_size:
        __success,
        __log_level("2"),
        __msg("call bpf_map_pop_elem{{.*}}; def: fp0-16");
    helper_map_output_merged_sizes:
        __success,
        __log_level("2"),
        __msg("call bpf_map_pop_elem{{.*}}; use: fp0-16 fp0-24 may_def: fp0-16 fp0-24{{$}}");
    helper_bloom_peek_input:
        __success,
        __log_level("2"),
        __msg("call bpf_map_peek_elem{{.*}}; use: fp0-8{{$}}");
}

// Map key/value types, shaped like the C object's BTF (the kernel
// checks some of them member by member, so no explicit padding).
// translint: allow(padding)
arg_tags! {
    global_noop_btf_arg: 0: "arg:untrusted";
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct cnt8 {
    v: i64,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct bpf_dynptr {
    __opaque: [u64; 2],
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct task_struct {
    pid: i32,
}

bpf_map! {
    map {
        r#type: *const [i32; 1],
        max_entries: *const [i32; 1],
        key: *const i32,
        value: *const i64,
    }
}

bpf_map! {
    map_array {
        r#type: *const [i32; 3],
        max_entries: *const [i32; 1],
        key: *const u32,
        value: *const u32,
    }
}

bpf_map! {
    array_map_8b {
        r#type: *const [i32; 2],
        max_entries: *const [i32; 1],
        key: *const u32,
        value: *const u64,
    }
}

bpf_map! {
    queue_8b {
        r#type: *const [i32; 22],
        max_entries: *const [i32; 1],
        value: *const u64,
    }
}

bpf_map! {
    queue_16b {
        r#type: *const [i32; 22],
        max_entries: *const [i32; 1],
        value: *const [u64; 2],
    }
}

bpf_map! {
    bloom_8b {
        r#type: *const [i32; 30],
        max_entries: *const [i32; 16],
        value: *const u64,
    }
}

#[no_mangle]
static mut global_dynptr_buf: [i8; 8] = [0; 8];

extern "C" {
    fn bpf_iter_num_new(a0: *mut c_void, a1: i32, a2: i32) -> i32;
    fn bpf_iter_num_next(a0: *mut c_void) -> *mut c_void;
    fn bpf_iter_num_destroy(a0: *mut c_void);
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: simple_read_simple_write
extern "C" fn simple_read_simple_write() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64 *)(r10 - 8);",
            "r2 = *(u64 *)(r10 - 24);",
            "*(u64 *)(r10 - 8) = r1;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: read_write_join
extern "C" fn read_write_join() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "if r0 > 42 goto 1f;",
            "r0 = *(u64 *)(r10 - 8);",
            "*(u64 *)(r10 - 32) = r0;",
            "*(u64 *)(r10 - 40) = r0;",
            "exit;",
            "1:",
            "r0 = *(u64 *)(r10 - 16);",
            "*(u64 *)(r10 - 32) = r0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: must_write_not_same_slot
extern "C" fn must_write_not_same_slot() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = -8;",
            "if r0 > 42 goto 1f;",
            "r1 = -16;",
            "1:",
            "r2 = r10;",
            "r2 += r1;",
            "*(u64 *)(r2 + 0) = r0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: may_write_two_precise_offsets
extern "C" fn may_write_two_precise_offsets() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = r10;",
            "if r0 > 42 goto 1f;",
            "r1 += -8;",
            "goto 2f;",
            "1:",
            "r1 += -16;",
            "2:",
            "*(u64 *)(r1 + 0) = r0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: must_write_not_same_type
extern "C" fn must_write_not_same_type() {
    unsafe {
        core::arch::asm!(
            "*(u64*)(r10 - 8) = 0;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map} ll;",
            "call 1;",
            "if r0 != 0 goto 1f;",
            "r0 = r10;",
            "r0 += -16;",
            "1:",
            "*(u64 *)(r0 + 0) = 42;",
            "exit;",
            map = sym map,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: caller_stack_write
extern "C" fn caller_stack_write() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -8;",
            "call {write_first_param};",
            "exit;",
            write_first_param = sym write_first_param,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: write_first_param
extern "C" fn write_first_param() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r1 + 0) = 7;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: global_callee_arg
extern "C" fn global_callee_arg() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 8) = 0;",
            "r1 = r10;",
            "r1 += -8;",
            "call {global_noop_arg};",
            "exit;",
            global_noop_arg = sym global_noop_arg,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: global_noop_int_arg
extern "C" fn global_noop_int_arg() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -8;",
            "r1 -= r10;",
            "call {global_int_arg};",
            "exit;",
            global_int_arg = sym global_int_arg,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: global_callee_dynptr_arg
extern "C" fn global_callee_dynptr_arg() {
    unsafe {
        core::arch::asm!(
            "r1 = {global_dynptr_buf} ll;",
            "r2 = 8;",
            "r3 = 0;",
            "r4 = r10;",
            "r4 += -32;",
            "call 197;",
            "r1 = r10;",
            "r1 += -32;",
            "call {global_noop_dynptr_arg};",
            "exit;",
            global_dynptr_buf = sym global_dynptr_buf,
            global_noop_dynptr_arg = sym global_noop_dynptr_arg,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: global_callee_btf_arg
extern "C" fn global_callee_btf_arg() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 8) = 0;",
            "r1 = r10;",
            "r1 += -8;",
            "call {global_noop_btf_arg};",
            "exit;",
            global_noop_btf_arg = sym global_noop_btf_arg,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: imprecise_frame_write
extern "C" fn imprecise_frame_write() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -8;",
            "call {imprecise_frame_writer};",
            "r0 = 0;",
            "exit;",
            imprecise_frame_writer = sym imprecise_frame_writer,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: imprecise_frame_writer
extern "C" fn imprecise_frame_writer() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "call 7;",
            "r1 = r6;",
            "if r0 == 0 goto 1f;",
            "r1 = r10;",
            "r1 += -8;",
            "1:",
            "r2 = 0;",
            "*(u64 *)(r1 + 0) = r2;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: caller_stack_read
extern "C" fn caller_stack_read() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -8;",
            "call {read_first_param};",
            "r1 = r10;",
            "r1 += -16;",
            "call {read_first_param};",
            "exit;",
            read_first_param = sym read_first_param,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: read_first_param
extern "C" fn read_first_param() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: arg_track_join_convergence
extern "C" fn arg_track_join_convergence() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "r2 = 2;",
            "call {arg_track_join_convergence_subprog};",
            "r0 = 0;",
            "exit;",
            arg_track_join_convergence_subprog = sym arg_track_join_convergence_subprog,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: arg_track_join_convergence_subprog
extern "C" fn arg_track_join_convergence_subprog() {
    unsafe {
        core::arch::asm!(
            "if r1 == 0 goto 1f;",
            "r0 = r1;",
            "goto 2f;",
            "1:",
            "r0 = r2;",
            "2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: caller_stack_pruning
extern "C" fn caller_stack_pruning() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "if r0 == 42 goto 1f;",
            "r0 = {map} ll;",
            "1:",
            "*(u64 *)(r10 - 8) = r0;",
            "r1 = r10;",
            "r1 += -8;",
            "call {read_first_param2};",
            "exit;",
            map = sym map,
            read_first_param2 = sym read_first_param2,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: read_first_param2
extern "C" fn read_first_param2() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u64 *)(r1 + 0);",
            "r0 = 0;",
            "goto +0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: caller_stack_pruning_callback
extern "C" fn caller_stack_pruning_callback() {
    unsafe {
        core::arch::asm!(
            "r0 = {map} ll;",
            "*(u64 *)(r10 - 8) = r0;",
            "r1 = 2;",
            "r2 = {loop_cb} ll;",
            "r3 = r10;",
            "r3 += -8;",
            "r4 = 0;",
            "call 181;",
            "r0 = 42;",
            "exit;",
            map = sym map,
            loop_cb = sym loop_cb,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: loop_cb
extern "C" fn loop_cb() {
    unsafe {
        core::arch::asm!(
            "r6 = r2;",
            "r1 = *(u64 *)(r6 + 0);",
            "*(u64*)(r10 - 8) = 7;",
            "r2 = r10;",
            "r2 += -8;",
            "call 1;",
            "*(u64 *)(r6 + 0) = 0;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: syzbot_postorder_bug1
extern "C" fn syzbot_postorder_bug1() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "if r0 != 0 goto -1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: caller_stack_write_tail_call
extern "C" fn caller_stack_write_tail_call() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "*(u64 *)(r10 - 8) = -8;",
            "call 7;",
            "if r0 != 42 goto 1f;",
            "goto 2f;",
            "1:",
            "*(u64 *)(r10 - 8) = -4096;",
            "2:",
            "r1 = r6;",
            "r2 = r10;",
            "r2 += -8;",
            "call {write_tail_call};",
            "r1 = *(u64 *)(r10 - 8);",
            "r2 = r10;",
            "r2 += r1;",
            "r0 = *(u64 *)(r2 + 0);",
            "exit;",
            write_tail_call = sym write_tail_call,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: write_tail_call
extern "C" fn write_tail_call() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "r6 = r2;",
            "r2 = {map_array} ll;",
            "r3 = 0;",
            "call 12;",
            "*(u64 *)(r6 + 0) = -16;",
            "r0 = 0;",
            "exit;",
            map_array = sym map_array,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: subprog_precise_stack_access
extern "C" fn subprog_precise_stack_access() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 8) = 0;",
            "*(u64 *)(r10 - 16) = 0;",
            "*(u64 *)(r10 - 24) = 0;",
            "*(u64 *)(r10 - 32) = 0;",
            "r1 = r10;",
            "r1 += -32;",
            "call {precise_read_two};",
            "r0 = 0;",
            "exit;",
            precise_read_two = sym precise_read_two,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: precise_read_two
extern "C" fn precise_read_two() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u64 *)(r1 + 0);",
            "r2 = *(u64 *)(r1 + 8);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: subprog_multilevel_conservative
extern "C" fn subprog_multilevel_conservative() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 8) = 0;",
            "*(u64 *)(r10 - 16) = 0;",
            "*(u64 *)(r10 - 24) = 0;",
            "*(u64 *)(r10 - 32) = 0;",
            "r1 = r10;",
            "r1 += -32;",
            "call {forward_to_inner};",
            "r0 = 0;",
            "exit;",
            forward_to_inner = sym forward_to_inner,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: forward_to_inner
extern "C" fn forward_to_inner() {
    unsafe {
        core::arch::asm!(
            "call {inner_callee};",
            "r0 = 0;",
            "exit;",
            inner_callee = sym inner_callee,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: inner_callee
extern "C" fn inner_callee() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u64 *)(r1 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callee_consumed_caller_stack
extern "C" fn callee_consumed_caller_stack() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "if r0 == 42 goto 1f;",
            "r0 = {map} ll;",
            "1:",
            "*(u64 *)(r10 - 8) = r0;",
            "r1 = r10;",
            "r1 += -8;",
            "call {consume_and_call_inner};",
            "r0 = 0;",
            "exit;",
            map = sym map,
            consume_and_call_inner = sym consume_and_call_inner,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: consume_and_call_inner
extern "C" fn consume_and_call_inner() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u64 *)(r1 + 0);",
            "call {do_nothing2};",
            "r0 = 0;",
            "goto +0;",
            "r0 = 0;",
            "goto +0;",
            "r0 = 0;",
            "goto +0;",
            "r0 = 0;",
            "goto +0;",
            "exit;",
            do_nothing2 = sym do_nothing2,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: do_nothing2
extern "C" fn do_nothing2() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "r0 = 0;",
            "r0 = 0;",
            "r0 = 0;",
            "r0 = 0;",
            "r0 = 0;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_zero_to_misc_unsound_array_lookup
extern "C" fn stack_zero_to_misc_unsound_array_lookup() {
    unsafe {
        core::arch::asm!(
            "*(u32 *)(r10 - 4) = 0;",
            "call 7;",
            "if r0 != 0 goto l_nonconst0;",
            "goto l_lookup0;",
            "l_nonconst0:",
            "*(u8 *)(r10 - 4) = r0;",
            "l_lookup0:",
            "r2 = r10;",
            "r2 += -4;",
            "r1 = {array_map_8b} ll;",
            "call 1;",
            "r0 = *(u64 *)(r0 + 0);",
            "exit;",
            array_map_8b = sym array_map_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: subprog_stack_zero_to_misc_unsound
extern "C" fn subprog_stack_zero_to_misc_unsound() {
    unsafe {
        core::arch::asm!(
            "*(u32 *)(r10 - 4) = 0;",
            "r1 = r10;",
            "r1 += -4;",
            "call {maybe_clobber_key};",
            "r2 = r10;",
            "r2 += -4;",
            "r1 = {array_map_8b} ll;",
            "call 1;",
            "r0 = *(u64 *)(r0 + 0);",
            "exit;",
            array_map_8b = sym array_map_8b,
            maybe_clobber_key = sym maybe_clobber_key,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: maybe_clobber_key
extern "C" fn maybe_clobber_key() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "call 7;",
            "if r0 == 0 goto 1f;",
            "*(u8 *)(r6 + 0) = r0;",
            "1:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: spill_reload_inflates_stack_liveness
extern "C" fn spill_reload_inflates_stack_liveness() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 24) = r1;",
            "*(u64 *)(r10 - 16) = r1;",
            "*(u64 *)(r10 - 8) = 0;",
            "r1 = r10;",
            "r1 += -24;",
            "call {modifier2};",
            "r1 = r10;",
            "r1 += -24;",
            "call {spill_reload_reader2};",
            "r0 = 0;",
            "exit;",
            modifier2 = sym modifier2,
            spill_reload_reader2 = sym spill_reload_reader2,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: modifier2
extern "C" fn modifier2() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "call 7;",
            "if r0 == 0 goto 1f;",
            "*(u64 *)(r6 + 8) = r0;",
            "r0 = 0;",
            "exit;",
            "1:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: spill_reload_reader2
extern "C" fn spill_reload_reader2() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 8) = r1;",
            "call 7;",
            "r1 = *(u64 *)(r10 - 8);",
            "r0 = *(u64 *)(r1 + 16);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

// __kfunc_btf_root: the C's reference to each kfunc the asm calls, for its
// BTF prototype (llc emits one only for a real call or address load).
#[no_mangle]
#[inline(never)]
extern "C" fn __kfunc_btf_root() {
    unsafe {
        bpf_iter_num_new(core::ptr::null_mut(), 0, 0);
        bpf_iter_num_next(core::ptr::null_mut());
        bpf_iter_num_destroy(core::ptr::null_mut());
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: kfunc_iter_stack_liveness
extern "C" fn kfunc_iter_stack_liveness() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 8) = 0;",
            "*(u64 *)(r10 - 16) = 0;",
            "r1 = r10;",
            "r1 += -24;",
            "r2 = 0;",
            "r3 = 10;",
            "call {bpf_iter_num_new};",
            "1:",
            "r1 = r10;",
            "r1 += -24;",
            "call {bpf_iter_num_next};",
            "if r0 == 0 goto 2f;",
            "goto 1b;",
            "2:",
            "r1 = r10;",
            "r1 += -24;",
            "call {bpf_iter_num_destroy};",
            "r0 = 0;",
            "exit;",
            bpf_iter_num_new = sym bpf_iter_num_new,
            bpf_iter_num_next = sym bpf_iter_num_next,
            bpf_iter_num_destroy = sym bpf_iter_num_destroy,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: spill_ptr_liveness_type_confusion
extern "C" fn spill_ptr_liveness_type_confusion() {
    unsafe {
        core::arch::asm!(
            "r1 = {map} ll;",
            "*(u32 *)(r10 - 32) = 0;",
            "r2 = r10;",
            "r2 += -32;",
            "call 1;",
            "if r0 == 0 goto l_exit1;",
            "r6 = r0;",
            "call 7;",
            "if r0 != 0 goto l_scalar1;",
            "*(u64 *)(r10 - 8) = r6;",
            "goto l_merge1;",
            "l_scalar1:",
            "r1 = 42;",
            "*(u64 *)(r10 - 8) = r1;",
            "l_merge1:",
            "r1 = r10;",
            "r1 += -8;",
            "*(u64 *)(r10 - 16) = r1;",
            "goto +0;",
            "goto +0;",
            "goto +0;",
            "r1 = *(u64 *)(r10 - 16);",
            "r0 = *(u64 *)(r1 + 0);",
            "r0 = *(u64 *)(r0 + 0);",
            "exit;",
            "l_exit1:",
            "r0 = 0;",
            "exit;",
            map = sym map,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: four_byte_write_kills_slot
extern "C" fn four_byte_write_kills_slot() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 8) = 0;",
            "*(u32 *)(r10 - 8) = 0;",
            "r0 = *(u64 *)(r10 - 8);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: dead_half_spi_write
extern "C" fn dead_half_spi_write() {
    unsafe {
        core::arch::asm!(
            "*(u32 *)(r10 - 8) = 0;",
            "*(u32 *)(r10 - 4) = 0;",
            "r0 = *(u32 *)(r10 - 4);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: four_byte_read_upper_half
extern "C" fn four_byte_read_upper_half() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 8) = 0;",
            "r0 = *(u32 *)(r10 - 8);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: two_byte_write_no_kill
extern "C" fn two_byte_write_no_kill() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 8) = 0;",
            "*(u16 *)(r10 - 4) = 0;",
            "r0 = *(u32 *)(r10 - 4);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: one_byte_write_no_kill
extern "C" fn one_byte_write_no_kill() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 8) = 0;",
            "*(u8 *)(r10 - 4) = 0;",
            "r0 = *(u32 *)(r10 - 4);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: high_stack_second_bitmask_word
extern "C" fn high_stack_second_bitmask_word() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 264) = 0;",
            "r0 = *(u64 *)(r10 - 264);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: two_four_byte_writes_kill_full_spi
extern "C" fn two_four_byte_writes_kill_full_spi() {
    unsafe {
        core::arch::asm!(
            "*(u32 *)(r10 - 8) = 0;",
            "*(u32 *)(r10 - 4) = 0;",
            "r0 = *(u64 *)(r10 - 8);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: both_branches_kill_slot
extern "C" fn both_branches_kill_slot() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "if r0 != 0 goto 1f;",
            "*(u64 *)(r10 - 8) = 0;",
            "goto 2f;",
            "1:",
            "*(u32 *)(r10 - 4) = 0;",
            "2:",
            "r0 = *(u32 *)(r10 - 4);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: half_spi_clean_preserves_stack_zero
extern "C" fn half_spi_clean_preserves_stack_zero() {
    unsafe {
        core::arch::asm!(
            "*(u32 *)(r10 - 4) = 0;",
            "*(u32 *)(r10 - 8) = 0;",
            "call 7;",
            "if r0 != 0 goto l_nonconst2;",
            "goto l_lookup2;",
            "l_nonconst2:",
            "*(u8 *)(r10 - 4) = r0;",
            "l_lookup2:",
            "r2 = r10;",
            "r2 += -4;",
            "r1 = {array_map_8b} ll;",
            "call 1;",
            "r0 = *(u64 *)(r0 + 0);",
            "exit;",
            array_map_8b = sym array_map_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: dead_spill_at_merge_enables_pruning
extern "C" fn dead_spill_at_merge_enables_pruning() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r6 = 7;",
            "if r0 != 0 goto l_skip3;",
            "*(u64 *)(r10 - 8) = r6;",
            "call 7;",
            "r6 = *(u64 *)(r10 - 8);",
            "l_skip3:",
            "r0 = r6;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: fp_add_loses_precision_kills_liveness
extern "C" fn fp_add_loses_precision_kills_liveness() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "if r0 != 0 goto l_pathB4;",
            "r1 = 0;",
            "*(u64 *)(r10 - 8) = r1;",
            "goto l_merge4;",
            "l_pathB4:",
            "r1 = 42;",
            "*(u64 *)(r10 - 8) = r1;",
            "l_merge4:",
            "r6 = r10;",
            "r6 += -24;",
            "r6 += 8;",
            "r7 = 0;",
            "*(u64 *)(r6 + 0) = r7;",
            "r2 = *(u64 *)(r10 - 8);",
            "if r2 == 42 goto l_danger4;",
            "r0 = 0;",
            "exit;",
            "l_danger4:",
            "r1 = 0;",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: fp_spill_loses_precision_kills_liveness
extern "C" fn fp_spill_loses_precision_kills_liveness() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "if r0 != 0 goto l_pathB5;",
            "r1 = 0;",
            "*(u64 *)(r10 - 8) = r1;",
            "goto l_merge5;",
            "l_pathB5:",
            "r1 = 42;",
            "*(u64 *)(r10 - 8) = r1;",
            "l_merge5:",
            "r6 = r10;",
            "r6 += -64;",
            "*(u64 *)(r10 - 160) = r6;",
            "r6 = *(u64 *)(r10 - 160);",
            "r7 = 0;",
            "*(u64 *)(r6 + 0) = r7;",
            "r2 = *(u64 *)(r10 - 8);",
            "if r2 == 42 goto l_danger5;",
            "r0 = *(u64 *)(r10 - 56);",
            "exit;",
            "l_danger5:",
            "r1 = 0;",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: conditional_stx_in_subprog
extern "C" fn conditional_stx_in_subprog() {
    unsafe {
        core::arch::asm!(
            "r1 = 42;",
            "*(u64 *)(r10 - 8) = r1;",
            "r1 = r10;",
            "r1 += -8;",
            "call {cond_writer};",
            "r0 = *(u64 *)(r10 - 8);",
            "exit;",
            cond_writer = sym cond_writer,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: cond_writer
extern "C" fn cond_writer() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "call 7;",
            "if r0 == 0 goto 1f;",
            "*(u64 *)(r6 + 0) = r0;",
            "1:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: multiple_callsites_different_offsets
extern "C" fn multiple_callsites_different_offsets() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 16) = 0;",
            "*(u64 *)(r10 - 32) = 0;",
            "r1 = r10;",
            "r1 += -16;",
            "call {read_first_param};",
            "r1 = r10;",
            "r1 += -32;",
            "call {read_first_param};",
            "r0 = 0;",
            "exit;",
            read_first_param = sym read_first_param,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: nested_fp_passthrough
extern "C" fn nested_fp_passthrough() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 8) = 0;",
            "*(u64 *)(r10 - 16) = 0;",
            "*(u64 *)(r10 - 24) = 0;",
            "*(u64 *)(r10 - 32) = 0;",
            "r1 = r10;",
            "r1 += -32;",
            "call {outer_forwarder};",
            "r0 = 0;",
            "exit;",
            outer_forwarder = sym outer_forwarder,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: outer_forwarder
extern "C" fn outer_forwarder() {
    unsafe {
        core::arch::asm!(
            "call {inner_reader};",
            "r0 = 0;",
            "exit;",
            inner_reader = sym inner_reader,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: inner_reader
extern "C" fn inner_reader() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u64 *)(r1 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callee_must_write_before_read
extern "C" fn callee_must_write_before_read() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -8;",
            "call {write_then_read};",
            "r0 = 0;",
            "exit;",
            write_then_read = sym write_then_read,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: write_then_read
extern "C" fn write_then_read() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r7 = 99;",
            "*(u64 *)(r6 + 0) = r7;",
            "r0 = *(u64 *)(r6 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: return_site_liveness_bleeding
extern "C" fn return_site_liveness_bleeding() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 8) = 0;",
            "r1 = r10;",
            "r1 += -8;",
            "call {read_first_param};",
            "r0 = *(u64 *)(r10 - 8);",
            "r1 = r10;",
            "r1 += -8;",
            "call {read_first_param};",
            "r0 = 0;",
            "exit;",
            read_first_param = sym read_first_param,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callback_conditional_read_beyond_ctx
extern "C" fn callback_conditional_read_beyond_ctx() {
    unsafe {
        core::arch::asm!(
            "r1 = 42;",
            "*(u64 *)(r10 - 8) = r1;",
            "*(u64 *)(r10 - 16) = r1;",
            "r1 = 2;",
            "r2 = {cb_cond_read} ll;",
            "r3 = r10;",
            "r3 += -8;",
            "r4 = 0;",
            "call 181;",
            "r0 = 0;",
            "exit;",
            cb_cond_read = sym cb_cond_read,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: cb_cond_read
extern "C" fn cb_cond_read() {
    unsafe {
        core::arch::asm!(
            "r6 = r2;",
            "call 7;",
            "if r0 == 0 goto 1f;",
            "r0 = *(u64 *)(r6 - 8);",
            "1:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callback_write_before_read_kills
extern "C" fn callback_write_before_read_kills() {
    unsafe {
        core::arch::asm!(
            "r1 = 42;",
            "*(u64 *)(r10 - 8) = r1;",
            "*(u64 *)(r10 - 16) = r1;",
            "r1 = 2;",
            "r2 = {cb_write_read} ll;",
            "r3 = r10;",
            "r3 += -8;",
            "r4 = 0;",
            "call 181;",
            "r0 = 0;",
            "exit;",
            cb_write_read = sym cb_write_read,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: cb_write_read
extern "C" fn cb_write_read() {
    unsafe {
        core::arch::asm!(
            "r6 = r2;",
            "r7 = 99;",
            "*(u64 *)(r6 - 8) = r7;",
            "r0 = *(u64 *)(r6 - 8);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callback_conditional_write_preserves
extern "C" fn callback_conditional_write_preserves() {
    unsafe {
        core::arch::asm!(
            "r1 = 42;",
            "*(u64 *)(r10 - 8) = r1;",
            "*(u64 *)(r10 - 16) = r1;",
            "r1 = 2;",
            "r2 = {cb_cond_write_read} ll;",
            "r3 = r10;",
            "r3 += -8;",
            "r4 = 0;",
            "call 181;",
            "r0 = 0;",
            "exit;",
            cb_cond_write_read = sym cb_cond_write_read,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: cb_cond_write_read
extern "C" fn cb_cond_write_read() {
    unsafe {
        core::arch::asm!(
            "r6 = r2;",
            "call 7;",
            "if r0 == 0 goto 1f;",
            "*(u64 *)(r6 - 8) = r0;",
            "1:",
            "r0 = *(u64 *)(r6 - 8);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callback_two_calls_different_ctx
extern "C" fn callback_two_calls_different_ctx() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 8) = 0;",
            "*(u64 *)(r10 - 24) = 0;",
            "r1 = 1;",
            "r2 = {cb_read_ctx} ll;",
            "r3 = r10;",
            "r3 += -8;",
            "r4 = 0;",
            "call 181;",
            "r1 = 1;",
            "r2 = {cb_read_ctx} ll;",
            "r3 = r10;",
            "r3 += -24;",
            "r4 = 0;",
            "call 181;",
            "r0 = 0;",
            "exit;",
            cb_read_ctx = sym cb_read_ctx,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: cb_read_ctx
extern "C" fn cb_read_ctx() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u64 *)(r2 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: transitive_parent_stack_read_unsound
extern "C" fn transitive_parent_stack_read_unsound() {
    unsafe {
        core::arch::asm!(
            "r1 = {map} ll;",
            "*(u32 *)(r10 - 32) = 0;",
            "r2 = r10;",
            "r2 += -32;",
            "call 1;",
            "if r0 == 0 goto l_exit6;",
            "r6 = r0;",
            "call 7;",
            "if r0 != 0 goto l_scalar6;",
            "*(u64 *)(r10 - 8) = r6;",
            "goto l_merge6;",
            "l_scalar6:",
            "r1 = 42;",
            "*(u64 *)(r10 - 8) = r1;",
            "l_merge6:",
            "r1 = r10;",
            "r1 += -8;",
            "call {mid_fwd};",
            "r0 = 0;",
            "exit;",
            "l_exit6:",
            "r0 = 0;",
            "exit;",
            map = sym map,
            mid_fwd = sym mid_fwd,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: mid_fwd
extern "C" fn mid_fwd() {
    unsafe {
        core::arch::asm!(
            "call {grandchild_deref};",
            "r0 = 0;",
            "exit;",
            grandchild_deref = sym grandchild_deref,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: grandchild_deref
extern "C" fn grandchild_deref() {
    unsafe {
        core::arch::asm!(
            "goto +0;",
            "goto +0;",
            "r0 = *(u64 *)(r1 + 0);",
            "r0 = *(u64 *)(r0 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: two_fp_clear_stack_threshold
extern "C" fn two_fp_clear_stack_threshold() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -8;",
            "call {mid_two_fp_threshold};",
            "r0 = 0;",
            "exit;",
            mid_two_fp_threshold = sym mid_two_fp_threshold,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: mid_two_fp_threshold
extern "C" fn mid_two_fp_threshold() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r7 = r10;",
            "r7 += -16;",
            "*(u64 *)(r10 - 8) = r7;",
            "*(u64 *)(r10 - 16) = r6;",
            "r1 = r10;",
            "r1 += -8;",
            "r2 = r6;",
            "call {inner_nop_fptest};",
            "r1 = *(u64 *)(r10 - 8);",
            "r0 = *(u64 *)(r1 + 0);",
            "r0 = 0;",
            "exit;",
            inner_nop_fptest = sym inner_nop_fptest,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: inner_nop_fptest
extern "C" fn inner_nop_fptest() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: one_fp_clear_stack_threshold
extern "C" fn one_fp_clear_stack_threshold() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -8;",
            "call {mid_one_fp_threshold};",
            "r0 = 0;",
            "exit;",
            mid_one_fp_threshold = sym mid_one_fp_threshold,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: mid_one_fp_threshold
extern "C" fn mid_one_fp_threshold() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r7 = r10;",
            "r7 += -16;",
            "*(u64 *)(r10 - 8) = r7;",
            "*(u64 *)(r10 - 16) = r6;",
            "r1 = r10;",
            "r1 += -8;",
            "call {inner_nop_fptest};",
            "r1 = *(u64 *)(r10 - 8);",
            "r0 = *(u64 *)(r1 + 0);",
            "r0 = 0;",
            "exit;",
            inner_nop_fptest = sym inner_nop_fptest,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: helper_parent_stack_read_unsound
extern "C" fn helper_parent_stack_read_unsound() {
    unsafe {
        core::arch::asm!(
            "*(u32 *)(r10 - 4) = 0;",
            "call 7;",
            "if r0 != 0 goto l_clobber7;",
            "goto l_merge7;",
            "l_clobber7:",
            "*(u8 *)(r10 - 4) = r0;",
            "l_merge7:",
            "r1 = r10;",
            "r1 += -4;",
            "call {fwd_parent_key_to_helper};",
            "r0 = 0;",
            "exit;",
            fwd_parent_key_to_helper = sym fwd_parent_key_to_helper,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: fwd_parent_key_to_helper
extern "C" fn fwd_parent_key_to_helper() {
    unsafe {
        core::arch::asm!(
            "goto +0;",
            "r2 = r1;",
            "r1 = {array_map_8b} ll;",
            "call 1;",
            "r0 = *(u64 *)(r0 + 0);",
            "r0 = 0;",
            "exit;",
            array_map_8b = sym array_map_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: helper_arg_fallback_keeps_scanning
extern "C" fn helper_arg_fallback_keeps_scanning() {
    unsafe {
        core::arch::asm!(
            "r1 = 42;",
            "*(u64 *)(r10 - 8) = r1;",
            "r1 = r10;",
            "r1 += -8;",
            "call {helper_update_parent_after_local_fallback};",
            "r0 = 0;",
            "exit;",
            helper_update_parent_after_local_fallback = sym helper_update_parent_after_local_fallback,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: helper_update_parent_after_local_fallback
extern "C" fn helper_update_parent_after_local_fallback() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "call 7;",
            "r0 &= 8;",
            "*(u64 *)(r10 - 16) = 0;",
            "*(u64 *)(r10 - 8) = 0;",
            "r2 = r10;",
            "r2 += -16;",
            "r2 += r0;",
            "r1 = {array_map_8b} ll;",
            "r3 = r6;",
            "r4 = 0;",
            "call 2;",
            "r0 = 0;",
            "exit;",
            array_map_8b = sym array_map_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: propagate_callee_ancestor_chain
extern "C" fn propagate_callee_ancestor_chain() {
    unsafe {
        core::arch::asm!(
            "r1 = {map} ll;",
            "*(u32 *)(r10 - 32) = 0;",
            "r2 = r10;",
            "r2 += -32;",
            "call 1;",
            "if r0 == 0 goto l_exit8;",
            "r6 = r0;",
            "call 7;",
            "if r0 != 0 goto l_scalar8;",
            "*(u64 *)(r10 - 8) = r6;",
            "goto l_merge8;",
            "l_scalar8:",
            "r1 = 42;",
            "*(u64 *)(r10 - 8) = r1;",
            "l_merge8:",
            "r1 = 99;",
            "*(u64 *)(r10 - 16) = r1;",
            "r1 = r10;",
            "r1 += -8;",
            "r2 = r10;",
            "r2 += -16;",
            "call {mid_seq_touch};",
            "r0 = 0;",
            "exit;",
            "l_exit8:",
            "r0 = 0;",
            "exit;",
            map = sym map,
            mid_seq_touch = sym mid_seq_touch,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: mid_seq_touch
extern "C" fn mid_seq_touch() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r0 = *(u64 *)(r2 + 0);",
            "call {nop_callee};",
            "r1 = r6;",
            "call {deref_ancestor};",
            "r0 = 0;",
            "exit;",
            nop_callee = sym nop_callee,
            deref_ancestor = sym deref_ancestor,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: nop_callee
extern "C" fn nop_callee() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: deref_ancestor
extern "C" fn deref_ancestor() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u64 *)(r1 + 0);",
            "r0 = *(u64 *)(r0 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: spilled_fp_cross_frame_deref
extern "C" fn spilled_fp_cross_frame_deref() {
    unsafe {
        core::arch::asm!(
            "r1 = {map} ll;",
            "*(u32 *)(r10 - 32) = 0;",
            "r2 = r10;",
            "r2 += -32;",
            "call 1;",
            "if r0 == 0 goto l_exit9;",
            "*(u64 *)(r10 - 24) = r0;",
            "r1 = r10;",
            "r1 += -24;",
            "*(u64 *)(r10 - 8) = r1;",
            "r1 = r10;",
            "r1 += -8;",
            "call {mid_fwd_spilled_ptr};",
            "r0 = 0;",
            "exit;",
            "l_exit9:",
            "r0 = 0;",
            "exit;",
            map = sym map,
            mid_fwd_spilled_ptr = sym mid_fwd_spilled_ptr,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: mid_fwd_spilled_ptr
extern "C" fn mid_fwd_spilled_ptr() {
    unsafe {
        core::arch::asm!(
            "call {load_ptr_deref_grandchild};",
            "r0 = 0;",
            "exit;",
            load_ptr_deref_grandchild = sym load_ptr_deref_grandchild,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: load_ptr_deref_grandchild
extern "C" fn load_ptr_deref_grandchild() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u64 *)(r1 + 0);",
            "r0 = *(u64 *)(r2 + 0);",
            "r0 = *(u64 *)(r0 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: test_merge_nonlocal_live
extern "C" fn test_merge_nonlocal_live() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64 *)(r10 - 8) = r1;",
            "*(u64 *)(r10 - 16) = r1;",
            "r1 = r10;",
            "r1 += -8;",
            "call {merge_wrapper_a};",
            "r1 = r10;",
            "r1 += -16;",
            "call {merge_wrapper_b};",
            "r0 = 0;",
            "exit;",
            merge_wrapper_a = sym merge_wrapper_a,
            merge_wrapper_b = sym merge_wrapper_b,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: merge_wrapper_a
extern "C" fn merge_wrapper_a() {
    unsafe {
        core::arch::asm!(
            "call {merge_shared_mid};",
            "r0 = 0;",
            "exit;",
            merge_shared_mid = sym merge_shared_mid,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: merge_wrapper_b
extern "C" fn merge_wrapper_b() {
    unsafe {
        core::arch::asm!(
            "call {merge_shared_mid};",
            "r0 = 0;",
            "exit;",
            merge_shared_mid = sym merge_shared_mid,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: merge_shared_mid
extern "C" fn merge_shared_mid() {
    unsafe {
        core::arch::asm!(
            "call {merge_leaf_read};",
            "r0 = 0;",
            "exit;",
            merge_leaf_read = sym merge_leaf_read,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: merge_leaf_read
extern "C" fn merge_leaf_read() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u64 *)(r1 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bpf_loop_two_callbacks
extern "C" fn bpf_loop_two_callbacks() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64 *)(r10 - 8) = r1;",
            "*(u64 *)(r10 - 16) = r1;",
            "r1 = r10;",
            "r1 += -8;",
            "call {dyn_wrapper_a};",
            "r1 = r10;",
            "r1 += -16;",
            "call {dyn_wrapper_b};",
            "r0 = 0;",
            "exit;",
            dyn_wrapper_a = sym dyn_wrapper_a,
            dyn_wrapper_b = sym dyn_wrapper_b,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: dyn_wrapper_a
extern "C" fn dyn_wrapper_a() {
    unsafe {
        core::arch::asm!(
            "call {mid_dynamic_cb};",
            "r0 = 0;",
            "exit;",
            mid_dynamic_cb = sym mid_dynamic_cb,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: dyn_wrapper_b
extern "C" fn dyn_wrapper_b() {
    unsafe {
        core::arch::asm!(
            "call {mid_dynamic_cb};",
            "r0 = 0;",
            "exit;",
            mid_dynamic_cb = sym mid_dynamic_cb,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: mid_dynamic_cb
extern "C" fn mid_dynamic_cb() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "call 7;",
            "if r0 == 0 goto 1f;",
            "r2 = {dyn_cb_a} ll;",
            "goto 2f;",
            "1:",
            "r2 = {dyn_cb_b} ll;",
            "2:",
            "r1 = 1;",
            "r3 = r6;",
            "r4 = 0;",
            "call 181;",
            "r0 = 0;",
            "exit;",
            dyn_cb_a = sym dyn_cb_a,
            dyn_cb_b = sym dyn_cb_b,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: dyn_cb_a
extern "C" fn dyn_cb_a() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u64 *)(r2 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: dyn_cb_b
extern "C" fn dyn_cb_b() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u64 *)(r2 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_or_non_stack_write
extern "C" fn stack_or_non_stack_write() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 8) = 0;",
            "r2 = r10;",
            "r2 += -4;",
            "r1 = {map} ll;",
            "call 1;",
            "if r0 != 0 goto 1f;",
            "r0 = r10;",
            "r0 += -8;",
            "1:",
            "*(u64 *)(r0 + 0) = 7;",
            "r0 = *(u64 *)(r10 - 8);",
            "exit;",
            map = sym map,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: shared_instance_must_write_overwrite
extern "C" fn shared_instance_must_write_overwrite() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "*(u64 *)(r10 - 8) = r1;",
            "*(u64 *)(r10 - 16) = r1;",
            "r1 = r10;",
            "r1 += -8;",
            "r2 = r10;",
            "r2 += -16;",
            "call {forwarding_rw};",
            "r1 = r10;",
            "r1 += -16;",
            "r2 = r10;",
            "r2 += -8;",
            "call {forwarding_rw};",
            "r0 = 0;",
            "exit;",
            forwarding_rw = sym forwarding_rw,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: forwarding_rw
extern "C" fn forwarding_rw() {
    unsafe {
        core::arch::asm!(
            "call {write_first_read_second};",
            "exit;",
            write_first_read_second = sym write_first_read_second,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: write_first_read_second
extern "C" fn write_first_read_second() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r1 + 0) = 42;",
            "r0 = *(u64 *)(r2 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: merge_preserves_may_write
extern "C" fn merge_preserves_may_write() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64 *)(r10 - 24) = r1;",
            "r1 = {map} ll;",
            "r2 = r10;",
            "r2 += -24;",
            "call 1;",
            "if r0 == 0 goto 1f;",
            "r1 = r10;",
            "r1 += -16;",
            "r2 = r0;",
            "call {mvs_mid};",
            "r1 = r10;",
            "r1 += -16;",
            "r2 = r10;",
            "r2 += -8;",
            "call {mvs_mid};",
            "1:",
            "r0 = 0;",
            "exit;",
            map = sym map,
            mvs_mid = sym mvs_mid,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: mvs_mid
extern "C" fn mvs_mid() {
    unsafe {
        core::arch::asm!(
            "call {mvs_leaf};",
            "exit;",
            mvs_leaf = sym mvs_leaf,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: mvs_leaf
extern "C" fn mvs_leaf() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r2 + 0) = 42;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stale_must_write_cross_callsite
extern "C" fn stale_must_write_cross_callsite() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 8) = 0;",
            "*(u32 *)(r10 - 16) = 0;",
            "r1 = {map} ll;",
            "r2 = r10;",
            "r2 += -16;",
            "call 1;",
            "if r0 == 0 goto 1f;",
            "r1 = r0;",
            "r2 = r10;",
            "r2 += -8;",
            "call {fwd_to_stale_wr};",
            "r1 = r10;",
            "r1 += -8;",
            "r2 = r1;",
            "call {fwd_to_stale_wr};",
            "1:",
            "r0 = 0;",
            "exit;",
            map = sym map,
            fwd_to_stale_wr = sym fwd_to_stale_wr,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: fwd_to_stale_wr
extern "C" fn fwd_to_stale_wr() {
    unsafe {
        core::arch::asm!(
            "call {stale_wr_leaf};",
            "exit;",
            stale_wr_leaf = sym stale_wr_leaf,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: stale_wr_leaf
extern "C" fn stale_wr_leaf() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r1 + 0) = 42;",
            "r0 = *(u64 *)(r2 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: load_acquire_dont_clear_dst
extern "C" fn load_acquire_dont_clear_dst() {
    unsafe {
        core::arch::asm!(
            "r0 = r10;",
            "r0 += -16;",
            "*(u64 *)(r0 + 0) = r0;",
            ".8byte 1099511627995;",
            "r0 = *(u64 *)(r10 - 16);",
            "*(u64 *)(r0 + 0) = 42;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: atomic_rmw
extern "C" fn atomic_rmw() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64 *)(r10 - 8) = r1;",
            ".8byte 4294449883;",
            ".8byte 8589417179;",
            ".8byte 970662091483;",
            "r0 = 0;",
            ".8byte 1039381568219;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: load_acquire_fills_spilled_ptr
extern "C" fn load_acquire_fills_spilled_ptr() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -8;",
            "*(u64 *)(r10 - 16) = r1;",
            ".8byte 1103805588187;",
            "*(u64 *)(r2 + 0) = 42;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: store_release_spills_ptr
extern "C" fn store_release_spills_ptr() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -8;",
            ".8byte 1172525030107;",
            "r2 = *(u64 *)(r10 - 16);",
            "*(u64 *)(r2 + 0) = 42;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: atomic_rmw_fills_spilled_ptr
extern "C" fn atomic_rmw_fills_spilled_ptr() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -8;",
            "*(u64 *)(r10 - 16) = r1;",
            "r2 = 0;",
            ".8byte 970661571291;",
            "*(u64 *)(r2 + 0) = 42;",
            "*(u64 *)(r10 - 16) = r1;",
            "r3 = 0;",
            ".8byte 8588901083;",
            "*(u64 *)(r3 + 0) = 42;",
            "*(u64 *)(r10 - 16) = r1;",
            "r0 = 0;",
            "r4 = 0;",
            ".8byte 1039381056219;",
            "*(u64 *)(r0 + 0) = 42;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: atomic_rmw_fills_parent_spilled_ptr
extern "C" fn atomic_rmw_fills_parent_spilled_ptr() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -8;",
            "*(u64 *)(r10 - 16) = r1;",
            "r1 = r10;",
            "r1 += -16;",
            "call {atomic_rmw_fills_parent_spilled_ptr_callee};",
            "r0 = 0;",
            "exit;",
            atomic_rmw_fills_parent_spilled_ptr_callee = sym atomic_rmw_fills_parent_spilled_ptr_callee,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: atomic_rmw_fills_parent_spilled_ptr_callee
extern "C" fn atomic_rmw_fills_parent_spilled_ptr_callee() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            ".8byte 966367650267;",
            "*(u64 *)(r2 + 0) = 42;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: imprecise_fill_loses_cross_frame
extern "C" fn imprecise_fill_loses_cross_frame() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 8) = 0;",
            "r1 = r10;",
            "r1 += -8;",
            "call {imprecise_fill_cross_frame};",
            "exit;",
            imprecise_fill_cross_frame = sym imprecise_fill_cross_frame,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: imprecise_fill_cross_frame
extern "C" fn imprecise_fill_cross_frame() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 8) = r1;",
            "r1 = r10;",
            "r2 = -8;",
            "r1 += r2;",
            "r1 = *(u64 *)(r1 + 0);",
            "r0 = *(u64 *)(r1 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: spill_join_with_multi_off
extern "C" fn spill_join_with_multi_off() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 24) = 0;",
            "*(u64 *)(r10 - 32) = 0;",
            "r1 = r10;",
            "r1 += -24;",
            "*(u64 *)(r10 - 8) = r1;",
            "r1 = r10;",
            "r1 += -32;",
            "*(u64 *)(r10 - 16) = r1;",
            "call 7;",
            "if r0 == 0 goto 1f;",
            "r1 = r10;",
            "r1 += -8;",
            "goto 2f;",
            "1:",
            "r1 = r10;",
            "r1 += -16;",
            "2:",
            "r2 = r10;",
            "r2 += -24;",
            "*(u64 *)(r1 + 0) = r2;",
            "r0 = *(u64 *)(r10 - 8);",
            "r0 = *(u64 *)(r0 + 0);",
            "r0 = *(u64 *)(r10 - 16);",
            "r0 = *(u64 *)(r0 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: spill_join_with_imprecise_off
extern "C" fn spill_join_with_imprecise_off() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 24) = 0;",
            "*(u64 *)(r10 - 32) = 0;",
            "r1 = r10;",
            "r1 += -24;",
            "*(u64 *)(r10 - 8) = r1;",
            "r1 = r10;",
            "r1 += -32;",
            "*(u64 *)(r10 - 16) = r1;",
            "r1 = r10;",
            "r2 = -8;",
            "r1 += r2;",
            "r3 = r10;",
            "r3 += -24;",
            "*(u64 *)(r1 + 0) = r3;",
            "r0 = *(u64 *)(r10 - 16);",
            "r0 = *(u64 *)(r0 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: st_imm_join_with_multi_off
extern "C" fn st_imm_join_with_multi_off() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 24) = 0;",
            "*(u64 *)(r10 - 32) = 0;",
            "r1 = r10;",
            "r1 += -24;",
            "*(u64 *)(r10 - 8) = r1;",
            "r1 = r10;",
            "r1 += -32;",
            "*(u64 *)(r10 - 16) = r1;",
            "call 7;",
            "if r0 == 0 goto 1f;",
            "r1 = r10;",
            "r1 += -8;",
            "goto 2f;",
            "1:",
            "r1 = r10;",
            "r1 += -16;",
            "2:",
            "*(u64 *)(r1 + 0) = 0;",
            "r0 = *(u64 *)(r10 - 16);",
            "r0 = *(u64 *)(r0 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: st_imm_join_with_single_off
extern "C" fn st_imm_join_with_single_off() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -16;",
            "*(u64 *)(r10 - 8) = r2;",
            "r1 = r10;",
            "r1 += -8;",
            "*(u64 *)(r1 + 0) = 0;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: st_imm_join_with_imprecise_off
extern "C" fn st_imm_join_with_imprecise_off() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 24) = 0;",
            "*(u64 *)(r10 - 32) = 0;",
            "r1 = r10;",
            "r1 += -24;",
            "*(u64 *)(r10 - 8) = r1;",
            "r1 = r10;",
            "r1 += -32;",
            "*(u64 *)(r10 - 16) = r1;",
            "r1 = r10;",
            "r2 = -8;",
            "r1 += r2;",
            "*(u64 *)(r1 + 0) = 0;",
            "r0 = *(u64 *)(r10 - 16);",
            "r0 = *(u64 *)(r0 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: imprecise_dst_spill_join
extern "C" fn imprecise_dst_spill_join() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 24) = 0;",
            "*(u32 *)(r10 - 32) = 0;",
            "r1 = {map} ll;",
            "r2 = r10;",
            "r2 += -32;",
            "call 1;",
            "if r0 == 0 goto 1f;",
            "r1 = r10;",
            "r1 += -24;",
            "r2 = r0;",
            "call {imprecise_dst_spill_join_sub};",
            "1:",
            "r0 = 0;",
            "exit;",
            map = sym map,
            imprecise_dst_spill_join_sub = sym imprecise_dst_spill_join_sub,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: imprecise_dst_spill_join_sub
extern "C" fn imprecise_dst_spill_join_sub() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r8 = r2;",
            "*(u64 *)(r10 - 16) = 0;",
            "r7 = r10;",
            "r7 += -16;",
            "*(u64 *)(r10 - 8) = r7;",
            "call 7;",
            "r1 = r6;",
            "if r0 == 0 goto 1f;",
            "r1 = r10;",
            "r1 += -8;",
            "1:",
            "*(u64 *)(r1 + 0) = r8;",
            "r0 = *(u64 *)(r10 - 8);",
            "*(u64 *)(r0 + 0) = 42;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: narrow_store_defines_nothing
extern "C" fn narrow_store_defines_nothing() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u64 *)(r10 - 8);",
            "*(u8 *)(r10 - 1) = r0;",
            "*(u16 *)(r10 - 4) = r0;",
            "r0 = *(u64 *)(r10 - 8);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: merge_keeps_whole_frame_read
extern "C" fn merge_keeps_whole_frame_read() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64 *)(r10 - 8) = r1;",
            "*(u64 *)(r10 - 16) = r1;",
            "*(u64 *)(r10 - 248) = r1;",
            "call 7;",
            "r0 &= 8;",
            "r1 = r10;",
            "r1 += -16;",
            "r1 += r0;",
            "call {merge_read_all_mid};",
            "r1 = r10;",
            "r1 += -248;",
            "call {merge_read_all_mid};",
            "r0 = 0;",
            "exit;",
            merge_read_all_mid = sym merge_read_all_mid,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: merge_read_all_mid
extern "C" fn merge_read_all_mid() {
    unsafe {
        core::arch::asm!(
            "call {merge_read_all_callee};",
            "exit;",
            merge_read_all_callee = sym merge_read_all_callee,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: merge_read_all_callee
extern "C" fn merge_read_all_callee() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: spill_below_512_stays_precise
extern "C" fn spill_below_512_stays_precise() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64 *)(r10 - 8) = r1;",
            "r1 = r10;",
            "r1 += -8;",
            "*(u64 *)(r10 - 520) = r1;",
            "r1 = *(u64 *)(r10 - 520);",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: helper_output_unknown_size
extern "C" fn helper_output_unknown_size() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 7;",
            "r0 += 1;",
            "r2 = r0;",
            "r1 = r10;",
            "r1 += -8;",
            "r3 = 0;",
            "call 113;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: helper_map_output_known_size
extern "C" fn helper_map_output_known_size() {
    unsafe {
        core::arch::asm!(
            "r1 = {queue_8b} ll;",
            "r2 = r10;",
            "r2 += -16;",
            "call 88;",
            "r0 = 0;",
            "exit;",
            queue_8b = sym queue_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: helper_map_output_merged_sizes
extern "C" fn helper_map_output_merged_sizes() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 16) = 0;",
            "*(u64 *)(r10 - 24) = 0;",
            "call 7;",
            "r1 = {queue_8b} ll;",
            "if r0 == 0 goto 1f;",
            "r1 = {queue_16b} ll;",
            "1:",
            "r2 = r10;",
            "r2 += -24;",
            "call 88;",
            "r0 = 0;",
            "exit;",
            queue_8b = sym queue_8b,
            queue_16b = sym queue_16b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: helper_bloom_peek_input
extern "C" fn helper_bloom_peek_input() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 8) = 0;",
            "r1 = {bloom_8b} ll;",
            "r2 = r10;",
            "r2 += -8;",
            "call 89;",
            "r0 = 0;",
            "exit;",
            bloom_8b = sym bloom_8b,
            options(nostack)
        );
    }
}

include!("hand/verifier_live_stack.rs");

bpf_object!("GPL");
