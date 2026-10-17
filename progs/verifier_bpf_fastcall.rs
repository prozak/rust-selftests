// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]
#![allow(function_casts_as_integer)]

// Translation of tools/testing/selftests/bpf/progs/verifier_bpf_fastcall.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_bpf_fastcall.rs
// (include!d below): kfunc_bpf_rdonly_cast.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_bpf_fastcall` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: simple canary_arm64_riscv64 canary_zero_spills wrong_reg_in_pattern1 wrong_reg_in_pattern2 wrong_reg_in_pattern3 wrong_base_in_pattern wrong_insn_in_pattern wrong_off_in_pattern1 wrong_off_in_pattern2 wrong_size_in_pattern partial_pattern min_stack_offset bad_fixed_read bad_fixed_write bad_varying_read bad_varying_write bad_write_in_subprog bad_write_in_subprog_aux bad_helper_write helper_uninit_stack helper_uninit_stack_callee helper_uninit_stack_caller helper_reads_fastcall_spill read_caller_stack_callee callee_reads_fastcall_spill helper_zero_size_buffer invalidate_one_subprog invalidate_one_subprog_aux subprogs_use_independent_offsets subprogs_use_independent_offsets_aux helper_call_does_not_prevent_bpf_fastcall jump_to_first_spill jump_to_call jump_to_fill unconditional_jump_to_fill may_goto_interaction_x86_64 may_goto_interaction dummy_loop_callback bpf_loop_interaction1 bpf_loop_interaction2 cumulative_stack_depth cumulative_stack_depth_subprog kfunc_bpf_cast_to_kern_ctx kfunc_bpf_rdonly_cast kfunc_root

// (from the hand file)
// BTF_TYPE_ID: bpf_attr_type_id union bpf_attr

use bpf_rs_core::{bpf_map, bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    simple:
        __arch_x86_64,
        __log_level("4"),
        __msg("subprog 0 (simple) main insns_self {{[0-9]+}} insns_total {{[0-9]+}} stack 8"),
        __xlated("4: r5 = 5"),
        __xlated("5: r0 = "),
        __xlated("6: r0 = &(void __percpu *)(r0)"),
        __xlated("7: r0 = *(u32 *)(r0 +0)"),
        __xlated("8: exit"),
        __success;
    canary_arm64_riscv64:
        __arch_arm64,
        __arch_riscv64,
        __xlated("0: r1 = 1"),
        __xlated("1: call bpf_get_smp_processor_id"),
        __xlated("2: exit"),
        __success;
    canary_zero_spills:
        __arch_x86_64,
        __xlated("1: r0 = &(void __percpu *)(r0)"),
        __xlated("..."),
        __xlated("3: exit"),
        __success;
    wrong_reg_in_pattern1:
        __arch_x86_64,
        __log_level("4"),
        __msg("subprog 0 (wrong_reg_in_pattern1) main {{.*}} stack 16"),
        __xlated("1: *(u64 *)(r10 -16) = r1"),
        __xlated("..."),
        __xlated("3: r0 = &(void __percpu *)(r0)"),
        __xlated("..."),
        __xlated("5: r2 = *(u64 *)(r10 -16)"),
        __success;
    wrong_reg_in_pattern2:
        __arch_x86_64,
        __xlated("1: *(u64 *)(r10 -16) = r6"),
        __xlated("..."),
        __xlated("3: r0 = &(void __percpu *)(r0)"),
        __xlated("..."),
        __xlated("5: r6 = *(u64 *)(r10 -16)"),
        __success;
    wrong_reg_in_pattern3:
        __arch_x86_64,
        __xlated("1: *(u64 *)(r10 -16) = r0"),
        __xlated("..."),
        __xlated("3: r0 = &(void __percpu *)(r0)"),
        __xlated("..."),
        __xlated("5: r0 = *(u64 *)(r10 -16)"),
        __success;
    wrong_base_in_pattern:
        __arch_x86_64,
        __xlated("2: *(u64 *)(r2 -16) = r1"),
        __xlated("..."),
        __xlated("4: r0 = &(void __percpu *)(r0)"),
        __xlated("..."),
        __xlated("6: r1 = *(u64 *)(r10 -16)"),
        __success;
    wrong_insn_in_pattern:
        __arch_x86_64,
        __xlated("1: *(u64 *)(r10 -16) = r1"),
        __xlated("..."),
        __xlated("3: r0 = &(void __percpu *)(r0)"),
        __xlated("..."),
        __xlated("5: r2 = 1"),
        __success;
    wrong_off_in_pattern1:
        __arch_x86_64,
        __xlated("2: *(u64 *)(r10 -16) = r1"),
        __xlated("..."),
        __xlated("4: r0 = &(void __percpu *)(r0)"),
        __xlated("..."),
        __xlated("6: r1 = *(u64 *)(r10 -8)"),
        __success;
    wrong_off_in_pattern2:
        __arch_x86_64,
        __xlated("1: *(u32 *)(r10 -4) = r1"),
        __xlated("..."),
        __xlated("3: r0 = &(void __percpu *)(r0)"),
        __xlated("..."),
        __xlated("5: r1 = *(u32 *)(r10 -4)"),
        __success;
    wrong_size_in_pattern:
        __arch_x86_64,
        __xlated("1: *(u32 *)(r10 -16) = r1"),
        __xlated("..."),
        __xlated("3: r0 = &(void __percpu *)(r0)"),
        __xlated("..."),
        __xlated("5: r1 = *(u32 *)(r10 -16)"),
        __success;
    partial_pattern:
        __arch_x86_64,
        __xlated("2: *(u32 *)(r10 -8) = r1"),
        __xlated("..."),
        __xlated("4: r0 = &(void __percpu *)(r0)"),
        __xlated("..."),
        __xlated("6: r1 = *(u32 *)(r10 -8)"),
        __success;
    min_stack_offset:
        __arch_x86_64,
        __xlated("0: r1 = 1"),
        __xlated("1: r2 = 2"),
        __xlated("2: *(u64 *)(r10 -8) = r1"),
        __xlated("3: *(u64 *)(r10 -16) = r2"),
        __xlated("..."),
        __xlated("5: r0 = &(void __percpu *)(r0)"),
        __xlated("..."),
        __xlated("7: r2 = *(u64 *)(r10 -16)"),
        __xlated("8: r1 = *(u64 *)(r10 -8)"),
        __xlated("..."),
        __xlated("10: r0 = &(void __percpu *)(r0)"),
        __xlated("..."),
        __xlated("12: exit"),
        __success;
    bad_fixed_read:
        __arch_x86_64,
        __xlated("1: *(u64 *)(r10 -8) = r1"),
        __xlated("..."),
        __xlated("3: r0 = &(void __percpu *)(r0)"),
        __xlated("..."),
        __xlated("5: r1 = *(u64 *)(r10 -8)"),
        __success;
    bad_fixed_write:
        __arch_x86_64,
        __xlated("1: *(u64 *)(r10 -8) = r1"),
        __xlated("..."),
        __xlated("3: r0 = &(void __percpu *)(r0)"),
        __xlated("..."),
        __xlated("5: r1 = *(u64 *)(r10 -8)"),
        __success;
    bad_varying_read:
        __arch_x86_64,
        __xlated("6: *(u64 *)(r10 -16) = r1"),
        __xlated("..."),
        __xlated("8: r0 = &(void __percpu *)(r0)"),
        __xlated("..."),
        __xlated("10: r1 = *(u64 *)(r10 -16)"),
        __success;
    bad_varying_write:
        __arch_x86_64,
        __xlated("6: *(u64 *)(r10 -16) = r1"),
        __xlated("..."),
        __xlated("8: r0 = &(void __percpu *)(r0)"),
        __xlated("..."),
        __xlated("10: r1 = *(u64 *)(r10 -16)"),
        __success;
    bad_write_in_subprog:
        __arch_x86_64,
        __xlated("1: *(u64 *)(r10 -8) = r1"),
        __xlated("..."),
        __xlated("3: r0 = &(void __percpu *)(r0)"),
        __xlated("..."),
        __xlated("5: r1 = *(u64 *)(r10 -8)"),
        __success;
    bad_helper_write:
        __arch_x86_64,
        __xlated("1: *(u64 *)(r10 -8) = r1"),
        __xlated("..."),
        __xlated("3: r0 = &(void __percpu *)(r0)"),
        __xlated("..."),
        __xlated("5: r1 = *(u64 *)(r10 -8)"),
        __success;
    helper_uninit_stack:
        __log_level("4"),
        __msg_unpriv("subprog 0 (helper_uninit_stack) main {{.*}} stack 64"),
        __xlated_unpriv("*(u64 *)(r10 -8) = r1"),
        __xlated_unpriv("..."),
        __xlated_unpriv("r1 = *(u64 *)(r10 -8)"),
        __caps_unpriv("39 | 12"),
        __success_unpriv;
    helper_uninit_stack_caller:
        __log_level("4"),
        __msg_unpriv("subprog 0 (helper_uninit_stack_caller) main {{.*}} stack 64"),
        __xlated_unpriv("*(u64 *)(r10 -8) = r1"),
        __xlated_unpriv("..."),
        __xlated_unpriv("r1 = *(u64 *)(r10 -8)"),
        __caps_unpriv("39 | 12"),
        __success_unpriv;
    helper_reads_fastcall_spill:
        __log_level("4"),
        __msg("subprog 0 (helper_reads_fastcall_spill) main {{.*}} stack 8"),
        __xlated("*(u64 *)(r10 -8) = r1"),
        __xlated("..."),
        __xlated("r1 = *(u64 *)(r10 -8)"),
        __success;
    callee_reads_fastcall_spill:
        __log_level("4"),
        __msg("subprog 0 (callee_reads_fastcall_spill) main {{.*}} stack 8"),
        __xlated("*(u64 *)(r10 -8) = r1"),
        __xlated("..."),
        __xlated("r1 = *(u64 *)(r10 -8)"),
        __success;
    helper_zero_size_buffer:
        __arch_x86_64,
        __log_level("4"),
        __msg("subprog 0 (helper_zero_size_buffer) main {{.*}} stack 0"),
        __xlated("0: r1 = 1"),
        __xlated("1: r0 ="),
        __success;
    invalidate_one_subprog:
        __arch_x86_64,
        __xlated("1: *(u64 *)(r10 -8) = r1"),
        __xlated("..."),
        __xlated("3: r0 = &(void __percpu *)(r0)"),
        __xlated("..."),
        __xlated("5: r1 = *(u64 *)(r10 -8)"),
        __xlated("..."),
        __xlated("9: call pc+1"),
        __xlated("..."),
        __xlated("10: exit"),
        __xlated("11: r1 = 1"),
        __xlated("..."),
        __xlated("13: r0 = &(void __percpu *)(r0)"),
        __xlated("..."),
        __xlated("15: exit"),
        __success;
    subprogs_use_independent_offsets:
        __arch_x86_64,
        __xlated("0: r1 = 1"),
        __xlated("..."),
        __xlated("2: r0 = &(void __percpu *)(r0)"),
        __xlated("..."),
        __xlated("4: call pc+1"),
        __xlated("5: exit"),
        __xlated("6: r1 = 1"),
        __xlated("..."),
        __xlated("8: r0 = &(void __percpu *)(r0)"),
        __xlated("..."),
        __xlated("10: *(u64 *)(r10 -16) = r1"),
        __xlated("11: exit"),
        __success;
    helper_call_does_not_prevent_bpf_fastcall:
        __arch_x86_64,
        __log_level("4"),
        __msg("subprog 0 (helper_call_does_not_prevent_bpf_fastcall) main {{.*}} stack 8"),
        __xlated("2: r0 = &(void __percpu *)(r0)"),
        __success;
    jump_to_first_spill:
        __arch_x86_64,
        __log_level("4"),
        __msg("subprog 0 (jump_to_first_spill) main {{.*}} stack 0"),
        __xlated("2: if r0 == 0x2a goto pc+0"),
        __xlated("3: r0 = "),
        __xlated("4: r0 = &(void __percpu *)(r0)"),
        __success;
    jump_to_call:
        __arch_x86_64,
        __log_level("4"),
        __msg("subprog 0 (jump_to_call) main {{.*}} stack 8"),
        __xlated("2: if r0 == 0x2a goto pc+1"),
        __xlated("3: *(u64 *)(r10 -8) = r1"),
        __xlated("..."),
        __xlated("7: r1 = *(u64 *)(r10 -8)"),
        __success;
    jump_to_fill:
        __arch_x86_64,
        __log_level("4"),
        __msg("subprog 0 (jump_to_fill) main {{.*}} stack 8"),
        __xlated("2: if r0 == 0x2a goto pc+4"),
        __xlated("3: *(u64 *)(r10 -8) = r1"),
        __xlated("..."),
        __xlated("7: r1 = *(u64 *)(r10 -8)"),
        __success;
    unconditional_jump_to_fill:
        __arch_x86_64,
        __log_level("4"),
        __msg("subprog 0 (unconditional_jump_to_fill) main {{.*}} stack 8"),
        __xlated("3: *(u64 *)(r10 -8) = r1"),
        __xlated("..."),
        __xlated("7: r1 = *(u64 *)(r10 -8)"),
        __xlated("8: exit"),
        __xlated("9: goto pc-3"),
        __success;
    may_goto_interaction_x86_64:
        __arch_x86_64,
        __log_level("4"),
        __msg("subprog 0 (may_goto_interaction_x86_64) main {{.*}} stack 24"),
        __xlated("0: *(u64 *)(r10 -24) ="),
        __xlated("1: *(u64 *)(r10 -16) ="),
        __xlated("2: r1 = 1"),
        __xlated("..."),
        __xlated("4: r0 = &(void __percpu *)(r0)"),
        __xlated("..."),
        __xlated("6: r12 = *(u64 *)(r10 -24)"),
        __xlated("7: if r12 == 0x0 goto pc+6"),
        __xlated("8: r12 -= 1"),
        __xlated("9: if r12 != 0x0 goto pc+2"),
        __xlated("10: r12 = -24"),
        __xlated("11: call unknown"),
        __xlated("12: *(u64 *)(r10 -24) = r12"),
        __xlated("13: *(u64 *)(r10 -8) = r1"),
        __xlated("14: exit"),
        __success;
    may_goto_interaction:
        __arch_arm64,
        __arch_riscv64,
        __arch_loongarch,
        __log_level("4"),
        __msg("subprog 0 (may_goto_interaction) main {{.*}} stack 24"),
        __xlated("0: *(u64 *)(r10 -24) ="),
        __xlated("1: *(u64 *)(r10 -16) ="),
        __xlated("2: r1 = 1"),
        __xlated("3: call bpf_get_smp_processor_id"),
        __xlated("4: r12 = *(u64 *)(r10 -24)"),
        __xlated("5: if r12 == 0x0 goto pc+6"),
        __xlated("6: r12 -= 1"),
        __xlated("7: if r12 != 0x0 goto pc+2"),
        __xlated("8: r12 = -24"),
        __xlated("9: call unknown"),
        __xlated("10: *(u64 *)(r10 -24) = r12"),
        __xlated("11: *(u64 *)(r10 -8) = r1"),
        __xlated("12: exit"),
        __success;
    bpf_loop_interaction1:
        __arch_x86_64,
        __log_level("4"),
        __msg("subprog 0 (bpf_loop_interaction1) main {{.*}} stack 32"),
        __msg("subprog 1 (dummy_loop_callback) static {{.*}} stack 0"),
        __xlated("2: r1 = 1"),
        __xlated("3: r0 ="),
        __xlated("4: r0 = &(void __percpu *)(r0)"),
        __xlated("5: r0 = *(u32 *)(r0 +0)"),
        __xlated("6: r2 ="),
        __xlated("7: r3 = 0"),
        __xlated("8: r4 = 0"),
        __xlated("..."),
        __xlated("12: *(u64 *)(r10 -32) = r6"),
        __xlated("13: *(u64 *)(r10 -24) = r7"),
        __xlated("14: *(u64 *)(r10 -16) = r8"),
        __xlated("..."),
        __xlated("21: call pc+8"),
        __xlated("..."),
        __xlated("28: r0 = 0"),
        __xlated("29: exit"),
        __xlated("30: r0 = 0"),
        __xlated("31: exit"),
        __success;
    bpf_loop_interaction2:
        __arch_x86_64,
        __log_level("4"),
        __msg("subprog 0 (bpf_loop_interaction2) main {{.*}} stack 40"),
        __msg("subprog 1 (dummy_loop_callback) static {{.*}} stack 0"),
        __xlated("2: r1 = 42"),
        __xlated("3: r0 ="),
        __xlated("4: r0 = &(void __percpu *)(r0)"),
        __xlated("5: r0 = *(u32 *)(r0 +0)"),
        __xlated("6: *(u64 *)(r10 -16) = r1"),
        __xlated("7: call"),
        __xlated("8: r1 = *(u64 *)(r10 -16)"),
        __xlated("..."),
        __xlated("15: *(u64 *)(r10 -40) = r6"),
        __xlated("16: *(u64 *)(r10 -32) = r7"),
        __xlated("17: *(u64 *)(r10 -24) = r8"),
        __success;
    cumulative_stack_depth:
        __arch_x86_64,
        __log_level("4"),
        __msg("stack depth max 512"),
        __msg("subprog 0 (cumulative_stack_depth) main {{.*}} stack 512"),
        __msg("subprog 1 (cumulative_stack_depth_subprog) static {{.*}} stack 0"),
        __xlated("r0 = &(void __percpu *)(r0)"),
        __success;
    kfunc_bpf_cast_to_kern_ctx:
        __xlated("0: r2 = 1"),
        __xlated("1: r0 = r1"),
        __xlated("2: r0 = r2"),
        __xlated("3: exit"),
        __success;
    kfunc_bpf_rdonly_cast:
        __xlated("3: r3 = 1"),
        __xlated("4: r0 = r1"),
        __xlated("5: r0 = r3");
}

bpf_map! {
    fastcall_map {
        r#type: *const [i32; 2],
        max_entries: *const [i32; 1],
        key: *const u32,
        value: *const u64,
    }
}

extern "C" {
    fn bpf_cast_to_kern_ctx(a0: *mut c_void) -> *mut c_void;
    fn bpf_rdonly_cast(a0: *mut c_void, a1: u32) -> *mut c_void;
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: simple
extern "C" fn simple() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "r2 = 2;",
            "r3 = 3;",
            "r4 = 4;",
            "r5 = 5;",
            "*(u64 *)(r10 - 16) = r1;",
            "*(u64 *)(r10 - 24) = r2;",
            "*(u64 *)(r10 - 32) = r3;",
            "*(u64 *)(r10 - 40) = r4;",
            "*(u64 *)(r10 - 48) = r5;",
            "call 8;",
            "r5 = *(u64 *)(r10 - 48);",
            "r4 = *(u64 *)(r10 - 40);",
            "r3 = *(u64 *)(r10 - 32);",
            "r2 = *(u64 *)(r10 - 24);",
            "r1 = *(u64 *)(r10 - 16);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: canary_arm64_riscv64
extern "C" fn canary_arm64_riscv64() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "*(u64 *)(r10 - 16) = r1;",
            "call 8;",
            "r1 = *(u64 *)(r10 - 16);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: canary_zero_spills
extern "C" fn canary_zero_spills() {
    unsafe {
        core::arch::asm!(
            "call 8;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: wrong_reg_in_pattern1
extern "C" fn wrong_reg_in_pattern1() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "*(u64 *)(r10 - 16) = r1;",
            "call 8;",
            "r2 = *(u64 *)(r10 - 16);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: wrong_reg_in_pattern2
extern "C" fn wrong_reg_in_pattern2() {
    unsafe {
        core::arch::asm!(
            "r6 = 1;",
            "*(u64 *)(r10 - 16) = r6;",
            "call 8;",
            "r6 = *(u64 *)(r10 - 16);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: wrong_reg_in_pattern3
extern "C" fn wrong_reg_in_pattern3() {
    unsafe {
        core::arch::asm!(
            "r0 = 1;",
            "*(u64 *)(r10 - 16) = r0;",
            "call 8;",
            "r0 = *(u64 *)(r10 - 16);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: wrong_base_in_pattern
extern "C" fn wrong_base_in_pattern() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "r2 = r10;",
            "*(u64 *)(r2 - 16) = r1;",
            "call 8;",
            "r1 = *(u64 *)(r10 - 16);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: wrong_insn_in_pattern
extern "C" fn wrong_insn_in_pattern() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "*(u64 *)(r10 - 16) = r1;",
            "call 8;",
            "r2 = 1;",
            "r1 = *(u64 *)(r10 - 16);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: wrong_off_in_pattern1
extern "C" fn wrong_off_in_pattern1() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "*(u64 *)(r10 - 8) = r1;",
            "*(u64 *)(r10 - 16) = r1;",
            "call 8;",
            "r1 = *(u64 *)(r10 - 8);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: wrong_off_in_pattern2
extern "C" fn wrong_off_in_pattern2() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "*(u32 *)(r10 - 4) = r1;",
            "call 8;",
            "r1 = *(u32 *)(r10 - 4);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: wrong_size_in_pattern
extern "C" fn wrong_size_in_pattern() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "*(u32 *)(r10 - 16) = r1;",
            "call 8;",
            "r1 = *(u32 *)(r10 - 16);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: partial_pattern
extern "C" fn partial_pattern() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "r2 = 2;",
            "*(u32 *)(r10 - 8) = r1;",
            "*(u64 *)(r10 - 16) = r2;",
            "call 8;",
            "r2 = *(u64 *)(r10 - 16);",
            "r1 = *(u32 *)(r10 - 8);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: min_stack_offset
extern "C" fn min_stack_offset() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "r2 = 2;",
            "*(u64 *)(r10 - 8) = r1;",
            "*(u64 *)(r10 - 16) = r2;",
            "call 8;",
            "r2 = *(u64 *)(r10 - 16);",
            "r1 = *(u64 *)(r10 - 8);",
            "*(u64 *)(r10 - 24) = r1;",
            "*(u64 *)(r10 - 32) = r2;",
            "call 8;",
            "r2 = *(u64 *)(r10 - 32);",
            "r1 = *(u64 *)(r10 - 24);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bad_fixed_read
extern "C" fn bad_fixed_read() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "*(u64 *)(r10 - 8) = r1;",
            "call 8;",
            "r1 = *(u64 *)(r10 - 8);",
            "r1 = r10;",
            "r1 += -8;",
            "r1 = *(u64 *)(r1 - 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bad_fixed_write
extern "C" fn bad_fixed_write() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "*(u64 *)(r10 - 8) = r1;",
            "call 8;",
            "r1 = *(u64 *)(r10 - 8);",
            "r1 = r10;",
            "r1 += -8;",
            "*(u64 *)(r1 - 0) = r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bad_varying_read
extern "C" fn bad_varying_read() {
    unsafe {
        core::arch::asm!(
            "r6 = *(u64 *)(r1 + 0);",
            "r6 &= 0x7;",
            "r6 += 0x2;",
            "r7 = 0;",
            "r7 -= r6;",
            "r1 = 1;",
            "*(u64 *)(r10 - 16) = r1;",
            "call 8;",
            "r1 = *(u64 *)(r10 - 16);",
            "r1 = r10;",
            "r1 += r7;",
            "r1 = *(u8 *)(r1 - 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bad_varying_write
extern "C" fn bad_varying_write() {
    unsafe {
        core::arch::asm!(
            "r6 = *(u64 *)(r1 + 0);",
            "r6 &= 0x7;",
            "r6 += 0x2;",
            "r7 = 0;",
            "r7 -= r6;",
            "r1 = 1;",
            "*(u64 *)(r10 - 16) = r1;",
            "call 8;",
            "r1 = *(u64 *)(r10 - 16);",
            "r1 = r10;",
            "r1 += r7;",
            "*(u8 *)(r1 - 0) = r7;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bad_write_in_subprog
extern "C" fn bad_write_in_subprog() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "*(u64 *)(r10 - 8) = r1;",
            "call 8;",
            "r1 = *(u64 *)(r10 - 8);",
            "r1 = r10;",
            "r1 += -8;",
            "call {bad_write_in_subprog_aux};",
            "exit;",
            bad_write_in_subprog_aux = sym bad_write_in_subprog_aux,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: bad_write_in_subprog_aux
extern "C" fn bad_write_in_subprog_aux() {
    unsafe {
        core::arch::asm!(
            "r0 = 1;",
            "*(u64 *)(r1 - 0) = r0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bad_helper_write
extern "C" fn bad_helper_write() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "*(u64 *)(r10 - 8) = r1;",
            "call 8;",
            "r1 = *(u64 *)(r10 - 8);",
            "r1 = r10;",
            "r1 += -8;",
            "r2 = 1;",
            "r3 = 42;",
            "call 113;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: helper_uninit_stack
extern "C" fn helper_uninit_stack() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 8) = r1;",
            "call 8;",
            "r1 = *(u64 *)(r10 - 8);",
            "r2 = 0;",
            "r3 = r10;",
            "r3 += -64;",
            "r4 = 8;",
            "call 26;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: helper_uninit_stack_callee
extern "C" fn helper_uninit_stack_callee() {
    unsafe {
        core::arch::asm!(
            "r3 = r2;",
            "r2 = 0;",
            "r4 = 8;",
            "call 26;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: helper_uninit_stack_caller
extern "C" fn helper_uninit_stack_caller() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 8) = r1;",
            "call 8;",
            "r1 = *(u64 *)(r10 - 8);",
            "r2 = r10;",
            "r2 += -64;",
            "call {helper_uninit_stack_callee};",
            "r0 = 0;",
            "exit;",
            helper_uninit_stack_callee = sym helper_uninit_stack_callee,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: helper_reads_fastcall_spill
extern "C" fn helper_reads_fastcall_spill() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64 *)(r10 - 8) = r1;",
            "call 8;",
            "r1 = *(u64 *)(r10 - 8);",
            "r1 = {fastcall_map} ll;",
            "r2 = r10;",
            "r2 += -8;",
            "call 1;",
            "r0 = 0;",
            "exit;",
            fastcall_map = sym fastcall_map,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: read_caller_stack_callee
extern "C" fn read_caller_stack_callee() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callee_reads_fastcall_spill
extern "C" fn callee_reads_fastcall_spill() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "*(u64 *)(r10 - 8) = r1;",
            "call 8;",
            "r1 = *(u64 *)(r10 - 8);",
            "r1 = r10;",
            "r1 += -8;",
            "call {read_caller_stack_callee};",
            "r0 = 0;",
            "exit;",
            read_caller_stack_callee = sym read_caller_stack_callee,
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: helper_zero_size_buffer
extern "C" fn helper_zero_size_buffer() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "*(u64 *)(r10 - 8) = r1;",
            "call 8;",
            "r1 = *(u64 *)(r10 - 8);",
            "r1 = r10;",
            "r1 += -64;",
            "r2 = 0;",
            "r3 = 0;",
            "call 113;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: invalidate_one_subprog
extern "C" fn invalidate_one_subprog() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "*(u64 *)(r10 - 8) = r1;",
            "call 8;",
            "r1 = *(u64 *)(r10 - 8);",
            "r1 = r10;",
            "r1 += -8;",
            "r1 = *(u64 *)(r1 - 0);",
            "call {invalidate_one_subprog_aux};",
            "exit;",
            invalidate_one_subprog_aux = sym invalidate_one_subprog_aux,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: invalidate_one_subprog_aux
extern "C" fn invalidate_one_subprog_aux() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "*(u64 *)(r10 - 8) = r1;",
            "call 8;",
            "r1 = *(u64 *)(r10 - 8);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: subprogs_use_independent_offsets
extern "C" fn subprogs_use_independent_offsets() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "*(u64 *)(r10 - 16) = r1;",
            "call 8;",
            "r1 = *(u64 *)(r10 - 16);",
            "call {subprogs_use_independent_offsets_aux};",
            "exit;",
            subprogs_use_independent_offsets_aux = sym subprogs_use_independent_offsets_aux,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: subprogs_use_independent_offsets_aux
extern "C" fn subprogs_use_independent_offsets_aux() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "*(u64 *)(r10 - 24) = r1;",
            "call 8;",
            "r1 = *(u64 *)(r10 - 24);",
            "*(u64 *)(r10 - 16) = r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: helper_call_does_not_prevent_bpf_fastcall
extern "C" fn helper_call_does_not_prevent_bpf_fastcall() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "*(u64 *)(r10 - 8) = r1;",
            "call 8;",
            "r1 = *(u64 *)(r10 - 8);",
            "*(u64 *)(r10 - 8) = r1;",
            "call 7;",
            "r1 = *(u64 *)(r10 - 8);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jump_to_first_spill
extern "C" fn jump_to_first_spill() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = 1;",
            "if r0 == 42 goto l0_0;",
            "l0_0:",
            "*(u64 *)(r10 - 8) = r1;",
            "call 8;",
            "r1 = *(u64 *)(r10 - 8);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jump_to_call
extern "C" fn jump_to_call() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = 1;",
            "if r0 == 42 goto l0_1;",
            "*(u64 *)(r10 - 8) = r1;",
            "l0_1:",
            "call 8;",
            "r1 = *(u64 *)(r10 - 8);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jump_to_fill
extern "C" fn jump_to_fill() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = 1;",
            "if r0 == 42 goto l0_2;",
            "*(u64 *)(r10 - 8) = r1;",
            "call 8;",
            "l0_2:",
            "r1 = *(u64 *)(r10 - 8);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: unconditional_jump_to_fill
extern "C" fn unconditional_jump_to_fill() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = 1;",
            "if r0 == 42 goto l1_3;",
            "*(u64 *)(r10 - 8) = r1;",
            "call 8;",
            "l0_3:",
            "r1 = *(u64 *)(r10 - 8);",
            "exit;",
            "l1_3:",
            "goto l0_3;",
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: may_goto_interaction_x86_64
extern "C" fn may_goto_interaction_x86_64() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "*(u64 *)(r10 - 16) = r1;",
            "call 8;",
            "r1 = *(u64 *)(r10 - 16);",
            ".8byte 65765;",
            "*(u64 *)(r10 - 8) = r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: may_goto_interaction
extern "C" fn may_goto_interaction() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "*(u64 *)(r10 - 16) = r1;",
            "call 8;",
            "r1 = *(u64 *)(r10 - 16);",
            ".8byte 65765;",
            "*(u64 *)(r10 - 8) = r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: dummy_loop_callback
extern "C" fn dummy_loop_callback() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bpf_loop_interaction1
extern "C" fn bpf_loop_interaction1() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "*(u64 *)(r10 - 16) = r1;",
            "call 8;",
            "r1 = *(u64 *)(r10 - 16);",
            "r2 = {dummy_loop_callback};",
            "r3 = 0;",
            "r4 = 0;",
            "call 181;",
            "r0 = 0;",
            "exit;",
            dummy_loop_callback = in(reg) dummy_loop_callback as usize,
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

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bpf_loop_interaction2
extern "C" fn bpf_loop_interaction2() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r1 = 42;",
            "*(u64 *)(r10 - 16) = r1;",
            "call 8;",
            "r1 = *(u64 *)(r10 - 16);",
            "*(u64 *)(r10 - 16) = r1;",
            "call 7;",
            "r1 = *(u64 *)(r10 - 16);",
            "r2 = {dummy_loop_callback};",
            "r3 = 0;",
            "r4 = 0;",
            "call 181;",
            "r0 = 0;",
            "exit;",
            dummy_loop_callback = in(reg) dummy_loop_callback as usize,
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

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: cumulative_stack_depth
extern "C" fn cumulative_stack_depth() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r1 = 42;",
            "*(u64 *)(r10 - 512) = r1;",
            "call {cumulative_stack_depth_subprog};",
            "exit;",
            cumulative_stack_depth_subprog = sym cumulative_stack_depth_subprog,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: cumulative_stack_depth_subprog
extern "C" fn cumulative_stack_depth_subprog() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 8) = r1;",
            "call 8;",
            "r1 = *(u64 *)(r10 - 8);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/getsockname_unix"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: kfunc_bpf_cast_to_kern_ctx
extern "C" fn kfunc_bpf_cast_to_kern_ctx() {
    unsafe {
        core::arch::asm!(
            "r2 = 1;",
            "*(u64 *)(r10 - 32) = r2;",
            "call {bpf_cast_to_kern_ctx};",
            "r2 = *(u64 *)(r10 - 32);",
            "r0 = r2;",
            "exit;",
            bpf_cast_to_kern_ctx = sym bpf_cast_to_kern_ctx,
            options(nostack)
        );
    }
}

// kfunc_root: the C's reference to each kfunc the asm calls, for its
// BTF prototype (llc emits one only for a real call or address load).
#[no_mangle]
#[inline(never)]
extern "C" fn kfunc_root() {
    unsafe {
        bpf_cast_to_kern_ctx(core::ptr::null_mut());
        bpf_rdonly_cast(core::ptr::null_mut(), 0);
    }
}

include!("hand/verifier_bpf_fastcall.rs");

bpf_object!("GPL");
