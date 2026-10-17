// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_gotox.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_gotox.rs
// (include!d below): terminal_gotox_subprog2, test_subprog.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_gotox` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: jump_table_ok jump_table_reserved_field_src_reg jump_table_reserved_field_non_zero_off jump_table_reserved_field_non_zero_imm jump_table_terminal_gotox terminal_gotox_subprog1 terminal_gotox_subprog2 jump_table_terminal_gotox_subprog jump_table_no_jump_table jump_table_incorrect_dst_reg_type jump_table_invalid_read_size_u32 jump_table_invalid_read_size_u16 jump_table_invalid_read_size_u8 jump_table_misaligned_access jump_table_invalid_mem_acceess_pos jump_table_invalid_mem_acceess_neg jump_table_add_sub_ok jump_table_no_writes jump_table_use_reg_r0 jump_table_use_reg_r1 jump_table_use_reg_r2 jump_table_use_reg_r3 jump_table_use_reg_r4 jump_table_use_reg_r5 jump_table_use_reg_r6 jump_table_use_reg_r7 jump_table_use_reg_r8 jump_table_use_reg_r9 test_subprog jump_table_outside_subprog jump_table_contains_non_unique_values spill_fill_ptr_to_insn too_many_gotox_edges gotox_edges_at_limit gotox_edges_subprog gotox_edges_across_subprogs jump_table_target_nop

use bpf_rs_core::{bpf_object, test_tags};
#[allow(unused_imports)]
use core::ffi::c_void;

test_tags! {
    jump_table_ok:
        __success,
        __retval("1");
    jump_table_reserved_field_src_reg:
        __failure,
        __msg("BPF_JA|BPF_X uses reserved fields");
    jump_table_reserved_field_non_zero_off:
        __failure,
        __msg("BPF_JA|BPF_X uses reserved fields");
    jump_table_reserved_field_non_zero_imm:
        __failure,
        __msg("BPF_JA|BPF_X uses reserved fields");
    jump_table_terminal_gotox:
        __success,
        __retval("0");
    jump_table_terminal_gotox_subprog:
        __success,
        __retval("0");
    jump_table_no_jump_table:
        __failure,
        __msg("no jump tables found for subprog starting at 0"),
        __msg(">>> 1 | (0d) gotox r0");
    jump_table_incorrect_dst_reg_type:
        __failure,
        __msg("R1 has type scalar, expected PTR_TO_INSN");
    jump_table_invalid_read_size_u32:
        __failure,
        __msg("Invalid read of 4 bytes from insn_array");
    jump_table_invalid_read_size_u16:
        __failure,
        __msg("Invalid read of 2 bytes from insn_array");
    jump_table_invalid_read_size_u8:
        __failure,
        __msg("Invalid read of 1 bytes from insn_array");
    jump_table_misaligned_access:
        __failure,
        __msg("misaligned value access off 1+0 size 8");
    jump_table_invalid_mem_acceess_pos:
        __failure,
        __msg("invalid access to map value, value_size=16 off=24 size=8");
    jump_table_invalid_mem_acceess_neg:
        __failure,
        __msg("R0 min value is negative");
    jump_table_add_sub_ok:
        __success,
        __retval("1");
    jump_table_no_writes:
        __failure,
        __msg("write into map forbidden, value_size=16 off=8 size=8");
    jump_table_use_reg_r0:
        __success,
        __retval("1");
    jump_table_use_reg_r1:
        __success,
        __retval("1");
    jump_table_use_reg_r2:
        __success,
        __retval("1");
    jump_table_use_reg_r3:
        __success,
        __retval("1");
    jump_table_use_reg_r4:
        __success,
        __retval("1");
    jump_table_use_reg_r5:
        __success,
        __retval("1");
    jump_table_use_reg_r6:
        __success,
        __retval("1");
    jump_table_use_reg_r7:
        __success,
        __retval("1");
    jump_table_use_reg_r8:
        __success,
        __retval("1");
    jump_table_use_reg_r9:
        __success,
        __retval("1");
    jump_table_outside_subprog:
        __failure,
        __msg("jump table of subprog starting at 0 spans multiple subprogs");
    jump_table_contains_non_unique_values:
        __success,
        __retval("1");
    spill_fill_ptr_to_insn:
        __success;
    too_many_gotox_edges:
        __description("too-many-gotox-edges"),
        __failure,
        __msg("number of indirect jump edges in the program exceeds");
    gotox_edges_at_limit:
        __description("gotox-edges-at-limit"),
        __failure,
        __msg("Too many nested loops");
    gotox_edges_across_subprogs:
        __description("gotox-edges-across-subprogs"),
        __failure,
        __msg("number of indirect jump edges in the program exceeds");
    jump_table_target_nop:
        __success,
        __retval("0"),
        __xlated("goto pc+0");
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jump_table_ok
extern "C" fn jump_table_ok() {
    unsafe {
        core::arch::asm!(
            ".pushsection .jumptables,\"\",@progbits;",
            "jt0_0:",
            ".quad ret0_0 - socket;",
            ".quad ret1_0 - socket;",
            ".size jt0_0, 16;",
            ".global jt0_0;",
            ".popsection;",
            "r0 = jt0_0 ll;",
            "r0 += 8;",
            "r0 = *(u64 *)(r0 + 0);",
            ".8byte 13;",
            "ret0_0:",
            "r0 = 0;",
            "exit;",
            "ret1_0:",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jump_table_reserved_field_src_reg
extern "C" fn jump_table_reserved_field_src_reg() {
    unsafe {
        core::arch::asm!(
            ".pushsection .jumptables,\"\",@progbits;",
            "jt0_1:",
            ".quad ret0_1 - socket;",
            ".quad ret1_1 - socket;",
            ".size jt0_1, 16;",
            ".global jt0_1;",
            ".popsection;",
            "r0 = jt0_1 ll;",
            "r0 += 8;",
            "r0 = *(u64 *)(r0 + 0);",
            ".8byte 4109;",
            "ret0_1:",
            "r0 = 0;",
            "exit;",
            "ret1_1:",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jump_table_reserved_field_non_zero_off
extern "C" fn jump_table_reserved_field_non_zero_off() {
    unsafe {
        core::arch::asm!(
            ".pushsection .jumptables,\"\",@progbits;",
            "jt0_2:",
            ".quad ret0_2 - socket;",
            ".quad ret1_2 - socket;",
            ".size jt0_2, 16;",
            ".global jt0_2;",
            ".popsection;",
            "r0 = jt0_2 ll;",
            "r0 += 8;",
            "r0 = *(u64 *)(r0 + 0);",
            ".8byte 65549;",
            "ret0_2:",
            "r0 = 0;",
            "exit;",
            "ret1_2:",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jump_table_reserved_field_non_zero_imm
extern "C" fn jump_table_reserved_field_non_zero_imm() {
    unsafe {
        core::arch::asm!(
            ".pushsection .jumptables,\"\",@progbits;",
            "jt0_3:",
            ".quad ret0_3 - socket;",
            ".quad ret1_3 - socket;",
            ".size jt0_3, 16;",
            ".global jt0_3;",
            ".popsection;",
            "r0 = jt0_3 ll;",
            "r0 += 8;",
            "r0 = *(u64 *)(r0 + 0);",
            ".8byte 4294967309;",
            "ret0_3:",
            "r0 = 0;",
            "exit;",
            "ret1_3:",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jump_table_terminal_gotox
extern "C" fn jump_table_terminal_gotox() {
    unsafe {
        core::arch::asm!(
            ".pushsection .jumptables,\"\",@progbits;",
            "jt0_4:",
            ".quad ret0_4 - socket;",
            ".size jt0_4, 8;",
            ".global jt0_4;",
            ".popsection;",
            "r0 = jt0_4 ll;",
            "r0 = *(u64 *)(r0 + 0);",
            "goto end_4;",
            "ret0_4:",
            "r0 = 0;",
            "exit;",
            "end_4:",
            ".8byte 13;",
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: terminal_gotox_subprog1
extern "C" fn terminal_gotox_subprog1() {
    unsafe {
        core::arch::asm!(
            ".pushsection .jumptables,\"\",@progbits;",
            "jt0_5:",
            ".quad ret0_5 - .text;",
            ".size jt0_5, 8;",
            ".global jt0_5;",
            ".popsection;",
            "r0 = jt0_5 ll;",
            "r0 = *(u64 *)(r0 + 0);",
            "goto end_5;",
            "ret0_5:",
            "r0 = 0;",
            "exit;",
            "end_5:",
            ".8byte 13;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jump_table_terminal_gotox_subprog
extern "C" fn jump_table_terminal_gotox_subprog() {
    unsafe {
        core::arch::asm!(
            "call {terminal_gotox_subprog1};",
            "call {terminal_gotox_subprog2};",
            "exit;",
            terminal_gotox_subprog1 = sym terminal_gotox_subprog1,
            terminal_gotox_subprog2 = sym terminal_gotox_subprog2,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jump_table_no_jump_table
extern "C" fn jump_table_no_jump_table() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            ".8byte 13;",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jump_table_incorrect_dst_reg_type
extern "C" fn jump_table_incorrect_dst_reg_type() {
    unsafe {
        core::arch::asm!(
            ".pushsection .jumptables,\"\",@progbits;",
            "jt0_6:",
            ".quad ret0_6 - socket;",
            ".quad ret1_6 - socket;",
            ".size jt0_6, 16;",
            ".global jt0_6;",
            ".popsection;",
            "r0 = jt0_6 ll;",
            "r0 += 8;",
            "r0 = *(u64 *)(r0 + 0);",
            "r1 = 42;",
            ".8byte 269;",
            "ret0_6:",
            "r0 = 0;",
            "exit;",
            "ret1_6:",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jump_table_invalid_read_size_u32
extern "C" fn jump_table_invalid_read_size_u32() {
    unsafe {
        core::arch::asm!(
            ".pushsection .jumptables,\"\",@progbits;",
            "jt0_7:",
            ".quad ret0_7 - socket;",
            ".quad ret1_7 - socket;",
            ".size jt0_7, 16;",
            ".global jt0_7;",
            ".popsection;",
            "r0 = jt0_7 ll;",
            "r0 += 8;",
            "r0 = *(u32 *)(r0 + 0);",
            ".8byte 13;",
            "ret0_7:",
            "r0 = 0;",
            "exit;",
            "ret1_7:",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jump_table_invalid_read_size_u16
extern "C" fn jump_table_invalid_read_size_u16() {
    unsafe {
        core::arch::asm!(
            ".pushsection .jumptables,\"\",@progbits;",
            "jt0_8:",
            ".quad ret0_8 - socket;",
            ".quad ret1_8 - socket;",
            ".size jt0_8, 16;",
            ".global jt0_8;",
            ".popsection;",
            "r0 = jt0_8 ll;",
            "r0 += 8;",
            "r0 = *(u16 *)(r0 + 0);",
            ".8byte 13;",
            "ret0_8:",
            "r0 = 0;",
            "exit;",
            "ret1_8:",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jump_table_invalid_read_size_u8
extern "C" fn jump_table_invalid_read_size_u8() {
    unsafe {
        core::arch::asm!(
            ".pushsection .jumptables,\"\",@progbits;",
            "jt0_9:",
            ".quad ret0_9 - socket;",
            ".quad ret1_9 - socket;",
            ".size jt0_9, 16;",
            ".global jt0_9;",
            ".popsection;",
            "r0 = jt0_9 ll;",
            "r0 += 8;",
            "r0 = *(u8 *)(r0 + 0);",
            ".8byte 13;",
            "ret0_9:",
            "r0 = 0;",
            "exit;",
            "ret1_9:",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jump_table_misaligned_access
extern "C" fn jump_table_misaligned_access() {
    unsafe {
        core::arch::asm!(
            ".pushsection .jumptables,\"\",@progbits;",
            "jt0_10:",
            ".quad ret0_10 - socket;",
            ".quad ret1_10 - socket;",
            ".size jt0_10, 16;",
            ".global jt0_10;",
            ".popsection;",
            "r0 = jt0_10 ll;",
            "r0 += 1;",
            "r0 = *(u64 *)(r0 + 0);",
            ".8byte 13;",
            "ret0_10:",
            "r0 = 0;",
            "exit;",
            "ret1_10:",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jump_table_invalid_mem_acceess_pos
extern "C" fn jump_table_invalid_mem_acceess_pos() {
    unsafe {
        core::arch::asm!(
            ".pushsection .jumptables,\"\",@progbits;",
            "jt0_11:",
            ".quad ret0_11 - socket;",
            ".quad ret1_11 - socket;",
            ".size jt0_11, 16;",
            ".global jt0_11;",
            ".popsection;",
            "r0 = jt0_11 ll;",
            "r0 += 24;",
            "r0 = *(u64 *)(r0 + 0);",
            ".8byte 13;",
            "ret0_11:",
            "r0 = 0;",
            "exit;",
            "ret1_11:",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jump_table_invalid_mem_acceess_neg
extern "C" fn jump_table_invalid_mem_acceess_neg() {
    unsafe {
        core::arch::asm!(
            ".pushsection .jumptables,\"\",@progbits;",
            "jt0_12:",
            ".quad ret0_12 - socket;",
            ".quad ret1_12 - socket;",
            ".size jt0_12, 16;",
            ".global jt0_12;",
            ".popsection;",
            "r0 = jt0_12 ll;",
            "r0 -= 24;",
            "r0 = *(u64 *)(r0 + 0);",
            ".8byte 13;",
            "ret0_12:",
            "r0 = 0;",
            "exit;",
            "ret1_12:",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jump_table_add_sub_ok
extern "C" fn jump_table_add_sub_ok() {
    unsafe {
        core::arch::asm!(
            ".pushsection .jumptables,\"\",@progbits;",
            "jt0_13:",
            ".quad ret0_13 - socket;",
            ".quad ret1_13 - socket;",
            ".size jt0_13, 16;",
            ".global jt0_13;",
            ".popsection;",
            "r0 = jt0_13 ll;",
            "r0 -= 24;",
            "r0 += 32;",
            "r0 = *(u64 *)(r0 + 0);",
            ".8byte 13;",
            "ret0_13:",
            "r0 = 0;",
            "exit;",
            "ret1_13:",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jump_table_no_writes
extern "C" fn jump_table_no_writes() {
    unsafe {
        core::arch::asm!(
            ".pushsection .jumptables,\"\",@progbits;",
            "jt0_14:",
            ".quad ret0_14 - socket;",
            ".quad ret1_14 - socket;",
            ".size jt0_14, 16;",
            ".global jt0_14;",
            ".popsection;",
            "r0 = jt0_14 ll;",
            "r0 += 8;",
            "r1 = 0xbeef;",
            "*(u64 *)(r0 + 0) = r1;",
            ".8byte 13;",
            "ret0_14:",
            "r0 = 0;",
            "exit;",
            "ret1_14:",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jump_table_use_reg_r0
extern "C" fn jump_table_use_reg_r0() {
    unsafe {
        core::arch::asm!(
            ".pushsection .jumptables,\"\",@progbits;",
            "jt0_15:",
            ".quad ret0_15 - socket;",
            ".quad ret1_15 - socket;",
            ".size jt0_15, 16;",
            ".global jt0_15;",
            ".popsection;",
            "r0 = jt0_15 ll;",
            "r0 += 8;",
            "r0 = *(u64 *)(r0 + 0);",
            ".8byte 13;",
            "ret0_15:",
            "r0 = 0;",
            "exit;",
            "ret1_15:",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jump_table_use_reg_r1
extern "C" fn jump_table_use_reg_r1() {
    unsafe {
        core::arch::asm!(
            ".pushsection .jumptables,\"\",@progbits;",
            "jt0_16:",
            ".quad ret0_16 - socket;",
            ".quad ret1_16 - socket;",
            ".size jt0_16, 16;",
            ".global jt0_16;",
            ".popsection;",
            "r0 = jt0_16 ll;",
            "r0 += 8;",
            "r1 = *(u64 *)(r0 + 0);",
            ".8byte 269;",
            "ret0_16:",
            "r0 = 0;",
            "exit;",
            "ret1_16:",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jump_table_use_reg_r2
extern "C" fn jump_table_use_reg_r2() {
    unsafe {
        core::arch::asm!(
            ".pushsection .jumptables,\"\",@progbits;",
            "jt0_17:",
            ".quad ret0_17 - socket;",
            ".quad ret1_17 - socket;",
            ".size jt0_17, 16;",
            ".global jt0_17;",
            ".popsection;",
            "r0 = jt0_17 ll;",
            "r0 += 8;",
            "r2 = *(u64 *)(r0 + 0);",
            ".8byte 525;",
            "ret0_17:",
            "r0 = 0;",
            "exit;",
            "ret1_17:",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jump_table_use_reg_r3
extern "C" fn jump_table_use_reg_r3() {
    unsafe {
        core::arch::asm!(
            ".pushsection .jumptables,\"\",@progbits;",
            "jt0_18:",
            ".quad ret0_18 - socket;",
            ".quad ret1_18 - socket;",
            ".size jt0_18, 16;",
            ".global jt0_18;",
            ".popsection;",
            "r0 = jt0_18 ll;",
            "r0 += 8;",
            "r3 = *(u64 *)(r0 + 0);",
            ".8byte 781;",
            "ret0_18:",
            "r0 = 0;",
            "exit;",
            "ret1_18:",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jump_table_use_reg_r4
extern "C" fn jump_table_use_reg_r4() {
    unsafe {
        core::arch::asm!(
            ".pushsection .jumptables,\"\",@progbits;",
            "jt0_19:",
            ".quad ret0_19 - socket;",
            ".quad ret1_19 - socket;",
            ".size jt0_19, 16;",
            ".global jt0_19;",
            ".popsection;",
            "r0 = jt0_19 ll;",
            "r0 += 8;",
            "r4 = *(u64 *)(r0 + 0);",
            ".8byte 1037;",
            "ret0_19:",
            "r0 = 0;",
            "exit;",
            "ret1_19:",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jump_table_use_reg_r5
extern "C" fn jump_table_use_reg_r5() {
    unsafe {
        core::arch::asm!(
            ".pushsection .jumptables,\"\",@progbits;",
            "jt0_20:",
            ".quad ret0_20 - socket;",
            ".quad ret1_20 - socket;",
            ".size jt0_20, 16;",
            ".global jt0_20;",
            ".popsection;",
            "r0 = jt0_20 ll;",
            "r0 += 8;",
            "r5 = *(u64 *)(r0 + 0);",
            ".8byte 1293;",
            "ret0_20:",
            "r0 = 0;",
            "exit;",
            "ret1_20:",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jump_table_use_reg_r6
extern "C" fn jump_table_use_reg_r6() {
    unsafe {
        core::arch::asm!(
            ".pushsection .jumptables,\"\",@progbits;",
            "jt0_21:",
            ".quad ret0_21 - socket;",
            ".quad ret1_21 - socket;",
            ".size jt0_21, 16;",
            ".global jt0_21;",
            ".popsection;",
            "r0 = jt0_21 ll;",
            "r0 += 8;",
            "r6 = *(u64 *)(r0 + 0);",
            ".8byte 1549;",
            "ret0_21:",
            "r0 = 0;",
            "exit;",
            "ret1_21:",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jump_table_use_reg_r7
extern "C" fn jump_table_use_reg_r7() {
    unsafe {
        core::arch::asm!(
            ".pushsection .jumptables,\"\",@progbits;",
            "jt0_22:",
            ".quad ret0_22 - socket;",
            ".quad ret1_22 - socket;",
            ".size jt0_22, 16;",
            ".global jt0_22;",
            ".popsection;",
            "r0 = jt0_22 ll;",
            "r0 += 8;",
            "r7 = *(u64 *)(r0 + 0);",
            ".8byte 1805;",
            "ret0_22:",
            "r0 = 0;",
            "exit;",
            "ret1_22:",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jump_table_use_reg_r8
extern "C" fn jump_table_use_reg_r8() {
    unsafe {
        core::arch::asm!(
            ".pushsection .jumptables,\"\",@progbits;",
            "jt0_23:",
            ".quad ret0_23 - socket;",
            ".quad ret1_23 - socket;",
            ".size jt0_23, 16;",
            ".global jt0_23;",
            ".popsection;",
            "r0 = jt0_23 ll;",
            "r0 += 8;",
            "r8 = *(u64 *)(r0 + 0);",
            ".8byte 2061;",
            "ret0_23:",
            "r0 = 0;",
            "exit;",
            "ret1_23:",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jump_table_use_reg_r9
extern "C" fn jump_table_use_reg_r9() {
    unsafe {
        core::arch::asm!(
            ".pushsection .jumptables,\"\",@progbits;",
            "jt0_24:",
            ".quad ret0_24 - socket;",
            ".quad ret1_24 - socket;",
            ".size jt0_24, 16;",
            ".global jt0_24;",
            ".popsection;",
            "r0 = jt0_24 ll;",
            "r0 += 8;",
            "r9 = *(u64 *)(r0 + 0);",
            ".8byte 2317;",
            "ret0_24:",
            "r0 = 0;",
            "exit;",
            "ret1_24:",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jump_table_outside_subprog
extern "C" fn jump_table_outside_subprog() {
    unsafe {
        core::arch::asm!(
            ".pushsection .jumptables,\"\",@progbits;",
            "jt0_25:",
            ".quad ret0_25 - socket;",
            ".quad ret1_25 - socket;",
            ".quad ret_out_25 - socket;",
            ".size jt0_25, 24;",
            ".global jt0_25;",
            ".popsection;",
            "r0 = jt0_25 ll;",
            "r0 += 8;",
            "r0 = *(u64 *)(r0 + 0);",
            ".8byte 13;",
            "ret0_25:",
            "r0 = 0;",
            "exit;",
            "ret1_25:",
            "r0 = 1;",
            "call {test_subprog};",
            "exit;",
            "ret_out_25:",
            test_subprog = sym test_subprog,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jump_table_contains_non_unique_values
extern "C" fn jump_table_contains_non_unique_values() {
    unsafe {
        core::arch::asm!(
            ".pushsection .jumptables,\"\",@progbits;",
            "jt0_26:",
            ".quad ret0_26 - socket;",
            ".quad ret1_26 - socket;",
            ".quad ret0_26 - socket;",
            ".quad ret1_26 - socket;",
            ".quad ret0_26 - socket;",
            ".quad ret1_26 - socket;",
            ".quad ret0_26 - socket;",
            ".quad ret1_26 - socket;",
            ".quad ret0_26 - socket;",
            ".quad ret1_26 - socket;",
            ".size jt0_26, 80;",
            ".global jt0_26;",
            ".popsection;",
            "r0 = jt0_26 ll;",
            "r0 += 8;",
            "r0 = *(u64 *)(r0 + 0);",
            ".8byte 13;",
            "ret0_26:",
            "r0 = 0;",
            "exit;",
            "ret1_26:",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: spill_fill_ptr_to_insn
extern "C" fn spill_fill_ptr_to_insn() {
    unsafe {
        core::arch::asm!(
            ".pushsection .jumptables,\"\",@progbits;",
            "jt0_27:",
            ".quad ret0_27 - socket;",
            ".size jt0_27, 8;",
            ".global jt0_27;",
            ".popsection;",
            "r0 = jt0_27 ll;",
            "r0 = *(u64 *)(r0 + 0);",
            "*(u64 *)(r10 - 8) = r0;",
            "r0 = *(u64 *)(r10 - 8);",
            ".8byte 13;",
            "ret0_27:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: too_many_gotox_edges
extern "C" fn too_many_gotox_edges() {
    unsafe {
        core::arch::asm!(
            ".pushsection .jumptables,\"\",@progbits;",
            "jt_28:",
            ".global jt_28;",
            ".size jt_28, 8 * (1000 + 1);",
            ".popsection;",
            "r1 = jt_28 ll;",
            "r0 = 0;",
            ".rept 1000;",
            ".pushsection .jumptables,\"\",@progbits;",
            ".quad 1f - socket;",
            ".popsection;",
            "1:",
            ".8byte 13;",
            ".endr;",
            ".pushsection .jumptables,\"\",@progbits;",
            ".quad 2f - socket;",
            ".popsection;",
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
// BPF_NAKED: gotox_edges_at_limit
extern "C" fn gotox_edges_at_limit() {
    unsafe {
        core::arch::asm!(
            ".pushsection .jumptables,\"\",@progbits;",
            "jt_29:",
            ".global jt_29;",
            ".size jt_29, 8 * (1000);",
            ".popsection;",
            "r1 = jt_29 ll;",
            ".rept 1000;",
            ".pushsection .jumptables,\"\",@progbits;",
            ".quad 1f - socket;",
            ".popsection;",
            "r0 = *(u64 *)(r1 + 0);",
            "r1 += 8;",
            ".8byte 13;",
            "1:",
            ".endr;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: gotox_edges_subprog
extern "C" fn gotox_edges_subprog() {
    unsafe {
        core::arch::asm!(
            ".pushsection .jumptables,\"\",@progbits;",
            "jt_30:",
            ".global jt_30;",
            ".size jt_30, 8 * (750 + 1);",
            ".popsection;",
            "r1 = jt_30 ll;",
            "r0 = 0;",
            ".rept 750;",
            ".pushsection .jumptables,\"\",@progbits;",
            ".quad 1f - .text;",
            ".popsection;",
            "1:",
            ".8byte 13;",
            ".endr;",
            ".pushsection .jumptables,\"\",@progbits;",
            ".quad 2f - .text;",
            ".popsection;",
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
// BPF_NAKED: gotox_edges_across_subprogs
extern "C" fn gotox_edges_across_subprogs() {
    unsafe {
        core::arch::asm!(
            ".pushsection .jumptables,\"\",@progbits;",
            "jt_31:",
            ".global jt_31;",
            ".size jt_31, 8 * (750 + 1);",
            ".popsection;",
            "r1 = jt_31 ll;",
            "r0 = 0;",
            ".rept 750;",
            ".pushsection .jumptables,\"\",@progbits;",
            ".quad 1f - socket;",
            ".popsection;",
            "1:",
            ".8byte 13;",
            ".endr;",
            ".pushsection .jumptables,\"\",@progbits;",
            ".quad 2f - socket;",
            ".popsection;",
            "2:",
            "call {gotox_edges_subprog};",
            "exit;",
            gotox_edges_subprog = sym gotox_edges_subprog,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jump_table_target_nop
extern "C" fn jump_table_target_nop() {
    unsafe {
        core::arch::asm!(
            ".pushsection .jumptables,\"\",@progbits;",
            "jt0_32:",
            ".quad nop_32 - socket;",
            ".size jt0_32, 8;",
            ".global jt0_32;",
            ".popsection;",
            "r0 = jt0_32 ll;",
            "r0 = *(u64 *)(r0 + 0);",
            ".8byte 13;",
            "nop_32:",
            "goto +0;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

include!("hand/verifier_gotox.rs");

bpf_object!("GPL");
