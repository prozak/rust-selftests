// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_spill_fill.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_spill_fill.rs
// (include!d below): spill_fill_dynptr_subprog, spill_fill_const_ptr_to_dynptr.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_spill_fill` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: check_valid_spill_fill valid_spill_fill_skb_mark spill_fill_ptr_to_mem with_invalid_reg_offset_0 check_corrupted_spill_fill check_corrupted_spill_fill_lsb check_corrupted_spill_fill_msb scalar_offset_to_skb_data_1 uninit_u32_from_the_stack u16_offset_to_skb_data u64_offset_to_skb_data _6_offset_to_skb_data addr_offset_to_skb_data scalar_offset_to_skb_data_2 and_then_at_fp_8 spill_32bit_of_64bit_fail spill_16bit_of_32bit_fail spill_subregs_preserve_stack_zero partial_stack_load_preserves_zeros partial_stack_load_preserves_partial_zeros stack_load_preserves_mixed_zero_and_zero_spill stack_load_preserves_const_precision stack_load_preserves_const_precision_subreg spill_32bit_range_track spill_64bit_of_64bit_ok spill_32bit_of_32bit_ok spill_16bit_of_16bit_ok spill_8bit_of_8bit_ok spill_unbounded fill_32bit_after_spill_64bit fill_32bit_after_spill_64bit_preserve_id fill_32bit_after_spill_64bit_clear_id old_imprecise_scalar_vs_cur_stack_misc old_precise_scalar_vs_cur_stack_misc old_stack_misc_vs_cur_scalar old_stack_misc_vs_cur_ctx_ptr stack_noperfmon_reject_invalid_read stack_noperfmon_spill_32bit_onto_64bit_slot old_imprecise_scalar32_vs_cur_stack_misc stack_noperfmon_reject_atomic_on_narrow_spill stack_noperfmon_reject_helper_read_of_narrow_spill var_off_write_over_scalar_spill partial_fill_from_cleaned_pointer_spill imprecise_scalar_spill_half_dead spill_fill_ptr_to_tp_buffer spill_fill_dynptr_subprog spill_fill_const_ptr_to_dynptr

use bpf_rs_core::{bpf_map, bpf_object, test_tags};
#[allow(unused_imports)]
use core::ffi::c_void;

test_tags! {
    check_valid_spill_fill:
        __description("check valid spill/fill"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R0 leaks addr"),
        __retval("0xbadcafe");
    valid_spill_fill_skb_mark:
        __description("check valid spill/fill, skb mark"),
        __success,
        __success_unpriv,
        __retval("0");
    spill_fill_ptr_to_mem:
        __description("check valid spill/fill, ptr to mem"),
        __success,
        __success_unpriv,
        __retval("0");
    with_invalid_reg_offset_0:
        __description("check with invalid reg offset 0"),
        __failure,
        __msg("R0 pointer arithmetic on ringbuf_mem_or_null prohibited"),
        __failure_unpriv;
    check_corrupted_spill_fill:
        __description("check corrupted spill/fill"),
        __failure,
        __msg("R0 invalid mem access 'scalar'"),
        __msg_unpriv("attempt to corrupt spilled"),
        __flag("BPF_F_ANY_ALIGNMENT");
    check_corrupted_spill_fill_lsb:
        __description("check corrupted spill/fill, LSB"),
        __success,
        __failure_unpriv,
        __msg_unpriv("attempt to corrupt spilled"),
        __retval("0xbadcafe");
    check_corrupted_spill_fill_msb:
        __description("check corrupted spill/fill, MSB"),
        __success,
        __failure_unpriv,
        __msg_unpriv("attempt to corrupt spilled"),
        __retval("0xbadcafe");
    scalar_offset_to_skb_data_1:
        __description("Spill and refill a u32 const scalar.  Offset to skb->data"),
        __success,
        __retval("0");
    uninit_u32_from_the_stack:
        __description("Spill a u32 const, refill from another half of the uninit u32 from the stack"),
        __success,
        __failure_unpriv,
        __msg_unpriv("invalid read from stack off -4+0 size 4"),
        __retval("0");
    u16_offset_to_skb_data:
        __description("Spill a u32 const scalar.  Refill as u16.  Offset to skb->data"),
        __success,
        __retval("0");
    u64_offset_to_skb_data:
        __description("Spill u32 const scalars.  Refill as u64.  Offset to skb->data"),
        __failure,
        __msg("math between pkt pointer and register with unbounded min value is not allowed");
    _6_offset_to_skb_data:
        __description("Spill a u32 const scalar.  Refill as u16 from MSB.  Offset to skb->data"),
        __failure,
        __msg("invalid access to packet");
    addr_offset_to_skb_data:
        __description("Spill and refill a u32 const scalar at non 8byte aligned stack addr.  Offset to skb->data"),
        __failure,
        __msg("invalid access to packet");
    scalar_offset_to_skb_data_2:
        __description("Spill and refill a umax=40 bounded scalar.  Offset to skb->data"),
        __success,
        __retval("0");
    and_then_at_fp_8:
        __description("Spill a u32 scalar at fp-4 and then at fp-8"),
        __success,
        __retval("0");
    spill_32bit_of_64bit_fail:
        __description("32-bit spill of 64-bit reg should clear ID"),
        __failure,
        __msg("math between ctx pointer and 4294967295 is not allowed");
    spill_16bit_of_32bit_fail:
        __description("16-bit spill of 32-bit reg should clear ID"),
        __failure,
        __msg("dereference of modified ctx ptr R6 off=65535 disallowed");
    spill_subregs_preserve_stack_zero:
        __log_level("2"),
        __success,
        __msg("fp-8=0m??scalar()"),
        __msg("fp-16=00mm??scalar()"),
        __msg("fp-24=00mm???scalar()");
    partial_stack_load_preserves_zeros:
        __log_level("2"),
        __success,
        __msg("2: (7a) *(u64 *)(r10 -8) = 0          ; R10=fp0 fp-8=0"),
        __msg("4: (7b) *(u64 *)(r10 -16) = r0        ; R0=0 R10=fp0 fp-16=0"),
        __msg("6: (71) r2 = *(u8 *)(r10 -1)          ; R2=0 R10=fp0 fp-8=0"),
        __msg("10: (71) r2 = *(u8 *)(r10 -9)         ; R2=0 R10=fp0 fp-16=0"),
        __msg("11: (0f) r1 += r2"),
        __msg("mark_precise: frame0: last_idx 11 first_idx 0 subseq_idx -1"),
        __msg("mark_precise: frame0: regs=r2 stack= before 10: (71) r2 = *(u8 *)(r10 -9)"),
        __msg("mark_precise: frame0: regs= stack=-16 before 9: (bf) r1 = r6"),
        __msg("mark_precise: frame0: regs= stack=-16 before 8: (73) *(u8 *)(r1 +0) = r2"),
        __msg("mark_precise: frame0: regs= stack=-16 before 7: (0f) r1 += r2"),
        __msg("mark_precise: frame0: regs= stack=-16 before 6: (71) r2 = *(u8 *)(r10 -1)"),
        __msg("mark_precise: frame0: regs= stack=-16 before 5: (bf) r1 = r6"),
        __msg("mark_precise: frame0: regs= stack=-16 before 4: (7b) *(u64 *)(r10 -16) = r0"),
        __msg("mark_precise: frame0: regs=r0 stack= before 3: (b7) r0 = 0");
    partial_stack_load_preserves_partial_zeros:
        __log_level("2"),
        __success,
        __msg("2: (62) *(u32 *)(r10 -4) = 0          ; R10=fp0 fp-8=0000????"),
        __msg("4: (71) r2 = *(u8 *)(r10 -1)          ; R2=0 R10=fp0 fp-8=0000????"),
        __msg("5: (0f) r1 += r2"),
        __msg("mark_precise: frame0: last_idx 5 first_idx 0 subseq_idx -1"),
        __msg("mark_precise: frame0: regs=r2 stack= before 4: (71) r2 = *(u8 *)(r10 -1)");
    stack_load_preserves_mixed_zero_and_zero_spill:
        __log_level("2"),
        __success,
        __msg("mark_precise: frame0: regs= stack=-8"),
        __msg("R2=0");
    stack_load_preserves_const_precision:
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __success,
        __msg("3: (7a) *(u64 *)(r10 -8) = 1          ; R10=fp0 fp-8=1"),
        __msg("5: (7b) *(u64 *)(r10 -16) = r0        ; R0=1 R10=fp0 fp-16=1"),
        __msg("8: (79) r2 = *(u64 *)(r10 -8)         ; R2=1 R10=fp0 fp-8=1"),
        __msg("9: (0f) r1 += r2"),
        __msg("mark_precise: frame0: last_idx 9 first_idx 7 subseq_idx -1"),
        __msg("mark_precise: frame0: regs=r2 stack= before 8: (79) r2 = *(u64 *)(r10 -8)"),
        __msg("mark_precise: frame0: regs= stack=-8 before 7: (bf) r1 = r6"),
        __msg("mark_precise: frame0: parent state regs= stack=-8:  R6=map_value(map=.data.two_byte_,ks=4,vs=2) R10=fp0 fp-8=P1 fp-16=1"),
        __msg("mark_precise: frame0: last_idx 6 first_idx 3 subseq_idx 7"),
        __msg("mark_precise: frame0: regs= stack=-8 before 6: (05) goto pc+0"),
        __msg("mark_precise: frame0: regs= stack=-8 before 5: (7b) *(u64 *)(r10 -16) = r0"),
        __msg("mark_precise: frame0: regs= stack=-8 before 4: (b7) r0 = 1"),
        __msg("mark_precise: frame0: regs= stack=-8 before 3: (7a) *(u64 *)(r10 -8) = 1"),
        __msg("10: R1=map_value(map=.data.two_byte_,ks=4,vs=2,imm=1) R2=1"),
        __msg("12: (79) r2 = *(u64 *)(r10 -16)       ; R2=1 R10=fp0 fp-16=1"),
        __msg("13: (0f) r1 += r2"),
        __msg("mark_precise: frame0: last_idx 13 first_idx 7 subseq_idx -1"),
        __msg("mark_precise: frame0: regs=r2 stack= before 12: (79) r2 = *(u64 *)(r10 -16)"),
        __msg("mark_precise: frame0: regs= stack=-16 before 11: (bf) r1 = r6"),
        __msg("mark_precise: frame0: regs= stack=-16 before 10: (73) *(u8 *)(r1 +0) = r2"),
        __msg("mark_precise: frame0: regs= stack=-16 before 9: (0f) r1 += r2"),
        __msg("mark_precise: frame0: regs= stack=-16 before 8: (79) r2 = *(u64 *)(r10 -8)"),
        __msg("mark_precise: frame0: regs= stack=-16 before 7: (bf) r1 = r6"),
        __msg("mark_precise: frame0: parent state regs= stack=-16:  R6=map_value(map=.data.two_byte_,ks=4,vs=2) R10=fp0 fp-8=P1 fp-16=P1"),
        __msg("mark_precise: frame0: last_idx 6 first_idx 3 subseq_idx 7"),
        __msg("mark_precise: frame0: regs= stack=-16 before 6: (05) goto pc+0"),
        __msg("mark_precise: frame0: regs= stack=-16 before 5: (7b) *(u64 *)(r10 -16) = r0"),
        __msg("mark_precise: frame0: regs=r0 stack= before 4: (b7) r0 = 1"),
        __msg("14: R1=map_value(map=.data.two_byte_,ks=4,vs=2,imm=1) R2=1");
    stack_load_preserves_const_precision_subreg:
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __success,
        __msg("3: (62) *(u32 *)(r10 -8) = 1          ; R10=fp0 fp-8=????1"),
        __msg("5: (63) *(u32 *)(r10 -16) = r0        ; R0=1 R10=fp0 fp-16=????1"),
        __msg("8: (61) r2 = *(u32 *)(r10 -8)         ; R2=1 R10=fp0 fp-8=????1"),
        __msg("9: (0f) r1 += r2"),
        __msg("mark_precise: frame0: last_idx 9 first_idx 7 subseq_idx -1"),
        __msg("mark_precise: frame0: regs=r2 stack= before 8: (61) r2 = *(u32 *)(r10 -8)"),
        __msg("mark_precise: frame0: regs= stack=-8 before 7: (bf) r1 = r6"),
        __msg("mark_precise: frame0: parent state regs= stack=-8:  R6=map_value(map=.data.two_byte_,ks=4,vs=2) R10=fp0 fp-8=????P1 fp-16=????1"),
        __msg("mark_precise: frame0: last_idx 6 first_idx 3 subseq_idx 7"),
        __msg("mark_precise: frame0: regs= stack=-8 before 6: (05) goto pc+0"),
        __msg("mark_precise: frame0: regs= stack=-8 before 5: (63) *(u32 *)(r10 -16) = r0"),
        __msg("mark_precise: frame0: regs= stack=-8 before 4: (b7) r0 = 1"),
        __msg("mark_precise: frame0: regs= stack=-8 before 3: (62) *(u32 *)(r10 -8) = 1"),
        __msg("10: R1=map_value(map=.data.two_byte_,ks=4,vs=2,imm=1) R2=1"),
        __msg("12: (61) r2 = *(u32 *)(r10 -16)       ; R2=1 R10=fp0 fp-16=????1"),
        __msg("13: (0f) r1 += r2"),
        __msg("mark_precise: frame0: last_idx 13 first_idx 7 subseq_idx -1"),
        __msg("mark_precise: frame0: regs=r2 stack= before 12: (61) r2 = *(u32 *)(r10 -16)"),
        __msg("mark_precise: frame0: regs= stack=-16 before 11: (bf) r1 = r6"),
        __msg("mark_precise: frame0: regs= stack=-16 before 10: (73) *(u8 *)(r1 +0) = r2"),
        __msg("mark_precise: frame0: regs= stack=-16 before 9: (0f) r1 += r2"),
        __msg("mark_precise: frame0: regs= stack=-16 before 8: (61) r2 = *(u32 *)(r10 -8)"),
        __msg("mark_precise: frame0: regs= stack=-16 before 7: (bf) r1 = r6"),
        __msg("mark_precise: frame0: parent state regs= stack=-16:  R6=map_value(map=.data.two_byte_,ks=4,vs=2) R10=fp0 fp-8=????P1 fp-16=????P1"),
        __msg("mark_precise: frame0: last_idx 6 first_idx 3 subseq_idx 7"),
        __msg("mark_precise: frame0: regs= stack=-16 before 6: (05) goto pc+0"),
        __msg("mark_precise: frame0: regs= stack=-16 before 5: (63) *(u32 *)(r10 -16) = r0"),
        __msg("mark_precise: frame0: regs=r0 stack= before 4: (b7) r0 = 1"),
        __msg("14: R1=map_value(map=.data.two_byte_,ks=4,vs=2,imm=1) R2=1");
    spill_32bit_range_track:
        __description("32-bit spilled reg range should be tracked"),
        __success,
        __retval("0");
    spill_64bit_of_64bit_ok:
        __description("64-bit spill of 64-bit reg should assign ID"),
        __success,
        __retval("0");
    spill_32bit_of_32bit_ok:
        __description("32-bit spill of 32-bit reg should assign ID"),
        __success,
        __retval("0");
    spill_16bit_of_16bit_ok:
        __description("16-bit spill of 16-bit reg should assign ID"),
        __success,
        __retval("0");
    spill_8bit_of_8bit_ok:
        __description("8-bit spill of 8-bit reg should assign ID"),
        __success,
        __retval("0");
    spill_unbounded:
        __description("spill unbounded reg, then range check src"),
        __success,
        __retval("0");
    fill_32bit_after_spill_64bit:
        __description("32-bit fill after 64-bit spill"),
        __success,
        __retval("0");
    fill_32bit_after_spill_64bit_preserve_id:
        __description("32-bit fill after 64-bit spill of 32-bit value should preserve ID"),
        __success,
        __retval("0");
    fill_32bit_after_spill_64bit_clear_id:
        __description("32-bit fill after 64-bit spill should clear ID"),
        __failure,
        __msg("math between ctx pointer and 4294967295 is not allowed");
    old_imprecise_scalar_vs_cur_stack_misc:
        __success,
        __log_level("2"),
        __msg("8: (79) r1 = *(u64 *)(r10 -8)"),
        __msg("8: safe"),
        __msg("processed 11 insns"),
        __failure_unpriv,
        __msg_unpriv("8: (79) r1 = *(u64 *)(r10 -8)"),
        __msg_unpriv("9: (95) exit"),
        __msg_unpriv("8: (79) r1 = *(u64 *)(r10 -8)"),
        __msg_unpriv("invalid read from stack off -8+2 size 8"),
        __flag("BPF_F_TEST_STATE_FREQ");
    old_precise_scalar_vs_cur_stack_misc:
        __success,
        __log_level("2"),
        __msg("if r1 == 0x2a goto pc+0"),
        __msg("if r1 == 0x2a goto pc+0"),
        __msg("processed 15 insns"),
        __flag("BPF_F_TEST_STATE_FREQ");
    old_stack_misc_vs_cur_scalar:
        __success,
        __log_level("2"),
        __msg("8: (79) r0 = *(u64 *)(r10 -8)"),
        __msg("8: safe"),
        __msg("processed 11 insns"),
        __flag("BPF_F_TEST_STATE_FREQ");
    old_stack_misc_vs_cur_ctx_ptr:
        __success,
        __log_level("2"),
        __msg("8: (79) r1 = *(u64 *)(r10 -8)"),
        __msg("9: (95) exit"),
        __msg("from 2 to 7"),
        __msg("8: safe"),
        __msg("processed 11 insns"),
        __flag("BPF_F_TEST_STATE_FREQ");
    stack_noperfmon_reject_invalid_read:
        __description("stack_noperfmon: reject read of invalid slots"),
        __success,
        __caps_unpriv("39"),
        __failure_unpriv,
        __msg_unpriv("invalid read from stack off -8+1 size 8"),
        __msg_unpriv("Verification failed: Memory Safety: Uninitialized stack read"),
        __msg_unpriv("Initialize every byte in the stack range before reading it");
    stack_noperfmon_spill_32bit_onto_64bit_slot:
        __description("stack_noperfmon: narrow spill onto 64-bit scalar spilled slots"),
        __success,
        __caps_unpriv("39"),
        __success_unpriv;
    old_imprecise_scalar32_vs_cur_stack_misc:
        __success,
        __log_level("2"),
        __msg("8: (79) r1 = *(u64 *)(r10 -8)"),
        __msg("8: safe"),
        __msg("processed 11 insns"),
        __flag("BPF_F_TEST_STATE_FREQ");
    stack_noperfmon_reject_atomic_on_narrow_spill:
        __description("stack_noperfmon: reject non-fetch atomic on narrow spill"),
        __success,
        __caps_unpriv("39"),
        __failure_unpriv,
        __msg_unpriv("invalid read from stack off -8+4 size 8");
    stack_noperfmon_reject_helper_read_of_narrow_spill:
        __description("stack_noperfmon: reject helper read of narrow spill"),
        __success,
        __caps_unpriv("39"),
        __failure_unpriv,
        __msg_unpriv("invalid read from stack R2 off -8+4 size 8");
    var_off_write_over_scalar_spill:
        __success;
    partial_fill_from_cleaned_pointer_spill:
        __description("partial fill from cleaned pointer spill"),
        __failure,
        __log_level("2"),
        __msg("1: (05) goto pc+0"),
        __msg("2: (61) r0 = *(u32 *)(r10 -4)"),
        __msg("invalid size of register fill"),
        __flag("BPF_F_TEST_STATE_FREQ");
    imprecise_scalar_spill_half_dead:
        __failure,
        __msg("access may be outside object bounds"),
        __flag("BPF_F_TEST_STATE_FREQ");
    spill_fill_ptr_to_tp_buffer:
        __success;
    spill_fill_const_ptr_to_dynptr:
        __success;
}

// Map key/value types, shaped like the C object's BTF (the kernel
// checks some of them member by member, so no explicit padding).
// translint: allow(padding)
#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct bpf_dynptr {
    __opaque: [u64; 2],
}

bpf_map! {
    map_ringbuf {
        r#type: *const [i32; 27],
        max_entries: *const [i32; 4096],
    }
}

#[no_mangle]
static mut dptr_mem_buf: [i8; 16] = [0; 16];

#[link_section = ".data.single_byte_buf"]
#[no_mangle]
static mut single_byte_buf: [i8; 1] = [0];

#[link_section = ".data.two_byte_buf"]
#[no_mangle]
static mut two_byte_buf: [i8; 2] = [0, 0];

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: check_valid_spill_fill
extern "C" fn check_valid_spill_fill() {
    unsafe {
        core::arch::asm!(
            "*(u64*)(r10 - 8) = r1;",
            "r2 = *(u64*)(r10 - 8);",
            "r0 = r2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: valid_spill_fill_skb_mark
extern "C" fn valid_spill_fill_skb_mark() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "*(u64*)(r10 - 8) = r6;",
            "r0 = *(u64*)(r10 - 8);",
            "r0 = *(u32*)(r0 + 8);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: spill_fill_ptr_to_mem
extern "C" fn spill_fill_ptr_to_mem() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r1 = {map_ringbuf} ll;",
            "r2 = 8;",
            "r3 = 0;",
            "call 131;",
            "r6 = r0;",
            "if r0 == 0 goto l0_0;",
            "*(u64*)(r10 - 8) = r6;",
            "r7 = *(u64*)(r10 - 8);",
            "r1 = 0;",
            "*(u64*)(r7 + 0) = r1;",
            "r1 = r7;",
            "r2 = 0;",
            "call 132;",
            "l0_0:",
            "r0 = 0;",
            "exit;",
            map_ringbuf = sym map_ringbuf,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: with_invalid_reg_offset_0
extern "C" fn with_invalid_reg_offset_0() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r1 = {map_ringbuf} ll;",
            "r2 = 8;",
            "r3 = 0;",
            "call 131;",
            "r6 = r0;",
            "r0 += 1;",
            "if r0 == 0 goto l0_1;",
            "r1 = 0;",
            "*(u32*)(r6 + 0) = r1;",
            "r1 = r6;",
            "r2 = 0;",
            "call 132;",
            "l0_1:",
            "r0 = 0;",
            "exit;",
            map_ringbuf = sym map_ringbuf,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: check_corrupted_spill_fill
extern "C" fn check_corrupted_spill_fill() {
    unsafe {
        core::arch::asm!(
            "*(u64*)(r10 - 8) = r1;",
            "r0 = 0x23;",
            "*(u8*)(r10 - 7) = r0;",
            "r0 = *(u64*)(r10 - 8);",
            "r0 = *(u64*)(r0 + 8);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: check_corrupted_spill_fill_lsb
extern "C" fn check_corrupted_spill_fill_lsb() {
    unsafe {
        core::arch::asm!(
            "*(u64*)(r10 - 8) = r1;",
            "r0 = 0xcafe;",
            "*(u16*)(r10 - 8) = r0;",
            "r0 = *(u64*)(r10 - 8);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: check_corrupted_spill_fill_msb
extern "C" fn check_corrupted_spill_fill_msb() {
    unsafe {
        core::arch::asm!(
            "*(u64*)(r10 - 8) = r1;",
            "r0 = 0x12345678;",
            "*(u32*)(r10 - 4) = r0;",
            "r0 = *(u64*)(r10 - 8);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: scalar_offset_to_skb_data_1
extern "C" fn scalar_offset_to_skb_data_1() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "w4 = 20;",
            "*(u32*)(r10 - 8) = r4;",
            "r4 = *(u32*)(r10 - 8);",
            "r0 = r2;",
            "r0 += r4;",
            "if r0 > r3 goto l0_2;",
            "r0 = *(u32*)(r2 + 0);",
            "l0_2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: uninit_u32_from_the_stack
extern "C" fn uninit_u32_from_the_stack() {
    unsafe {
        core::arch::asm!(
            "w4 = 20;",
            "*(u32*)(r10 - 8) = r4;",
            "r4 = *(u32*)(r10 - 4);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: u16_offset_to_skb_data
extern "C" fn u16_offset_to_skb_data() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "w4 = 20;",
            "*(u32*)(r10 - 8) = r4;",
            "r4 = *(u16*)(r10 - 8);",
            "r0 = r2;",
            "r0 += r4;",
            "if r0 > r3 goto l0_3;",
            "r0 = *(u32*)(r2 + 0);",
            "l0_3:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: u64_offset_to_skb_data
extern "C" fn u64_offset_to_skb_data() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "w6 = 0;",
            "w7 = 20;",
            "*(u32*)(r10 - 4) = r6;",
            "*(u32*)(r10 - 8) = r7;",
            "r4 = *(u64*)(r10 - 8);",
            "r0 = r2;",
            "r0 += r4;",
            "if r0 > r3 goto l0_4;",
            "r0 = *(u32*)(r2 + 0);",
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
// BPF_NAKED: _6_offset_to_skb_data
extern "C" fn _6_offset_to_skb_data() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "w4 = 20;",
            "*(u32*)(r10 - 8) = r4;",
            "r4 = *(u16*)(r10 - 6);",
            "r0 = r2;",
            "r0 += r4;",
            "if r0 > r3 goto l0_5;",
            "r0 = *(u32*)(r2 + 0);",
            "l0_5:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: addr_offset_to_skb_data
extern "C" fn addr_offset_to_skb_data() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "w4 = 20;",
            "*(u32*)(r10 - 8) = r4;",
            "*(u32*)(r10 - 4) = r4;",
            "r4 = *(u32*)(r10 - 4);",
            "r0 = r2;",
            "r0 += r4;",
            "if r0 > r3 goto l0_6;",
            "r0 = *(u32*)(r2 + 0);",
            "l0_6:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: scalar_offset_to_skb_data_2
extern "C" fn scalar_offset_to_skb_data_2() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r4 = *(u64*)(r1 + 152);",
            "if r4 <= 40 goto l0_7;",
            "r0 = 0;",
            "exit;",
            "l0_7:",
            "*(u32*)(r10 - 8) = r4;",
            "r4 = *(u32*)(r10 - 8);",
            "r2 += r4;",
            "r0 = r2;",
            "r2 += 20;",
            "if r2 > r3 goto l1_7;",
            "r0 = *(u32*)(r0 + 0);",
            "l1_7:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: and_then_at_fp_8
extern "C" fn and_then_at_fp_8() {
    unsafe {
        core::arch::asm!(
            "w4 = 4321;",
            "*(u32*)(r10 - 4) = r4;",
            "*(u32*)(r10 - 8) = r4;",
            "r4 = *(u64*)(r10 - 8);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: spill_32bit_of_64bit_fail
extern "C" fn spill_32bit_of_64bit_fail() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "call 7;",
            "r0 &= 0x8;",
            "r1 = 0xffffffff;",
            "r1 <<= 32;",
            "r1 += r0;",
            "r2 = r1;",
            "*(u32*)(r10 - 8) = r1;",
            "r2 = *(u32*)(r10 - 8);",
            "r3 = 0;",
            "if r2 != r3 goto l0_8;",
            "l0_8:",
            "r1 >>= 32;",
            "r6 += r1;",
            "r0 = *(u32*)(r6 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: spill_16bit_of_32bit_fail
extern "C" fn spill_16bit_of_32bit_fail() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "call 7;",
            "r0 &= 0x8;",
            "w1 = 0xffff0000;",
            "r1 += r0;",
            "r2 = r1;",
            "*(u16*)(r10 - 8) = r1;",
            "r2 = *(u16*)(r10 - 8);",
            "r3 = 0;",
            "if r2 != r3 goto l0_9;",
            "l0_9:",
            "r1 >>= 16;",
            "r6 += r1;",
            "r0 = *(u32*)(r6 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: spill_subregs_preserve_stack_zero
extern "C" fn spill_subregs_preserve_stack_zero() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            ".8byte 4294904434;",
            "*(u8 *)(r10 -2) = r0;",
            "*(u32 *)(r10 -8) = r0;",
            ".8byte 4294314602;",
            "*(u16 *)(r10 -12) = r0;",
            "*(u16 *)(r10 -16) = r0;",
            ".8byte 4293790314;",
            "*(u16 *)(r10 -20) = r0;",
            "*(u8 *)(r10 -24) = r0;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: partial_stack_load_preserves_zeros
extern "C" fn partial_stack_load_preserves_zeros() {
    unsafe {
        core::arch::asm!(
            ".8byte 4294445690;",
            "r0 = 0;",
            "*(u64 *)(r10 -16) = r0;",
            "r1 = {single_byte_buf};",
            "r2 = *(u8 *)(r10 -1);",
            "r1 += r2;",
            "*(u8 *)(r1 + 0) = r2;",
            "r1 = {single_byte_buf};",
            "r2 = *(u8 *)(r10 -9);",
            "r1 += r2;",
            "*(u8 *)(r1 + 0) = r2;",
            "r1 = {single_byte_buf};",
            "r2 = *(u16 *)(r10 -2);",
            "r1 += r2;",
            "*(u8 *)(r1 + 0) = r2;",
            "r1 = {single_byte_buf};",
            "r2 = *(u16 *)(r10 -10);",
            "r1 += r2;",
            "*(u8 *)(r1 + 0) = r2;",
            "r1 = {single_byte_buf};",
            "r2 = *(u32 *)(r10 -4);",
            "r1 += r2;",
            "*(u8 *)(r1 + 0) = r2;",
            "r1 = {single_byte_buf};",
            "r2 = *(u32 *)(r10 -12);",
            "r1 += r2;",
            "*(u8 *)(r1 + 0) = r2;",
            "r1 = {single_byte_buf};",
            "r2 = *(u64 *)(r10 -8);",
            "r1 += r2;",
            "*(u8 *)(r1 + 0) = r2;",
            "r1 = {single_byte_buf};",
            "r2 = *(u64 *)(r10 -16);",
            "r1 += r2;",
            "*(u8 *)(r1 + 0) = r2;",
            "r0 = 0;",
            "exit;",
            single_byte_buf = in(reg) core::ptr::addr_of!(single_byte_buf),
            out("r0") _,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: partial_stack_load_preserves_partial_zeros
extern "C" fn partial_stack_load_preserves_partial_zeros() {
    unsafe {
        core::arch::asm!(
            ".8byte 4294707810;",
            "r1 = {single_byte_buf};",
            "r2 = *(u8 *)(r10 -1);",
            "r1 += r2;",
            "*(u8 *)(r1 + 0) = r2;",
            "r1 = {single_byte_buf};",
            "r2 = *(u16 *)(r10 -2);",
            "r1 += r2;",
            "*(u8 *)(r1 + 0) = r2;",
            "r1 = {single_byte_buf};",
            "r2 = *(u32 *)(r10 -4);",
            "r1 += r2;",
            "*(u8 *)(r1 + 0) = r2;",
            "r0 = 0;",
            "exit;",
            single_byte_buf = in(reg) core::ptr::addr_of!(single_byte_buf),
            out("r0") _,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_load_preserves_mixed_zero_and_zero_spill
extern "C" fn stack_load_preserves_mixed_zero_and_zero_spill() {
    unsafe {
        core::arch::asm!(
            ".8byte 4294707810;",
            "r0 = 0;",
            "*(u32 *)(r10 -8) = r0;",
            "r1 = {single_byte_buf};",
            "r2 = *(u64 *)(r10 -8);",
            "r1 += r2;",
            "*(u8 *)(r1 + 0) = r2;",
            "r0 = 0;",
            "exit;",
            single_byte_buf = in(reg) core::ptr::addr_of!(single_byte_buf),
            out("r0") _,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_load_preserves_const_precision
extern "C" fn stack_load_preserves_const_precision() {
    unsafe {
        core::arch::asm!(
            "goto +0;",
            ".8byte 8589412986;",
            "r0 = 1;",
            "*(u64 *)(r10 -16) = r0;",
            "goto +0;",
            "r1 = {two_byte_buf};",
            "r2 = *(u64 *)(r10 -8);",
            "r1 += r2;",
            "*(u8 *)(r1 + 0) = r2;",
            "r1 = {two_byte_buf};",
            "r2 = *(u64 *)(r10 -16);",
            "r1 += r2;",
            "*(u8 *)(r1 + 0) = r2;",
            "r0 = 0;",
            "exit;",
            two_byte_buf = in(reg) core::ptr::addr_of!(two_byte_buf),
            out("r0") _,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_load_preserves_const_precision_subreg
extern "C" fn stack_load_preserves_const_precision_subreg() {
    unsafe {
        core::arch::asm!(
            "goto +0;",
            ".8byte 8589412962;",
            "r0 = 1;",
            "*(u32 *)(r10 -16) = r0;",
            "goto +0;",
            "r1 = {two_byte_buf};",
            "r2 = *(u32 *)(r10 -8);",
            "r1 += r2;",
            "*(u8 *)(r1 + 0) = r2;",
            "r1 = {two_byte_buf};",
            "r2 = *(u32 *)(r10 -16);",
            "r1 += r2;",
            "*(u8 *)(r1 + 0) = r2;",
            "r2 = *(u64 *)(r10 -8);",
            "r2 = *(u64 *)(r10 -16);",
            "r0 = 0;",
            "exit;",
            two_byte_buf = in(reg) core::ptr::addr_of!(two_byte_buf),
            out("r0") _,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: spill_32bit_range_track
extern "C" fn spill_32bit_range_track() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "r0 &= 65535;",
            "r1 = r0;",
            "*(u32*)(r10 - 8) = r0;",
            "if r0 < 1 goto l0_10;",
            "r1 = *(u32*)(r10 - 8);",
            "if r1 >= 1 goto l0_10;",
            "r0 = *(u64*)(r9 + 0);",
            "l0_10:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: spill_64bit_of_64bit_ok
extern "C" fn spill_64bit_of_64bit_ok() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 0x80000000;",
            "r0 <<= 32;",
            "*(u64*)(r10 - 8) = r0;",
            "r1 = *(u64*)(r10 - 8);",
            "r2 = 0;",
            "if r1 != r2 goto l0_11;",
            "if r0 == r2 goto l0_11;",
            "r0 = *(u64*)(r9 + 0);",
            "exit;",
            "l0_11:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: spill_32bit_of_32bit_ok
extern "C" fn spill_32bit_of_32bit_ok() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w0 &= 0x80000000;",
            "*(u32*)(r10 - 8) = r0;",
            "r1 = *(u32*)(r10 - 8);",
            "r2 = 0;",
            "if r1 != r2 goto l0_12;",
            "if r0 == r2 goto l0_12;",
            "r0 = *(u64*)(r9 + 0);",
            "exit;",
            "l0_12:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: spill_16bit_of_16bit_ok
extern "C" fn spill_16bit_of_16bit_ok() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 0x8000;",
            "*(u16*)(r10 - 8) = r0;",
            "r1 = *(u16*)(r10 - 8);",
            "r2 = 0;",
            "if r1 != r2 goto l0_13;",
            "if r0 == r2 goto l0_13;",
            "r0 = *(u64*)(r9 + 0);",
            "exit;",
            "l0_13:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: spill_8bit_of_8bit_ok
extern "C" fn spill_8bit_of_8bit_ok() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 0x80;",
            "*(u8*)(r10 - 8) = r0;",
            "r1 = *(u8*)(r10 - 8);",
            "r2 = 0;",
            "if r1 != r2 goto l0_14;",
            "if r0 == r2 goto l0_14;",
            "r0 = *(u64*)(r9 + 0);",
            "exit;",
            "l0_14:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: spill_unbounded
extern "C" fn spill_unbounded() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "*(u64*)(r10 - 8) = r0;",
            "if r0 > 16 goto l0_15;",
            "r0 = *(u64*)(r10 - 8);",
            "if r0 <= 16 goto l0_15;",
            "r0 = *(u64*)(r9 + 0);",
            "l0_15:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: fill_32bit_after_spill_64bit
extern "C" fn fill_32bit_after_spill_64bit() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 <<= 32;",
            "*(u64*)(r10 - 8) = r0;",
            "r0 = *(u32*)(r10 - 8);",
            "if r0 == 0 goto l0_16;",
            "r0 = *(u64*)(r9 + 0);",
            "l0_16:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: fill_32bit_after_spill_64bit_preserve_id
extern "C" fn fill_32bit_after_spill_64bit_preserve_id() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w0 &= 0xffffffff;",
            "*(u64*)(r10 - 8) = r0;",
            "r1 = *(u32*)(r10 - 8);",
            "r2 = 0;",
            "if r1 != r2 goto l0_17;",
            "if r0 == r2 goto l0_17;",
            "r0 = *(u64*)(r9 + 0);",
            "exit;",
            "l0_17:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: fill_32bit_after_spill_64bit_clear_id
extern "C" fn fill_32bit_after_spill_64bit_clear_id() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "call 7;",
            "r0 &= 0x8;",
            "r1 = 0xffffffff;",
            "r1 <<= 32;",
            "r1 += r0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = *(u32*)(r10 - 8);",
            "r3 = 0;",
            "if r2 != r3 goto l0_18;",
            "l0_18:",
            "r1 >>= 32;",
            "r6 += r1;",
            "r0 = *(u32*)(r6 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: old_imprecise_scalar_vs_cur_stack_misc
extern "C" fn old_imprecise_scalar_vs_cur_stack_misc() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "if r0 == 0 goto 1f;",
            "r0 = 42;",
            "*(u64*)(r10 - 8) = r0;",
            "goto 2f;",
            "1:",
            "call 5;",
            "*(u16*)(r10 - 8) = r0;",
            "*(u16*)(r10 - 4) = r0;",
            "2:",
            "r1 = *(u64*)(r10 - 8);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: old_precise_scalar_vs_cur_stack_misc
extern "C" fn old_precise_scalar_vs_cur_stack_misc() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "if r0 == 0 goto 1f;",
            "r0 = 42;",
            "*(u64*)(r10 - 8) = r0;",
            "goto 2f;",
            "1:",
            "call 5;",
            "*(u64*)(r10 - 8) = r0;",
            "*(u32*)(r10 - 4) = r0;",
            "2:",
            "r1 = *(u64*)(r10 - 8);",
            "if r1 == 42 goto +0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: old_stack_misc_vs_cur_scalar
extern "C" fn old_stack_misc_vs_cur_scalar() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "if r0 == 0 goto 1f;",
            "call 5;",
            "*(u16*)(r10 - 8) = r0;",
            "*(u16*)(r10 - 4) = r0;",
            "goto 2f;",
            "1:",
            "r0 = 42;",
            "*(u64*)(r10 - 8) = r0;",
            "2:",
            "r0 = *(u64*)(r10 - 8);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: old_stack_misc_vs_cur_ctx_ptr
extern "C" fn old_stack_misc_vs_cur_ctx_ptr() {
    unsafe {
        core::arch::asm!(
            "r9 = r1;",
            "call 5;",
            "if r0 == 0 goto 1f;",
            "call 5;",
            "*(u64*)(r10 - 8) = r0;",
            "*(u32*)(r10 - 4) = r0;",
            "goto 2f;",
            "1:",
            "*(u64*)(r10 - 8) = r9;",
            "2:",
            "r1 = *(u64*)(r10 - 8);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_noperfmon_reject_invalid_read
extern "C" fn stack_noperfmon_reject_invalid_read() {
    unsafe {
        core::arch::asm!(
            "r2 = 1;",
            "r6 = r10;",
            "r6 += -8;",
            "*(u8 *)(r6 + 0) = r2;",
            "r2 = *(u64 *)(r6 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_noperfmon_spill_32bit_onto_64bit_slot
extern "C" fn stack_noperfmon_spill_32bit_onto_64bit_slot() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "*(u64 *)(r10 - 8) = r0;",
            "*(u32 *)(r10 - 8) = r0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: old_imprecise_scalar32_vs_cur_stack_misc
extern "C" fn old_imprecise_scalar32_vs_cur_stack_misc() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "if r0 == 0 goto 1f;",
            "r0 = 42;",
            "*(u32*)(r10 - 8) = r0;",
            "goto 2f;",
            "1:",
            "call 5;",
            "*(u16*)(r10 - 8) = r0;",
            "*(u16*)(r10 - 6) = r0;",
            "2:",
            "r1 = *(u64*)(r10 - 8);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_noperfmon_reject_atomic_on_narrow_spill
extern "C" fn stack_noperfmon_reject_atomic_on_narrow_spill() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "*(u32 *)(r10 - 8) = r1;",
            "lock *(u64 *)(r10 - 8) += r1;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_noperfmon_reject_helper_read_of_narrow_spill
extern "C" fn stack_noperfmon_reject_helper_read_of_narrow_spill() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "*(u32 *)(r10 - 8) = r1;",
            "r1 = {map_ringbuf} ll;",
            "r2 = r10;",
            "r2 += -8;",
            "r3 = 8;",
            "r4 = 0;",
            "call 130;",
            "r0 = 0;",
            "exit;",
            map_ringbuf = sym map_ringbuf,
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: var_off_write_over_scalar_spill
extern "C" fn var_off_write_over_scalar_spill() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "r6 = r0;",
            "r6 &= 4;",
            "r7 = 0xdeadbeef00000000 ll;",
            "*(u64 *)(r10 - 16) = r7;",
            "r8 = r10;",
            "r8 += r6;",
            "r8 += -12;",
            "r9 = 0;",
            "*(u32 *)(r8 + 0) = r9;",
            "r0 = *(u32 *)(r10 - 16);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: partial_fill_from_cleaned_pointer_spill
extern "C" fn partial_fill_from_cleaned_pointer_spill() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 8) = r1;",
            "goto +0;",
            "r0 = *(u32 *)(r10 - 4);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: imprecise_scalar_spill_half_dead
extern "C" fn imprecise_scalar_spill_half_dead() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "if r0 > 42 goto 1f;",
            "r6 = 0;",
            "goto 2f;",
            "1:",
            "r6 = 100500;",
            "2:",
            "goto +0;",
            "*(u64 *)(r10 - 8) = r6;",
            "goto +0;",
            "r7 = *(u32 *)(r10 - 4);",
            "r1 = {single_byte_buf} ll;",
            "r1 += r7;",
            "r0 = *(u8 *)(r1 + 0);",
            "exit;",
            single_byte_buf = sym single_byte_buf,
            options(nostack)
        );
    }
}

#[link_section = "raw_tracepoint.w"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: spill_fill_ptr_to_tp_buffer
extern "C" fn spill_fill_ptr_to_tp_buffer() {
    unsafe {
        core::arch::asm!(
            "r6 = *(u64*)(r1 + 0);",
            "*(u64*)(r10 - 8) = r6;",
            "r7 = *(u64*)(r10 - 8);",
            "r0 = 0;",
            "*(u64*)(r7 + 0) = r0;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

include!("hand/verifier_spill_fill.rs");

bpf_object!("GPL");
