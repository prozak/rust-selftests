// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]
#![feature(linkage)]

// Translation of tools/testing/selftests/bpf/progs/verifier_precision.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_precision.rs
// (include!d below): subprog_mem_arg, null_kfunc_arg_dynptr_slice.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_precision` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: bpf_neg bpf_end_to_le bpf_end_to_be bpf_end_bswap bpf_load_acquire bpf_store_release state_loop_first_last_equal __bpf_cond_op_r10 bpf_cond_op_r10 bpf_cond_op_not_r10 bpf_neg_2 bpf_neg_3 bpf_neg_4 bpf_neg_5 bpf_atomic_fetch_add_precision bpf_atomic_xchg_precision bpf_atomic_fetch_or_precision bpf_atomic_fetch_and_precision bpf_atomic_fetch_xor_precision bpf_atomic_cmpxchg_precision bpf_atomic_fetch_add_dual_precision bpf_atomic_cmpxchg_dual_precision bpf_atomic_fetch_add_map_precision bpf_atomic_cmpxchg_map_precision bpf_atomic_fetch_add_32bit_precision bpf_atomic_cmpxchg_32bit_precision null_mem_arg_zero_size subprog_mem_arg null_mem_arg_global_subprog null_kfunc_arg_dynptr_slice __kfunc_btf_root

use bpf_rs_core::{bpf_map, bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    bpf_neg:
        __success,
        __log_level("2"),
        __msg("mark_precise: frame0: regs=r2 stack= before 3: (bf) r1 = r10"),
        __msg("mark_precise: frame0: regs=r2 stack= before 2: (55) if r2 != 0xfffffff8 goto pc+2"),
        __msg("mark_precise: frame0: regs=r2 stack= before 1: (87) r2 = -r2"),
        __msg("mark_precise: frame0: regs=r2 stack= before 0: (b7) r2 = 8");
    bpf_end_to_le:
        __success,
        __log_level("2"),
        __msg("mark_precise: frame0: regs=r2 stack= before 3: (bf) r1 = r10"),
        __msg("mark_precise: frame0: regs=r2 stack= before 2: (55) if r2 != 0x0 goto pc+2"),
        __msg("mark_precise: frame0: regs=r2 stack= before 1: (d4) r2 = le16 r2"),
        __msg("mark_precise: frame0: regs=r2 stack= before 0: (b7) r2 = 0");
    bpf_end_to_be:
        __success,
        __log_level("2"),
        __msg("mark_precise: frame0: regs=r2 stack= before 3: (bf) r1 = r10"),
        __msg("mark_precise: frame0: regs=r2 stack= before 2: (55) if r2 != 0x0 goto pc+2"),
        __msg("mark_precise: frame0: regs=r2 stack= before 1: (dc) r2 = be16 r2"),
        __msg("mark_precise: frame0: regs=r2 stack= before 0: (b7) r2 = 0");
    bpf_end_bswap:
        __success,
        __log_level("2"),
        __msg("mark_precise: frame0: regs=r2 stack= before 3: (bf) r1 = r10"),
        __msg("mark_precise: frame0: regs=r2 stack= before 2: (55) if r2 != 0x0 goto pc+2"),
        __msg("mark_precise: frame0: regs=r2 stack= before 1: (d7) r2 = bswap16 r2"),
        __msg("mark_precise: frame0: regs=r2 stack= before 0: (b7) r2 = 0");
    bpf_load_acquire:
        __success,
        __log_level("2"),
        __msg("mark_precise: frame0: regs=r2 stack= before 3: (bf) r3 = r10"),
        __msg("mark_precise: frame0: regs=r2 stack= before 2: (db) r2 = load_acquire((u64 *)(r10 -8))"),
        __msg("mark_precise: frame0: regs= stack=-8 before 1: (7b) *(u64 *)(r10 -8) = r1"),
        __msg("mark_precise: frame0: regs=r1 stack= before 0: (b7) r1 = 8");
    bpf_store_release:
        __success,
        __log_level("2"),
        __msg("mark_precise: frame0: regs=r1 stack= before 3: (bf) r2 = r10"),
        __msg("mark_precise: frame0: regs=r1 stack= before 2: (79) r1 = *(u64 *)(r10 -8)"),
        __msg("mark_precise: frame0: regs= stack=-8 before 1: (db) store_release((u64 *)(r10 -8), r1)"),
        __msg("mark_precise: frame0: regs=r1 stack= before 0: (b7) r1 = 8");
    state_loop_first_last_equal:
        __success,
        __log_level("2"),
        __msg("2: (07) r0 += 1                       ; R0=6"),
        __msg("3: (35) if r0 >= 0xa goto pc+1"),
        __msg("mark_precise: frame0: last_idx 3 first_idx 3 subseq_idx -1"),
        __msg("mark_precise: frame0: regs=r0 stack= before 2: (07) r0 += 1"),
        __msg("mark_precise: frame0: regs=r0 stack= before 1: (07) r0 += 1"),
        __msg("mark_precise: frame0: regs=r0 stack= before 4: (05) goto pc-4"),
        __msg("mark_precise: frame0: regs=r0 stack= before 3: (35) if r0 >= 0xa goto pc+1"),
        __msg("mark_precise: frame0: parent state regs= stack=:  R0=P4"),
        __msg("3: R0=6");
    bpf_cond_op_r10:
        __success,
        __log_level("2"),
        __msg("8: (bd) if r2 <= r10 goto pc+3"),
        __msg("9: (35) if r1 >= 0xffe3fff8 goto pc+0"),
        __msg("10: (b5) if r2 <= 0x8 goto pc+0"),
        __msg("mark_precise: frame1: last_idx 10 first_idx 0 subseq_idx -1"),
        __msg("mark_precise: frame1: regs=r2 stack= before 9: (35) if r1 >= 0xffe3fff8 goto pc+0"),
        __msg("mark_precise: frame1: regs=r2 stack= before 8: (bd) if r2 <= r10 goto pc+3"),
        __msg("mark_precise: frame1: regs=r2 stack= before 7: (05) goto pc+0");
    bpf_cond_op_not_r10:
        __success,
        __log_level("2"),
        __msg("3: (bf) r3 = r10"),
        __msg("4: (bd) if r3 <= r2 goto pc+1"),
        __msg("5: (b5) if r2 <= 0x8 goto pc+2"),
        __msg("mark_precise: frame0: last_idx 5 first_idx 0 subseq_idx -1"),
        __msg("mark_precise: frame0: regs=r2 stack= before 4: (bd) if r3 <= r2 goto pc+1"),
        __msg("mark_precise: frame0: regs=r2 stack= before 3: (bf) r3 = r10");
    bpf_neg_2:
        __success,
        __log_level("2"),
        __msg("0: (b7) r0 = 1                        ; R0=1"),
        __msg("1: (84) w0 = -w0                      ; R0=0xffffffff"),
        __msg("mark_precise: frame0: last_idx 2 first_idx 0 subseq_idx -1"),
        __msg("mark_precise: frame0: regs=r0 stack= before 1: (84) w0 = -w0"),
        __msg("mark_precise: frame0: regs=r0 stack= before 0: (b7) r0 = 1");
    bpf_neg_3:
        __failure,
        __msg("At program exit the register R0 has");
    bpf_neg_4:
        __success,
        __log_level("2"),
        __msg("0: (b7) r0 = 1                        ; R0=1"),
        __msg("1: (87) r0 = -r0                      ; R0=-1"),
        __msg("mark_precise: frame0: last_idx 2 first_idx 0 subseq_idx -1"),
        __msg("mark_precise: frame0: regs=r0 stack= before 1: (87) r0 = -r0"),
        __msg("mark_precise: frame0: regs=r0 stack= before 0: (b7) r0 = 1");
    bpf_neg_5:
        __failure,
        __msg("At program exit the register R0 has");
    bpf_atomic_fetch_add_precision:
        __success,
        __log_level("2"),
        __msg("mark_precise: frame0: regs=r2 stack= before 4: (bf) r3 = r10"),
        __msg("mark_precise: frame0: regs=r2 stack= before 3: (db) r2 = atomic64_fetch_add((u64 *)(r10 -8), r2)"),
        __msg("mark_precise: frame0: regs= stack=-8 before 2: (b7) r2 = 0"),
        __msg("mark_precise: frame0: regs= stack=-8 before 1: (7b) *(u64 *)(r10 -8) = r1"),
        __msg("mark_precise: frame0: regs=r1 stack= before 0: (b7) r1 = 8");
    bpf_atomic_xchg_precision:
        __success,
        __log_level("2"),
        __msg("mark_precise: frame0: regs=r2 stack= before 4: (bf) r3 = r10"),
        __msg("mark_precise: frame0: regs=r2 stack= before 3: (db) r2 = atomic64_xchg((u64 *)(r10 -8), r2)"),
        __msg("mark_precise: frame0: regs= stack=-8 before 2: (b7) r2 = 0"),
        __msg("mark_precise: frame0: regs= stack=-8 before 1: (7b) *(u64 *)(r10 -8) = r1"),
        __msg("mark_precise: frame0: regs=r1 stack= before 0: (b7) r1 = 8");
    bpf_atomic_fetch_or_precision:
        __success,
        __log_level("2"),
        __msg("mark_precise: frame0: regs=r2 stack= before 4: (bf) r3 = r10"),
        __msg("mark_precise: frame0: regs=r2 stack= before 3: (db) r2 = atomic64_fetch_or((u64 *)(r10 -8), r2)"),
        __msg("mark_precise: frame0: regs= stack=-8 before 2: (b7) r2 = 0"),
        __msg("mark_precise: frame0: regs= stack=-8 before 1: (7b) *(u64 *)(r10 -8) = r1"),
        __msg("mark_precise: frame0: regs=r1 stack= before 0: (b7) r1 = 8");
    bpf_atomic_fetch_and_precision:
        __success,
        __log_level("2"),
        __msg("mark_precise: frame0: regs=r2 stack= before 4: (bf) r3 = r10"),
        __msg("mark_precise: frame0: regs=r2 stack= before 3: (db) r2 = atomic64_fetch_and((u64 *)(r10 -8), r2)"),
        __msg("mark_precise: frame0: regs= stack=-8 before 2: (b7) r2 = 0"),
        __msg("mark_precise: frame0: regs= stack=-8 before 1: (7b) *(u64 *)(r10 -8) = r1"),
        __msg("mark_precise: frame0: regs=r1 stack= before 0: (b7) r1 = 8");
    bpf_atomic_fetch_xor_precision:
        __success,
        __log_level("2"),
        __msg("mark_precise: frame0: regs=r2 stack= before 4: (bf) r3 = r10"),
        __msg("mark_precise: frame0: regs=r2 stack= before 3: (db) r2 = atomic64_fetch_xor((u64 *)(r10 -8), r2)"),
        __msg("mark_precise: frame0: regs= stack=-8 before 2: (b7) r2 = 0"),
        __msg("mark_precise: frame0: regs= stack=-8 before 1: (7b) *(u64 *)(r10 -8) = r1"),
        __msg("mark_precise: frame0: regs=r1 stack= before 0: (b7) r1 = 8");
    bpf_atomic_cmpxchg_precision:
        __success,
        __log_level("2"),
        __msg("mark_precise: frame0: regs=r0 stack= before 5: (bf) r3 = r10"),
        __msg("mark_precise: frame0: regs=r0 stack= before 4: (db) r0 = atomic64_cmpxchg((u64 *)(r10 -8), r0, r2)"),
        __msg("mark_precise: frame0: regs= stack=-8 before 3: (b7) r2 = 0"),
        __msg("mark_precise: frame0: regs= stack=-8 before 2: (b7) r0 = 0"),
        __msg("mark_precise: frame0: regs= stack=-8 before 1: (7b) *(u64 *)(r10 -8) = r1"),
        __msg("mark_precise: frame0: regs=r1 stack= before 0: (b7) r1 = 8");
    bpf_atomic_fetch_add_dual_precision:
        __success,
        __log_level("2"),
        __msg("mark_precise: frame0: regs=r2,r3 stack= before 4: (79) r3 = *(u64 *)(r10 -8)"),
        __msg("mark_precise: frame0: regs=r2 stack= before 3: (db) r2 = atomic64_fetch_add((u64 *)(r10 -8), r2)"),
        __msg("mark_precise: frame0: regs= stack=-8 before 2: (b7) r2 = 0"),
        __msg("mark_precise: frame0: regs= stack=-8 before 1: (7b) *(u64 *)(r10 -8) = r1"),
        __msg("mark_precise: frame0: regs=r1 stack= before 0: (b7) r1 = 8");
    bpf_atomic_cmpxchg_dual_precision:
        __success,
        __log_level("2"),
        __msg("mark_precise: frame0: regs=r0,r3 stack= before 5: (79) r3 = *(u64 *)(r10 -8)"),
        __msg("mark_precise: frame0: regs=r0 stack= before 4: (db) r0 = atomic64_cmpxchg((u64 *)(r10 -8), r0, r2)"),
        __msg("mark_precise: frame0: regs= stack=-8 before 3: (b7) r2 = 0"),
        __msg("mark_precise: frame0: regs= stack=-8 before 2: (b7) r0 = 8"),
        __msg("mark_precise: frame0: regs= stack=-8 before 1: (7b) *(u64 *)(r10 -8) = r1"),
        __msg("mark_precise: frame0: regs=r1 stack= before 0: (b7) r1 = 8");
    bpf_atomic_fetch_add_map_precision:
        __success,
        __log_level("2"),
        __msg("mark_precise: frame0: regs=r1 stack= before 10: (57) r1 &= 7"),
        __msg("mark_precise: frame0: regs=r1 stack= before 9: (db) r1 = atomic64_fetch_add((u64 *)(r0 +0), r1)"),
        __not_msg("falling back to forcing all scalars precise");
    bpf_atomic_cmpxchg_map_precision:
        __success,
        __log_level("2"),
        __msg("mark_precise: frame0: regs=r0 stack= before 12: (57) r0 &= 7"),
        __msg("mark_precise: frame0: regs=r0 stack= before 11: (db) r0 = atomic64_cmpxchg((u64 *)(r6 +0), r0, r1)"),
        __not_msg("falling back to forcing all scalars precise");
    bpf_atomic_fetch_add_32bit_precision:
        __success,
        __log_level("2"),
        __msg("mark_precise: frame0: regs=r1 stack= before 10: (57) r1 &= 7"),
        __msg("mark_precise: frame0: regs=r1 stack= before 9: (c3) r1 = atomic_fetch_add((u32 *)(r0 +0), r1)"),
        __not_msg("falling back to forcing all scalars precise");
    bpf_atomic_cmpxchg_32bit_precision:
        __success,
        __log_level("2"),
        __msg("mark_precise: frame0: regs=r0 stack= before 12: (57) r0 &= 7"),
        __msg("mark_precise: frame0: regs=r0 stack= before 11: (c3) r0 = atomic_cmpxchg((u32 *)(r6 +0), r0, r1)"),
        __not_msg("falling back to forcing all scalars precise");
    null_mem_arg_zero_size:
        __flag("BPF_F_TEST_STATE_FREQ"),
        __failure,
        __msg("R1 type=scalar expected=fp");
    null_mem_arg_global_subprog:
        __flag("BPF_F_TEST_STATE_FREQ"),
        __failure,
        __msg("R1 type=scalar expected=fp");
    null_kfunc_arg_dynptr_slice:
        __flag("BPF_F_TEST_STATE_FREQ"),
        __failure,
        __msg("R3 type=scalar expected=fp");
}

bpf_map! {
    precision_map {
        r#type: *const [i32; 2],
        max_entries: *const [i32; 1],
        key: *const u32,
        value: *const u64,
    }
}

extern "C" {
    fn bpf_dynptr_from_skb(a0: *mut c_void, a1: u64, a2: *mut c_void) -> i32;
    fn bpf_dynptr_slice(a0: *mut c_void, a1: u64, a2: *mut c_void, a3: u64) -> *mut c_void;
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bpf_neg
extern "C" fn bpf_neg() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r2 = 8;",
            "r2 = -r2;",
            "if r2 != -8 goto 1f;",
            "r1 = r10;",
            "r1 += r2;",
            "1:",
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
// BPF_NAKED: bpf_end_to_le
extern "C" fn bpf_end_to_le() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "r2 = le16 r2;",
            "if r2 != 0 goto 1f;",
            "r1 = r10;",
            "r1 += r2;",
            "1:",
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
// BPF_NAKED: bpf_end_to_be
extern "C" fn bpf_end_to_be() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "r2 = be16 r2;",
            "if r2 != 0 goto 1f;",
            "r1 = r10;",
            "r1 += r2;",
            "1:",
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
// BPF_NAKED: bpf_end_bswap
extern "C" fn bpf_end_bswap() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "r2 = bswap16 r2;",
            "if r2 != 0 goto 1f;",
            "r1 = r10;",
            "r1 += r2;",
            "1:",
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
// BPF_NAKED: bpf_load_acquire
extern "C" fn bpf_load_acquire() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r1 = 8;",
            "*(u64 *)(r10 - 8) = r1;",
            ".8byte 1103806112475;",
            "r3 = r10;",
            "r3 += r2;",
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
// BPF_NAKED: bpf_store_release
extern "C" fn bpf_store_release() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r1 = 8;",
            ".8byte 1172525554395;",
            "r1 = *(u64 *)(r10 - 8);",
            "r2 = r10;",
            "r2 += r1;",
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
// BPF_NAKED: state_loop_first_last_equal
extern "C" fn state_loop_first_last_equal() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "l0_0:",
            "r0 += 1;",
            "r0 += 1;",
            "if r0 >= 10 goto l1_0;",
            "goto l0_0;",
            "l1_0:",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: __bpf_cond_op_r10
extern "C" fn __bpf_cond_op_r10() {
    unsafe {
        core::arch::asm!(
            "r2 = 2314885393468386424 ll;",
            "goto +0;",
            "if r2 <= r10 goto +3;",
            "if r1 >= -1835016 goto +0;",
            "if r2 <= 8 goto +0;",
            "if r3 <= 0 goto +0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bpf_cond_op_r10
extern "C" fn bpf_cond_op_r10() {
    unsafe {
        core::arch::asm!(
            "r3 = 0 ll;",
            "call {__bpf_cond_op_r10};",
            "r0 = 0;",
            "exit;",
            __bpf_cond_op_r10 = sym __bpf_cond_op_r10,
            options(nostack)
        );
    }
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bpf_cond_op_not_r10
extern "C" fn bpf_cond_op_not_r10() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "r2 = 2314885393468386424 ll;",
            "r3 = r10;",
            "if r3 <= r2 goto +1;",
            "if r2 <= 8 goto +2;",
            "r0 = 2 ll;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "lsm.s/socket_connect"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bpf_neg_2
extern "C" fn bpf_neg_2() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r0 = 1;",
            "w0 = -w0;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "lsm.s/socket_connect"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bpf_neg_3
extern "C" fn bpf_neg_3() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r0 = 10000;",
            "w0 = -w0;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "lsm.s/socket_connect"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bpf_neg_4
extern "C" fn bpf_neg_4() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r0 = 1;",
            "r0 = -r0;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "lsm.s/socket_connect"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bpf_neg_5
extern "C" fn bpf_neg_5() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r0 = 10000;",
            "r0 = -r0;",
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
// BPF_NAKED: bpf_atomic_fetch_add_precision
extern "C" fn bpf_atomic_fetch_add_precision() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r1 = 8;",
            "*(u64 *)(r10 - 8) = r1;",
            "r2 = 0;",
            ".8byte 8589421275;",
            "r3 = r10;",
            "r3 += r2;",
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
// BPF_NAKED: bpf_atomic_xchg_precision
extern "C" fn bpf_atomic_xchg_precision() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r1 = 8;",
            "*(u64 *)(r10 - 8) = r1;",
            "r2 = 0;",
            ".8byte 970662095579;",
            "r3 = r10;",
            "r3 += r2;",
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
// BPF_NAKED: bpf_atomic_fetch_or_precision
extern "C" fn bpf_atomic_fetch_or_precision() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r1 = 8;",
            "*(u64 *)(r10 - 8) = r1;",
            "r2 = 0;",
            ".8byte 283467328219;",
            "r3 = r10;",
            "r3 += r2;",
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
// BPF_NAKED: bpf_atomic_fetch_and_precision
extern "C" fn bpf_atomic_fetch_and_precision() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r1 = 8;",
            "*(u64 *)(r10 - 8) = r1;",
            "r2 = 0;",
            ".8byte 352186804955;",
            "r3 = r10;",
            "r3 += r2;",
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
// BPF_NAKED: bpf_atomic_fetch_xor_precision
extern "C" fn bpf_atomic_fetch_xor_precision() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r1 = 8;",
            "*(u64 *)(r10 - 8) = r1;",
            "r2 = 0;",
            ".8byte 695784188635;",
            "r3 = r10;",
            "r3 += r2;",
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
// BPF_NAKED: bpf_atomic_cmpxchg_precision
extern "C" fn bpf_atomic_cmpxchg_precision() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r1 = 8;",
            "*(u64 *)(r10 - 8) = r1;",
            "r0 = 0;",
            "r2 = 0;",
            ".8byte 1039381572315;",
            "r3 = r10;",
            "r3 += r0;",
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
// BPF_NAKED: bpf_atomic_fetch_add_dual_precision
extern "C" fn bpf_atomic_fetch_add_dual_precision() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r1 = 8;",
            "*(u64 *)(r10 - 8) = r1;",
            "r2 = 0;",
            ".8byte 8589421275;",
            "r3 = *(u64 *)(r10 - 8);",
            "r4 = r2;",
            "r4 += r3;",
            "r4 &= 7;",
            "r5 = r10;",
            "r5 += r4;",
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
// BPF_NAKED: bpf_atomic_cmpxchg_dual_precision
extern "C" fn bpf_atomic_cmpxchg_dual_precision() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r1 = 8;",
            "*(u64 *)(r10 - 8) = r1;",
            "r0 = 8;",
            "r2 = 0;",
            ".8byte 1039381572315;",
            "r3 = *(u64 *)(r10 - 8);",
            "r4 = r0;",
            "r4 += r3;",
            "r4 &= 7;",
            "r5 = r10;",
            "r5 += r4;",
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
// BPF_NAKED: bpf_atomic_fetch_add_map_precision
extern "C" fn bpf_atomic_fetch_add_map_precision() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64 *)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {precision_map} ll;",
            "call 1;",
            "if r0 == 0 goto 1f;",
            "r1 = 0;",
            ".8byte 4294971611;",
            "r1 &= 7;",
            "r2 = r10;",
            "r2 += r1;",
            "1:",
            "r0 = 0;",
            "exit;",
            precision_map = sym precision_map,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bpf_atomic_cmpxchg_map_precision
extern "C" fn bpf_atomic_cmpxchg_map_precision() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64 *)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {precision_map} ll;",
            "call 1;",
            "if r0 == 0 goto 1f;",
            "r6 = r0;",
            "r0 = 0;",
            "r1 = 0;",
            ".8byte 1035087124187;",
            "r0 &= 7;",
            "r2 = r10;",
            "r2 += r0;",
            "1:",
            "r0 = 0;",
            "exit;",
            precision_map = sym precision_map,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bpf_atomic_fetch_add_32bit_precision
extern "C" fn bpf_atomic_fetch_add_32bit_precision() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64 *)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {precision_map} ll;",
            "call 1;",
            "if r0 == 0 goto 1f;",
            "r1 = 0;",
            ".8byte 4294971587;",
            "r1 &= 7;",
            "r2 = r10;",
            "r2 += r1;",
            "1:",
            "r0 = 0;",
            "exit;",
            precision_map = sym precision_map,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bpf_atomic_cmpxchg_32bit_precision
extern "C" fn bpf_atomic_cmpxchg_32bit_precision() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64 *)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {precision_map} ll;",
            "call 1;",
            "if r0 == 0 goto 1f;",
            "r6 = r0;",
            "r0 = 0;",
            "r1 = 0;",
            ".8byte 1035087124163;",
            "r0 &= 7;",
            "r2 = r10;",
            "r2 += r0;",
            "1:",
            "r0 = 0;",
            "exit;",
            precision_map = sym precision_map,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "?tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: null_mem_arg_zero_size
extern "C" fn null_mem_arg_zero_size() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = 42;",
            "if r0 > 42 goto 1f;",
            "r1 = 0;",
            "1:",
            "r2 = 0;",
            "r3 = 0;",
            "r4 = 0;",
            "r5 = 0;",
            "call 28;",
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
// BPF_NAKED: null_mem_arg_global_subprog
extern "C" fn null_mem_arg_global_subprog() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = 42;",
            "if r0 > 42 goto 1f;",
            "r1 = 0;",
            "1:",
            "call {subprog_mem_arg};",
            "r0 = 0;",
            "exit;",
            subprog_mem_arg = sym subprog_mem_arg,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

// __kfunc_btf_root: the C's reference to each kfunc the asm calls, for its
// BTF prototype (llc emits one only for a real call or address load).
#[no_mangle]
#[inline(never)]
extern "C" fn __kfunc_btf_root() {
    unsafe {
        bpf_dynptr_slice(core::ptr::null_mut(), 0, core::ptr::null_mut(), 0);
    }
}

include!("hand/verifier_precision.rs");

bpf_object!("GPL");
