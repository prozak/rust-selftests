// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]
#![allow(function_casts_as_integer)]

// Translation of tools/testing/selftests/bpf/progs/verifier_linked_scalars.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_linked_scalars.rs
// (include!d below): alu32_negative_offset, spurious_precision_marks.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_linked_scalars` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: scalars sync_linked_regs_preserves_id scalars_neg scalars_neg_sub scalars_neg_alu32_add scalars_neg_alu32_sub scalars_pos scalars_sub_neg_imm scalars_double_add scalars_sync_delta_overflow scalars_sync_delta_overflow_large_range scalars_alu32_big_offset scalars_alu32_basic scalars_alu32_wrap scalars_alu32_zext_linked_reg scalars_alu32_alu64_cross_type scalars_alu32_alu64_regsafe_pruning alu32_negative_offset dummy_calls spurious_precision_marks scalars_self_add_clears_id scalars_self_add_alu32_clears_id scalars_stale_delta_from_cleared_id scalars_stale_delta_from_cleared_id_alu32 add_const_base_id_pruning

use bpf_rs_core::{bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    scalars:
        __description("scalars: find linked scalars"),
        __failure,
        __msg("math between fp pointer and 2147483647 is not allowed");
    sync_linked_regs_preserves_id:
        __success;
    scalars_neg:
        __success;
    scalars_neg_sub:
        __success;
    scalars_neg_alu32_add:
        __success;
    scalars_neg_alu32_sub:
        __success;
    scalars_pos:
        __success;
    scalars_sub_neg_imm:
        __success;
    scalars_double_add:
        __failure,
        __msg("div by zero");
    scalars_sync_delta_overflow:
        __success;
    scalars_sync_delta_overflow_large_range:
        __success;
    scalars_alu32_big_offset:
        __success;
    scalars_alu32_basic:
        __failure,
        __msg("div by zero");
    scalars_alu32_wrap:
        __success;
    scalars_alu32_zext_linked_reg:
        __success;
    scalars_alu32_alu64_cross_type:
        __failure,
        __msg("div by zero");
    scalars_alu32_alu64_regsafe_pruning:
        __failure,
        __msg("div by zero"),
        __flag("BPF_F_TEST_STATE_FREQ");
    alu32_negative_offset:
        __success;
    spurious_precision_marks:
        __success,
        __flag("BPF_F_TEST_STATE_FREQ");
    scalars_self_add_clears_id:
        __failure,
        __msg("div by zero");
    scalars_self_add_alu32_clears_id:
        __failure,
        __msg("div by zero");
    scalars_stale_delta_from_cleared_id:
        __failure,
        __msg("div by zero");
    scalars_stale_delta_from_cleared_id_alu32:
        __failure,
        __msg("div by zero");
    add_const_base_id_pruning:
        __description("linked scalars: add_const base_id must be consistent for pruning"),
        __failure,
        __msg("invalid variable-offset"),
        __flag("BPF_F_TEST_STATE_FREQ");
}

extern "C" {
    fn bpf_iter_num_new(a0: *mut c_void, a1: i32, a2: i32) -> i32;
    fn bpf_iter_num_next(a0: *mut c_void) -> *mut c_void;
    fn bpf_iter_num_destroy(a0: *mut c_void);
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: scalars
extern "C" fn scalars() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "r1 = 0x80000001 ll;",
            "r1 /= 1;",
            "r2 = r1;",
            "r4 = r1;",
            "w2 += 0x7FFFFFFF;",
            "w4 += 0;",
            "if r2 == 0 goto l0_0;",
            "exit;",
            "l0_0:",
            "r4 >>= 63;",
            "r3 = 1;",
            "r3 -= r4;",
            "r3 *= 0x7FFFFFFF;",
            "r3 += r10;",
            "*(u8*)(r3 - 1) = r0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sync_linked_regs_preserves_id
extern "C" fn sync_linked_regs_preserves_id() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 0xff;",
            "r1 = r0;",
            "r1 += 4;",
            "if r1 < 10 goto l0_1;",
            "r2 = r0;",
            "if r1 < 14 goto l0_1;",
            "if r0 >= 10 goto l0_1;",
            "r0 /= 0;",
            "l0_1:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: scalars_neg
extern "C" fn scalars_neg() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 0xff;",
            "r1 = r0;",
            "r1 += -4;",
            "if r1 s< 0 goto l0_2;",
            "if r0 != 0 goto l0_2;",
            "r0 /= 0;",
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
// BPF_NAKED: scalars_neg_sub
extern "C" fn scalars_neg_sub() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 0xff;",
            "r1 = r0;",
            "r1 -= 4;",
            "if r1 s< 0 goto l0_3;",
            "if r0 != 0 goto l0_3;",
            "r0 /= 0;",
            "l0_3:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: scalars_neg_alu32_add
extern "C" fn scalars_neg_alu32_add() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w0 &= 0xff;",
            "w1 = w0;",
            "w1 += -4;",
            "if w1 s< 0 goto l0_4;",
            "if w0 != 0 goto l0_4;",
            "r0 /= 0;",
            "l0_4:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: scalars_neg_alu32_sub
extern "C" fn scalars_neg_alu32_sub() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w0 &= 0xff;",
            "w1 = w0;",
            "w1 -= 4;",
            "if w1 s< 0 goto l0_5;",
            "if w0 != 0 goto l0_5;",
            "r0 /= 0;",
            "l0_5:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: scalars_pos
extern "C" fn scalars_pos() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 0xff;",
            "r1 = r0;",
            "r1 += 4;",
            "if r1 < 6 goto l0_6;",
            "if r0 != 0 goto l0_6;",
            "r0 /= 0;",
            "l0_6:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: scalars_sub_neg_imm
extern "C" fn scalars_sub_neg_imm() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 0xff;",
            "r1 = r0;",
            "r1 -= -4;",
            "if r1 < 6 goto l0_7;",
            "if r0 != 0 goto l0_7;",
            "r0 /= 0;",
            "l0_7:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: scalars_double_add
extern "C" fn scalars_double_add() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 0xff;",
            "r1 = r0;",
            "r1 += 2;",
            "r1 += 2;",
            "if r1 < 6 goto l0_8;",
            "if r0 != 0 goto l0_8;",
            "r0 /= 0;",
            "l0_8:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: scalars_sync_delta_overflow
extern "C" fn scalars_sync_delta_overflow() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 0xff;",
            "r1 = r0;",
            "r2 = r0;",
            "r1 += -2147483648;",
            "r2 += 1;",
            "if r2 s< 100 goto l0_9;",
            "if r1 s< 0 goto l0_9;",
            "r0 /= 0;",
            "l0_9:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: scalars_sync_delta_overflow_large_range
extern "C" fn scalars_sync_delta_overflow_large_range() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 0xff;",
            "r1 = r0;",
            "r2 = r0;",
            "r1 += 2147483647;",
            "r2 += -1;",
            "if r2 s< 0 goto l0_10;",
            "if r1 s>= 0 goto l0_10;",
            "r0 /= 0;",
            "l0_10:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: scalars_alu32_big_offset
extern "C" fn scalars_alu32_big_offset() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w0 &= 0xff;",
            "w1 = w0;",
            "w1 += 0x7FFFFFFF;",
            "if w1 s>= 0 goto l0_11;",
            "if w0 != 0 goto l0_11;",
            "r0 /= 0;",
            "l0_11:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: scalars_alu32_basic
extern "C" fn scalars_alu32_basic() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = r0;",
            "w1 += 1;",
            "if r1 > 10 goto 1f;",
            "r0 >>= 32;",
            "if r0 == 0 goto 1f;",
            "r0 /= 0;",
            "1: r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: scalars_alu32_wrap
extern "C" fn scalars_alu32_wrap() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w0 |= 0xffffff00;",
            "r1 = r0;",
            "w1 += 0x100;",
            "if r1 > 0x80 goto l0_12;",
            "r2 = r0;",
            "r2 >>= 32;",
            "if r2 == 0 goto l0_12;",
            "r0 /= 0;",
            "l0_12:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: scalars_alu32_zext_linked_reg
extern "C" fn scalars_alu32_zext_linked_reg() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w6 = w0;",
            "r7 = r6;",
            "w7 += 1;",
            "r8 = 0xFFFFffff ll;",
            "if r6 < r8 goto l0_13;",
            "r7 >>= 32;",
            "if r7 == 0 goto l0_13;",
            "r0 /= 0;",
            "l0_13:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: scalars_alu32_alu64_cross_type
extern "C" fn scalars_alu32_alu64_cross_type() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w6 = w0;",
            "r7 = r6;",
            "w7 += 1;",
            "r8 = r6;",
            "r8 += 2;",
            "r9 = 0xFFFFffff ll;",
            "if r7 < r9 goto l0_14;",
            "if r8 > 0 goto l1_14;",
            "goto l0_14;",
            "l1_14:",
            "r0 /= 0;",
            "l0_14:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: scalars_alu32_alu64_regsafe_pruning
extern "C" fn scalars_alu32_alu64_regsafe_pruning() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w6 = w0;",
            "r7 = r6;",
            "call 7;",
            "if r0 > 0 goto l_pathb_15;",
            "w7 += 1;",
            "goto l_merge_15;",
            "l_pathb_15:",
            "r7 += 1;",
            "l_merge_15:",
            "r9 = 0xFFFFffff ll;",
            "if r6 < r9 goto l0_15;",
            "r7 >>= 32;",
            "if r7 == 0 goto l0_15;",
            "r0 /= 0;",
            "l0_15:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

// dummy_calls: the C's reference to each kfunc the asm calls, for its
// BTF prototype (llc emits one only for a real call or address load).
#[no_mangle]
#[inline(never)]
extern "C" fn dummy_calls() {
    unsafe {
        bpf_iter_num_new(core::ptr::null_mut(), 0, 0);
        bpf_iter_num_next(core::ptr::null_mut());
        bpf_iter_num_destroy(core::ptr::null_mut());
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: scalars_self_add_clears_id
extern "C" fn scalars_self_add_clears_id() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r6 = r0;",
            "r7 = r6;",
            "call 7;",
            "r8 = r0;",
            "r9 = r8;",
            "if r7 != 1 goto l_exit_16;",
            "r6 += r6;",
            "if r7 == r9 goto l_exit_16;",
            "if r6 == 3 goto l_exit_16;",
            "r0 /= 0;",
            "l_exit_16:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: scalars_self_add_alu32_clears_id
extern "C" fn scalars_self_add_alu32_clears_id() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w6 = w0;",
            "w7 = w6;",
            "call 7;",
            "w8 = w0;",
            "w9 = w8;",
            "if w7 != 1 goto l_exit_17;",
            "w6 += w6;",
            "if w7 == w9 goto l_exit_17;",
            "if w6 == 3 goto l_exit_17;",
            "r0 /= 0;",
            "l_exit_17:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: scalars_stale_delta_from_cleared_id
extern "C" fn scalars_stale_delta_from_cleared_id() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r6 = r0;",
            "r6 += 5;",
            "r6 ^= 0;",
            "r8 = r6;",
            "r8 += 3;",
            "r9 = r6;",
            "if r9 != 10 goto l_exit_18;",
            "if r8 == 8 goto l_exit_18;",
            "r0 /= 0;",
            "l_exit_18:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: scalars_stale_delta_from_cleared_id_alu32
extern "C" fn scalars_stale_delta_from_cleared_id_alu32() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w6 = w0;",
            "w6 += 5;",
            "w6 ^= 0;",
            "w8 = w6;",
            "w8 += 3;",
            "w9 = w6;",
            "if w9 != 10 goto l_exit_19;",
            "if w8 == 8 goto l_exit_19;",
            "r0 /= 0;",
            "l_exit_19:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: add_const_base_id_pruning
extern "C" fn add_const_base_id_pruning() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 16) = r1;",
            "call 7;",
            "r6 = r0;",
            "r6 &= 1;",
            "if r6 >= 1 goto l_true_20;",
            "call 7;",
            "r2 = r0;",
            "r2 &= 0xff;",
            "r3 = r2;",
            "r3 += 10;",
            "r6 = 0;",
            "goto l_merge_20;",
            "l_true_20:",
            "call 7;",
            "r2 = r0;",
            "r2 &= 0xff;",
            "r4 = r0;",
            "r4 &= 0xff;",
            "r3 = r4;",
            "r3 += 10;",
            "r6 = 0;",
            "l_merge_20:",
            "if r2 >= 6 goto l_exit_20;",
            "r3 -= 10;",
            "r9 = r10;",
            "r9 += -16;",
            "r9 += r3;",
            "*(u8*)(r9 + 0) = r6;",
            "l_exit_20:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

include!("hand/verifier_linked_scalars.rs");

bpf_object!("GPL");
