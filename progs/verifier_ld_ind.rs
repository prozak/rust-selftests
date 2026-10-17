// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]
#![allow(function_casts_as_integer)]

// Translation of tools/testing/selftests/bpf/progs/verifier_ld_ind.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_ld_ind.rs
// (include!d below): ld_abs_callback_reject, ld_ind_callback_subprog_reject, ld_ind_global_static, ld_ind_global, ld_ind_global_callback, ld_ind_global_callback_reject, ld_ind_global_subprog_ok.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_ld_ind` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: ind_check_calling_conv_r1 ind_check_calling_conv_r2 ind_check_calling_conv_r3 ind_check_calling_conv_r4 ind_check_calling_conv_r5 ind_check_calling_conv_r7 ldabs_subprog ldind_subprog ld_abs_subprog_early_exit ld_ind_subprog_early_exit ld_abs_subprog_both_paths_safe ld_ind_subprog_both_paths_safe ld_abs_callback ld_abs_callback_reject ld_ind_callback_subprog ld_ind_callback ld_ind_callback_subprog_reject ld_ind_global_static ld_ind_global ld_ind_global_callback ld_ind_global_callback_reject ld_ind_global_subprog_ok ldabs_void_subprog ld_abs_void_subprog_reject ldind_void_subprog ld_ind_void_subprog_reject

use bpf_rs_core::{bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    ind_check_calling_conv_r1:
        __description("ld_ind: check calling conv, r1"),
        __failure,
        __msg("R1 !read_ok"),
        __failure_unpriv;
    ind_check_calling_conv_r2:
        __description("ld_ind: check calling conv, r2"),
        __failure,
        __msg("R2 !read_ok"),
        __failure_unpriv;
    ind_check_calling_conv_r3:
        __description("ld_ind: check calling conv, r3"),
        __failure,
        __msg("R3 !read_ok"),
        __failure_unpriv;
    ind_check_calling_conv_r4:
        __description("ld_ind: check calling conv, r4"),
        __failure,
        __msg("R4 !read_ok"),
        __failure_unpriv;
    ind_check_calling_conv_r5:
        __description("ld_ind: check calling conv, r5"),
        __failure,
        __msg("R5 !read_ok"),
        __failure_unpriv;
    ind_check_calling_conv_r7:
        __description("ld_ind: check calling conv, r7"),
        __success,
        __success_unpriv,
        __retval("1");
    ld_abs_subprog_early_exit:
        __description("ld_abs: subprog early exit on ld_abs failure"),
        __failure,
        __msg("R9 !read_ok");
    ld_ind_subprog_early_exit:
        __description("ld_ind: subprog early exit on ld_ind failure"),
        __failure,
        __msg("R9 !read_ok");
    ld_abs_subprog_both_paths_safe:
        __description("ld_abs: subprog with both paths safe"),
        __success;
    ld_ind_subprog_both_paths_safe:
        __description("ld_ind: subprog with both paths safe"),
        __success;
    ld_abs_callback_reject:
        __description("ld_abs: reject in callback"),
        __failure,
        __msg("cannot use BPF_LD_[ABS|IND] within callback");
    ld_ind_callback_subprog_reject:
        __description("ld_ind: reject in callback subprog"),
        __failure,
        __msg("cannot use BPF_LD_[ABS|IND] within callback");
    ld_ind_global_callback_reject:
        __description("ld_ind: reject in callback global subprog"),
        __failure,
        __msg("cannot use BPF_LD_[ABS|IND] within callback");
    ld_ind_global_subprog_ok:
        __description("ld_ind: allow in non-callback global subprog"),
        __success;
    ld_abs_void_subprog_reject:
        __description("ld_abs: reject void return subprog"),
        __failure,
        __msg("LD_ABS is only allowed in functions that return 'int'");
    ld_ind_void_subprog_reject:
        __description("ld_ind: reject void return subprog"),
        __failure,
        __msg("LD_ABS is only allowed in functions that return 'int'");
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ind_check_calling_conv_r1
extern "C" fn ind_check_calling_conv_r1() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r1 = 1;",
            ".8byte -9007199254736832;",
            "r0 = r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ind_check_calling_conv_r2
extern "C" fn ind_check_calling_conv_r2() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r2 = 1;",
            ".8byte -9007199254732736;",
            "r0 = r2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ind_check_calling_conv_r3
extern "C" fn ind_check_calling_conv_r3() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r3 = 1;",
            ".8byte -9007199254728640;",
            "r0 = r3;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ind_check_calling_conv_r4
extern "C" fn ind_check_calling_conv_r4() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r4 = 1;",
            ".8byte -9007199254724544;",
            "r0 = r4;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ind_check_calling_conv_r5
extern "C" fn ind_check_calling_conv_r5() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r5 = 1;",
            ".8byte -9007199254720448;",
            "r0 = r5;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ind_check_calling_conv_r7
extern "C" fn ind_check_calling_conv_r7() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r7 = 1;",
            ".8byte -9007199254712256;",
            "r0 = r7;",
            "exit;",
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: ldabs_subprog
extern "C" fn ldabs_subprog() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            ".8byte 32;",
            "r0 = 1;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: ldind_subprog
extern "C" fn ldind_subprog() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r7 = 0;",
            ".8byte 28736;",
            "r0 = 1;",
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
// BPF_NAKED: ld_abs_subprog_early_exit
extern "C" fn ld_abs_subprog_early_exit() {
    unsafe {
        core::arch::asm!(
            "call {ldabs_subprog};",
            "if r0 != 0 goto l_exit_0;",
            "r0 = r9;",
            "l_exit_0:",
            "r0 = 0;",
            "exit;",
            ldabs_subprog = sym ldabs_subprog,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ld_ind_subprog_early_exit
extern "C" fn ld_ind_subprog_early_exit() {
    unsafe {
        core::arch::asm!(
            "call {ldind_subprog};",
            "if r0 != 0 goto l_exit_1;",
            "r0 = r9;",
            "l_exit_1:",
            "r0 = 0;",
            "exit;",
            ldind_subprog = sym ldind_subprog,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ld_abs_subprog_both_paths_safe
extern "C" fn ld_abs_subprog_both_paths_safe() {
    unsafe {
        core::arch::asm!(
            "call {ldabs_subprog};",
            "r0 = 0;",
            "exit;",
            ldabs_subprog = sym ldabs_subprog,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ld_ind_subprog_both_paths_safe
extern "C" fn ld_ind_subprog_both_paths_safe() {
    unsafe {
        core::arch::asm!(
            "call {ldind_subprog};",
            "r0 = 0;",
            "exit;",
            ldind_subprog = sym ldind_subprog,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: ld_abs_callback
extern "C" fn ld_abs_callback() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r6 = *(u64 *)(r2 + 0);",
            ".8byte 32;",
            "r0 = 0;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: ld_ind_callback_subprog
extern "C" fn ld_ind_callback_subprog() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r7 = 0;",
            ".8byte 28736;",
            "r0 = 0;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: ld_ind_callback
extern "C" fn ld_ind_callback() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r1 = *(u64 *)(r2 + 0);",
            "call {ld_ind_callback_subprog};",
            "exit;",
            ld_ind_callback_subprog = sym ld_ind_callback_subprog,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: ldabs_void_subprog
extern "C" fn ldabs_void_subprog() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            ".8byte 32;",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ld_abs_void_subprog_reject
extern "C" fn ld_abs_void_subprog_reject() {
    unsafe {
        core::arch::asm!(
            "call {ldabs_void_subprog};",
            "r0 = 0;",
            "exit;",
            ldabs_void_subprog = sym ldabs_void_subprog,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: ldind_void_subprog
extern "C" fn ldind_void_subprog() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r7 = 0;",
            ".8byte 28736;",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ld_ind_void_subprog_reject
extern "C" fn ld_ind_void_subprog_reject() {
    unsafe {
        core::arch::asm!(
            "call {ldind_void_subprog};",
            "r0 = 0;",
            "exit;",
            ldind_void_subprog = sym ldind_void_subprog,
            options(nostack)
        );
    }
}

include!("hand/verifier_ld_ind.rs");

bpf_object!("GPL");
