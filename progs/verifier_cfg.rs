// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_cfg.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_cfg.rs
// (include!d below): tail_call_or_throw_subprog.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_cfg` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: unreachable unreachable2 out_of_range_jump out_of_range_jump2 cross_subprog_target jump_across_subprog_boundary fallthrough_subprog subprog_fallthrough invalid_dw_ldsx loop_back_edge loop2_back_edge conditional_loop conditional_loop2 uncond_loop_after_cond_jmp never_ending_subprog uncond_loop_in_subprog_after_cond_jmp tail_call_or_throw_subprog tail_call_in_subprog_without_exit

use bpf_rs_core::{bpf_map, bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    unreachable:
        __description("unreachable"),
        __failure,
        __msg("unreachable"),
        __failure_unpriv;
    unreachable2:
        __description("unreachable2"),
        __failure,
        __msg("unreachable"),
        __failure_unpriv;
    out_of_range_jump:
        __description("out of range jump"),
        __failure,
        __msg("jump out of range"),
        __failure_unpriv;
    out_of_range_jump2:
        __description("out of range jump2"),
        __failure,
        __msg("jump out of range"),
        __failure_unpriv;
    jump_across_subprog_boundary:
        __description("jump across subprogram boundary"),
        __failure,
        __msg("jump out of range from insn 1"),
        __msg("jump_across_subprog_boundary @ verifier_cfg.rs");
    subprog_fallthrough:
        __description("subprogram fallthrough"),
        __failure,
        __msg("last insn is not an exit or jmp"),
        __msg("fallthrough_subprog @ verifier_cfg.rs");
    invalid_dw_ldsx:
        __description("invalid DW LDSX instruction in diagnostics"),
        __failure,
        __msg("BUG_ldx_99"),
        __log_level("2");
    loop_back_edge:
        __description("loop (back-edge)"),
        __failure,
        __msg("unreachable insn 1"),
        __msg_unpriv("back-edge");
    loop2_back_edge:
        __description("loop2 (back-edge)"),
        __failure,
        __msg("unreachable insn 4"),
        __msg_unpriv("back-edge");
    conditional_loop:
        __description("conditional loop"),
        __failure,
        __msg("infinite loop detected"),
        __msg_unpriv("back-edge");
    conditional_loop2:
        __description("conditional loop (2)"),
        __success,
        __failure_unpriv,
        __msg_unpriv("back-edge from insn 10 to 11");
    uncond_loop_after_cond_jmp:
        __description("unconditional loop after conditional jump"),
        __failure,
        __msg("infinite loop detected"),
        __failure_unpriv,
        __msg_unpriv("back-edge from insn 3 to 2");
    uncond_loop_in_subprog_after_cond_jmp:
        __description("unconditional loop after conditional jump"),
        __failure,
        __msg("infinite loop detected");
    tail_call_in_subprog_without_exit:
        __description("tail call in a subprogram without an exit"),
        __arch_x86_64,
        __arch_arm64,
        __success;
}

bpf_map! {
    map_array {
        r#type: *const [i32; 3],
        max_entries: *const [i32; 1],
        key: *const u32,
        value: *const u32,
    }
}

extern "C" {
    fn bpf_throw(a0: u64);
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: unreachable
extern "C" fn unreachable() {
    unsafe {
        core::arch::asm!(
            "exit;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: unreachable2
extern "C" fn unreachable2() {
    unsafe {
        core::arch::asm!(
            "goto l0_0;",
            "goto l0_0;",
            "l0_0:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: out_of_range_jump
extern "C" fn out_of_range_jump() {
    unsafe {
        core::arch::asm!(
            "goto l0_1;",
            "exit;",
            "l0_1:",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: out_of_range_jump2
extern "C" fn out_of_range_jump2() {
    unsafe {
        core::arch::asm!(
            "goto -2;",
            "exit;",
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: cross_subprog_target
extern "C" fn cross_subprog_target() -> i32 {
    let ret: i32;
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

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jump_across_subprog_boundary
extern "C" fn jump_across_subprog_boundary() {
    unsafe {
        core::arch::asm!(
            "call {cross_subprog_target};",
            "goto +1;",
            "exit;",
            cross_subprog_target = sym cross_subprog_target,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: fallthrough_subprog
extern "C" fn fallthrough_subprog() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: subprog_fallthrough
extern "C" fn subprog_fallthrough() {
    unsafe {
        core::arch::asm!(
            "call {fallthrough_subprog};",
            "exit;",
            fallthrough_subprog = sym fallthrough_subprog,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: invalid_dw_ldsx
extern "C" fn invalid_dw_ldsx() {
    unsafe {
        core::arch::asm!(
            ".8byte 153;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: loop_back_edge
extern "C" fn loop_back_edge() {
    unsafe {
        core::arch::asm!(
            "l0_2:",
            "goto l0_2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: loop2_back_edge
extern "C" fn loop2_back_edge() {
    unsafe {
        core::arch::asm!(
            "l0_3:",
            "r1 = r0;",
            "r2 = r0;",
            "r3 = r0;",
            "goto l0_3;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: conditional_loop
extern "C" fn conditional_loop() {
    unsafe {
        core::arch::asm!(
            "r0 = r1;",
            "l0_4:",
            "r2 = r0;",
            "r3 = r0;",
            "if r1 == 0 goto l0_4;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: conditional_loop2
extern "C" fn conditional_loop2() {
    unsafe {
        core::arch::asm!(
            "r9 = 2 ll;",
            "r3 = 0x20 ll;",
            "r4 = 0x35 ll;",
            "r8 = r4;",
            "goto l1_5;",
            "l0_5:",
            "r9 -= r3;",
            "r9 -= r4;",
            "r9 -= r8;",
            "l1_5:",
            "r8 += r4;",
            "if r8 < 0x64 goto l0_5;",
            "r0 = r9;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: uncond_loop_after_cond_jmp
extern "C" fn uncond_loop_after_cond_jmp() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "if r0 > 0 goto l1_6;",
            "l0_6:",
            "r0 = 1;",
            "goto l0_6;",
            "l1_6:",
            "exit;",
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: never_ending_subprog
extern "C" fn never_ending_subprog() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "r0 = r1;",
            "goto -1;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: uncond_loop_in_subprog_after_cond_jmp
extern "C" fn uncond_loop_in_subprog_after_cond_jmp() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "if r0 > 0 goto l1_7;",
            "l0_7:",
            "r0 += 1;",
            "call {never_ending_subprog};",
            "l1_7:",
            "exit;",
            never_ending_subprog = sym never_ending_subprog,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: tail_call_in_subprog_without_exit
extern "C" fn tail_call_in_subprog_without_exit() {
    unsafe {
        core::arch::asm!(
            "call {tail_call_or_throw_subprog};",
            "exit;",
            tail_call_or_throw_subprog = sym tail_call_or_throw_subprog,
            options(nostack)
        );
    }
}

include!("hand/verifier_cfg.rs");

bpf_object!("GPL");
