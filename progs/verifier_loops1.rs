// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_loops1.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_loops1` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: bounded_loop_count_to_4 bounded_loop_count_to_20 from_positive_unknown_to_4 from_totally_unknown_to_4 count_to_4_with_equality loop_start_in_the_middle loop_containing_a_forward_jump jumps_out_rather_than_in loop_after_a_conditional_jump bounded_recursion bounded_recursion__1 infinite_loop_in_two_jumps infinite_loop_three_jump_trick back_jump_to_1st_insn_1 back_jump_to_1st_insn_2 back_jump_to_1st_insn_2__1 jump_to_1st_insn_2 jump_to_1st_insn_2__1 not_an_inifinite_loop maybe_exit_scc_bug1 loop_stack_frames_reg bounded_loop_stack_frames_reg

use bpf_rs_core::{bpf_object, test_tags};

test_tags! {
    bounded_loop_count_to_4:
        __description("bounded loop, count to 4"),
        __success,
        __retval("4");
    bounded_loop_count_to_20:
        __description("bounded loop, count to 20"),
        __success;
    from_positive_unknown_to_4:
        __description("bounded loop, count from positive unknown to 4"),
        __success;
    from_totally_unknown_to_4:
        __description("bounded loop, count from totally unknown to 4"),
        __success;
    count_to_4_with_equality:
        __description("bounded loop, count to 4 with equality"),
        __success;
    loop_start_in_the_middle:
        __description("bounded loop, start in the middle"),
        __success,
        __failure_unpriv,
        __msg_unpriv("back-edge");
    loop_containing_a_forward_jump:
        __description("bounded loop containing a forward jump"),
        __success,
        __retval("4");
    jumps_out_rather_than_in:
        __description("bounded loop that jumps out rather than in"),
        __success;
    loop_after_a_conditional_jump:
        __description("infinite loop after a conditional jump"),
        __failure,
        __msg("program is too large");
    bounded_recursion:
        __description("bounded recursion"),
        __failure,
        __msg("recursive call from");
    infinite_loop_in_two_jumps:
        __description("infinite loop in two jumps"),
        __failure,
        __msg("loop detected");
    infinite_loop_three_jump_trick:
        __description("infinite loop: three-jump trick"),
        __failure,
        __msg("loop detected");
    back_jump_to_1st_insn_1:
        __description("not-taken loop with back jump to 1st insn"),
        __success,
        __retval("123");
    back_jump_to_1st_insn_2:
        __description("taken loop with back jump to 1st insn"),
        __success,
        __retval("55");
    jump_to_1st_insn_2:
        __description("taken loop with back jump to 1st insn, 2"),
        __success,
        __retval("55");
    not_an_inifinite_loop:
        __success;
    maybe_exit_scc_bug1:
        __arch_x86_64,
        __caps_unpriv("39");
    bounded_loop_stack_frames_reg:
        __description("bounded loop changing stack frame in a register"),
        __success,
        __retval("1"),
        __flag("BPF_F_TEST_STATE_FREQ");
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bounded_loop_count_to_4
extern "C" fn bounded_loop_count_to_4() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "l0_0:",
            "r0 += 1;",
            "if r0 < 4 goto l0_0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bounded_loop_count_to_20
extern "C" fn bounded_loop_count_to_20() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "l0_1:",
            "r0 += 3;",
            "if r0 < 20 goto l0_1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: from_positive_unknown_to_4
extern "C" fn from_positive_unknown_to_4() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "if r0 s< 0 goto l0_2;",
            "l1_2:",
            "r0 += 1;",
            "if r0 < 4 goto l1_2;",
            "l0_2:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: from_totally_unknown_to_4
extern "C" fn from_totally_unknown_to_4() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "l0_3:",
            "r0 += 1;",
            "if r0 < 4 goto l0_3;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: count_to_4_with_equality
extern "C" fn count_to_4_with_equality() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "l0_4:",
            "r0 += 1;",
            "if r0 != 4 goto l0_4;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: loop_start_in_the_middle
extern "C" fn loop_start_in_the_middle() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "goto l0_5;",
            "l1_5:",
            "r0 += 1;",
            "l0_5:",
            "if r0 < 4 goto l1_5;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: loop_containing_a_forward_jump
extern "C" fn loop_containing_a_forward_jump() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "l1_6:",
            "r0 += 1;",
            "if r0 == r0 goto l0_6;",
            "l0_6:",
            "if r0 < 4 goto l1_6;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jumps_out_rather_than_in
extern "C" fn jumps_out_rather_than_in() {
    unsafe {
        core::arch::asm!(
            "r6 = 0;",
            "l1_7:",
            "r6 += 1;",
            "if r6 > 10000 goto l0_7;",
            "call 7;",
            "goto l1_7;",
            "l0_7:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: loop_after_a_conditional_jump
extern "C" fn loop_after_a_conditional_jump() {
    unsafe {
        core::arch::asm!(
            "r0 = 5;",
            "if r0 < 4 goto l0_8;",
            "l1_8:",
            "r0 += 1;",
            "goto l1_8;",
            "l0_8:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bounded_recursion
extern "C" fn bounded_recursion() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "call {bounded_recursion__1};",
            "exit;",
            bounded_recursion__1 = sym bounded_recursion__1,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: bounded_recursion__1
extern "C" fn bounded_recursion__1() {
    unsafe {
        core::arch::asm!(
            "r1 += 1;",
            "r0 = r1;",
            "if r1 < 4 goto l0_9;",
            "exit;",
            "l0_9:",
            "call {bounded_recursion__1};",
            "exit;",
            bounded_recursion__1 = sym bounded_recursion__1,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: infinite_loop_in_two_jumps
extern "C" fn infinite_loop_in_two_jumps() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "l1_10:",
            "goto l0_10;",
            "l0_10:",
            "if r0 < 4 goto l1_10;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: infinite_loop_three_jump_trick
extern "C" fn infinite_loop_three_jump_trick() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "l2_11:",
            "r0 += 1;",
            "r0 &= 1;",
            "if r0 < 2 goto l0_11;",
            "exit;",
            "l0_11:",
            "r0 += 1;",
            "r0 &= 1;",
            "if r0 < 2 goto l1_11;",
            "exit;",
            "l1_11:",
            "r0 += 1;",
            "r0 &= 1;",
            "if r0 < 2 goto l2_11;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: back_jump_to_1st_insn_1
extern "C" fn back_jump_to_1st_insn_1() {
    unsafe {
        core::arch::asm!(
            "l0_12:",
            "r0 = 123;",
            "if r0 == 4 goto l0_12;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: back_jump_to_1st_insn_2
extern "C" fn back_jump_to_1st_insn_2() {
    unsafe {
        core::arch::asm!(
            "r1 = 10;",
            "r2 = 0;",
            "call {back_jump_to_1st_insn_2__1};",
            "exit;",
            back_jump_to_1st_insn_2__1 = sym back_jump_to_1st_insn_2__1,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: back_jump_to_1st_insn_2__1
extern "C" fn back_jump_to_1st_insn_2__1() {
    unsafe {
        core::arch::asm!(
            "l0_13:",
            "r2 += r1;",
            "r1 -= 1;",
            "if r1 != 0 goto l0_13;",
            "r0 = r2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jump_to_1st_insn_2
extern "C" fn jump_to_1st_insn_2() {
    unsafe {
        core::arch::asm!(
            "r1 = 10;",
            "r2 = 0;",
            "call {jump_to_1st_insn_2__1};",
            "exit;",
            jump_to_1st_insn_2__1 = sym jump_to_1st_insn_2__1,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: jump_to_1st_insn_2__1
extern "C" fn jump_to_1st_insn_2__1() {
    unsafe {
        core::arch::asm!(
            "l0_14:",
            "r2 += r1;",
            "r1 -= 1;",
            "if w1 != 0 goto l0_14;",
            "r0 = r2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: not_an_inifinite_loop
extern "C" fn not_an_inifinite_loop() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 0xff;",
            "*(u64 *)(r10 - 8) = r0;",
            "r0 = 0;",
            "loop_15:",
            "r0 = *(u64 *)(r10 - 8);",
            "if r0 > 10 goto exit_15;",
            "r0 += 1;",
            "*(u64 *)(r10 - 8) = r0;",
            "r0 = 0;",
            "goto loop_15;",
            "exit_15:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: maybe_exit_scc_bug1
extern "C" fn maybe_exit_scc_bug1() {
    unsafe {
        core::arch::asm!(
            "r0 = 100;",
            "1:*(u64 *)(r10 - 512) = r0;",
            "if r0 <= 0x0 goto 1b;",
            "exit;",
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: loop_stack_frames_reg
extern "C" fn loop_stack_frames_reg() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 8) = 1;",
            "1:r0 = *(u64 *)(r1 + 0);",
            "if r0 != 0 goto 2f;",
            "r1 = r10;",
            "r1 += -8;",
            "goto 1b;",
            "2:exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bounded_loop_stack_frames_reg
extern "C" fn bounded_loop_stack_frames_reg() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 8) = 0;",
            "r1 = r10;",
            "r1 += -8;",
            "call {loop_stack_frames_reg};",
            "exit;",
            loop_stack_frames_reg = sym loop_stack_frames_reg,
            options(nostack)
        );
    }
}

bpf_object!("GPL");
