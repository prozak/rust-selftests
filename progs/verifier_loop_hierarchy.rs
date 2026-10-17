// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_loop_hierarchy.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_loop_hierarchy` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: loop_single loop_two_independent loop_nested fwd_edges_no_loop loop_nested_siblings loop_three_levels loop_with_if_else loop_irreducible loop_self loop_nested_siblings_common_ancestors loop_outer_backedge_from_inner

use bpf_rs_core::{bpf_object, test_tags};

test_tags! {
    loop_single:
        __success,
        __log_level("2"),
        __msg("loop at 1{{$}}"),
        __msg("Program dump"),
        __msg("         -1   0: {{.*}} (b7) r0 = 0"),
        __msg("  1       0   1: {{.*}} (07) r0 += 1"),
        __msg("  1   1   1   2: {{.*}} (a5) if r0 < 0xa goto pc-2"),
        __msg("          2   3: {{.*}} (95) exit");
    loop_two_independent:
        __success,
        __log_level("2"),
        __msg("loop at 1{{$}}"),
        __msg("loop at 4{{$}}"),
        __msg("Program dump"),
        __msg("         -1   0: {{.*}} (b7) r0 = 0"),
        __msg("  2       0   1: {{.*}} (07) r0 += 1"),
        __msg("  2   1   1   2: {{.*}} (a5) if r0 < 0xa goto pc-2"),
        __msg("          2   3: {{.*}} (b7) r1 = 0"),
        __msg("  1       3   4: {{.*}} (07) r1 += 1"),
        __msg("  1   4   4   5: {{.*}} (a5) if r1 < 0xa goto pc-2"),
        __msg("          5   6: {{.*}} (95) exit");
    loop_nested:
        __success,
        __log_level("2"),
        __msg("loop at 1{{$}}"),
        __msg("loop at 3, nested in 1"),
        __msg("Program dump"),
        __msg("         -1   0: {{.*}} (b7) r0 = 0"),
        __msg("  1       0   1: {{.*}} (07) r0 += 1"),
        __msg("  1   1   1   2: {{.*}} (b7) r1 = 0"),
        __msg("  1   1   2   3: {{.*}} (07) r1 += 1"),
        __msg("  1   3   3   4: {{.*}} (a5) if r1 < 0x5 goto pc-2"),
        __msg("  1   1   4   5: {{.*}} (a5) if r0 < 0xa goto pc-5"),
        __msg("          5   6: {{.*}} (95) exit");
    fwd_edges_no_loop:
        __success,
        __log_level("2"),
        __msg("Program dump"),
        __msg("         -1   0: {{.*}} (85) call bpf_get_prandom_u32"),
        __msg("          0   1: {{.*}} (25) if r0 > 0x0 goto pc+2"),
        __msg("          1   2: {{.*}} (b7) r0 = 2"),
        __msg("          2   3: {{.*}} (05) goto pc+1"),
        __msg("          1   4: {{.*}} (b7) r0 = 3"),
        __msg("          1   5: {{.*}} (95) exit");
    loop_nested_siblings:
        __success,
        __log_level("2"),
        __msg("loop at 1{{$}}"),
        __msg("loop at 3, nested in 1"),
        __msg("loop at 6, nested in 1"),
        __msg("Program dump"),
        __msg("         -1   0: {{.*}} (b7) r0 = 0"),
        __msg("  1       0   1: {{.*}} (07) r0 += 1"),
        __msg("  1   1   1   2: {{.*}} (b7) r1 = 0"),
        __msg("  1   1   2   3: {{.*}} (07) r1 += 1"),
        __msg("  1   3   3   4: {{.*}} (a5) if r1 < 0x5 goto pc-2"),
        __msg("  1   1   4   5: {{.*}} (b7) r2 = 0"),
        __msg("  1   1   5   6: {{.*}} (07) r2 += 1"),
        __msg("  1   6   6   7: {{.*}} (a5) if r2 < 0x5 goto pc-2"),
        __msg("  1   1   7   8: {{.*}} (a5) if r0 < 0xa goto pc-8"),
        __msg("          8   9: {{.*}} (95) exit");
    loop_three_levels:
        __success,
        __log_level("2"),
        __msg("loop at 1{{$}}"),
        __msg("loop at 3, nested in 1"),
        __msg("loop at 5, nested in 3"),
        __msg("Program dump"),
        __msg("         -1   0: {{.*}} (b7) r0 = 0"),
        __msg("  1       0   1: {{.*}} (07) r0 += 1"),
        __msg("  1   1   1   2: {{.*}} (b7) r1 = 0"),
        __msg("  1   1   2   3: {{.*}} (07) r1 += 1"),
        __msg("  1   3   3   4: {{.*}} (b7) r2 = 0"),
        __msg("  1   3   4   5: {{.*}} (07) r2 += 1"),
        __msg("  1   5   5   6: {{.*}} (a5) if r2 < 0x3 goto pc-2"),
        __msg("  1   3   6   7: {{.*}} (a5) if r1 < 0x5 goto pc-5"),
        __msg("  1   1   7   8: {{.*}} (a5) if r0 < 0xa goto pc-8"),
        __msg("          8   9: {{.*}} (95) exit");
    loop_with_if_else:
        __success,
        __log_level("2"),
        __msg("loop at 1"),
        __msg("Program dump"),
        __msg("         -1   0: {{.*}} (b7) r0 = 0"),
        __msg("  1       0   1: {{.*}} (07) r0 += 1"),
        __msg("  1   1   1   2: {{.*}} (bf) r1 = r0"),
        __msg("  1   1   2   3: {{.*}} (25) if r1 > 0x5 goto pc+1"),
        __msg("  1   1   3   4: {{.*}} (b7) r1 = 1"),
        __msg("  1   1   3   5: {{.*}} (0f) r0 += r1"),
        __msg("  1   1   5   6: {{.*}} (a5) if r0 < 0x64 goto pc-6"),
        __msg("          6   7: {{.*}} (95) exit");
    loop_irreducible:
        __success,
        __log_level("2"),
        __msg("loop at 3, irreducible"),
        __msg("Program dump"),
        __msg("         -1   0: {{.*}} (85) call bpf_get_prandom_u32#7"),
        __msg("          0   1: {{.*}} (b7) r1 = 0"),
        __msg("          1   2: {{.*}} (25) if r0 > 0x5 goto pc+2"),
        __msg("  1       2   3: {{.*}} (b7) r1 = 1"),
        __msg("  1   3   3   4: {{.*}} (05) goto pc+1"),
        __msg("          2   5: {{.*}} (b7) r1 = 2"),
        __msg("  1   3   2   6: {{.*}} (0f) r0 += r1"),
        __msg("  1   3   6   7: {{.*}} (a5) if r0 < 0x10 goto pc-5"),
        __msg("          7   8: {{.*}} (95) exit");
    loop_self:
        __failure,
        __log_level("2"),
        __msg("loop at 1"),
        __msg("infinite loop detected at insn 1");
    loop_nested_siblings_common_ancestors:
        __success,
        __log_level("2"),
        __msg("loop at 1{{$}}"),
        __msg_next("  backedge from 10, latch at 10"),
        __msg_next("  exit from 10 to 11"),
        __msg_next("loop at 3, nested in 1"),
        __msg_next("  backedge from 9, latch at 9"),
        __msg_next("  exit from 9 to 10"),
        __msg_next("loop at 5, nested in 3"),
        __msg_next("  backedge from 6, latch at 6"),
        __msg_next("  exit from 6 to 7"),
        __msg_next("loop at 7, nested in 3"),
        __msg_next("  backedge from 8, latch at 8"),
        __msg_next("  exit from 8 to 9");
    loop_outer_backedge_from_inner:
        __success,
        __log_level("2"),
        __msg("loop at 2{{$}}"),
        __msg_next("  backedge from 4{{$}}"),
        __msg_next("  exit from 5 to 7"),
        __msg_next("loop at 3, nested in 2"),
        __msg_next("  backedge from 6, latch at 5"),
        __msg_next("  exit from 4 to 2"),
        __msg_next("  exit from 5 to 7");
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: loop_single
extern "C" fn loop_single() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "1: r0 += 1;",
            "if r0 < 10 goto 1b;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: loop_two_independent
extern "C" fn loop_two_independent() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "1: r0 += 1;",
            "if r0 < 10 goto 1b;",
            "r1 = 0;",
            "2: r1 += 1;",
            "if r1 < 10 goto 2b;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: loop_nested
extern "C" fn loop_nested() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "1: r0 += 1;",
            "r1 = 0;",
            "2: r1 += 1;",
            "if r1 < 5 goto 2b;",
            "if r0 < 10 goto 1b;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: fwd_edges_no_loop
extern "C" fn fwd_edges_no_loop() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "if r0 > 0 goto 1f;",
            "r0 = 2;",
            "goto 2f;",
            "1: r0 = 3;",
            "2: exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: loop_nested_siblings
extern "C" fn loop_nested_siblings() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "1: r0 += 1;",
            "r1 = 0;",
            "2: r1 += 1;",
            "if r1 < 5 goto 2b;",
            "r2 = 0;",
            "3: r2 += 1;",
            "if r2 < 5 goto 3b;",
            "if r0 < 10 goto 1b;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: loop_three_levels
extern "C" fn loop_three_levels() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "1: r0 += 1;",
            "r1 = 0;",
            "2: r1 += 1;",
            "r2 = 0;",
            "3: r2 += 1;",
            "if r2 < 3 goto 3b;",
            "if r1 < 5 goto 2b;",
            "if r0 < 10 goto 1b;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: loop_with_if_else
extern "C" fn loop_with_if_else() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "1: r0 += 1;",
            "r1 = r0;",
            "if r1 > 5 goto 2f;",
            "r1 = 1;",
            "2: r0 += r1;",
            "if r0 < 100 goto 1b;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: loop_irreducible
extern "C" fn loop_irreducible() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = 0;",
            "if r0 > 5 goto 2f;",
            "1: r1 = 1;",
            "goto 3f;",
            "2: r1 = 2;",
            "3: r0 += r1;",
            "if r0 < 16 goto 1b;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: loop_self
extern "C" fn loop_self() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "1: if r0 < 10 goto 1b;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: loop_nested_siblings_common_ancestors
extern "C" fn loop_nested_siblings_common_ancestors() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "1: r0 += 1;",
            "r1 = 0;",
            "2: r1 += 1;",
            "r2 = 0;",
            "3: r2 += 1;",
            "if r2 < 3 goto 3b;",
            "4: r2 += -1;",
            "if r2 != 0 goto 4b;",
            "if r1 < 4 goto 2b;",
            "if r0 < 5 goto 1b;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: loop_outer_backedge_from_inner
extern "C" fn loop_outer_backedge_from_inner() {
    unsafe {
        core::arch::asm!(
            "r6 = 99;",
            "r2 = 2;",
            "2: r6 += 1;",
            "3: r2 += 1;",
            "4: if r2 == 3 goto 2b;",
            "5: if r6 > 100 goto 7f;",
            "goto 3b;",
            "7: r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
