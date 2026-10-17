// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_idoms.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_idoms` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: straight_line_ldimm64 asymmetric_diamond simple_loop loop_with_if_else_body nested_loops multi_backedge_header irreducible idoms_diamond_sub multi_subprog idoms_entry_header_sub entry_is_loop_header self_loop gotox_jump_table

use bpf_rs_core::{bpf_object, test_tags};

test_tags! {
    straight_line_ldimm64:
        __success,
        __log_level("2"),
        __msg("Program dump"),
        __msg("{{.*}} -1   0: {{.*}} (b7) r0 = 0"),
        __msg("{{.*}}  0   1: {{.*}} (18) r1 = 0x1122334455667788"),
        __msg("{{.*}}  1   3: {{.*}} (07) r0 += 1"),
        __msg("{{.*}}  3   4: {{.*}} (0f) r0 += r1"),
        __msg("{{.*}}  4   5: {{.*}} (95) exit");
    asymmetric_diamond:
        __success,
        __log_level("2"),
        __msg("Program dump"),
        __msg("{{.*}} -1   0: {{.*}} (85) call bpf_get_prandom_u32#7"),
        __msg("{{.*}}  0   1: {{.*}} (25) if r0 > 0x0 goto pc+5"),
        __msg("{{.*}}  1   2: {{.*}} (b7) r1 = 1"),
        __msg("{{.*}}  2   3: {{.*}} (b7) r1 = 2"),
        __msg("{{.*}}  3   4: {{.*}} (b7) r1 = 3"),
        __msg("{{.*}}  4   5: {{.*}} (b7) r1 = 4"),
        __msg("{{.*}}  5   6: {{.*}} (05) goto pc+1"),
        __msg("{{.*}}  1   7: {{.*}} (b7) r1 = 9"),
        __msg("{{.*}}  1   8: {{.*}} (95) exit");
    simple_loop:
        __success,
        __log_level("2"),
        __msg("Program dump"),
        __msg("{{.*}} -1   0: {{.*}} (b7) r0 = 0"),
        __msg("{{.*}}  0   1: {{.*}} (07) r0 += 1"),
        __msg("{{.*}}  1   2: {{.*}} (a5) if r0 < 0xa goto pc-2"),
        __msg("{{.*}}  2   3: {{.*}} (95) exit");
    loop_with_if_else_body:
        __success,
        __log_level("2"),
        __msg("Program dump"),
        __msg("{{.*}} -1   0: {{.*}} (b7) r0 = 0"),
        __msg("{{.*}}  0   1: {{.*}} (07) r0 += 1"),
        __msg("{{.*}}  1   2: {{.*}} (bf) r1 = r0"),
        __msg("{{.*}}  2   3: {{.*}} (25) if r1 > 0x5 goto pc+1"),
        __msg("{{.*}}  3   4: {{.*}} (b7) r1 = 1"),
        __msg("{{.*}}  3   5: {{.*}} (0f) r0 += r1"),
        __msg("{{.*}}  5   6: {{.*}} (a5) if r0 < 0x64 goto pc-6"),
        __msg("{{.*}}  6   7: {{.*}} (95) exit");
    nested_loops:
        __success,
        __log_level("2"),
        __msg("Program dump"),
        __msg("{{.*}} -1   0: {{.*}} (b7) r0 = 0"),
        __msg("{{.*}}  0   1: {{.*}} (07) r0 += 1"),
        __msg("{{.*}}  1   2: {{.*}} (b7) r1 = 0"),
        __msg("{{.*}}  2   3: {{.*}} (07) r1 += 1"),
        __msg("{{.*}}  3   4: {{.*}} (a5) if r1 < 0x5 goto pc-2"),
        __msg("{{.*}}  4   5: {{.*}} (a5) if r0 < 0xa goto pc-5"),
        __msg("{{.*}}  5   6: {{.*}} (95) exit");
    multi_backedge_header:
        __success,
        __log_level("2"),
        __msg("Program dump"),
        __msg("{{.*}} -1   0: {{.*}} (b7) r6 = 0"),
        __msg("{{.*}}  0   1: {{.*}} (07) r6 += 1"),
        __msg("{{.*}}  1   2: {{.*}} (25) if r6 > 0xa goto pc+3"),
        __msg("{{.*}}  2   3: {{.*}} (bf) r7 = r6"),
        __msg("{{.*}}  3   4: {{.*}} (a5) if r7 < 0x5 goto pc-4"),
        __msg("{{.*}}  4   5: {{.*}} (05) goto pc-5"),
        __msg("{{.*}}  2   6: {{.*}} (b7) r0 = 0"),
        __msg("{{.*}}  6   7: {{.*}} (95) exit");
    irreducible:
        __success,
        __log_level("2"),
        __msg("Program dump"),
        __msg("{{.*}} -1   0: {{.*}} (85) call bpf_get_prandom_u32#7"),
        __msg("{{.*}}  0   1: {{.*}} (b7) r1 = 0"),
        __msg("{{.*}}  1   2: {{.*}} (25) if r0 > 0x5 goto pc+2"),
        __msg("{{.*}}  2   3: {{.*}} (b7) r1 = 1"),
        __msg("{{.*}}  3   4: {{.*}} (05) goto pc+1"),
        __msg("{{.*}}  2   5: {{.*}} (b7) r1 = 2"),
        __msg("{{.*}}  2   6: {{.*}} (0f) r0 += r1"),
        __msg("{{.*}}  6   7: {{.*}} (a5) if r0 < 0x10 goto pc-5"),
        __msg("{{.*}}  7   8: {{.*}} (95) exit");
    multi_subprog:
        __success,
        __log_level("2"),
        __msg("Program dump"),
        __msg("{{.*}} -1   0: {{.*}} (85) call pc+1"),
        __msg("{{.*}}  0   1: {{.*}} (95) exit"),
        __msg("{{.*}} -1   2: {{.*}} (85) call bpf_get_prandom_u32#7"),
        __msg("{{.*}}  2   3: {{.*}} (25) if r0 > 0x0 goto pc+2"),
        __msg("{{.*}}  3   4: {{.*}} (b7) r0 = 1"),
        __msg("{{.*}}  4   5: {{.*}} (05) goto pc+1"),
        __msg("{{.*}}  3   6: {{.*}} (b7) r0 = 2"),
        __msg("{{.*}}  3   7: {{.*}} (95) exit");
    entry_is_loop_header:
        __success,
        __log_level("2"),
        __msg("Program dump"),
        __msg("{{.*}} -1   0: {{.*}} (b7) r1 = 0"),
        __msg("{{.*}}  0   1: {{.*}} (85) call pc+1"),
        __msg("{{.*}}  1   2: {{.*}} (95) exit"),
        __msg("{{.*}} -1   3: {{.*}} (07) r1 += 1"),
        __msg("{{.*}}  3   4: {{.*}} (a5) if r1 < 0xa goto pc-2"),
        __msg("{{.*}}  4   5: {{.*}} (b7) r0 = 0"),
        __msg("{{.*}}  5   6: {{.*}} (95) exit");
    self_loop:
        __failure,
        __log_level("2"),
        __msg("Program dump"),
        __msg("{{.*}} -1   0: {{.*}} (85) call bpf_get_prandom_u32#7"),
        __msg("{{.*}}  0   1: {{.*}} (a5) if r0 < 0xa goto pc-1"),
        __msg("{{.*}}  1   2: {{.*}} (95) exit"),
        __msg("infinite loop detected");
    gotox_jump_table:
        __success,
        __log_level("2"),
        __msg("Program dump"),
        __msg("{{.*}} -1   0: {{.*}} (18) r0 = {{0x[0-9a-f]+}}"),
        __msg("{{.*}}  0   2: {{.*}} (07) r0 += 8"),
        __msg("{{.*}}  2   3: {{.*}} (79) r0 = *(u64 *)(r0 +0)"),
        __msg("{{.*}}  3   4: {{.*}} (0d) gotox r0"),
        __msg("{{.*}}  4   5: {{.*}} (b7) r0 = 0"),
        __msg("{{.*}}  5   6: {{.*}} (95) exit"),
        __msg("{{.*}}  4   7: {{.*}} (b7) r0 = 1"),
        __msg("{{.*}}  7   8: {{.*}} (95) exit");
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: straight_line_ldimm64
extern "C" fn straight_line_ldimm64() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "r1 = 0x1122334455667788 ll;",
            "r0 += 1;",
            "r0 += r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: asymmetric_diamond
extern "C" fn asymmetric_diamond() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "if r0 > 0 goto 1f;",
            "r1 = 1;",
            "r1 = 2;",
            "r1 = 3;",
            "r1 = 4;",
            "goto 2f;",
            "1: r1 = 9;",
            "2: exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: simple_loop
extern "C" fn simple_loop() {
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
// BPF_NAKED: loop_with_if_else_body
extern "C" fn loop_with_if_else_body() {
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
// BPF_NAKED: nested_loops
extern "C" fn nested_loops() {
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
// BPF_NAKED: multi_backedge_header
extern "C" fn multi_backedge_header() {
    unsafe {
        core::arch::asm!(
            "r6 = 0;",
            "1: r6 += 1;",
            "if r6 > 10 goto 2f;",
            "r7 = r6;",
            "if r7 < 5 goto 1b;",
            "goto 1b;",
            "2: r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: irreducible
extern "C" fn irreducible() {
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

#[no_mangle]
#[inline(never)]
// BPF_NAKED: idoms_diamond_sub
extern "C" fn idoms_diamond_sub() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "call 7;",
            "if r0 > 0 goto 1f;",
            "r0 = 1;",
            "goto 2f;",
            "1: r0 = 2;",
            "2: exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: multi_subprog
extern "C" fn multi_subprog() {
    unsafe {
        core::arch::asm!(
            "call {idoms_diamond_sub};",
            "exit;",
            idoms_diamond_sub = sym idoms_diamond_sub,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: idoms_entry_header_sub
extern "C" fn idoms_entry_header_sub() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "1: r1 += 1;",
            "if r1 < 10 goto 1b;",
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
// BPF_NAKED: entry_is_loop_header
extern "C" fn entry_is_loop_header() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "call {idoms_entry_header_sub};",
            "exit;",
            idoms_entry_header_sub = sym idoms_entry_header_sub,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: self_loop
extern "C" fn self_loop() {
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
// BPF_NAKED: gotox_jump_table
extern "C" fn gotox_jump_table() {
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

bpf_object!("GPL");
