// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_scalar_ids.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_scalar_ids` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: linked_regs_bpf_k linked_regs_bpf_x_src linked_regs_bpf_x_dst linked_regs_broken_link precision_many_frames precision_many_frames__foo precision_many_frames__bar precision_stack precision_stack__foo precision_two_ids linked_regs_too_many_regs linked_regs_broken_link_2 cjmp_no_linked_regs_trigger check_ids_in_regsafe check_ids_in_regsafe_2 no_scalar_id_for_const no_scalar_id_for_const32 ignore_unique_scalar_ids_cur ignore_unique_scalar_ids_old two_nil_old_ids_one_cur_id two_old_ids_one_cur_id linked_regs_and_subreg_def ldsx_fill_scalar_id_not_shared

use bpf_rs_core::{bpf_map, bpf_object, test_tags};

test_tags! {
    linked_regs_bpf_k:
        __success,
        __log_level("2"),
        __msg("6: (0f) r3 += r0"),
        __msg("frame0: regs=r0 stack= before 4: (25) if r1 > 0x7 goto pc+0"),
        __msg("frame0: parent state regs=r0,r1,r2 stack=:"),
        __msg("frame0: regs=r0,r1,r2 stack= before 3: (bf) r2 = r0"),
        __msg("from 4 to 5: "),
        __msg("6: (0f) r3 += r0"),
        __msg("frame0: regs=r0 stack= before 5: (bf) r3 = r10"),
        __msg("frame0: regs=r0 stack= before 4: (25) if r1 > 0x7 goto pc+0"),
        __msg("frame0: parent state regs= stack=:"),
        __flag("BPF_F_TEST_STATE_FREQ");
    linked_regs_bpf_x_src:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("frame0: regs=r0 stack= before 5: (2d) if r1 > r3 goto pc+0"),
        __msg("frame0: parent state regs=r0,r1,r2,r3 stack=:"),
        __msg("frame0: regs=r0,r1,r2,r3 stack= before 4: (b7) r3 = 7");
    linked_regs_bpf_x_dst:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("frame0: regs=r3 stack= before 5: (2d) if r1 > r3 goto pc+0"),
        __msg("frame0: parent state regs=r0,r1,r2,r3 stack=:"),
        __msg("frame0: regs=r0,r1,r2,r3 stack= before 4: (b7) r3 = 7");
    linked_regs_broken_link:
        __success,
        __log_level("2"),
        __msg("7: (0f) r3 += r0"),
        __msg("frame0: regs=r0 stack= before 6: (bf) r3 = r10"),
        __msg("frame0: parent state regs=r0 stack=:"),
        __msg("frame0: regs=r0 stack= before 5: (25) if r0 > 0x7 goto pc+0"),
        __msg("frame0: parent state regs=r0,r2 stack=:"),
        __flag("BPF_F_TEST_STATE_FREQ");
    precision_many_frames:
        __success,
        __log_level("2"),
        __msg("17: (0f) r2 += r1"),
        __msg("frame2: last_idx 17 first_idx 14 subseq_idx -1 "),
        __msg("frame2: regs=r1 stack= before 16: (bf) r2 = r10"),
        __msg("frame2: parent state regs=r1 stack="),
        __msg("frame1: parent state regs= stack="),
        __msg("frame0: parent state regs= stack="),
        __msg("frame2: last_idx 13 first_idx 13 subseq_idx 14 "),
        __msg("frame2: regs=r1 stack= before 13: (25) if r1 > 0x7 goto pc+0"),
        __msg("frame2: parent state regs=r1 stack="),
        __msg("frame1: parent state regs=r6,r7 stack="),
        __msg("frame0: parent state regs=r6 stack="),
        __msg("frame2: last_idx 9 first_idx 9 subseq_idx 13"),
        __msg("frame2: regs=r1 stack= before 9: (85) call pc+3"),
        __msg("frame1: parent state regs=r1,r6,r7 stack="),
        __msg("frame0: parent state regs=r6 stack="),
        __msg("frame1: last_idx 8 first_idx 7 subseq_idx 9"),
        __msg("frame1: regs=r1,r6,r7 stack= before 8: (bf) r7 = r1"),
        __msg("frame1: regs=r1,r6 stack= before 7: (bf) r6 = r1"),
        __msg("frame1: parent state regs=r1 stack="),
        __msg("frame0: parent state regs=r6 stack="),
        __msg("frame1: last_idx 4 first_idx 4 subseq_idx 7"),
        __msg("frame1: regs=r1 stack= before 4: (85) call pc+2"),
        __msg("frame0: parent state regs=r1,r6 stack="),
        __msg("frame0: last_idx 3 first_idx 1 subseq_idx 4"),
        __msg("frame0: regs=r1,r6 stack= before 3: (bf) r6 = r0"),
        __msg("frame0: regs=r0,r1 stack= before 2: (bf) r1 = r0"),
        __msg("frame0: regs=r0 stack= before 1: (57) r0 &= 255"),
        __flag("BPF_F_TEST_STATE_FREQ");
    precision_stack:
        __success,
        __log_level("2"),
        __msg("12: (0f) r2 += r1"),
        __msg("frame1: regs=r1 stack= before 11: (bf) r2 = r10"),
        __msg("frame1: regs=r1 stack= before 10: (25) if r1 > 0x7 goto pc+0"),
        __msg("frame1: regs=r1 stack=-8,-16 before 9: (7b) *(u64 *)(r10 -16) = r1"),
        __msg("frame1: regs=r1 stack=-8 before 8: (7b) *(u64 *)(r10 -8) = r1"),
        __msg("frame1: regs=r1 stack= before 4: (85) call pc+3"),
        __msg("frame0: regs=r1 stack=-8 before 3: (7b) *(u64 *)(r10 -8) = r1"),
        __msg("frame0: regs=r1 stack= before 2: (bf) r1 = r0"),
        __msg("frame0: regs=r0 stack= before 1: (57) r0 &= 255"),
        __flag("BPF_F_TEST_STATE_FREQ");
    precision_two_ids:
        __success,
        __log_level("2"),
        __msg("12: (0f) r3 += r7"),
        __msg("frame0: regs=r7 stack= before 11: (bf) r3 = r10"),
        __msg("frame0: regs=r7 stack= before 9: (25) if r7 > 0x7 goto pc+0"),
        __msg("frame0: regs=r6,r7 stack= before 3: (bf) r7 = r0"),
        __msg("frame0: regs=r0,r6 stack= before 2: (bf) r6 = r0"),
        __msg("13: (0f) r3 += r9"),
        __msg("frame0: regs=r9 stack= before 12: (0f) r3 += r7"),
        __msg("frame0: regs=r9 stack= before 10: (25) if r9 > 0x7 goto pc+0"),
        __msg("frame0: regs=r8,r9 stack= before 7: (bf) r9 = r0"),
        __msg("frame0: regs=r0,r8 stack= before 6: (bf) r8 = r0"),
        __flag("BPF_F_TEST_STATE_FREQ");
    linked_regs_too_many_regs:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("7: (25) if r5 > 0x7 goto pc+0         ; R5=scalar(smin="),
        __msg("12: (bf) r5 = r5                      ; R5=scalar(id=2"),
        __msg("frame0: regs=r0 stack= before 7: (25) if r5 > 0x7 goto pc+0"),
        __msg("frame0: parent state regs=r0,r1,r2,r3,r4 stack=:");
    linked_regs_broken_link_2:
        __failure,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("regs=r7 stack= before 5: (3d) if r8 >= r0"),
        __msg("parent state regs=r0,r7,r8"),
        __msg("regs=r0,r7,r8 stack= before 4: (25) if r0 > 0x1"),
        __msg("div by zero");
    cjmp_no_linked_regs_trigger:
        __success,
        __log_level("2"),
        __msg("3: (25) if r1 > 0x100 goto pc+0"),
        __msg("frame0: regs=r1 stack= before 2: (bf) r1 = r0");
    check_ids_in_regsafe:
        __failure,
        __msg("register with unbounded min value"),
        __flag("BPF_F_TEST_STATE_FREQ");
    check_ids_in_regsafe_2:
        __failure,
        __msg("register with unbounded min value"),
        __flag("BPF_F_TEST_STATE_FREQ");
    no_scalar_id_for_const:
        __success,
        __log_level("2"),
        __msg("14: (1d) if r3 == r4 goto pc+0"),
        __msg("frame 0: propagating r3,r4"),
        __msg("14: safe"),
        __msg("processed 18 insns"),
        __flag("BPF_F_TEST_STATE_FREQ");
    no_scalar_id_for_const32:
        __success,
        __log_level("2"),
        __msg("14: (1e) if w3 == w4 goto pc+0"),
        __msg("frame 0: propagating r3,r4"),
        __msg("14: safe"),
        __msg("processed 18 insns"),
        __flag("BPF_F_TEST_STATE_FREQ");
    ignore_unique_scalar_ids_cur:
        __success,
        __log_level("2"),
        __msg("6: (25) if r6 > 0x7 goto pc+1"),
        __msg("7: (57) r1 &= 255"),
        __msg("8: (bf) r2 = r10"),
        __msg("from 6 to 8: safe"),
        __msg("processed 12 insns"),
        __flag("BPF_F_TEST_STATE_FREQ");
    ignore_unique_scalar_ids_old:
        __success,
        __log_level("2"),
        __msg("6: (25) if r6 > 0x7 goto pc+1"),
        __msg("7: (05) goto pc+1"),
        __msg("9: (bf) r2 = r10"),
        __msg("9: safe"),
        __msg("processed 13 insns"),
        __flag("BPF_F_TEST_STATE_FREQ");
    two_nil_old_ids_one_cur_id:
        __success,
        __log_level("2"),
        __msg("12: safe"),
        __msg("processed 17 insns"),
        __flag("BPF_F_TEST_STATE_FREQ");
    two_old_ids_one_cur_id:
        __success,
        __log_level("2"),
        __msg("16: (95) exit"),
        __msg("16: (95) exit"),
        __msg("processed 22 insns"),
        __flag("BPF_F_TEST_STATE_FREQ");
    linked_regs_and_subreg_def:
        __flag("BPF_F_TEST_RND_HI32"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("4: (77) r1 >>= 32                     ; R1=0"),
        __msg("5: (bf) r0 = r1                       ; R0=0 R1=0"),
        __msg("6: (95) exit"),
        __msg("from 3 to 4"),
        __msg("4: (77) r1 >>= 32                     ; R1=0"),
        __msg("5: (bf) r0 = r1                       ; R0=0 R1=0"),
        __msg("6: (95) exit"),
        __xlated("call unknown"),
        __xlated("r0 &= 2147483647"),
        __xlated("w1 = w0"),
        __xlated("if w0 < 0xa goto pc+0"),
        __xlated("r1 >>= 32"),
        __xlated("r0 = r1"),
        __xlated("exit");
    ldsx_fill_scalar_id_not_shared:
        __failure,
        __msg("R0 max value is outside of the allowed memory range");
}

bpf_map! {
    map_hash_8b {
        r#type: *const [i32; 1],
        max_entries: *const [i32; 1],
        key: *const i64,
        value: *const i64,
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: linked_regs_bpf_k
extern "C" fn linked_regs_bpf_k() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "r0 &= 0xff;",
            "r1 = r0;",
            "r2 = r0;",
            "if r1 > 7 goto +0;",
            "r3 = r10;",
            "r3 += r0;",
            "r1 = r1;",
            "r2 = r2;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: linked_regs_bpf_x_src
extern "C" fn linked_regs_bpf_x_src() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "r0 &= 0xff;",
            "r1 = r0;",
            "r2 = r0;",
            "r3 = 7;",
            "if r1 > r3 goto +0;",
            "r4 = r10;",
            "r4 += r0;",
            "r1 = r1;",
            "r2 = r2;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: linked_regs_bpf_x_dst
extern "C" fn linked_regs_bpf_x_dst() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "r0 &= 0xff;",
            "r1 = r0;",
            "r2 = r0;",
            "r3 = 7;",
            "if r1 > r3 goto +0;",
            "r4 = r10;",
            "r4 += r3;",
            "r0 = r0;",
            "r1 = r1;",
            "r2 = r2;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: linked_regs_broken_link
extern "C" fn linked_regs_broken_link() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "r0 &= 0xff;",
            "r1 = r0;",
            "r2 = r0;",
            "r1 = 0;",
            "if r0 > 7 goto +0;",
            "r3 = r10;",
            "r3 += r0;",
            "r1 = r1;",
            "r2 = r2;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: precision_many_frames
extern "C" fn precision_many_frames() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "r0 &= 0xff;",
            "r1 = r0;",
            "r6 = r0;",
            "call {precision_many_frames__foo};",
            "r6 = r6;",
            "exit;",
            precision_many_frames__foo = sym precision_many_frames__foo,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: precision_many_frames__foo
extern "C" fn precision_many_frames__foo() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r7 = r1;",
            "call {precision_many_frames__bar};",
            "r6 = r6;",
            "r7 = r7;",
            "exit;",
            precision_many_frames__bar = sym precision_many_frames__bar,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: precision_many_frames__bar
extern "C" fn precision_many_frames__bar() {
    unsafe {
        core::arch::asm!(
            "if r1 > 7 goto +0;",
            "r6 = 0;",
            "r7 = 0;",
            "r2 = r10;",
            "r2 += r1;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: precision_stack
extern "C" fn precision_stack() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "r0 &= 0xff;",
            "r1 = r0;",
            "*(u64*)(r10 - 8) = r1;",
            "call {precision_stack__foo};",
            "r0 = *(u64*)(r10 - 8);",
            "r0 = 0;",
            "exit;",
            precision_stack__foo = sym precision_stack__foo,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: precision_stack__foo
extern "C" fn precision_stack__foo() {
    unsafe {
        core::arch::asm!(
            "*(u64*)(r10 - 8) = r1;",
            "*(u64*)(r10 - 16) = r1;",
            "if r1 > 7 goto +0;",
            "r2 = r10;",
            "r2 += r1;",
            "r0 = *(u64*)(r10 - 8);",
            "r0 = *(u64*)(r10 - 16);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: precision_two_ids
extern "C" fn precision_two_ids() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "r0 &= 0xff;",
            "r6 = r0;",
            "r7 = r0;",
            "call 5;",
            "r0 &= 0xff;",
            "r8 = r0;",
            "r9 = r0;",
            "r0 = 0;",
            "if r7 > 7 goto +0;",
            "if r9 > 7 goto +0;",
            "r3 = r10;",
            "r3 += r7;",
            "r3 += r9;",
            "r6 = r6;",
            "r8 = r8;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: linked_regs_too_many_regs
extern "C" fn linked_regs_too_many_regs() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "r0 &= 0xff;",
            "r1 = r0;",
            "r2 = r0;",
            "r3 = r0;",
            "r4 = r0;",
            "r5 = r0;",
            "if r5 > 7 goto +0;",
            "r1 = r1;",
            "r2 = r2;",
            "r3 = r3;",
            "r4 = r4;",
            "r5 = r5;",
            "r7 = r10;",
            "r7 += r0;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: linked_regs_broken_link_2
extern "C" fn linked_regs_broken_link_2() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r7 = r0;",
            "r8 = r0;",
            "call 7;",
            "if r0 > 1 goto +0;",
            "if r8 >= r0 goto 1f;",
            "r8 += r8;",
            "if r7 == 0 goto 1f;",
            "r0 /= 0;",
            "1:r0 = 42;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: cjmp_no_linked_regs_trigger
extern "C" fn cjmp_no_linked_regs_trigger() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "r0 &= 0xff;",
            "r1 = r0;",
            "if r1 > 256 goto +0;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: check_ids_in_regsafe
extern "C" fn check_ids_in_regsafe() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r9 = r10;",
            "r9 += -8;",
            "call 5;",
            "r7 = r0;",
            "call 5;",
            "r6 = r0;",
            "if r6 > r7 goto l1_0;",
            "r7 = r6;",
            "l1_0:",
            "if r7 > 4 goto l2_0;",
            "r9 += r6;",
            "r0 = *(u8*)(r9 + 0);",
            "l2_0:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: check_ids_in_regsafe_2
extern "C" fn check_ids_in_regsafe_2() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r9 = r10;",
            "r9 += -16;",
            "call 5;",
            "r8 = r0;",
            "call 5;",
            "r7 = r0;",
            "call 5;",
            "r6 = r0;",
            "r0 = 0;",
            "if r6 > r7 goto l1_1;",
            "r6 = r7;",
            "l0_1:",
            "if r7 > 4 goto l2_1;",
            "r9 += r6;",
            "r9 += r7;",
            "r9 += r8;",
            "r0 = *(u8*)(r9 + 0);",
            "l2_1:",
            "r0 = 0;",
            "exit;",
            "l1_1:",
            "r6 = r8;",
            "goto l0_1;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: no_scalar_id_for_const
extern "C" fn no_scalar_id_for_const() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "if r0 > 7 goto l0_2;",
            "r1 = 0;",
            "r1 ^= r1;",
            "r1 = r1;",
            "r3 = r1;",
            "r4 = r1;",
            "goto l1_2;",
            "l0_2:",
            "r1 = 0;",
            "r1 ^= r1;",
            "r2 = 0;",
            "r2 ^= r2;",
            "r3 = r1;",
            "r4 = r2;",
            "l1_2:",
            "if r3 == r4 goto +0;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: no_scalar_id_for_const32
extern "C" fn no_scalar_id_for_const32() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "if r0 > 7 goto l0_3;",
            "w1 = 0;",
            "w1 ^= w1;",
            "w1 = w1;",
            "w3 = w1;",
            "w4 = w1;",
            "goto l1_3;",
            "l0_3:",
            "w1 = 0;",
            "w1 ^= w1;",
            "w2 = 0;",
            "w2 ^= w2;",
            "w3 = w1;",
            "w4 = w2;",
            "l1_3:",
            "if w3 == w4 goto +0;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ignore_unique_scalar_ids_cur
extern "C" fn ignore_unique_scalar_ids_cur() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "r6 = r0;",
            "call 5;",
            "r0 &= 0xff;",
            "r1 = r0;",
            "r0 = 0;",
            "if r6 > 7 goto l0_4;",
            "r1 &= 0xff;",
            "l0_4:",
            "r2 = r10;",
            "r2 += r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ignore_unique_scalar_ids_old
extern "C" fn ignore_unique_scalar_ids_old() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "r6 = r0;",
            "call 5;",
            "r0 &= 0xff;",
            "r1 = r0;",
            "r0 = 0;",
            "if r6 > 7 goto l1_5;",
            "goto l0_5;",
            "l1_5:",
            "r1 &= 0xff;",
            "l0_5:",
            "r2 = r10;",
            "r2 += r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: two_nil_old_ids_one_cur_id
extern "C" fn two_nil_old_ids_one_cur_id() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "r0 &= 0xff;",
            "r6 = r0;",
            "r6 *= 1;",
            "call 5;",
            "r0 &= 0xff;",
            "r7 = r0;",
            "r7 *= 1;",
            "r0 = 0;",
            "if r6 > r7 goto l0_6;",
            "goto l1_6;",
            "l0_6:",
            "r6 = r7;",
            "l1_6:",
            "r2 = r10;",
            "r2 += r6;",
            "r2 += r7;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: two_old_ids_one_cur_id
extern "C" fn two_old_ids_one_cur_id() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "r0 &= 0xff;",
            "r6 = r0;",
            "r8 = r0;",
            "call 5;",
            "r0 &= 0xff;",
            "r7 = r0;",
            "r9 = r0;",
            "r0 = 0;",
            "if r6 > r7 goto l0_7;",
            "goto l1_7;",
            "l0_7:",
            "r6 = r7;",
            "l1_7:",
            "r2 = r10;",
            "r2 += r6;",
            "r2 += r7;",
            "r9 += r8;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: linked_regs_and_subreg_def
extern "C" fn linked_regs_and_subreg_def() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "r0 &= 0x7fffffff;",
            "w1 = w0;",
            "if w0 < 10 goto +0;",
            "r1 >>= 32;",
            "r0 = r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ldsx_fill_scalar_id_not_shared
extern "C" fn ldsx_fill_scalar_id_not_shared() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_8;",
            "r7 = *(u32*)(r0 + 0);",
            "r2 = 0x80000000 ll;",
            "r7 &= r2;",
            "r6 = r7;",
            "*(u32*)(r10 - 8) = r7;",
            "r4 = *(s32*)(r10 - 8);",
            "r5 = *(u32*)(r10 - 8);",
            "if r5 != r2 goto l0_8;",
            "r4 >>= 63;",
            "r0 += r4;",
            "r0 = *(u8*)(r0 + 7);",
            "l0_8:",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

bpf_object!("GPL");
