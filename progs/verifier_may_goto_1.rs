// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_may_goto_1.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_may_goto_1` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: may_goto_simple may_goto_batch_0 may_goto_batch_1 may_goto_batch_2 timed_may_goto_preserves_regs mg_ret1 mg_ret2 mg_call_first may_goto_subprog_call_first mg_cb_stop mg_cb_cont mg_func_first may_goto_subprog_func_first

use bpf_rs_core::{bpf_object, test_tags};

test_tags! {
    may_goto_simple:
        __description("may_goto 0"),
        __arch_x86_64,
        __arch_s390x,
        __arch_arm64,
        __arch_riscv64,
        __arch_loongarch,
        __xlated("0: r0 = 1"),
        __xlated("1: exit"),
        __success;
    may_goto_batch_0:
        __description("batch 2 of may_goto 0"),
        __arch_x86_64,
        __arch_s390x,
        __arch_arm64,
        __arch_riscv64,
        __arch_loongarch,
        __xlated("0: r0 = 1"),
        __xlated("1: exit"),
        __success;
    may_goto_batch_1:
        __description("may_goto batch with offsets 2/1/0"),
        __arch_x86_64,
        __arch_s390x,
        __arch_arm64,
        __arch_riscv64,
        __arch_loongarch,
        __xlated("0: r0 = 1"),
        __xlated("1: exit"),
        __success;
    may_goto_batch_2:
        __description("may_goto batch with offsets 2/0"),
        __arch_x86_64,
        __arch_s390x,
        __arch_arm64,
        __arch_riscv64,
        __arch_loongarch,
        __xlated("0: *(u64 *)(r10 -16) = 65535"),
        __xlated("1: *(u64 *)(r10 -8) = 0"),
        __xlated("2: r12 = *(u64 *)(r10 -16)"),
        __xlated("3: if r12 == 0x0 goto pc+6"),
        __xlated("4: r12 -= 1"),
        __xlated("5: if r12 != 0x0 goto pc+2"),
        __xlated("6: r12 = -16"),
        __xlated("7: call unknown"),
        __xlated("8: *(u64 *)(r10 -16) = r12"),
        __xlated("9: r0 = 1"),
        __xlated("10: r0 = 2"),
        __xlated("11: exit"),
        __success;
    timed_may_goto_preserves_regs:
        __description("timed may_goto preserves R0-R5"),
        __arch_x86_64,
        __arch_s390x,
        __arch_arm64,
        __arch_riscv64,
        __arch_loongarch,
        __success,
        __retval("0");
    may_goto_subprog_call_first:
        __description("may_goto in subprog that starts with a call"),
        __success,
        __retval("1");
    may_goto_subprog_func_first:
        __description("may_goto in subprog that starts with ld_imm64 of a func"),
        __success,
        __retval("1");
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: may_goto_simple
extern "C" fn may_goto_simple() {
    unsafe {
        core::arch::asm!(
            ".8byte 229;",
            "r0 = 1;",
            ".8byte 229;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: may_goto_batch_0
extern "C" fn may_goto_batch_0() {
    unsafe {
        core::arch::asm!(
            ".8byte 229;",
            ".8byte 229;",
            "r0 = 1;",
            ".8byte 229;",
            ".8byte 229;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: may_goto_batch_1
extern "C" fn may_goto_batch_1() {
    unsafe {
        core::arch::asm!(
            ".8byte 131301;",
            ".8byte 65765;",
            ".8byte 229;",
            "r0 = 1;",
            ".8byte 131301;",
            ".8byte 65765;",
            ".8byte 229;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: may_goto_batch_2
extern "C" fn may_goto_batch_2() {
    unsafe {
        core::arch::asm!(
            ".8byte 131301;",
            ".8byte 229;",
            "r0 = 1;",
            "r0 = 2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "syscall"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: timed_may_goto_preserves_regs
extern "C" fn timed_may_goto_preserves_regs() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r6 = r0;",
            "r0 = 0x1111;",
            "r0 += r6;",
            "r1 = 0x2222;",
            "r1 += r6;",
            "r2 = 0x3333;",
            "r2 += r6;",
            "r3 = 0x4444;",
            "r3 += r6;",
            "r4 = 0x5555;",
            "r4 += r6;",
            "r5 = 0x6666;",
            "r5 += r6;",
            ".8byte 65765;",
            ".8byte 4294836229;",
            "r0 -= r6;",
            "r1 -= r6;",
            "r2 -= r6;",
            "r3 -= r6;",
            "r4 -= r6;",
            "r5 -= r6;",
            "if r0 != 0x1111 goto 1f;",
            "if r1 != 0x2222 goto 2f;",
            "if r2 != 0x3333 goto 3f;",
            "if r3 != 0x4444 goto 4f;",
            "if r4 != 0x5555 goto 5f;",
            "if r5 != 0x6666 goto 6f;",
            "r0 = 0;",
            "exit;",
            "1:",
            "r0 = 1;",
            "exit;",
            "2:",
            "r0 = 2;",
            "exit;",
            "3:",
            "r0 = 3;",
            "exit;",
            "4:",
            "r0 = 4;",
            "exit;",
            "5:",
            "r0 = 5;",
            "exit;",
            "6:",
            "r0 = 6;",
            "exit;",
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: mg_ret1
extern "C" fn mg_ret1() {
    unsafe {
        core::arch::asm!(
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: mg_ret2
extern "C" fn mg_ret2() {
    unsafe {
        core::arch::asm!(
            "r0 = 2;",
            "exit;",
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: mg_call_first
extern "C" fn mg_call_first() {
    unsafe {
        core::arch::asm!(
            "call {mg_ret1};",
            "r1 = 0;",
            "1:",
            ".8byte 131301;",
            "r1 += 1;",
            "if r1 < 10 goto 1b;",
            "exit;",
            mg_ret1 = sym mg_ret1,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: may_goto_subprog_call_first
extern "C" fn may_goto_subprog_call_first() {
    unsafe {
        core::arch::asm!(
            "call {mg_ret1};",
            "call {mg_ret2};",
            "call {mg_call_first};",
            "exit;",
            mg_ret1 = sym mg_ret1,
            mg_ret2 = sym mg_ret2,
            mg_call_first = sym mg_call_first,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: mg_cb_stop
extern "C" fn mg_cb_stop() {
    unsafe {
        core::arch::asm!(
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: mg_cb_cont
extern "C" fn mg_cb_cont() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: mg_func_first
extern "C" fn mg_func_first() {
    unsafe {
        core::arch::asm!(
            "r2 = {mg_cb_stop} ll;",
            "r4 = r1;",
            "r1 = 2;",
            "r3 = 0;",
            "call 181;",
            "r1 = 0;",
            "1:",
            ".8byte 131301;",
            "r1 += 1;",
            "if r1 < 10 goto 1b;",
            "exit;",
            mg_cb_stop = sym mg_cb_stop,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: may_goto_subprog_func_first
extern "C" fn may_goto_subprog_func_first() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "r2 = {mg_cb_stop} ll;",
            "r3 = 0;",
            "r4 = 0;",
            "call 181;",
            "r1 = 1;",
            "r2 = {mg_cb_cont} ll;",
            "r3 = 0;",
            "r4 = 0;",
            "call 181;",
            "call 5;",
            "r1 = r0;",
            "r1 >>= 63;",
            "call {mg_func_first};",
            "exit;",
            mg_cb_stop = sym mg_cb_stop,
            mg_cb_cont = sym mg_cb_cont,
            mg_func_first = sym mg_func_first,
            options(nostack)
        );
    }
}

bpf_object!("GPL");
