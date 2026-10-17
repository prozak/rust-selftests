// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_bounds_step.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_bounds_step` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: step_arith64_no_overflow step_arith32_no_overflow step_neg_value_range step_arith32_overflow step_arith64_overflow step_mov32_truncate step_mov32_negative step_movsx step_linked_regs_add64 step_bounds_resync_after_arith step_movsx_bounds_on_line step_prune_hit_multiple step_prune_miss_non_multiple step_prune_hit_const_on_line step_prune_miss_const_off_line

use bpf_rs_core::{bpf_map, bpf_object, test_tags};

test_tags! {
    step_arith64_no_overflow:
        __success,
        __log_level("2"),
        __msg("r0 *= 3 {{.*}}step=0+3)"),
        __msg("r0 += 1 {{.*}}step=1+3)"),
        __msg("r0 *= 2 {{.*}}step=2+6)"),
        __msg("r0 <<= 1 {{.*}}step=4+12)");
    step_arith32_no_overflow:
        __success,
        __log_level("2"),
        __msg("w0 *= 3 {{.*}}step=0+3)"),
        __msg("w0 += 1 {{.*}}step=1+3)"),
        __msg("w0 *= 2 {{.*}}step=2+6)"),
        __msg("w1 = w0 {{.*}}R0=scalar({{.*}}step=2+6) R1=scalar({{.*}}step=2+6)"),
        __msg("w0 <<= 1 {{.*}}smax=umax=smax32=umax32=3064,"),
        __not_msg("step="),
        __msg("\n");
    step_neg_value_range:
        __success,
        __log_level("2"),
        __msg("r0 += -3 {{.*}}smax=smax32=6,step=0+3)");
    step_arith32_overflow:
        __success,
        __log_level("2"),
        __msg("w0 *= 7 {{.*}}umax=0xffffffff,"),
        __not_msg("step="),
        __msg("\n"),
        __msg("r2 = r0 {{.*}}R0=scalar({{.*}}step=0+3) R2=scalar({{.*}}step=0+3)"),
        __msg("w0 += 4 {{.*}}smax=umax=smax32=umax32=3,"),
        __not_msg("step="),
        __msg("\n"),
        __msg("w2 <<= 1 {{.*}}smax=umax=umax32=0xfffffffe,"),
        __not_msg("step="),
        __msg("\n");
    step_arith64_overflow:
        __success,
        __log_level("2"),
        __msg("r0 *= 3 {{.*}}smax=0x8000000000000004,"),
        __not_msg("step="),
        __msg("\n"),
        __msg("r0 += r1 {{.*}}step=0+3)"),
        __msg("r0 += 5 {{.*}}smax=0x8000000000000003,"),
        __not_msg("step="),
        __msg("\n"),
        __msg("r0 += r1 {{.*}}step=2+3)"),
        __msg("r0 += -5 {{.*}}umax=0x7fffffffffffffff,"),
        __not_msg("step="),
        __msg("\n"),
        __msg("r0 += r1 {{.*}}step=0+3)"),
        __msg("r0 <<= 1 {{.*}}smax=0x8000000000000016,"),
        __not_msg("step="),
        __msg("\n");
    step_mov32_truncate:
        __success,
        __log_level("2"),
        __msg("r0 += r1 {{.*}}step=1+3)"),
        __msg("w0 = w0 {{.*}}smax=umax=smax32=umax32=3,"),
        __not_msg("step="),
        __msg("\n");
    step_mov32_negative:
        __success,
        __log_level("2"),
        __msg("r0 += -4 {{.*}}step=2+3)"),
        __msg("w0 = w0 {{.*}}umax=0xffffffff,"),
        __not_msg("step="),
        __msg("\n");
    step_movsx:
        __success,
        __log_level("2"),
        __msg("r0 += 128 {{.*}}step=2+3)"),
        __msg("r0 = (s8)r0 {{.*}}smax=smax32=-125,"),
        __not_msg("step="),
        __msg("\n"),
        __msg("r0 += 32768 {{.*}}step=2+3)"),
        __msg("r0 = (s16)r0 {{.*}}smax=smax32=-32765,"),
        __not_msg("step="),
        __msg("\n"),
        __msg("r0 += r1 {{.*}}step=2+3)"),
        __msg("r0 = (s32)r0 {{.*}}smax=0xffffffff80000003,"),
        __not_msg("step="),
        __msg("\n");
    step_linked_regs_add64:
        __success,
        __log_level("2"),
        __msg("r1 += 1 {{.*}}step=1+3)"),
        __msg("if r0 > 0x6 {{.*}}R1=scalar({{.*}}smin=umin=smin32=umin32=1,smax=umax=smax32=umax32=7,{{.*}}step=1+3)");
    step_bounds_resync_after_arith:
        __success,
        __log_level("2"),
        __msg("r0 += 8 {{.*}}smin=umin=smin32=umin32=8,smax=umax=smax32=umax32=176,{{.*}}step=8+24)"),
        __msg("from 4 to 6: R0=scalar(smin=umin=smin32=umin32=32,smax=umax=smax32=umax32=176,{{.*}}step=8+24)"),
        __msg("r1 = r0 {{.*}}R1=scalar(id={{[0-9]+}},smin=umin=smin32=umin32=104,smax=umax=smax32=umax32=176,{{.*}}step=8+24)"),
        __msg("r1 += 24 {{.*}}R1=scalar({{.*}}smin=umin=smin32=umin32=128,smax=umax=smax32=umax32=200,{{.*}}step=8+24)");
    step_movsx_bounds_on_line:
        __success,
        __log_level("2"),
        __msg("r1 = (s16)r0 {{.*}}R1=scalar(id={{[0-9]+}},smin=smin32=0,smax=umax=smax32=umax32=168,{{.*}}step=0+24)"),
        __msg("r2 = (s16)r0 {{.*}}R2=scalar(smin=smin32=-24,smax=smax32=144,{{.*}}step=0+24)"),
        __msg("r3 = (s8)r0 {{.*}}R3=scalar(smin=smin32=-128,smax=smax32=127)"),
        __msg("w4 = (s16)w1 {{.*}}R4=scalar(id={{[0-9]+}},smin=smin32=0,smax=umax=smax32=umax32=168,{{.*}}step=0+24)"),
        __msg("w5 = (s8)w1 {{.*}}R5=scalar({{.*}}smin32=-128,smax32=127,var_off=(0x0; 0xffffffff))");
    step_prune_hit_multiple:
        __success,
        __log_level("2"),
        __msg("7: (27) r6 *= 4                       ; R6=scalar({{.*}}umin32=8,{{.*}}umax32=68,{{.*}},step=0+4)"),
        __msg("10: (27) r7 *= 2                      ; R7=scalar({{.*}}umin32=4,{{.*}}umax32=130,{{.*}},step=0+2)"),
        __msg("11: (25) if r0 > 0x2a goto pc+1"),
        __msg("from 11 to 13: safe"),
        __flag("BPF_F_TEST_STATE_FREQ");
    step_prune_miss_non_multiple:
        __success,
        __log_level("2"),
        __msg("6: (27) r6 *= 2                       ; R6=scalar({{.*}}smin32=0,{{.*}}umax32=30,{{.*}},step=0+2)"),
        __msg("8: (27) r7 *= 3                       ; R7=scalar({{.*}}smin32=0,{{.*}}umax32=189,{{.*}},step=0+3)"),
        __msg("9: (25) if r0 > 0x2a goto pc+1"),
        __msg("17: (95) exit"),
        __msg("from 9 to 11: R6=scalar({{.*}},step=0+2)"),
        __flag("BPF_F_TEST_STATE_FREQ");
    step_prune_hit_const_on_line:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("14: (27) r1 *= 3"),
        __msg("16: (b7) r1 = 6"),
        __msg("17: safe");
    step_prune_miss_const_off_line:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("14: (27) r1 *= 3"),
        __msg("16: (b7) r1 = 7"),
        __msg("19: R0=map_value({{.*}}imm=7) R1=7");
}

// Map key/value types, shaped like the C object's BTF (the kernel
// checks some of them member by member, so no explicit padding).
// translint: allow(padding)
#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct step_val {
    data: [u8; 1024],
}

bpf_map! {
    step_map {
        r#type: *const [i32; 2],
        max_entries: *const [i32; 1],
        key: *const u32,
        value: *const step_val,
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: step_arith64_no_overflow
extern "C" fn step_arith64_no_overflow() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 0xff;",
            "r0 *= 3;",
            "r0 += 1;",
            "r0 *= 2;",
            "r0 <<= 1;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: step_arith32_no_overflow
extern "C" fn step_arith32_no_overflow() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 0xff;",
            "w0 *= 3;",
            "w0 += 1;",
            "w0 *= 2;",
            "w1 = w0;",
            "w0 <<= 1;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: step_neg_value_range
extern "C" fn step_neg_value_range() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 3;",
            "r0 *= 3;",
            "r0 += -3;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: step_arith32_overflow
extern "C" fn step_arith32_overflow() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w0 *= 7;",
            "call 7;",
            "r0 &= 1;",
            "r0 *= 3;",
            "r1 = 0xfffffffc ll;",
            "r0 += r1;",
            "r2 = r0;",
            "w0 += 4;",
            "w2 <<= 1;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: step_arith64_overflow
extern "C" fn step_arith64_overflow() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 1;",
            "r2 = r0;",
            "r1 = 0x2aaaaaaaaaaaaaab ll;",
            "r0 += r1;",
            "r0 *= 3;",
            "r2 *= 3;",
            "r0 = r2;",
            "r1 = 0x7ffffffffffffffb ll;",
            "r0 += r1;",
            "r0 += 5;",
            "r0 = r2;",
            "r1 = 0x8000000000000001 ll;",
            "r0 += r1;",
            "r0 += -5;",
            "r0 = r2;",
            "r1 = 0x4000000000000008 ll;",
            "r0 += r1;",
            "r0 <<= 1;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: step_mov32_truncate
extern "C" fn step_mov32_truncate() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 1;",
            "r0 *= 3;",
            "r1 = 0x100000000 ll;",
            "r0 += r1;",
            "w0 = w0;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: step_mov32_negative
extern "C" fn step_mov32_negative() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 1;",
            "r0 *= 3;",
            "r0 += -4;",
            "w0 = w0;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: step_movsx
extern "C" fn step_movsx() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 1;",
            "r0 *= 3;",
            "r2 = r0;",
            "r0 += 128;",
            "r0 = (s8)r0;",
            "r0 = r2;",
            "r0 += 32768;",
            "r0 = (s16)r0;",
            "r0 = r2;",
            "r1 = 0x80000000 ll;",
            "r0 += r1;",
            "r0 = (s32)r0;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: step_linked_regs_add64
extern "C" fn step_linked_regs_add64() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 3;",
            "r0 *= 3;",
            "r1 = r0;",
            "r1 += 1;",
            "if r0 > 6 goto l_out_0;",
            "r0 = r1;",
            "l_out_0:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: step_bounds_resync_after_arith
extern "C" fn step_bounds_resync_after_arith() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 7;",
            "r0 *= 24;",
            "r0 += 8;",
            "if r0 & 0x10 goto l_set_1;",
            "goto l_out_1;",
            "l_set_1:",
            "if r0 <= 80 goto l_out_1;",
            "r1 = r0;",
            "r1 += 24;",
            "*(u64 *)(r10 - 8) = r1;",
            "l_out_1:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: step_movsx_bounds_on_line
extern "C" fn step_movsx_bounds_on_line() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 7;",
            "r0 *= 24;",
            "r1 = (s16)r0;",
            "r0 += -24;",
            "r2 = (s16)r0;",
            "r3 = (s8)r0;",
            "w4 = (s16)w1;",
            "w5 = (s8)w1;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: step_prune_hit_multiple
extern "C" fn step_prune_hit_multiple() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r6 = r0;",
            "call 7;",
            "r7 = r0;",
            "call 7;",
            "r6 &= 0x0f;",
            "r6 += 2;",
            "r6 *= 4;",
            "r7 &= 0x3f;",
            "r7 += 2;",
            "r7 *= 2;",
            "if r0 > 42 goto 1f;",
            "r6 = r7;",
            "1:",
            "r0 = r10;",
            "r6 = -r6;",
            "r0 += r6;",
            "*(u8 *)(r0 + 0) = 7;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: step_prune_miss_non_multiple
extern "C" fn step_prune_miss_non_multiple() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r6 = r0;",
            "call 7;",
            "r7 = r0;",
            "call 7;",
            "r6 &= 0x0f;",
            "r6 *= 2;",
            "r7 &= 0x3f;",
            "r7 *= 3;",
            "if r0 > 42 goto 1f;",
            "r6 = r7;",
            "1:",
            "r2 = r10;",
            "r6 += 1;",
            "r6 = -r6;",
            "r2 += r6;",
            "*(u8 *)(r2 + 0) = 7;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: step_prune_hit_const_on_line
extern "C" fn step_prune_hit_const_on_line() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r6 = r0;",
            "r1 = 0;",
            "*(u32*)(r10 - 4) = r1;",
            "r2 = r10;",
            "r2 += -4;",
            "r1 = {step_map} ll;",
            "call 1;",
            "if r0 == 0 goto l_out_2;",
            "r7 = r0;",
            "r1 = r6;",
            "r1 &= 0xff;",
            "if r6 > 0 goto l_cur_2;",
            "r1 *= 3;",
            "goto l_join_2;",
            "l_cur_2:",
            "r1 = 6;",
            "l_join_2:",
            "r0 = r7;",
            "r0 += r1;",
            "r2 = *(u8 *)(r0 + 0);",
            "l_out_2:",
            "r0 = 0;",
            "exit;",
            step_map = sym step_map,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: step_prune_miss_const_off_line
extern "C" fn step_prune_miss_const_off_line() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r6 = r0;",
            "r1 = 0;",
            "*(u32*)(r10 - 4) = r1;",
            "r2 = r10;",
            "r2 += -4;",
            "r1 = {step_map} ll;",
            "call 1;",
            "if r0 == 0 goto l_out_3;",
            "r7 = r0;",
            "r1 = r6;",
            "r1 &= 0xff;",
            "if r6 > 0 goto l_cur_3;",
            "r1 *= 3;",
            "goto l_join_3;",
            "l_cur_3:",
            "r1 = 7;",
            "l_join_3:",
            "r0 = r7;",
            "r0 += r1;",
            "r2 = *(u8 *)(r0 + 0);",
            "l_out_3:",
            "r0 = 0;",
            "exit;",
            step_map = sym step_map,
            options(nostack)
        );
    }
}

bpf_object!("GPL");
