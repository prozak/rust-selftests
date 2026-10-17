// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_align.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_align` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: mov shift addsub mul unknown_shift unknown_mul packet_const_offset packet_variable_offset packet_variable_offset_2 dubious_pointer_arithmetic variable_subtraction pointer_variable_subtraction

use bpf_rs_core::{bpf_object, test_tags};

test_tags! {
    mov:
        __success,
        __log_level("2"),
        __flag("BPF_F_ANY_ALIGNMENT"),
        __msg("0: R1=ctx() R10=fp0"),
        __msg("0: {{.*}} R3=2"),
        __msg("1: {{.*}} R3=4"),
        __msg("2: {{.*}} R3=8"),
        __msg("3: {{.*}} R3=16"),
        __msg("4: {{.*}} R3=32");
    shift:
        __success,
        __log_level("2"),
        __flag("BPF_F_ANY_ALIGNMENT"),
        __msg("0: R1=ctx() R10=fp0"),
        __msg("0: {{.*}}R3=1"),
        __msg("1: {{.*}}R3=2"),
        __msg("2: {{.*}}R3=4"),
        __msg("3: {{.*}}R3=8"),
        __msg("4: {{.*}}R3=16"),
        __msg("5: {{.*}}R3=1"),
        __msg("6: {{.*}}R4=32"),
        __msg("7: {{.*}}R4=16"),
        __msg("8: {{.*}}R4=8"),
        __msg("9: {{.*}}R4=4"),
        __msg("10: {{.*}}R4=2");
    addsub:
        __success,
        __log_level("2"),
        __flag("BPF_F_ANY_ALIGNMENT"),
        __msg("0: R1=ctx() R10=fp0"),
        __msg("0: {{.*}}R3=4"),
        __msg("1: {{.*}}R3=8"),
        __msg("2: {{.*}}R3=10"),
        __msg("3: {{.*}}R4=8"),
        __msg("4: {{.*}}R4=12"),
        __msg("5: {{.*}}R4=14");
    mul:
        __success,
        __log_level("2"),
        __flag("BPF_F_ANY_ALIGNMENT"),
        __msg("0: R1=ctx() R10=fp0"),
        __msg("0: {{.*}}R3=7"),
        __msg("1: {{.*}}R3=7"),
        __msg("2: {{.*}}R3=14"),
        __msg("3: {{.*}}R3=56");
    unknown_shift:
        __success,
        __log_level("2"),
        __flag("BPF_F_ANY_ALIGNMENT"),
        __msg("6: {{.*}} R2=pkt(r=8)"),
        __msg("6: {{.*}} R3={{[^)]*}}var_off=(0x0; 0xff)"),
        __msg("7: {{.*}} R3={{[^)]*}}var_off=(0x0; 0x1fe)"),
        __msg("8: {{.*}} R3={{[^)]*}}var_off=(0x0; 0x3fc)"),
        __msg("9: {{.*}} R3={{[^)]*}}var_off=(0x0; 0x7f8)"),
        __msg("10: {{.*}} R3={{[^)]*}}var_off=(0x0; 0xff0)"),
        __msg("12: {{.*}} R3=pkt_end()"),
        __msg("17: {{.*}} R4={{[^)]*}}var_off=(0x0; 0xff)"),
        __msg("18: {{.*}} R4={{[^)]*}}var_off=(0x0; 0x1fe0)"),
        __msg("19: {{.*}} R4={{[^)]*}}var_off=(0x0; 0xff0)"),
        __msg("20: {{.*}} R4={{[^)]*}}var_off=(0x0; 0x7f8)"),
        __msg("21: {{.*}} R4={{[^)]*}}var_off=(0x0; 0x3fc)"),
        __msg("22: {{.*}} R4={{[^)]*}}var_off=(0x0; 0x1fe)");
    unknown_mul:
        __success,
        __log_level("2"),
        __flag("BPF_F_ANY_ALIGNMENT"),
        __msg("6: {{.*}} R3={{[^)]*}}var_off=(0x0; 0xff)"),
        __msg("7: {{.*}} R4={{[^)]*}}var_off=(0x0; 0xff)"),
        __msg("8: {{.*}} R4={{[^)]*}}var_off=(0x0; 0xff)"),
        __msg("9: {{.*}} R4={{[^)]*}}var_off=(0x0; 0xff)"),
        __msg("10: {{.*}} R4={{[^)]*}}var_off=(0x0; 0x1fe)"),
        __msg("11: {{.*}} R4={{[^)]*}}var_off=(0x0; 0xff)"),
        __msg("12: {{.*}} R4={{[^)]*}}var_off=(0x0; 0x3fc)"),
        __msg("13: {{.*}} R4={{[^)]*}}var_off=(0x0; 0xff)"),
        __msg("14: {{.*}} R4={{[^)]*}}var_off=(0x0; 0x7f8)"),
        __msg("15: {{.*}} R4={{[^)]*}}var_off=(0x0; 0xff0)");
    packet_const_offset:
        __success,
        __log_level("2"),
        __msg("2: {{.*}} R5=pkt(r=0)"),
        __msg("4: {{.*}} R5=pkt(r=0,imm=14)"),
        __msg("5: {{.*}} R4=pkt(r=0,imm=14)"),
        __msg("9: {{.*}} R5=pkt(r=18,imm=14)"),
        __msg("10: {{.*}} R4={{[^)]*}}var_off=(0x0; 0xff){{.*}} R5=pkt(r=18,imm=14)"),
        __msg("13: {{.*}} R4={{[^)]*}}var_off=(0x0; 0xffff)"),
        __msg("14: {{.*}} R4={{[^)]*}}var_off=(0x0; 0xffff)");
    packet_variable_offset:
        __success,
        __log_level("2"),
        __flag("BPF_F_ANY_ALIGNMENT"),
        __msg("6: {{.*}} R2=pkt(r=8)"),
        __msg("7: {{.*}} R6={{[^)]*}}var_off=(0x0; 0x3fc)"),
        __msg("11: {{.*}} R5=pkt(id=1,{{[^)]*}},var_off=(0x2; 0x7fc)"),
        __msg("15: {{.*}} R5={{[^)]*}}var_off=(0x2; 0x7fc)"),
        __msg("18: {{.*}} R4={{[^)]*}}var_off=(0x0; 0x3fc){{.*}} R5={{[^)]*}}var_off=(0x0; 0x3fc)"),
        __msg("19: {{.*}} R5=pkt(id=2,{{[^)]*}}var_off=(0x2; 0x7fc)"),
        __msg("24: {{.*}} R5={{[^)]*}}var_off=(0x2; 0x7fc)"),
        __msg("26: {{.*}} R5=pkt(r=8,imm=14)"),
        __msg("28: {{.*}} R4={{[^)]*}}var_off=(0x2; 0x7fc){{.*}} R5={{[^)]*}}var_off=(0x2; 0x7fc)"),
        __msg("29: {{.*}} R5=pkt(id=3,{{[^)]*}}var_off=(0x2; 0xffc)"),
        __msg("31: {{.*}} R4={{[^)]*}}var_off=(0x2; 0xffc){{.*}} R5={{[^)]*}}var_off=(0x2; 0xffc)"),
        __msg("35: {{.*}} R5={{[^)]*}}var_off=(0x2; 0xffc)");
    packet_variable_offset_2:
        __success,
        __log_level("2"),
        __flag("BPF_F_ANY_ALIGNMENT"),
        __msg("6: {{.*}} R2=pkt(r=8)"),
        __msg("7: {{.*}} R6={{[^)]*}}var_off=(0x0; 0x3fc)"),
        __msg("8: {{.*}} R6={{[^)]*}}var_off=(0x2; 0x7fc)"),
        __msg("11: {{.*}} R5={{[^)]*}}var_off=(0x2; 0x7fc)"),
        __msg("12: {{.*}} R4={{[^)]*}}var_off=(0x2; 0xffc)"),
        __msg("15: {{.*}} R5={{[^)]*}}var_off=(0x2; 0x7fc)"),
        __msg("17: {{.*}} R6={{[^)]*}}var_off=(0x0; 0x3fc)"),
        __msg("19: {{.*}} R5={{[^)]*}}var_off=(0x2; 0xffc)"),
        __msg("20: {{.*}} R4={{[^)]*}}var_off=(0x2; 0x1ffc)"),
        __msg("23: {{.*}} R5={{[^)]*}}var_off=(0x2; 0xffc)");
    dubious_pointer_arithmetic:
        __failure,
        __log_level("2"),
        __msg("3: {{.*}} R5=pkt_end()"),
        __msg("5: {{.*}} R5={{[^)]*}}var_off=(0x0; 0xfffffffffffffffc)"),
        __msg("6: {{.*}} R5={{[^)]*}}var_off=(0x2; 0xfffffffffffffffc)"),
        __msg("9: {{.*}} R5={{[^)]*}}var_off=(0x2; 0x7ffffffffffffffc)"),
        __msg("11: {{.*}} R4={{[^)]*}}var_off=(0x2; 0x7ffffffffffffffc){{.*}} R6={{[^)]*}}var_off=(0x2; 0x7ffffffffffffffc)"),
        __msg("12: (07) r4 += 4"),
        __msg("pkt pointer offset -9223372036854775808 is not allowed");
    variable_subtraction:
        __success,
        __log_level("2"),
        __flag("BPF_F_ANY_ALIGNMENT"),
        __msg("6: {{.*}} R2=pkt(r=8)"),
        __msg("8: {{.*}} R6={{[^)]*}}var_off=(0x0; 0x3fc)"),
        __msg("9: {{.*}} R6={{[^)]*}}var_off=(0x2; 0x7fc)"),
        __msg("10: {{.*}} R7={{[^)]*}}var_off=(0x0; 0x3fc)"),
        __msg("11: {{.*}} R6={{[^)]*}}var_off=(0x2; 0xfffffffffffffffc)"),
        __msg("14: {{.*}} R6={{[^)]*}}var_off=(0x2; 0x7fc)"),
        __msg("20: {{.*}} R5={{[^)]*}}var_off=(0x2; 0x7fc)");
    pointer_variable_subtraction:
        __success,
        __log_level("2"),
        __flag("BPF_F_ANY_ALIGNMENT"),
        __msg("6: {{.*}} R2=pkt(r=8)"),
        __msg("9: {{.*}} R6={{[^)]*}}var_off=(0x0; 0x3c)"),
        __msg("10: {{.*}} R6={{[^)]*}}var_off=(0x2; 0x7c)"),
        __msg("13: R5={{[^)]*}}var_off=(0xffffffffffffff82; 0x7c)"),
        __msg("14: {{.*}} R7={{[^)]*}}var_off=(0x0; 0x7fc)"),
        __msg("16: {{.*}} R5={{[^)]*}}var_off=(0x2; 0x7fc)"),
        __msg("20: {{.*}} R5={{[^)]*}}var_off=(0x2; 0x7fc)");
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mov
extern "C" fn mov() {
    unsafe {
        core::arch::asm!(
            "r3 = 2;",
            "r3 = 4;",
            "r3 = 8;",
            "r3 = 16;",
            "r3 = 32;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: shift
extern "C" fn shift() {
    unsafe {
        core::arch::asm!(
            "r3 = 1;",
            "r3 <<= 1;",
            "r3 <<= 1;",
            "r3 <<= 1;",
            "r3 <<= 1;",
            "r3 >>= 4;",
            "r4 = 32;",
            "r4 >>= 1;",
            "r4 >>= 1;",
            "r4 >>= 1;",
            "r4 >>= 1;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: addsub
extern "C" fn addsub() {
    unsafe {
        core::arch::asm!(
            "r3 = 4;",
            "r3 += 4;",
            "r3 += 2;",
            "r4 = 8;",
            "r4 += 4;",
            "r4 += 2;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mul
extern "C" fn mul() {
    unsafe {
        core::arch::asm!(
            "r3 = 7;",
            "r3 *= 1;",
            "r3 *= 2;",
            "r3 *= 4;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: unknown_shift
extern "C" fn unknown_shift() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 8;",
            "if r3 >= r0 goto l99_0;",
            "exit;",
            "l99_0:",
            "r3 = *(u8*)(r2 + 0);",
            "r3 <<= 1;",
            "r3 <<= 1;",
            "r3 <<= 1;",
            "r3 <<= 1;",
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 8;",
            "if r3 >= r0 goto l98_0;",
            "exit;",
            "l98_0:",
            "r4 = *(u8*)(r2 + 0);",
            "r4 <<= 5;",
            "r4 >>= 1;",
            "r4 >>= 1;",
            "r4 >>= 1;",
            "r4 >>= 1;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: unknown_mul
extern "C" fn unknown_mul() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 8;",
            "if r3 >= r0 goto l99_1;",
            "exit;",
            "l99_1:",
            "r3 = *(u8*)(r2 + 0);",
            "r4 = r3;",
            "r4 *= 1;",
            "r4 = r3;",
            "r4 *= 2;",
            "r4 = r3;",
            "r4 *= 4;",
            "r4 = r3;",
            "r4 *= 8;",
            "r4 *= 2;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: packet_const_offset
extern "C" fn packet_const_offset() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r5 = r2;",
            "r0 = 0;",
            "r5 += 14;",
            "r4 = r5;",
            "r4 += 4;",
            "if r3 >= r4 goto l0_2;",
            "exit;",
            "l0_2:",
            "r4 = *(u8*)(r5 + 0);",
            "r4 = *(u8*)(r5 + 1);",
            "r4 = *(u8*)(r5 + 2);",
            "r4 = *(u8*)(r5 + 3);",
            "r4 = *(u16*)(r5 + 0);",
            "r4 = *(u16*)(r5 + 2);",
            "r4 = *(u32*)(r5 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: packet_variable_offset
extern "C" fn packet_variable_offset() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 8;",
            "if r3 >= r0 goto l99_3;",
            "exit;",
            "l99_3:",
            "r6 = *(u8*)(r2 + 0);",
            "r6 <<= 2;",
            "r5 = r2;",
            "r5 += 14;",
            "r5 += r6;",
            "r4 = r5;",
            "r4 += 4;",
            "if r3 >= r4 goto l0_3;",
            "exit;",
            "l0_3:",
            "r4 = *(u32*)(r5 + 0);",
            "r5 = r2;",
            "r5 += r6;",
            "r4 = r5;",
            "r5 += 14;",
            "r4 = r5;",
            "r4 += 4;",
            "if r3 >= r4 goto l1_3;",
            "exit;",
            "l1_3:",
            "r4 = *(u32*)(r5 + 0);",
            "r5 = r2;",
            "r5 += 14;",
            "r5 += r6;",
            "r4 = r5;",
            "r5 += 4;",
            "r5 += r6;",
            "r4 = r5;",
            "r4 += 4;",
            "if r3 >= r4 goto l2_3;",
            "exit;",
            "l2_3:",
            "r4 = *(u32*)(r5 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: packet_variable_offset_2
extern "C" fn packet_variable_offset_2() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 8;",
            "if r3 >= r0 goto l99_4;",
            "exit;",
            "l99_4:",
            "r6 = *(u8*)(r2 + 0);",
            "r6 <<= 2;",
            "r6 += 14;",
            "r5 = r2;",
            "r5 += r6;",
            "r4 = r5;",
            "r4 += 4;",
            "if r3 >= r4 goto l0_4;",
            "exit;",
            "l0_4:",
            "r6 = *(u32*)(r5 + 0);",
            "r6 &= 0xff;",
            "r6 <<= 2;",
            "r5 += r6;",
            "r4 = r5;",
            "r4 += 4;",
            "if r3 >= r4 goto l1_4;",
            "exit;",
            "l1_4:",
            "r6 = *(u32*)(r5 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: dubious_pointer_arithmetic
extern "C" fn dubious_pointer_arithmetic() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = 0;",
            "r5 = r3;",
            "r5 -= r2;",
            "r5 <<= 2;",
            "r5 += 14;",
            "if r5 s>= 0 goto l0_5;",
            "exit;",
            "l0_5:",
            "r6 = r2;",
            "r6 += r5;",
            "r4 = r6;",
            "r4 += 4;",
            "if r3 >= r4 goto l1_5;",
            "exit;",
            "l1_5:",
            "r4 = *(u32*)(r6 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: variable_subtraction
extern "C" fn variable_subtraction() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 8;",
            "if r3 >= r0 goto l99_6;",
            "exit;",
            "l99_6:",
            "r6 = *(u8*)(r2 + 0);",
            "r7 = r6;",
            "r6 <<= 2;",
            "r6 += 14;",
            "r7 <<= 2;",
            "r6 -= r7;",
            "if r6 s>= 0 goto l0_6;",
            "exit;",
            "l0_6:",
            "r5 = r2;",
            "r5 += r6;",
            "r4 = r5;",
            "r4 += 4;",
            "if r3 >= r4 goto l1_6;",
            "exit;",
            "l1_6:",
            "r6 = *(u32*)(r5 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pointer_variable_subtraction
extern "C" fn pointer_variable_subtraction() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 8;",
            "if r3 >= r0 goto l99_7;",
            "exit;",
            "l99_7:",
            "r6 = *(u8*)(r2 + 0);",
            "r7 = r6;",
            "r6 &= 0xf;",
            "r6 <<= 2;",
            "r6 += 14;",
            "r5 = r2;",
            "r5 -= r6;",
            "r7 <<= 2;",
            "r7 += 76;",
            "r5 += r7;",
            "r4 = r5;",
            "r4 += 4;",
            "if r3 >= r4 goto l0_7;",
            "exit;",
            "l0_7:",
            "r6 = *(u32*)(r5 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
