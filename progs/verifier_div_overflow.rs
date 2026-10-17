// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_div_overflow.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_div_overflow` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: div32_overflow_check_1 div32_overflow_check_2 div64_overflow_check_1 div64_overflow_check_2 mod32_overflow_check_1 mod32_overflow_check_2 mod64_overflow_check_1 mod64_overflow_check_2

use bpf_rs_core::{bpf_object, test_tags};

test_tags! {
    div32_overflow_check_1:
        __description("DIV32 overflow, check 1"),
        __success,
        __retval("0");
    div32_overflow_check_2:
        __description("DIV32 overflow, check 2"),
        __success,
        __retval("0");
    div64_overflow_check_1:
        __description("DIV64 overflow, check 1"),
        __success,
        __retval("0");
    div64_overflow_check_2:
        __description("DIV64 overflow, check 2"),
        __success,
        __retval("0");
    mod32_overflow_check_1:
        __description("MOD32 overflow, check 1"),
        __success,
        __retval("_INT_MIN");
    mod32_overflow_check_2:
        __description("MOD32 overflow, check 2"),
        __success,
        __retval("_INT_MIN");
    mod64_overflow_check_1:
        __description("MOD64 overflow, check 1"),
        __success,
        __retval("1");
    mod64_overflow_check_2:
        __description("MOD64 overflow, check 2"),
        __success,
        __retval("1");
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: div32_overflow_check_1
extern "C" fn div32_overflow_check_1() {
    unsafe {
        core::arch::asm!(
            "w1 = -1;",
            "w0 = -2147483648;",
            "w0 /= w1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: div32_overflow_check_2
extern "C" fn div32_overflow_check_2() {
    unsafe {
        core::arch::asm!(
            "w0 = -2147483648;",
            "w0 /= -1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: div64_overflow_check_1
extern "C" fn div64_overflow_check_1() {
    unsafe {
        core::arch::asm!(
            "r1 = -1;",
            "r2 = -9223372036854775808 ll;",
            "r2 /= r1;",
            "w0 = 0;",
            "if r0 == r2 goto l0_0;",
            "w0 = 1;",
            "l0_0:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: div64_overflow_check_2
extern "C" fn div64_overflow_check_2() {
    unsafe {
        core::arch::asm!(
            "r1 = -9223372036854775808 ll;",
            "r1 /= -1;",
            "w0 = 0;",
            "if r0 == r1 goto l0_1;",
            "w0 = 1;",
            "l0_1:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mod32_overflow_check_1
extern "C" fn mod32_overflow_check_1() {
    unsafe {
        core::arch::asm!(
            "w1 = -1;",
            "w0 = -2147483648;",
            "w0 %= w1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mod32_overflow_check_2
extern "C" fn mod32_overflow_check_2() {
    unsafe {
        core::arch::asm!(
            "w0 = -2147483648;",
            "w0 %= -1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mod64_overflow_check_1
extern "C" fn mod64_overflow_check_1() {
    unsafe {
        core::arch::asm!(
            "r1 = -1;",
            "r2 = -9223372036854775808 ll;",
            "r3 = r2;",
            "r2 %= r1;",
            "w0 = 0;",
            "if r3 != r2 goto l0_4;",
            "w0 = 1;",
            "l0_4:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mod64_overflow_check_2
extern "C" fn mod64_overflow_check_2() {
    unsafe {
        core::arch::asm!(
            "r2 = -9223372036854775808 ll;",
            "r3 = r2;",
            "r2 %= -1;",
            "w0 = 0;",
            "if r3 != r2 goto l0_5;",
            "w0 = 1;",
            "l0_5:",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
