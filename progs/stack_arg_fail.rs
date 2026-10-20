// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/stack_arg_fail.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py stack_arg_fail` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: r11_alu_reject r11_store_non_dw r11_store_unaligned r11_store_positive_off r11_load_negative_off r11_load_non_dw r11_store_zero_off

use bpf_rs_core::{bpf_object, test_tags};

test_tags! {
    r11_alu_reject:
        __description("r11 in ALU instruction"),
        __failure,
        __msg("R11 is invalid");
    r11_store_non_dw:
        __description("r11 store with non-DW size"),
        __failure,
        __msg("R11 is invalid");
    r11_store_unaligned:
        __description("r11 store with unaligned offset"),
        __failure,
        __msg("R11 is invalid");
    r11_store_positive_off:
        __description("r11 store with positive offset"),
        __failure,
        __msg("R11 is invalid");
    r11_load_negative_off:
        __description("r11 load with negative offset"),
        __failure,
        __msg("R11 is invalid");
    r11_load_non_dw:
        __description("r11 load with non-DW size"),
        __failure,
        __msg("R11 is invalid");
    r11_store_zero_off:
        __description("r11 store with zero offset"),
        __failure,
        __msg("R11 is invalid");
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: r11_alu_reject
extern "C" fn r11_alu_reject() {
    unsafe {
        core::arch::asm!(
            "r11 += 1;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: r11_store_non_dw
extern "C" fn r11_store_non_dw() {
    unsafe {
        core::arch::asm!(
            "*(u32 *)(r11 - 8) = r1;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: r11_store_unaligned
extern "C" fn r11_store_unaligned() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r11 - 4) = r1;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: r11_store_positive_off
extern "C" fn r11_store_positive_off() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r11 + 8) = r1;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: r11_load_negative_off
extern "C" fn r11_load_negative_off() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u64 *)(r11 - 8);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: r11_load_non_dw
extern "C" fn r11_load_non_dw() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u32 *)(r11 + 8);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: r11_store_zero_off
extern "C" fn r11_store_zero_off() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r11 + 0) = r1;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
