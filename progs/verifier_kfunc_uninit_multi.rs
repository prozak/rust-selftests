// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]
#![allow(function_casts_as_integer)]

// Translation of tools/testing/selftests/bpf/progs/verifier_kfunc_uninit_multi.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_kfunc_uninit_multi` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: __kfunc_btf_root multiple_outputs variable_size_preserves_other_output output_after_by_value_argument output_passed_on_stack

use bpf_rs_core::{bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    multiple_outputs:
        __success,
        __retval("42"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __caps_unpriv("39 | 12"),
        __prepare_priv,
        __success_unpriv;
    variable_size_preserves_other_output:
        __success,
        __retval("42"),
        __caps_unpriv("39 | 12"),
        __prepare_priv,
        __failure_unpriv,
        __msg_unpriv("invalid read from stack off -16+0 size 4");
    output_after_by_value_argument:
        __arch_x86_64,
        __arch_arm64,
        __success,
        __retval("42"),
        __caps_unpriv("39 | 12"),
        __prepare_priv,
        __failure_unpriv,
        __msg_unpriv("invalid read from stack off -8+0 size 4");
    output_passed_on_stack:
        __arch_x86_64,
        __arch_arm64,
        __arch_riscv64,
        __success,
        __retval("15"),
        __caps_unpriv("39 | 12"),
        __prepare_priv,
        __failure_unpriv,
        __msg_unpriv("invalid read from stack off -8+0 size 4");
}

// Map key/value types, shaped like the C object's BTF (the kernel
// checks some of them member by member, so no explicit padding).
// translint: allow(padding)
#[allow(non_camel_case_types)]
#[repr(C)]
struct prog_test_pair_arg {
    lo: u64,
    hi: u64,
}

extern "C" {
    fn bpf_kfunc_test_uninit_multi(a0: *mut c_void, a1: *mut c_void, a2: u32);
    fn bpf_kfunc_test_uninit_pair(a0: prog_test_pair_arg, a1: *mut c_void);
    fn bpf_kfunc_test_uninit_stack(a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: *mut c_void);
}

// __kfunc_btf_root: the C's reference to each kfunc the asm calls, for its
// BTF prototype (llc emits one only for a real call or address load).
#[no_mangle]
#[inline(never)]
extern "C" fn __kfunc_btf_root() {
    unsafe {
        core::arch::asm!("/* {0} {1} {2} */", in(reg) bpf_kfunc_test_uninit_multi as usize, in(reg) bpf_kfunc_test_uninit_pair as usize, in(reg) bpf_kfunc_test_uninit_stack as usize, options(nostack, preserves_flags));
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: multiple_outputs
extern "C" fn multiple_outputs() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 16) = 0;",
            "*(u64 *)(r10 - 8) = 0;",
            "goto +0;",
            "r1 = r10;",
            "r1 += -16;",
            "r2 = r10;",
            "r2 += -8;",
            "r3 = 8;",
            "call {bpf_kfunc_test_uninit_multi};",
            "r0 = *(u32 *)(r10 - 16);",
            "r1 = *(u32 *)(r10 - 8);",
            "if r1 != 0x2a2a2a2a goto 1f;",
            "r1 = *(u32 *)(r10 - 4);",
            "if r1 == 0x2a2a2a2a goto 2f;",
            "1:;",
            "r0 = 0;",
            "2:;",
            "exit;",
            bpf_kfunc_test_uninit_multi = sym bpf_kfunc_test_uninit_multi,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: variable_size_preserves_other_output
extern "C" fn variable_size_preserves_other_output() {
    unsafe {
        core::arch::asm!(
            "r3 = *(u32 *)(r1 + 0);",
            "r3 &= 7;",
            "*(u64 *)(r10 - 8) = 0;",
            "r1 = r10;",
            "r1 += -16;",
            "r2 = r10;",
            "r2 += -8;",
            "call {bpf_kfunc_test_uninit_multi};",
            "r0 = *(u32 *)(r10 - 16);",
            "exit;",
            bpf_kfunc_test_uninit_multi = sym bpf_kfunc_test_uninit_multi,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: output_after_by_value_argument
extern "C" fn output_after_by_value_argument() {
    unsafe {
        core::arch::asm!(
            "r1 = 20;",
            "r2 = 22;",
            "r3 = r10;",
            "r3 += -8;",
            "call {bpf_kfunc_test_uninit_pair};",
            "r0 = *(u32 *)(r10 - 8);",
            "exit;",
            bpf_kfunc_test_uninit_pair = sym bpf_kfunc_test_uninit_pair,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: output_passed_on_stack
extern "C" fn output_passed_on_stack() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "r2 = 2;",
            "r3 = 3;",
            "r4 = 4;",
            "r5 = 5;",
            "r6 = r10;",
            "r6 += -8;",
            "*(u64 *)(r11 - 8) = r6;",
            "call {bpf_kfunc_test_uninit_stack};",
            "r0 = *(u32 *)(r10 - 8);",
            "exit;",
            bpf_kfunc_test_uninit_stack = sym bpf_kfunc_test_uninit_stack,
            options(nostack)
        );
    }
}

bpf_object!("GPL");
