// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]
#![allow(function_casts_as_integer)]

// Translation of tools/testing/selftests/bpf/progs/verifier_kfunc_uninit.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_kfunc_uninit` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: __kfunc_btf_root struct_poisoned_at_checkpoint sized_buffer_poisoned_at_checkpoint initialized_input_alias uninitialized_input_alias uninitialized_struct_output_ignored variable_size_uninitialized_output_ignored partial_output_preserves_initialized_bytes uninitialized_sized_output_read variable_size_uninitialized_output_read fixed_struct_uninitialized_output_read partial_output_variable_size

use bpf_rs_core::{bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    struct_poisoned_at_checkpoint:
        __success,
        __retval("10"),
        __log_level("2"),
        __msg("call bpf_kfunc_test_uninit_struct{{.*}}; def: fp0-8 fp0-16"),
        __msg_unpriv("call bpf_kfunc_test_uninit_struct{{.*}}; use: fp0-8 fp0-16"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __caps_unpriv("39 | 12"),
        __prepare_priv,
        __success_unpriv;
    sized_buffer_poisoned_at_checkpoint:
        __success,
        __retval("0x2a2a2a2a"),
        __log_level("2"),
        __msg("call bpf_kfunc_test_uninit_mem{{.*}}; def: fp0-8"),
        __msg_unpriv("call bpf_kfunc_test_uninit_mem{{.*}}; use: fp0-8"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __caps_unpriv("39 | 12"),
        __prepare_priv,
        __success_unpriv;
    initialized_input_alias:
        __success,
        __retval("7"),
        __caps_unpriv("39 | 12"),
        __prepare_priv,
        __success_unpriv;
    uninitialized_input_alias:
        __success,
        __caps_unpriv("39 | 12"),
        __prepare_priv,
        __failure_unpriv,
        __msg_unpriv("invalid read from stack");
    uninitialized_struct_output_ignored:
        __success,
        __retval("0"),
        __caps_unpriv("39 | 12"),
        __prepare_priv,
        __success_unpriv;
    variable_size_uninitialized_output_ignored:
        __success,
        __retval("0"),
        __caps_unpriv("39 | 12"),
        __prepare_priv,
        __success_unpriv;
    partial_output_preserves_initialized_bytes:
        __success,
        __retval("49"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __caps_unpriv("39 | 12"),
        __prepare_priv,
        __success_unpriv;
    uninitialized_sized_output_read:
        __success,
        __retval("42"),
        __caps_unpriv("39 | 12"),
        __prepare_priv,
        __failure_unpriv,
        __msg_unpriv("invalid read from stack off -8+0 size 1");
    variable_size_uninitialized_output_read:
        __success,
        __retval("42"),
        __caps_unpriv("39 | 12"),
        __prepare_priv,
        __failure_unpriv,
        __msg_unpriv("invalid read from stack off -8+0 size 1");
    fixed_struct_uninitialized_output_read:
        __success,
        __retval("1"),
        __caps_unpriv("39 | 12"),
        __prepare_priv,
        __failure_unpriv,
        __msg_unpriv("invalid read from stack off -16+0 size 4");
    partial_output_variable_size:
        __success,
        __retval("49"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __caps_unpriv("39 | 12"),
        __prepare_priv,
        __success_unpriv;
}

extern "C" {
    fn bpf_kfunc_test_uninit_struct(a0: *mut c_void);
    fn bpf_kfunc_test_uninit_mem(a0: *mut c_void, a1: u32);
    fn bpf_kfunc_test_uninit_partial(a0: *mut c_void, a1: u32);
    fn bpf_kfunc_test_uninit_alias(a0: *mut c_void, a1: *mut c_void) -> i32;
}

// __kfunc_btf_root: the C's reference to each kfunc the asm calls, for its
// BTF prototype (llc emits one only for a real call or address load).
#[no_mangle]
#[inline(never)]
extern "C" fn __kfunc_btf_root() {
    unsafe {
        core::arch::asm!("/* {0} {1} {2} {3} */", in(reg) bpf_kfunc_test_uninit_struct as usize, in(reg) bpf_kfunc_test_uninit_mem as usize, in(reg) bpf_kfunc_test_uninit_partial as usize, in(reg) bpf_kfunc_test_uninit_alias as usize, options(nostack, preserves_flags));
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: struct_poisoned_at_checkpoint
extern "C" fn struct_poisoned_at_checkpoint() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 16) = 0;",
            "*(u64 *)(r10 - 8) = 0;",
            "goto +0;",
            "r1 = r10;",
            "r1 += -16;",
            "call {bpf_kfunc_test_uninit_struct};",
            "r0 = *(u32 *)(r10 - 16);",
            "r1 = *(u32 *)(r10 - 12);",
            "r0 += r1;",
            "r1 = *(u32 *)(r10 - 8);",
            "r0 += r1;",
            "r1 = *(u32 *)(r10 - 4);",
            "r0 += r1;",
            "exit;",
            bpf_kfunc_test_uninit_struct = sym bpf_kfunc_test_uninit_struct,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sized_buffer_poisoned_at_checkpoint
extern "C" fn sized_buffer_poisoned_at_checkpoint() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 8) = 0;",
            "goto +0;",
            "r1 = r10;",
            "r1 += -8;",
            "r2 = 8;",
            "call {bpf_kfunc_test_uninit_mem};",
            "r0 = *(u32 *)(r10 - 8);",
            "r1 = *(u32 *)(r10 - 4);",
            "if r0 == r1 goto +1;",
            "r0 = 0;",
            "exit;",
            bpf_kfunc_test_uninit_mem = sym bpf_kfunc_test_uninit_mem,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: initialized_input_alias
extern "C" fn initialized_input_alias() {
    unsafe {
        core::arch::asm!(
            "*(u32 *)(r10 - 8) = 7;",
            "r1 = r10;",
            "r1 += -8;",
            "r2 = r1;",
            "call {bpf_kfunc_test_uninit_alias};",
            "exit;",
            bpf_kfunc_test_uninit_alias = sym bpf_kfunc_test_uninit_alias,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: uninitialized_input_alias
extern "C" fn uninitialized_input_alias() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -8;",
            "r2 = r1;",
            "call {bpf_kfunc_test_uninit_alias};",
            "exit;",
            bpf_kfunc_test_uninit_alias = sym bpf_kfunc_test_uninit_alias,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: uninitialized_struct_output_ignored
extern "C" fn uninitialized_struct_output_ignored() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -16;",
            "call {bpf_kfunc_test_uninit_struct};",
            "r0 = 0;",
            "exit;",
            bpf_kfunc_test_uninit_struct = sym bpf_kfunc_test_uninit_struct,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: variable_size_uninitialized_output_ignored
extern "C" fn variable_size_uninitialized_output_ignored() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32 *)(r1 + 0);",
            "r2 &= 7;",
            "r2 += 1;",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_kfunc_test_uninit_mem};",
            "r0 = 0;",
            "exit;",
            bpf_kfunc_test_uninit_mem = sym bpf_kfunc_test_uninit_mem,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: partial_output_preserves_initialized_bytes
extern "C" fn partial_output_preserves_initialized_bytes() {
    unsafe {
        core::arch::asm!(
            "*(u8 *)(r10 - 8) = 0;",
            "*(u8 *)(r10 - 1) = 7;",
            "goto +0;",
            "r1 = r10;",
            "r1 += -8;",
            "r2 = 8;",
            "call {bpf_kfunc_test_uninit_partial};",
            "r0 = *(u8 *)(r10 - 8);",
            "r1 = *(u8 *)(r10 - 1);",
            "r0 += r1;",
            "exit;",
            bpf_kfunc_test_uninit_partial = sym bpf_kfunc_test_uninit_partial,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: uninitialized_sized_output_read
extern "C" fn uninitialized_sized_output_read() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -8;",
            "r2 = 8;",
            "call {bpf_kfunc_test_uninit_mem};",
            "r0 = *(u8 *)(r10 - 8);",
            "exit;",
            bpf_kfunc_test_uninit_mem = sym bpf_kfunc_test_uninit_mem,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: variable_size_uninitialized_output_read
extern "C" fn variable_size_uninitialized_output_read() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32 *)(r1 + 0);",
            "r2 &= 7;",
            "r2 += 1;",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_kfunc_test_uninit_mem};",
            "r0 = *(u8 *)(r10 - 8);",
            "exit;",
            bpf_kfunc_test_uninit_mem = sym bpf_kfunc_test_uninit_mem,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: fixed_struct_uninitialized_output_read
extern "C" fn fixed_struct_uninitialized_output_read() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -16;",
            "call {bpf_kfunc_test_uninit_struct};",
            "r0 = *(u32 *)(r10 - 16);",
            "exit;",
            bpf_kfunc_test_uninit_struct = sym bpf_kfunc_test_uninit_struct,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: partial_output_variable_size
extern "C" fn partial_output_variable_size() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32 *)(r1 + 0);",
            "r2 &= 7;",
            "r2 += 1;",
            "*(u8 *)(r10 - 8) = 0;",
            "*(u8 *)(r10 - 1) = 7;",
            "goto +0;",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_kfunc_test_uninit_partial};",
            "r0 = *(u8 *)(r10 - 8);",
            "r1 = *(u8 *)(r10 - 1);",
            "r0 += r1;",
            "exit;",
            bpf_kfunc_test_uninit_partial = sym bpf_kfunc_test_uninit_partial,
            options(nostack)
        );
    }
}

bpf_object!("GPL");
