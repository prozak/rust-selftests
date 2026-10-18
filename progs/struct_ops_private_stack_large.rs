// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/struct_ops_private_stack_large.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py struct_ops_private_stack_large` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: frame_2048_leaf test_1

// a `*mut c_void` is the C's `void *` in BTF (scripts/btf_rename.py)
// BTF_C_VOID: c_void

use bpf_rs_core::{bpf_object};
use core::ffi::c_void;

// Map key/value types, shaped like the C object's BTF (the kernel
// checks some of them member by member, so no explicit padding).
// translint: allow(padding)
/// The C's struct_ops map value: the kernel's struct of this name.
#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
struct bpf_testmod_ops3 {
    test_1: extern "C" fn() -> i32,
    test_2: *const c_void,
    test_arena: *const c_void,
    test_arena_nullable: *const c_void,
    test_arena_stack: *const c_void,
    test_arena_multislot: *const c_void,
}

#[no_mangle]
#[allow(non_upper_case_globals)]
static mut val: i64 = 0;

#[link_section = ".struct_ops"]
#[no_mangle]
#[allow(non_upper_case_globals)]
static mut testmod_1: bpf_testmod_ops3 = bpf_testmod_ops3 { test_1: test_1, test_2: core::ptr::null(), test_arena: core::ptr::null(), test_arena_nullable: core::ptr::null(), test_arena_stack: core::ptr::null(), test_arena_multislot: core::ptr::null() };

#[no_mangle]
#[inline(never)]
// BPF_NAKED: frame_2048_leaf
extern "C" fn frame_2048_leaf() -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "r1 = 30;",
            "*(u64 *)(r10 - 2048) = r1;",
            "r1 = 12;",
            "*(u64 *)(r10 - 8) = r1;",
            "r0 = *(u64 *)(r10 - 2048);",
            "r1 = *(u64 *)(r10 - 8);",
            "r0 += r1;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "struct_ops"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: test_1
extern "C" fn test_1() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r1 = 100;",
            "*(u64 *)(r10 - 2048) = r1;",
            "call {frame_2048_leaf};",
            "r1 = *(u64 *)(r10 - 2048);",
            "r0 += r1;",
            "r1 = {val} ll;",
            "*(u64 *)(r1 + 0) = r0;",
            "r0 = 0;",
            "exit;",
            val = sym val,
            frame_2048_leaf = sym frame_2048_leaf,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

bpf_object!("GPL");
