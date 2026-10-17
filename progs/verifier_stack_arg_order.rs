// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_stack_arg_order.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_stack_arg_order` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: subprog_bad_order_6args stack_arg_load_after_store subprog_call_before_load_6args stack_arg_load_after_call subprog_pruning_call_before_load_6args stack_arg_pruning_load_after_call subprog_bad_ptr_7args stack_arg_read_without_write_1 stack_arg_read_without_write_2

use bpf_rs_core::{bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    stack_arg_load_after_store:
        __description("stack_arg: r11 load after r11 store"),
        __failure,
        __msg("r11 load must be before any r11 store or call insn"),
        __btf_func_path("btf__verifier_stack_arg_order.bpf.o");
    stack_arg_load_after_call:
        __description("stack_arg: r11 load after a call"),
        __failure,
        __msg("r11 load must be before any r11 store or call insn"),
        __btf_func_path("btf__verifier_stack_arg_order.bpf.o");
    stack_arg_pruning_load_after_call:
        __description("stack_arg: pruning keeps r11 load ordering"),
        __failure,
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("r11 load must be before any r11 store or call insn"),
        __btf_func_path("btf__verifier_stack_arg_order.bpf.o");
    stack_arg_read_without_write_1:
        __description("stack_arg: read without caller write"),
        __failure,
        __msg("callee expects 7 args, stack arg1 is not initialized"),
        __btf_func_path("btf__verifier_stack_arg_order.bpf.o");
    stack_arg_read_without_write_2:
        __description("stack_arg: read with not-initialized caller write"),
        __failure,
        __msg("R0 !read_ok"),
        __btf_func_path("btf__verifier_stack_arg_order.bpf.o");
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: subprog_bad_order_6args
extern "C" fn subprog_bad_order_6args(_a: i32, _b: i32, _c: i32, _d: i32, _e: i32, _f: i32) -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r11 - 8) = r1;",
            "r0 = *(u64 *)(r11 + 8);",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_arg_load_after_store
extern "C" fn stack_arg_load_after_store() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "r2 = 2;",
            "r3 = 3;",
            "r4 = 4;",
            "r5 = 5;",
            "*(u64 *)(r11 - 8) = 6;",
            "call {subprog_bad_order_6args};",
            "exit;",
            subprog_bad_order_6args = sym subprog_bad_order_6args,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: subprog_call_before_load_6args
extern "C" fn subprog_call_before_load_6args(_a: i32, _b: i32, _c: i32, _d: i32, _e: i32, _f: i32) -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 = *(u64 *)(r11 + 8);",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_arg_load_after_call
extern "C" fn stack_arg_load_after_call() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "r2 = 2;",
            "r3 = 3;",
            "r4 = 4;",
            "r5 = 5;",
            "*(u64 *)(r11 - 8) = 6;",
            "call {subprog_call_before_load_6args};",
            "exit;",
            subprog_call_before_load_6args = sym subprog_call_before_load_6args,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: subprog_pruning_call_before_load_6args
extern "C" fn subprog_pruning_call_before_load_6args(_a: i32, _b: i32, _c: i32, _d: i32, _e: i32, _f: i32) -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "if r1 s> 0 goto l0_0;",
            "goto l1_0;",
            "l0_0:",
            "call 7;",
            "l1_0:",
            "r0 = *(u64 *)(r11 + 8);",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_arg_pruning_load_after_call
extern "C" fn stack_arg_pruning_load_after_call() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = r0;",
            "r2 = 2;",
            "r3 = 3;",
            "r4 = 4;",
            "r5 = 5;",
            "*(u64 *)(r11 - 8) = 6;",
            "call {subprog_pruning_call_before_load_6args};",
            "exit;",
            subprog_pruning_call_before_load_6args = sym subprog_pruning_call_before_load_6args,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: subprog_bad_ptr_7args
extern "C" fn subprog_bad_ptr_7args(_a: *mut c_void, _b: i32, _c: i32, _d: i32, _e: i32, _f: i32, _g: i32) {
    unsafe {
        core::arch::asm!(
            "r0 = *(u64 *)(r11 + 8);",
            "r1 = *(u64 *)(r11 + 16);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_arg_read_without_write_1
extern "C" fn stack_arg_read_without_write_1() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "r2 = 0;",
            "r3 = 0;",
            "r4 = 0;",
            "r5 = 0;",
            "call {subprog_bad_ptr_7args};",
            "exit;",
            subprog_bad_ptr_7args = sym subprog_bad_ptr_7args,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_arg_read_without_write_2
extern "C" fn stack_arg_read_without_write_2() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "r2 = 0;",
            "r3 = 0;",
            "r4 = 0;",
            "r5 = 0;",
            "*(u64 *)(r11 - 8) = 0;",
            "*(u64 *)(r11 - 16) = 0;",
            "call {subprog_bad_ptr_7args};",
            "call {subprog_bad_ptr_7args};",
            "exit;",
            subprog_bad_ptr_7args = sym subprog_bad_ptr_7args,
            options(nostack)
        );
    }
}

bpf_object!("GPL");
