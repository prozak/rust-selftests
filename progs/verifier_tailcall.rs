// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_tailcall.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_tailcall` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: invalid_map_for_tail_call subprog_tail_call tail_call_caller_stack_ok tail_call_caller_stack_too_large

use bpf_rs_core::{bpf_map, bpf_object, test_tags};

test_tags! {
    invalid_map_for_tail_call:
        __description("invalid map type for tail call"),
        __failure,
        __msg("expected prog array map for tail call"),
        __failure_unpriv;
    tail_call_caller_stack_ok:
        __description("tail call from subprog with 240 bytes of caller stack"),
        __success;
    tail_call_caller_stack_too_large:
        __description("tail call from subprog with 256 bytes of caller stack"),
        __failure,
        __msg("tail_calls are not allowed when call stack of previous frames is 256 bytes. Too large");
}

bpf_map! {
    map_array {
        r#type: *const [i32; 2],
        max_entries: *const [i32; 1],
        key: *const u32,
        value: *const u32,
    }
}

bpf_map! {
    jmp_table {
        r#type: *const [i32; 3],
        max_entries: *const [i32; 1],
        key_size: *const [i32; 4],
        value_size: *const [i32; 4],
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: invalid_map_for_tail_call
extern "C" fn invalid_map_for_tail_call() {
    unsafe {
        core::arch::asm!(
            "r2 = {map_array} ll;",
            "r3 = 0;",
            "call 12;",
            "exit;",
            map_array = sym map_array,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: subprog_tail_call
extern "C" fn subprog_tail_call() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r2 = {jmp_table} ll;",
            "r3 = 0;",
            "call 12;",
            "r0 = 0;",
            "exit;",
            jmp_table = sym jmp_table,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: tail_call_caller_stack_ok
extern "C" fn tail_call_caller_stack_ok() {
    unsafe {
        core::arch::asm!(
            "r2 = 42;",
            "*(u64 *)(r10 - 240) = r2;",
            "call {subprog_tail_call};",
            "r0 = 0;",
            "exit;",
            subprog_tail_call = sym subprog_tail_call,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: tail_call_caller_stack_too_large
extern "C" fn tail_call_caller_stack_too_large() {
    unsafe {
        core::arch::asm!(
            "r2 = 42;",
            "*(u64 *)(r10 - 256) = r2;",
            "call {subprog_tail_call};",
            "r0 = 0;",
            "exit;",
            subprog_tail_call = sym subprog_tail_call,
            options(nostack)
        );
    }
}

bpf_object!("GPL");
