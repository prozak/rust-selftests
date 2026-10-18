// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/tailcall_large_stack.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py tailcall_large_stack` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: classifier_0 subprog_tail entry

use bpf_rs_core::{bpf_map, bpf_object};

bpf_map! {
    jmp_table {
        r#type: *const [i32; 3],
        max_entries: *const [i32; 1],
        key_size: *const [i32; 4],
        value_size: *const [i32; 4],
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: classifier_0
extern "C" fn classifier_0() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r1 = 42;",
            "*(u64 *)(r10 - 2048) = r1;",
            "r1 = 7;",
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

#[no_mangle]
#[inline(never)]
// BPF_NAKED: subprog_tail
extern "C" fn subprog_tail() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r2 = 1;",
            "*(u64 *)(r10 - 1536) = r2;",
            "r2 = {jmp_table} ll;",
            "r3 = 0;",
            "call 12;",
            "r0 = 1;",
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
// BPF_NAKED: entry
extern "C" fn entry() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r2 = 2;",
            "*(u64 *)(r10 - 240) = r2;",
            "call {subprog_tail};",
            "exit;",
            subprog_tail = sym subprog_tail,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

bpf_object!("GPL");
