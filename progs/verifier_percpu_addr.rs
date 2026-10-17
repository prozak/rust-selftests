// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_percpu_addr.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_percpu_addr` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

use bpf_rs_core::{bpf_object, test_tags};

test_tags! {
    percpu_addr:
        __description("per-CPU address resolution"),
        __success,
        __arch_x86_64,
        __jited("\tmovabsq\t$0x{{.*}}, %rax"),
        __jited("\taddq\t%gs:{{.*}}, %rax"),
        __jited("\tmovabsq\t$0x{{.*}}, %rdi"),
        __jited("\taddq\t%gs:{{.*}}, %rdi"),
        __jited("\tmovabsq\t$0x{{.*}}, %rsi"),
        __jited("\taddq\t%gs:{{.*}}, %rsi"),
        __jited("\tmovabsq\t$0x{{.*}}, %rdx"),
        __jited("\taddq\t%gs:{{.*}}, %rdx"),
        __jited("\tmovabsq\t$0x{{.*}}, %rcx"),
        __jited("\taddq\t%gs:{{.*}}, %rcx"),
        __jited("\tmovabsq\t$0x{{.*}}, %r8"),
        __jited("\taddq\t%gs:{{.*}}, %r8"),
        __jited("\tmovabsq\t$0x{{.*}}, %rbx"),
        __jited("\taddq\t%gs:{{.*}}, %rbx"),
        __jited("\tmovabsq\t$0x{{.*}}, %r13"),
        __jited("\taddq\t%gs:{{.*}}, %r13"),
        __jited("\tmovabsq\t$0x{{.*}}, %r14"),
        __jited("\taddq\t%gs:{{.*}}, %r14"),
        __jited("\tmovabsq\t$0x{{.*}}, %r15"),
        __jited("\taddq\t%gs:{{.*}}, %r15");
}

#[link_section = ".percpu"]
#[no_mangle]
static mut percpu_data: i32 = 0;

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: percpu_addr
extern "C" fn percpu_addr() {
    unsafe {
        core::arch::asm!(
            "r0 = {percpu_data} ll;",
            "r1 = {percpu_data} ll;",
            "r2 = {percpu_data} ll;",
            "r3 = {percpu_data} ll;",
            "r4 = {percpu_data} ll;",
            "r5 = {percpu_data} ll;",
            "r6 = {percpu_data} ll;",
            "r7 = {percpu_data} ll;",
            "r8 = {percpu_data} ll;",
            "r9 = {percpu_data} ll;",
            "r0 = 0;",
            "exit;",
            percpu_data = sym percpu_data,
            options(nostack)
        );
    }
}

bpf_object!("GPL");
