// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]
#![allow(function_casts_as_integer)]

// Translation of tools/testing/selftests/bpf/progs/verifier_private_stack.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_private_stack.rs
// (include!d below): private_stack_exception_main_prog, subprog_exception, private_stack_exception_sub_prog, subprog2, subprog1, timer_cb1, timer_cb2, private_stack_async_callback_1, private_stack_async_callback_2, private_stack_max_depth.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_private_stack` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: private_stack_single_prog no_private_stack_nested cumulative_stack_depth_subprog private_stack_nested_1 loop_callback private_stack_callback private_stack_exception_main_prog subprog_exception private_stack_exception_sub_prog subprog2 subprog1 timer_cb1 timer_cb2 private_stack_async_callback_1 private_stack_async_callback_2 private_stack_max_depth

use bpf_rs_core::{bpf_map, bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    private_stack_single_prog:
        __description("Private stack, single prog"),
        __success,
        __arch_x86_64,
        __jited("\tmovabsq\t$0x{{.*}}, %r9"),
        __jited("\taddq\t%gs:{{.*}}, %r9"),
        __jited("\tmovl\t$0x2a, %edi"),
        __jited("\tmovq\t%rdi, -0x100(%r9)"),
        __arch_arm64,
        __jited("\tstp\tx25, x27, [sp, {{.*}}]!"),
        __jited("\tmov\tx27, {{.*}}"),
        __jited("\tmovk\tx27, {{.*}}, lsl #16"),
        __jited("\tmovk\tx27, {{.*}}"),
        __jited("\tmrs\tx10, TPIDR_EL{{[0-1]}}"),
        __jited("\tadd\tx27, x27, x10"),
        __jited("\tadd\tx25, x27, {{.*}}"),
        __jited("\tmov\tx0, #0x2a"),
        __jited("\tstr\tx0, [x27]"),
        __jited("..."),
        __jited("\tldp\tx25, x27, [sp], {{.*}}");
    no_private_stack_nested:
        __description("No private stack"),
        __success,
        __arch_x86_64,
        __jited("\tsubq\t$0x8, %rsp"),
        __arch_arm64,
        __jited("\tmov\tx25, sp"),
        __jited("\tsub\tsp, sp, #0x10");
    private_stack_nested_1:
        __description("Private stack, subtree > MAX_BPF_STACK"),
        __success,
        __log_level("4"),
        __msg("stack depth max 512"),
        __msg("subprog 0 (private_stack_nested_1) main {{.*}} stack 512"),
        __msg("subprog 1 (cumulative_stack_depth_subprog) static {{.*}} stack 32"),
        __arch_x86_64,
        __jited("\tmovabsq\t$0x{{.*}}, %r9"),
        __jited("\taddq\t%gs:{{.*}}, %r9"),
        __jited("\tmovl\t$0x2a, %edi"),
        __jited("\tmovq\t%rdi, -0x200(%r9)"),
        __jited("\tpushq\t%r9"),
        __jited("..."),
        __jited("\tcallq\t0x{{.*}}"),
        __jited("\tpopq\t%r9"),
        __jited("\txorl\t%eax, %eax"),
        __arch_arm64,
        __jited("\tstp\tx25, x27, [sp, {{.*}}]!"),
        __jited("\tmov\tx27, {{.*}}"),
        __jited("\tmovk\tx27, {{.*}}, lsl #16"),
        __jited("\tmovk\tx27, {{.*}}"),
        __jited("\tmrs\tx10, TPIDR_EL{{[0-1]}}"),
        __jited("\tadd\tx27, x27, x10"),
        __jited("\tadd\tx25, x27, {{.*}}"),
        __jited("\tmov\tx0, #0x2a"),
        __jited("\tstr\tx0, [x27]"),
        __jited("\tbl\t{{.*}}"),
        __jited("..."),
        __jited("\tldp\tx25, x27, [sp], {{.*}}");
    private_stack_callback:
        __description("Private stack, callback"),
        __success,
        __arch_x86_64,
        __jited("func #1"),
        __jited("\tendbr64"),
        __jited("\tnopl\t(%rax,%rax)"),
        __jited("\tnopl\t(%rax)"),
        __jited("\tpushq\t%rbp"),
        __jited("\tmovq\t%rsp, %rbp"),
        __jited("\tendbr64"),
        __jited("\tmovabsq\t$0x{{.*}}, %r9"),
        __jited("\taddq\t%gs:{{.*}}, %r9"),
        __jited("\tpushq\t%r9"),
        __jited("..."),
        __jited("\tcallq"),
        __jited("\tpopq\t%r9"),
        __jited("\tmovl\t$0x2a, %edi"),
        __jited("\tmovq\t%rdi, -0x200(%r9)"),
        __jited("\tpushq\t%r9"),
        __jited("..."),
        __jited("\tcallq"),
        __jited("\tpopq\t%r9"),
        __arch_arm64,
        __jited("func #1"),
        __jited("..."),
        __jited("\tstp\tx25, x27, [sp, {{.*}}]!"),
        __jited("\tmov\tx27, {{.*}}"),
        __jited("\tmovk\tx27, {{.*}}, lsl #16"),
        __jited("\tmovk\tx27, {{.*}}"),
        __jited("\tmrs\tx10, TPIDR_EL{{[0-1]}}"),
        __jited("\tadd\tx27, x27, x10"),
        __jited("\tadd\tx25, x27, {{.*}}"),
        __jited("\tbl\t0x{{.*}}"),
        __jited("\tmov\tx8, x0"),
        __jited("\tmov\tx0, #0x2a"),
        __jited("\tstr\tx0, [x27]"),
        __jited("\tbl\t0x{{.*}}"),
        __jited("\tmov\tx8, x0"),
        __jited("\tmov\tx8, #0x0"),
        __jited("\tldp\tx25, x27, [sp], {{.*}}");
    private_stack_exception_main_prog:
        __description("Private stack, exception in main prog"),
        __success,
        __retval("0"),
        __arch_x86_64,
        __jited("\tpushq\t%r9"),
        __jited("..."),
        __jited("\tcallq"),
        __jited("\tpopq\t%r9"),
        __arch_arm64,
        __jited("\tstp\tx29, x30, [sp, #-0x10]!"),
        __jited("\tmov\tx29, sp"),
        __jited("\tstp\txzr, x26, [sp, #-0x10]!"),
        __jited("\tmov\tx26, sp"),
        __jited("\tstp\tx19, x20, [sp, #-0x10]!"),
        __jited("\tstp\tx21, x22, [sp, #-0x10]!"),
        __jited("\tstp\tx23, x24, [sp, #-0x10]!"),
        __jited("\tstp\tx25, x26, [sp, #-0x10]!"),
        __jited("\tstp\tx27, x28, [sp, #-0x10]!"),
        __jited("\tmov\tx27, {{.*}}"),
        __jited("\tmovk\tx27, {{.*}}, lsl #16"),
        __jited("\tmovk\tx27, {{.*}}"),
        __jited("\tmrs\tx10, TPIDR_EL{{[0-1]}}"),
        __jited("\tadd\tx27, x27, x10"),
        __jited("\tadd\tx25, x27, {{.*}}"),
        __jited("\tmov\tx0, #0x2a"),
        __jited("\tstr\tx0, [x27]"),
        __jited("\tmov\tx0, #0x0"),
        __jited("\tbl\t0x{{.*}}"),
        __jited("\tmov\tx8, x0"),
        __jited("\tldp\tx27, x28, [sp], #0x10");
    private_stack_exception_sub_prog:
        __description("Private stack, exception in subprog"),
        __success,
        __retval("0"),
        __arch_x86_64,
        __jited("\tmovq\t%rdi, -0x200(%r9)"),
        __jited("\tpushq\t%r9"),
        __jited("..."),
        __jited("\tcallq"),
        __jited("\tpopq\t%r9"),
        __arch_arm64,
        __jited("\tstp\tx27, x28, [sp, #-0x10]!"),
        __jited("\tmov\tx27, {{.*}}"),
        __jited("\tmovk\tx27, {{.*}}, lsl #16"),
        __jited("\tmovk\tx27, {{.*}}"),
        __jited("\tmrs\tx10, TPIDR_EL{{[0-1]}}"),
        __jited("\tadd\tx27, x27, x10"),
        __jited("\tadd\tx25, x27, {{.*}}"),
        __jited("\tmov\tx0, #0x2a"),
        __jited("\tstr\tx0, [x27]"),
        __jited("\tbl\t0x{{.*}}"),
        __jited("\tmov\tx8, x0"),
        __jited("\tldp\tx27, x28, [sp], #0x10");
    private_stack_async_callback_1:
        __description("Private stack, async callback, not nested"),
        __success,
        __retval("0"),
        __arch_x86_64,
        __jited("\tmovabsq\t$0x{{.*}}, %r9"),
        __arch_arm64,
        __jited("\tmrs\tx10, TPIDR_EL{{[0-1]}}"),
        __jited("\tadd\tx27, x27, x10"),
        __jited("\tadd\tx25, x27, {{.*}}");
    private_stack_async_callback_2:
        __description("Private stack, async callback, potential nesting"),
        __success,
        __retval("0"),
        __load_if_JITed,
        __log_level("4"),
        __msg("stack depth max 272"),
        __msg("subprog 0 (private_stack_async_callback_2) main {{.*}} stack 8"),
        __msg("subprog 1 (timer_cb1) static {{.*}} stack 0"),
        __msg("subprog 2 (subprog1) static {{.*}} stack 256"),
        __msg("subprog 3 (subprog2) static {{.*}} stack 0"),
        __arch_x86_64,
        __jited("\tsubq\t$0x100, %rsp"),
        __arch_arm64,
        __jited("\tsub\tsp, sp, #0x100");
    private_stack_max_depth:
        __description("private stack, max stack depth is private stack"),
        __success,
        __log_level("4"),
        __msg("stack depth max 256"),
        __msg("subprog 0 (private_stack_max_depth) main {{.*}} stack 8"),
        __msg("subprog 1 (subprog1) static insns_self {{[0-9]+}} insns_total {{[0-9]+}} stack 256"),
        __msg("subprog 2 (subprog2) static insns_self {{[0-9]+}} insns_total {{[0-9]+}} stack 0");
}

// Map key/value types, shaped like the C object's BTF (the kernel
// checks some of them member by member, so no explicit padding).
// translint: allow(padding)
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_timer {
    __opaque: [u64; 2],
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct elem {
    t: bpf_timer,
    pad: [i8; 256],
}

bpf_map! {
    array {
        r#type: *const [i32; 2],
        max_entries: *const [i32; 1],
        key: *const i32,
        value: *const elem,
    }
}

#[no_mangle]
static mut glob: i32 = 0;

extern "C" {
    fn bpf_throw(a0: u64);
}

#[link_section = "kprobe"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: private_stack_single_prog
extern "C" fn private_stack_single_prog() {
    unsafe {
        core::arch::asm!(
            "r1 = 42;",
            "*(u64 *)(r10 - 256) = r1;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: no_private_stack_nested
extern "C" fn no_private_stack_nested() {
    unsafe {
        core::arch::asm!(
            "r1 = 42;",
            "*(u64 *)(r10 - 8) = r1;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: cumulative_stack_depth_subprog
extern "C" fn cumulative_stack_depth_subprog() {
    unsafe {
        core::arch::asm!(
            "r1 = 41;",
            "*(u64 *)(r10 - 32) = r1;",
            "call 8;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "kprobe"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: private_stack_nested_1
extern "C" fn private_stack_nested_1() {
    unsafe {
        core::arch::asm!(
            "r1 = 42;",
            "*(u64 *)(r10 - 512) = r1;",
            "call {cumulative_stack_depth_subprog};",
            "r0 = 0;",
            "exit;",
            cumulative_stack_depth_subprog = sym cumulative_stack_depth_subprog,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: loop_callback
extern "C" fn loop_callback() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = 42;",
            "*(u64 *)(r10 - 512) = r1;",
            "call {cumulative_stack_depth_subprog};",
            "r0 = 0;",
            "exit;",
            cumulative_stack_depth_subprog = sym cumulative_stack_depth_subprog,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: private_stack_callback
extern "C" fn private_stack_callback() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "r2 = {loop_callback};",
            "r3 = 0;",
            "r4 = 0;",
            "call 181;",
            "r0 = 0;",
            "exit;",
            loop_callback = in(reg) loop_callback as usize,
            out("r0") _,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
            options(nostack)
        );
    }
}

include!("hand/verifier_private_stack.rs");

bpf_object!("GPL");
