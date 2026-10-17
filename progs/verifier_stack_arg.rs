// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_stack_arg.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_stack_arg.rs
// (include!d below): subprog_6args, subprog_7args, subprog_deref_arg6.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_stack_arg` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: subprog_6args subprog_7args subprog_deref_arg6 stack_arg_6args stack_arg_two_subprogs stack_arg_read_uninitialized stack_arg_gap_at_minus8 stack_arg_pruning_type_mismatch stack_arg_release_ref stack_arg_stale_pkt_ptr stack_arg_null_propagation_fail stack_arg_missing_store_one_branch stack_arg_shared_store stack_arg_write_beyond_max stack_arg_write_unused_slot stack_arg_sequential_calls

use bpf_rs_core::{bpf_map, bpf_object, test_tags};
#[allow(unused_imports)]
use core::ffi::c_void;

test_tags! {
    stack_arg_6args:
        __description("stack_arg: subprog with 6 args"),
        __success,
        __retval("21");
    stack_arg_two_subprogs:
        __description("stack_arg: two subprogs with >5 args"),
        __success,
        __retval("90");
    stack_arg_read_uninitialized:
        __description("stack_arg: read from uninitialized stack arg slot"),
        __failure,
        __msg("invalid read from stack arg off 8 depth 0");
    stack_arg_gap_at_minus8:
        __description("stack_arg: gap at offset -8, only wrote -16"),
        __failure,
        __msg("callee expects 7 args, stack arg1 is not initialized");
    stack_arg_pruning_type_mismatch:
        __description("stack_arg: pruning with different stack arg types"),
        __failure,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("arg JOIN insn 9 -> 10 r1: fp0-8 + _ => fp0-8|fp0+0"),
        __msg("arg JOIN insn 9 -> 10 sa0: fp0-8 + _ => fp0-8|fp0+0"),
        __msg("R{{[0-9]}} invalid mem access 'scalar'");
    stack_arg_release_ref:
        __description("stack_arg: release_reference invalidates stack arg slot"),
        __failure,
        __msg("callee expects 6 args, stack arg1 is not initialized");
    stack_arg_stale_pkt_ptr:
        __description("stack_arg: pkt pointer in stack arg slot invalidated after pull_data"),
        __failure,
        __msg("callee expects 6 args, stack arg1 is not initialized");
    stack_arg_null_propagation_fail:
        __description("stack_arg: null propagation rejects deref on null branch"),
        __failure,
        __msg("R{{[0-9]}} invalid mem access 'scalar'");
    stack_arg_missing_store_one_branch:
        __description("stack_arg: missing store on one branch"),
        __failure,
        __msg("callee expects 7 args, stack arg1 is not initialized");
    stack_arg_shared_store:
        __description("stack_arg: share a store for both branches"),
        __success,
        __retval("0");
    stack_arg_write_beyond_max:
        __description("stack_arg: write beyond max outgoing depth"),
        __failure,
        __msg("stack arg write offset -80 exceeds max 7 stack args");
    stack_arg_write_unused_slot:
        __description("stack_arg: write unused stack arg slot"),
        __failure,
        __msg("func#0 writes 5 stack arg slots, but calls only require 2");
    stack_arg_sequential_calls:
        __description("stack_arg: sequential calls reuse slots"),
        __failure,
        __msg("callee expects 7 args, stack arg1 is not initialized");
}

bpf_map! {
    map_hash_8b {
        r#type: *const [i32; 1],
        max_entries: *const [i32; 1],
        key: *const i64,
        value: *const i64,
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_arg_6args
extern "C" fn stack_arg_6args() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "r2 = 2;",
            "r3 = 3;",
            "r4 = 4;",
            "r5 = 5;",
            "*(u64 *)(r11 - 8) = 6;",
            "call {subprog_6args};",
            "exit;",
            subprog_6args = sym subprog_6args,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_arg_two_subprogs
extern "C" fn stack_arg_two_subprogs() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "r2 = 2;",
            "r3 = 3;",
            "r4 = 4;",
            "r5 = 5;",
            "*(u64 *)(r11 - 8) = 10;",
            "call {subprog_6args};",
            "r6 = r0;",
            "r1 = 1;",
            "r2 = 2;",
            "r3 = 3;",
            "r4 = 4;",
            "r5 = 5;",
            "*(u64 *)(r11 - 16) = 30;",
            "*(u64 *)(r11 - 8) = 20;",
            "call {subprog_7args};",
            "r0 += r6;",
            "exit;",
            subprog_6args = sym subprog_6args,
            subprog_7args = sym subprog_7args,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_arg_read_uninitialized
extern "C" fn stack_arg_read_uninitialized() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u64 *)(r11 + 8);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_arg_gap_at_minus8
extern "C" fn stack_arg_gap_at_minus8() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "r2 = 2;",
            "r3 = 3;",
            "r4 = 4;",
            "r5 = 5;",
            "*(u64 *)(r11 - 16) = 30;",
            "call {subprog_7args};",
            "exit;",
            subprog_7args = sym subprog_7args,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_arg_pruning_type_mismatch
extern "C" fn stack_arg_pruning_type_mismatch() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r6 = r0;",
            "r7 = 0;",
            "*(u64 *)(r10 - 8) = r7;",
            "if r6 s> 3 goto l0_0;",
            "r1 = r10;",
            "r1 += -8;",
            "*(u64 *)(r11 - 8) = r1;",
            "goto l1_0;",
            "l0_0:",
            "*(u64 *)(r11 - 8) = 42;",
            "l1_0:",
            "r1 = r6;",
            "r2 = 0;",
            "r3 = 0;",
            "r4 = 0;",
            "r5 = 0;",
            "call {subprog_deref_arg6};",
            "exit;",
            subprog_deref_arg6 = sym subprog_deref_arg6,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_arg_release_ref
extern "C" fn stack_arg_release_ref() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r2 = 0;",
            "*(u32 *)(r10 - 8) = r2;",
            "*(u64 *)(r10 - 16) = r2;",
            "*(u64 *)(r10 - 24) = r2;",
            "*(u64 *)(r10 - 32) = r2;",
            "*(u64 *)(r10 - 40) = r2;",
            "*(u64 *)(r10 - 48) = r2;",
            "r1 = r6;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "if r0 == 0 goto l0_1;",
            "*(u64 *)(r11 - 8) = r0;",
            "r1 = r0;",
            "call 86;",
            "r1 = 1;",
            "r2 = 2;",
            "r3 = 3;",
            "r4 = 4;",
            "r5 = 5;",
            "call {subprog_deref_arg6};",
            "l0_1:",
            "r0 = 0;",
            "exit;",
            subprog_deref_arg6 = sym subprog_deref_arg6,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_arg_stale_pkt_ptr
extern "C" fn stack_arg_stale_pkt_ptr() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r7 = *(u32 *)(r6 + 76);",
            "r8 = *(u32 *)(r6 + 80);",
            "r0 = r7;",
            "r0 += 8;",
            "if r0 > r8 goto l0_2;",
            "*(u64 *)(r11 - 8) = r7;",
            "r1 = r6;",
            "r2 = 0;",
            "call 39;",
            "r1 = 1;",
            "r2 = 2;",
            "r3 = 3;",
            "r4 = 4;",
            "r5 = 5;",
            "call {subprog_deref_arg6};",
            "l0_2:",
            "r0 = 0;",
            "exit;",
            subprog_deref_arg6 = sym subprog_deref_arg6,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_arg_null_propagation_fail
extern "C" fn stack_arg_null_propagation_fail() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64 *)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "*(u64 *)(r11 - 8) = r0;",
            "if r0 != 0 goto l0_3;",
            "r1 = 0;",
            "r2 = 0;",
            "r3 = 0;",
            "r4 = 0;",
            "r5 = 0;",
            "call {subprog_deref_arg6};",
            "l0_3:",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            subprog_deref_arg6 = sym subprog_deref_arg6,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_arg_missing_store_one_branch
extern "C" fn stack_arg_missing_store_one_branch() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = 1;",
            "r2 = 2;",
            "r3 = 3;",
            "r4 = 4;",
            "r5 = 5;",
            "*(u64 *)(r11 - 16) = 20;",
            "if r0 > 0 goto l0_4;",
            "*(u64 *)(r11 - 8) = 10;",
            "r1 = 1;",
            "r2 = 2;",
            "r3 = 3;",
            "r4 = 4;",
            "r5 = 5;",
            "call {subprog_7args};",
            "goto l1_4;",
            "l0_4:",
            "r1 = 1;",
            "r2 = 2;",
            "r3 = 3;",
            "r4 = 4;",
            "r5 = 5;",
            "call {subprog_7args};",
            "l1_4:",
            "r0 = 0;",
            "exit;",
            subprog_7args = sym subprog_7args,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_arg_shared_store
extern "C" fn stack_arg_shared_store() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = 1;",
            "r2 = 2;",
            "r3 = 3;",
            "r4 = 4;",
            "r5 = 5;",
            "*(u64 *)(r11 - 16) = 20;",
            "if r0 > 0 goto l0_5;",
            "*(u64 *)(r11 - 8) = 10;",
            "r1 = 1;",
            "r2 = 2;",
            "r3 = 3;",
            "r4 = 4;",
            "r5 = 5;",
            "call {subprog_7args};",
            "goto l1_5;",
            "l0_5:",
            "*(u64 *)(r11 - 8) = 30;",
            "r1 = 1;",
            "r2 = 2;",
            "r3 = 3;",
            "r4 = 4;",
            "r5 = 5;",
            "call {subprog_7args};",
            "l1_5:",
            "r0 = 0;",
            "exit;",
            subprog_7args = sym subprog_7args,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_arg_write_beyond_max
extern "C" fn stack_arg_write_beyond_max() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "r2 = 2;",
            "r3 = 3;",
            "r4 = 4;",
            "r5 = 5;",
            "*(u64 *)(r11 - 80) = 99;",
            "*(u64 *)(r11 - 16) = 20;",
            "*(u64 *)(r11 - 8) = 10;",
            "call {subprog_7args};",
            "r0 = 0;",
            "exit;",
            subprog_7args = sym subprog_7args,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_arg_write_unused_slot
extern "C" fn stack_arg_write_unused_slot() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "r2 = 2;",
            "r3 = 3;",
            "r4 = 4;",
            "r5 = 5;",
            "*(u64 *)(r11 - 40) = 99;",
            "*(u64 *)(r11 - 16) = 20;",
            "*(u64 *)(r11 - 8) = 10;",
            "call {subprog_7args};",
            "r0 = 0;",
            "exit;",
            subprog_7args = sym subprog_7args,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_arg_sequential_calls
extern "C" fn stack_arg_sequential_calls() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "r2 = 2;",
            "r3 = 3;",
            "r4 = 4;",
            "r5 = 5;",
            "*(u64 *)(r11 - 8) = 6;",
            "*(u64 *)(r11 - 16) = 7;",
            "call {subprog_7args};",
            "r6 = r0;",
            "r1 = 1;",
            "r2 = 2;",
            "r3 = 3;",
            "r4 = 4;",
            "r5 = 5;",
            "call {subprog_7args};",
            "r0 += r6;",
            "exit;",
            subprog_7args = sym subprog_7args,
            options(nostack)
        );
    }
}

include!("hand/verifier_stack_arg.rs");

bpf_object!("GPL");
