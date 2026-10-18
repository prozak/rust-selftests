// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/uninit_stack.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/uninit_stack.rs
// (include!d below): dummy.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py uninit_stack` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: read_uninit_stack_fixed_off read_uninit_stack_var_off dummy helper_uninit_to_misc

use bpf_rs_core::{bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    helper_uninit_to_misc:
        __log_level("7"),
        __msg("fp-104=mmmmmmmm");
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: read_uninit_stack_fixed_off
extern "C" fn read_uninit_stack_fixed_off(_ctx: *mut c_void) -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "*(u64*)(r10 - 128) = r1;",
            "r1 = *(u8 *)(r10 - 8 );",
            "r0 += r1;",
            "r1 = *(u8 *)(r10 - 11);",
            "r1 = *(u8 *)(r10 - 13);",
            "r1 = *(u8 *)(r10 - 15);",
            "r1 = *(u16*)(r10 - 16);",
            "r1 = *(u32*)(r10 - 32);",
            "r1 = *(u64*)(r10 - 64);",
            "*(u32*)(r10 - 72) = r1;",
            "r1 = *(u64*)(r10 - 72);",
            "r0 = 0;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: read_uninit_stack_var_off
extern "C" fn read_uninit_stack_var_off(_ctx: *mut c_void) -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "call 7;",
            "*(u64*)(r10 - 64) = r0;",
            "r0 = -r0;",
            "if r0 s<= -32 goto exit_0;",
            "if r0 s>= 0 goto exit_0;",
            "r1 = r10;",
            "r1 += r0;",
            "r2 = *(u8*)(r1 + 0);",
            "exit_0:",
            "r0 = 0;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: helper_uninit_to_misc
extern "C" fn helper_uninit_to_misc(_ctx: *mut c_void) -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "*(u64*)(r10 - 128) = r1;",
            "r1 = r10;",
            "r1 += -128;",
            "r2 = 32;",
            "r3 = 0;",
            "call 112;",
            "call {dummy};",
            "r1 = *(u64*)(r10 - 104);",
            "r0 = 0;",
            "exit;",
            dummy = sym dummy,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

include!("hand/uninit_stack.rs");

bpf_object!("GPL");
