// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_int_ptr.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_int_ptr` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: arg_ptr_to_long_uninitialized ptr_to_long_half_uninitialized arg_ptr_to_long_misaligned to_long_size_sizeof_long arg_ptr_to_long_initialized

use bpf_rs_core::{bpf_object, test_tags};

test_tags! {
    arg_ptr_to_long_uninitialized:
        __description("arg pointer to long uninitialized"),
        __success;
    ptr_to_long_half_uninitialized:
        __description("arg pointer to long half-uninitialized"),
        __success,
        __retval("0");
    arg_ptr_to_long_misaligned:
        __description("arg pointer to long misaligned"),
        __failure,
        __msg("misaligned stack access off -20+0 size 8");
    to_long_size_sizeof_long:
        __description("arg pointer to long size < sizeof(long)"),
        __failure,
        __msg("invalid write to stack R4 off=-4 size=8");
    arg_ptr_to_long_initialized:
        __description("arg pointer to long initialized"),
        __success;
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: arg_ptr_to_long_uninitialized
extern "C" fn arg_ptr_to_long_uninitialized() {
    unsafe {
        core::arch::asm!(
            "r7 = r10;",
            "r7 += -8;",
            "r0 = 0x00303036;",
            "*(u64*)(r7 + 0) = r0;",
            "r1 = r7;",
            "r2 = 4;",
            "r3 = 0;",
            "r7 += -8;",
            "r4 = r7;",
            "call 106;",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_to_long_half_uninitialized
extern "C" fn ptr_to_long_half_uninitialized() {
    unsafe {
        core::arch::asm!(
            "r7 = r10;",
            "r7 += -8;",
            "r0 = 0x00303036;",
            "*(u64*)(r7 + 0) = r0;",
            "r1 = r7;",
            "r2 = 4;",
            "r3 = 0;",
            "r7 += -8;",
            "*(u32*)(r7 + 0) = r0;",
            "r4 = r7;",
            "call 106;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/sysctl"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: arg_ptr_to_long_misaligned
extern "C" fn arg_ptr_to_long_misaligned() {
    unsafe {
        core::arch::asm!(
            "r7 = r10;",
            "r7 += -8;",
            "r0 = 0x00303036;",
            "*(u64*)(r7 + 0) = r0;",
            "r1 = r7;",
            "r2 = 4;",
            "r3 = 0;",
            "r7 += -12;",
            "r0 = 0;",
            "*(u32*)(r7 + 0) = r0;",
            "*(u64*)(r7 + 4) = r0;",
            "r4 = r7;",
            "call 106;",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/sysctl"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: to_long_size_sizeof_long
extern "C" fn to_long_size_sizeof_long() {
    unsafe {
        core::arch::asm!(
            "r7 = r10;",
            "r7 += -16;",
            "r0 = 0x00303036;",
            "*(u64*)(r7 + 0) = r0;",
            "r1 = r7;",
            "r2 = 4;",
            "r3 = 0;",
            "r7 += 12;",
            "*(u32*)(r7 + 0) = r0;",
            "r4 = r7;",
            "call 106;",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/sysctl"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: arg_ptr_to_long_initialized
extern "C" fn arg_ptr_to_long_initialized() {
    unsafe {
        core::arch::asm!(
            "r7 = r10;",
            "r7 += -8;",
            "r0 = 0x00303036;",
            "*(u64*)(r7 + 0) = r0;",
            "r1 = r7;",
            "r2 = 4;",
            "r3 = 0;",
            "r7 += -8;",
            "*(u64*)(r7 + 0) = r0;",
            "r4 = r7;",
            "call 106;",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
