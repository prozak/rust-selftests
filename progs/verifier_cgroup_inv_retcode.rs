// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_cgroup_inv_retcode.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_cgroup_inv_retcode` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: with_invalid_return_code_test1 with_invalid_return_code_test2 with_invalid_return_code_test3 with_invalid_return_code_test4 with_invalid_return_code_test5 with_invalid_return_code_test6 with_invalid_return_code_test7

use bpf_rs_core::{bpf_object, test_tags};

test_tags! {
    with_invalid_return_code_test1:
        __description("bpf_exit with invalid return code. test1"),
        __failure,
        __msg("smin=0 smax=4294967295 should have been in [0, 1]");
    with_invalid_return_code_test2:
        __description("bpf_exit with invalid return code. test2"),
        __success;
    with_invalid_return_code_test3:
        __description("bpf_exit with invalid return code. test3"),
        __failure,
        __msg("smin=0 smax=3 should have been in [0, 1]");
    with_invalid_return_code_test4:
        __description("bpf_exit with invalid return code. test4"),
        __success;
    with_invalid_return_code_test5:
        __description("bpf_exit with invalid return code. test5"),
        __failure,
        __msg("smin=2 smax=2 should have been in [0, 1]");
    with_invalid_return_code_test6:
        __description("bpf_exit with invalid return code. test6"),
        __failure,
        __msg("R0 is not a known value (ctx)");
    with_invalid_return_code_test7:
        __description("bpf_exit with invalid return code. test7"),
        __failure,
        __msg("R0 has unknown scalar value should have been in [0, 1]");
}

#[link_section = "cgroup/sock"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: with_invalid_return_code_test1
extern "C" fn with_invalid_return_code_test1() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u32*)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/sock"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: with_invalid_return_code_test2
extern "C" fn with_invalid_return_code_test2() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u32*)(r1 + 0);",
            "r0 &= 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/sock"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: with_invalid_return_code_test3
extern "C" fn with_invalid_return_code_test3() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u32*)(r1 + 0);",
            "r0 &= 3;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/sock"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: with_invalid_return_code_test4
extern "C" fn with_invalid_return_code_test4() {
    unsafe {
        core::arch::asm!(
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/sock"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: with_invalid_return_code_test5
extern "C" fn with_invalid_return_code_test5() {
    unsafe {
        core::arch::asm!(
            "r0 = 2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/sock"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: with_invalid_return_code_test6
extern "C" fn with_invalid_return_code_test6() {
    unsafe {
        core::arch::asm!(
            "r0 = r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/sock"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: with_invalid_return_code_test7
extern "C" fn with_invalid_return_code_test7() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u32*)(r1 + 0);",
            "r2 = *(u32*)(r1 + 4);",
            "r0 *= r2;",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
