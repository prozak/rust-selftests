// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_meta_access.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_meta_access` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: meta_access_test1 meta_access_test2 meta_access_test3 meta_access_test4 meta_access_test5 meta_access_test6 meta_access_test7 meta_access_test8 meta_access_test9 meta_access_test10 meta_access_test11 meta_access_test12 meta_access_check_base_load_via_copy

use bpf_rs_core::{bpf_object, test_tags};

test_tags! {
    meta_access_test1:
        __description("meta access, test1"),
        __success,
        __retval("0");
    meta_access_test2:
        __description("meta access, test2"),
        __failure,
        __msg("R0 min value is negative");
    meta_access_test3:
        __description("meta access, test3"),
        __failure,
        __msg("invalid access to packet");
    meta_access_test4:
        __description("meta access, test4"),
        __failure,
        __msg("invalid access to packet");
    meta_access_test5:
        __description("meta access, test5"),
        __failure,
        __msg("R3 !read_ok");
    meta_access_test6:
        __description("meta access, test6"),
        __failure,
        __msg("invalid access to packet");
    meta_access_test7:
        __description("meta access, test7"),
        __success,
        __retval("0");
    meta_access_test8:
        __description("meta access, test8"),
        __success,
        __retval("0");
    meta_access_test9:
        __description("meta access, test9"),
        __failure,
        __msg("invalid access to packet");
    meta_access_test10:
        __description("meta access, test10"),
        __failure,
        __msg("invalid access to packet");
    meta_access_test11:
        __description("meta access, test11"),
        __success,
        __retval("0");
    meta_access_test12:
        __description("meta access, test12"),
        __success,
        __retval("0");
    meta_access_check_base_load_via_copy:
        __description("meta access, 8-aligned offset, check p, load a byte at p + 1 via p + 8"),
        __failure,
        __msg("invalid access to packet, off=51 size=1");
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: meta_access_test1
extern "C" fn meta_access_test1() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r0 = r2;",
            "r0 += 8;",
            "if r0 > r3 goto l0_0;",
            "r0 = *(u8*)(r2 + 0);",
            "l0_0:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: meta_access_test2
extern "C" fn meta_access_test2() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r0 = r2;",
            "r0 -= 8;",
            "r4 = r2;",
            "r4 += 8;",
            "if r4 > r3 goto l0_1;",
            "r0 = *(u8*)(r0 + 0);",
            "l0_1:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: meta_access_test3
extern "C" fn meta_access_test3() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 4);",
            "r0 = r2;",
            "r0 += 8;",
            "if r0 > r3 goto l0_2;",
            "r0 = *(u8*)(r2 + 0);",
            "l0_2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: meta_access_test4
extern "C" fn meta_access_test4() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 4);",
            "r4 = *(u32*)(r1 + 0);",
            "r0 = r4;",
            "r0 += 8;",
            "if r0 > r3 goto l0_3;",
            "r0 = *(u8*)(r2 + 0);",
            "l0_3:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: meta_access_test5
extern "C" fn meta_access_test5() {
    unsafe {
        core::arch::asm!(
            "r3 = *(u32*)(r1 + 8);",
            "r4 = *(u32*)(r1 + 0);",
            "r0 = r3;",
            "r0 += 8;",
            "if r0 > r4 goto l0_4;",
            "r2 = -8;",
            "call 54;",
            "r0 = *(u8*)(r3 + 0);",
            "l0_4:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: meta_access_test6
extern "C" fn meta_access_test6() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r0 = r3;",
            "r0 += 8;",
            "r4 = r2;",
            "r4 += 8;",
            "if r4 > r0 goto l0_5;",
            "r0 = *(u8*)(r2 + 0);",
            "l0_5:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: meta_access_test7
extern "C" fn meta_access_test7() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r0 = r3;",
            "r0 += 8;",
            "r4 = r2;",
            "r4 += 8;",
            "if r4 > r3 goto l0_6;",
            "r0 = *(u8*)(r2 + 0);",
            "l0_6:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: meta_access_test8
extern "C" fn meta_access_test8() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r4 = r2;",
            "r4 += 0xFFFF;",
            "if r4 > r3 goto l0_7;",
            "r0 = *(u8*)(r2 + 0);",
            "l0_7:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: meta_access_test9
extern "C" fn meta_access_test9() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r4 = r2;",
            "r4 += 0xFFFF;",
            "r4 += 1;",
            "if r4 > r3 goto l0_8;",
            "r0 = *(u8*)(r2 + 0);",
            "l0_8:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: meta_access_test10
extern "C" fn meta_access_test10() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r4 = *(u32*)(r1 + 4);",
            "r5 = 42;",
            "r6 = 24;",
            "*(u64*)(r10 - 8) = r5;",
            "lock *(u64 *)(r10 - 8) += r6;",
            "r5 = *(u64*)(r10 - 8);",
            "if r5 > 100 goto l0_9;",
            "r3 += r5;",
            "r5 = r3;",
            "r6 = r2;",
            "r6 += 8;",
            "if r6 > r5 goto l0_9;",
            "r2 = *(u8*)(r2 + 0);",
            "l0_9:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: meta_access_test11
extern "C" fn meta_access_test11() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r5 = 42;",
            "r6 = 24;",
            "*(u64*)(r10 - 8) = r5;",
            "lock *(u64 *)(r10 - 8) += r6;",
            "r5 = *(u64*)(r10 - 8);",
            "if r5 > 100 goto l0_10;",
            "r2 += r5;",
            "r5 = r2;",
            "r6 = r2;",
            "r6 += 8;",
            "if r6 > r3 goto l0_10;",
            "r5 = *(u8*)(r5 + 0);",
            "l0_10:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: meta_access_test12
extern "C" fn meta_access_test12() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r4 = *(u32*)(r1 + 4);",
            "r5 = r3;",
            "r5 += 16;",
            "if r5 > r4 goto l0_11;",
            "r0 = *(u8*)(r3 + 0);",
            "r5 = r2;",
            "r5 += 16;",
            "if r5 > r3 goto l0_11;",
            "r0 = *(u8*)(r2 + 0);",
            "l0_11:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: meta_access_check_base_load_via_copy
extern "C" fn meta_access_check_base_load_via_copy() {
    unsafe {
        core::arch::asm!(
            "r9 = r1;",
            "call 7;",
            "r4 = r0;",
            "r4 &= 0x38;",
            "if r4 > 50 goto l0_12;",
            "r2 = *(u32*)(r9 + 8);",
            "r3 = *(u32*)(r9 + 0);",
            "r5 = r2;",
            "r5 += r4;",
            "r6 = r5;",
            "r6 += 8;",
            "if r5 > r3 goto l0_12;",
            "r0 = *(u8*)(r6 - 7);",
            "l0_12:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
