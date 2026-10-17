// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_div0.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_div0` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: by_0_zero_check_1_1 by_0_zero_check_2_1 div64_by_0_zero_check by_0_zero_check_1_2 by_0_zero_check_2_2 mod64_by_0_zero_check _0_zero_check_ok_cls_1 _0_zero_check_1_cls_1 _0_zero_check_2_cls_1 by_0_zero_check_cls _0_zero_check_ok_cls_2 _0_zero_check_1_cls_2 _0_zero_check_2_cls_2 _0_zero_check_1_cls_3 _0_zero_check_2_cls_3

use bpf_rs_core::{bpf_object, test_tags};

test_tags! {
    by_0_zero_check_1_1:
        __description("DIV32 by 0, zero check 1"),
        __success,
        __success_unpriv,
        __retval("42");
    by_0_zero_check_2_1:
        __description("DIV32 by 0, zero check 2"),
        __success,
        __success_unpriv,
        __retval("42");
    div64_by_0_zero_check:
        __description("DIV64 by 0, zero check"),
        __success,
        __success_unpriv,
        __retval("42");
    by_0_zero_check_1_2:
        __description("MOD32 by 0, zero check 1"),
        __success,
        __success_unpriv,
        __retval("42");
    by_0_zero_check_2_2:
        __description("MOD32 by 0, zero check 2"),
        __success,
        __success_unpriv,
        __retval("42");
    mod64_by_0_zero_check:
        __description("MOD64 by 0, zero check"),
        __success,
        __success_unpriv,
        __retval("42");
    _0_zero_check_ok_cls_1:
        __description("DIV32 by 0, zero check ok, cls"),
        __success,
        __retval("8");
    _0_zero_check_1_cls_1:
        __description("DIV32 by 0, zero check 1, cls"),
        __success,
        __retval("0");
    _0_zero_check_2_cls_1:
        __description("DIV32 by 0, zero check 2, cls"),
        __success,
        __retval("0");
    by_0_zero_check_cls:
        __description("DIV64 by 0, zero check, cls"),
        __success,
        __retval("0");
    _0_zero_check_ok_cls_2:
        __description("MOD32 by 0, zero check ok, cls"),
        __success,
        __retval("2");
    _0_zero_check_1_cls_2:
        __description("MOD32 by 0, zero check 1, cls"),
        __success,
        __retval("1");
    _0_zero_check_2_cls_2:
        __description("MOD32 by 0, zero check 2, cls"),
        __success,
        __retval("1");
    _0_zero_check_1_cls_3:
        __description("MOD64 by 0, zero check 1, cls"),
        __success,
        __retval("2");
    _0_zero_check_2_cls_3:
        __description("MOD64 by 0, zero check 2, cls"),
        __success,
        __retval("-1");
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: by_0_zero_check_1_1
extern "C" fn by_0_zero_check_1_1() {
    unsafe {
        core::arch::asm!(
            "w0 = 42;",
            "w1 = 0;",
            "w2 = 1;",
            "w2 /= w1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: by_0_zero_check_2_1
extern "C" fn by_0_zero_check_2_1() {
    unsafe {
        core::arch::asm!(
            "w0 = 42;",
            "r1 = 0xffffffff00000000LL ll;",
            "w2 = 1;",
            "w2 /= w1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: div64_by_0_zero_check
extern "C" fn div64_by_0_zero_check() {
    unsafe {
        core::arch::asm!(
            "w0 = 42;",
            "w1 = 0;",
            "w2 = 1;",
            "r2 /= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: by_0_zero_check_1_2
extern "C" fn by_0_zero_check_1_2() {
    unsafe {
        core::arch::asm!(
            "w0 = 42;",
            "w1 = 0;",
            "w2 = 1;",
            "w2 %= w1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: by_0_zero_check_2_2
extern "C" fn by_0_zero_check_2_2() {
    unsafe {
        core::arch::asm!(
            "w0 = 42;",
            "r1 = 0xffffffff00000000LL ll;",
            "w2 = 1;",
            "w2 %= w1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mod64_by_0_zero_check
extern "C" fn mod64_by_0_zero_check() {
    unsafe {
        core::arch::asm!(
            "w0 = 42;",
            "w1 = 0;",
            "w2 = 1;",
            "r2 %= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: _0_zero_check_ok_cls_1
extern "C" fn _0_zero_check_ok_cls_1() {
    unsafe {
        core::arch::asm!(
            "w0 = 42;",
            "w1 = 2;",
            "w2 = 16;",
            "w2 /= w1;",
            "r0 = r2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: _0_zero_check_1_cls_1
extern "C" fn _0_zero_check_1_cls_1() {
    unsafe {
        core::arch::asm!(
            "w1 = 0;",
            "w0 = 1;",
            "w0 /= w1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: _0_zero_check_2_cls_1
extern "C" fn _0_zero_check_2_cls_1() {
    unsafe {
        core::arch::asm!(
            "r1 = 0xffffffff00000000LL ll;",
            "w0 = 1;",
            "w0 /= w1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: by_0_zero_check_cls
extern "C" fn by_0_zero_check_cls() {
    unsafe {
        core::arch::asm!(
            "w1 = 0;",
            "w0 = 1;",
            "r0 /= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: _0_zero_check_ok_cls_2
extern "C" fn _0_zero_check_ok_cls_2() {
    unsafe {
        core::arch::asm!(
            "w0 = 42;",
            "w1 = 3;",
            "w2 = 5;",
            "w2 %= w1;",
            "r0 = r2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: _0_zero_check_1_cls_2
extern "C" fn _0_zero_check_1_cls_2() {
    unsafe {
        core::arch::asm!(
            "w1 = 0;",
            "w0 = 1;",
            "w0 %= w1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: _0_zero_check_2_cls_2
extern "C" fn _0_zero_check_2_cls_2() {
    unsafe {
        core::arch::asm!(
            "r1 = 0xffffffff00000000LL ll;",
            "w0 = 1;",
            "w0 %= w1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: _0_zero_check_1_cls_3
extern "C" fn _0_zero_check_1_cls_3() {
    unsafe {
        core::arch::asm!(
            "w1 = 0;",
            "w0 = 2;",
            "r0 %= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: _0_zero_check_2_cls_3
extern "C" fn _0_zero_check_2_cls_3() {
    unsafe {
        core::arch::asm!(
            "w1 = 0;",
            "w0 = -1;",
            "r0 %= r1;",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
