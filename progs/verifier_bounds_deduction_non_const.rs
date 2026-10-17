// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_bounds_deduction_non_const.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_bounds_deduction_non_const` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: deducing_bounds_from_non_const_1 deducing_bounds_from_non_const_2 deducing_bounds_from_non_const_3 deducing_bounds_from_non_const_4 deducing_bounds_from_non_const_5 deducing_bounds_from_non_const_6 deducing_bounds_from_non_const_7 deducing_bounds_from_non_const_8 deducing_bounds_from_non_const_9 deducing_bounds_from_non_const_10 deducing_bounds_from_non_const_11 deducing_bounds_from_non_const_12 deducing_bounds_from_non_const_13 deducing_bounds_from_non_const_14 deducing_bounds_from_non_const_15 deducing_bounds_from_non_const_16 deducing_bounds_from_non_const_17 deducing_bounds_from_non_const_18 deducing_bounds_from_non_const_19 deducing_bounds_from_non_const_20 deducing_bounds_from_non_const_21 deducing_bounds_from_non_const_22 deducing_bounds_from_non_const_23 deducing_bounds_from_non_const_24 deducing_bounds_from_non_const_25 deducing_bounds_from_non_const_26 deducing_bounds_from_non_const_27 deducing_bounds_from_non_const_28 deducing_bounds_from_non_const_29 deducing_bounds_from_non_const_30

use bpf_rs_core::{bpf_object, test_tags};

test_tags! {
    deducing_bounds_from_non_const_1:
        __description("check deducing bounds from non-const, jmp64, <non_const> == <const>, 1"),
        __success,
        __retval("0");
    deducing_bounds_from_non_const_2:
        __description("check deducing bounds from non-const, jmp64, <non_const> == <const>, 2"),
        __success,
        __retval("0");
    deducing_bounds_from_non_const_3:
        __description("check deducing bounds from non-const, jmp64, <non_const> != <const>, 1"),
        __success,
        __retval("0");
    deducing_bounds_from_non_const_4:
        __description("check deducing bounds from non-const, jmp64, <non_const> != <const>, 2"),
        __success,
        __retval("0");
    deducing_bounds_from_non_const_5:
        __description("check deducing bounds from non-const, jmp32, <non_const> == <const>, 1"),
        __success,
        __retval("0");
    deducing_bounds_from_non_const_6:
        __description("check deducing bounds from non-const, jmp32, <non_const> == <const>, 2"),
        __success,
        __retval("0");
    deducing_bounds_from_non_const_7:
        __description("check deducing bounds from non-const, jmp32, <non_const> != <const>, 1"),
        __success,
        __retval("0");
    deducing_bounds_from_non_const_8:
        __description("check deducing bounds from non-const, jmp32, <non_const> != <const>, 2"),
        __success,
        __retval("0");
    deducing_bounds_from_non_const_9:
        __description("check deducing bounds from non-const, jmp64, <const> > <non_const>, 1"),
        __success,
        __retval("0");
    deducing_bounds_from_non_const_10:
        __description("check deducing bounds from non-const, jmp64, <const> > <non_const>, 2"),
        __success,
        __retval("0");
    deducing_bounds_from_non_const_11:
        __description("check deducing bounds from non-const, jmp64, <const> >= <non_const>"),
        __success,
        __retval("0");
    deducing_bounds_from_non_const_12:
        __description("check deducing bounds from non-const, jmp64, <const> < <non_const>"),
        __success,
        __retval("0");
    deducing_bounds_from_non_const_13:
        __description("check deducing bounds from non-const, jmp64, <const> <= <non_const>"),
        __success,
        __retval("0");
    deducing_bounds_from_non_const_14:
        __description("check deducing bounds from non-const, jmp64, <const> == <non_const>"),
        __success,
        __retval("0");
    deducing_bounds_from_non_const_15:
        __description("check deducing bounds from non-const, jmp64, <const> s> <non_const>"),
        __success,
        __retval("0");
    deducing_bounds_from_non_const_16:
        __description("check deducing bounds from non-const, jmp64, <const> s>= <non_const>"),
        __success,
        __retval("0");
    deducing_bounds_from_non_const_17:
        __description("check deducing bounds from non-const, jmp64, <const> s< <non_const>"),
        __success,
        __retval("0");
    deducing_bounds_from_non_const_18:
        __description("check deducing bounds from non-const, jmp64, <const> s<= <non_const>"),
        __success,
        __retval("0");
    deducing_bounds_from_non_const_19:
        __description("check deducing bounds from non-const, jmp64, <const> != <non_const>"),
        __success,
        __retval("0");
    deducing_bounds_from_non_const_20:
        __description("check deducing bounds from non-const, jmp32, <const> > <non_const>, 1"),
        __success,
        __retval("0");
    deducing_bounds_from_non_const_21:
        __description("check deducing bounds from non-const, jmp32, <const> > <non_const>, 2"),
        __success,
        __retval("0");
    deducing_bounds_from_non_const_22:
        __description("check deducing bounds from non-const, jmp32, <const> >= <non_const>"),
        __success,
        __retval("0");
    deducing_bounds_from_non_const_23:
        __description("check deducing bounds from non-const, jmp32, <const> < <non_const>"),
        __success,
        __retval("0");
    deducing_bounds_from_non_const_24:
        __description("check deducing bounds from non-const, jmp32, <const> <= <non_const>"),
        __success,
        __retval("0");
    deducing_bounds_from_non_const_25:
        __description("check deducing bounds from non-const, jmp32, <const> == <non_const>"),
        __success,
        __retval("0");
    deducing_bounds_from_non_const_26:
        __description("check deducing bounds from non-const, jmp32, <const> s> <non_const>"),
        __success,
        __retval("0");
    deducing_bounds_from_non_const_27:
        __description("check deducing bounds from non-const, jmp32, <const> s>= <non_const>"),
        __success,
        __retval("0");
    deducing_bounds_from_non_const_28:
        __description("check deducing bounds from non-const, jmp32, <const> s< <non_const>"),
        __success,
        __retval("0");
    deducing_bounds_from_non_const_29:
        __description("check deducing bounds from non-const, jmp32, <const> s<= <non_const>"),
        __success,
        __retval("0");
    deducing_bounds_from_non_const_30:
        __description("check deducing bounds from non-const, jmp32, <const> != <non_const>"),
        __success,
        __retval("0");
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deducing_bounds_from_non_const_1
extern "C" fn deducing_bounds_from_non_const_1() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "if r0 < 3 goto l0_0;",
            "r2 = 2;",
            "if r0 == r2 goto l1_0;",
            "l0_0:",
            "r0 = 0;",
            "exit;",
            "l1_0:",
            "r0 -= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deducing_bounds_from_non_const_2
extern "C" fn deducing_bounds_from_non_const_2() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "if r0 > 3 goto l0_1;",
            "r2 = 4;",
            "if r0 == r2 goto l1_1;",
            "l0_1:",
            "r0 = 0;",
            "exit;",
            "l1_1:",
            "r0 -= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deducing_bounds_from_non_const_3
extern "C" fn deducing_bounds_from_non_const_3() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "if r0 < 3 goto l0_2;",
            "r2 = 2;",
            "if r0 != r2 goto l0_2;",
            "goto l1_2;",
            "l0_2:",
            "r0 = 0;",
            "exit;",
            "l1_2:",
            "r0 -= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deducing_bounds_from_non_const_4
extern "C" fn deducing_bounds_from_non_const_4() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "if r0 > 3 goto l0_3;",
            "r2 = 4;",
            "if r0 != r2 goto l0_3;",
            "goto l1_3;",
            "l0_3:",
            "r0 = 0;",
            "exit;",
            "l1_3:",
            "r0 -= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deducing_bounds_from_non_const_5
extern "C" fn deducing_bounds_from_non_const_5() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "if w0 < 4 goto l0_4;",
            "w2 = 3;",
            "if w0 == w2 goto l1_4;",
            "l0_4:",
            "r0 = 0;",
            "exit;",
            "l1_4:",
            "r0 -= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deducing_bounds_from_non_const_6
extern "C" fn deducing_bounds_from_non_const_6() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "if w0 > 4 goto l0_5;",
            "w2 = 5;",
            "if w0 == w2 goto l1_5;",
            "l0_5:",
            "r0 = 0;",
            "exit;",
            "l1_5:",
            "r0 -= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deducing_bounds_from_non_const_7
extern "C" fn deducing_bounds_from_non_const_7() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "if w0 < 3 goto l0_6;",
            "w2 = 2;",
            "if w0 != w2 goto l0_6;",
            "goto l1_6;",
            "l0_6:",
            "r0 = 0;",
            "exit;",
            "l1_6:",
            "r0 -= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deducing_bounds_from_non_const_8
extern "C" fn deducing_bounds_from_non_const_8() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "if w0 > 3 goto l0_7;",
            "w2 = 4;",
            "if w0 != w2 goto l0_7;",
            "goto l1_7;",
            "l0_7:",
            "r0 = 0;",
            "exit;",
            "l1_7:",
            "r0 -= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deducing_bounds_from_non_const_9
extern "C" fn deducing_bounds_from_non_const_9() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "r2 = 0;",
            "if r2 > r0 goto l0_8;",
            "r0 = 0;",
            "exit;",
            "l0_8:",
            "r0 -= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deducing_bounds_from_non_const_10
extern "C" fn deducing_bounds_from_non_const_10() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "if r0 < 4 goto l0_9;",
            "r2 = 4;",
            "if r2 > r0 goto l1_9;",
            "l0_9:",
            "r0 = 0;",
            "exit;",
            "l1_9:",
            "r0 -= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deducing_bounds_from_non_const_11
extern "C" fn deducing_bounds_from_non_const_11() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "if r0 < 4 goto l0_10;",
            "r2 = 3;",
            "if r2 >= r0 goto l1_10;",
            "l0_10:",
            "r0 = 0;",
            "exit;",
            "l1_10:",
            "r0 -= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deducing_bounds_from_non_const_12
extern "C" fn deducing_bounds_from_non_const_12() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "if r0 > 4 goto l0_11;",
            "r2 = 4;",
            "if r2 < r0 goto l1_11;",
            "l0_11:",
            "r0 = 0;",
            "exit;",
            "l1_11:",
            "r0 -= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deducing_bounds_from_non_const_13
extern "C" fn deducing_bounds_from_non_const_13() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "if r0 >= 4 goto l0_12;",
            "r2 = 4;",
            "if r2 <= r0 goto l1_12;",
            "l0_12:",
            "r0 = 0;",
            "exit;",
            "l1_12:",
            "r0 -= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deducing_bounds_from_non_const_14
extern "C" fn deducing_bounds_from_non_const_14() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "if r0 < 3 goto l0_13;",
            "r2 = 2;",
            "if r2 == r0 goto l1_13;",
            "l0_13:",
            "r0 = 0;",
            "exit;",
            "l1_13:",
            "r0 -= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deducing_bounds_from_non_const_15
extern "C" fn deducing_bounds_from_non_const_15() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "if r0 s< 4 goto l0_14;",
            "r2 = 4;",
            "if r2 s> r0 goto l1_14;",
            "l0_14:",
            "r0 = 0;",
            "exit;",
            "l1_14:",
            "r0 -= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deducing_bounds_from_non_const_16
extern "C" fn deducing_bounds_from_non_const_16() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "if r0 s< 4 goto l0_15;",
            "r2 = 3;",
            "if r2 s>= r0 goto l1_15;",
            "l0_15:",
            "r0 = 0;",
            "exit;",
            "l1_15:",
            "r0 -= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deducing_bounds_from_non_const_17
extern "C" fn deducing_bounds_from_non_const_17() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "if r0 s> 4 goto l0_16;",
            "r2 = 4;",
            "if r2 s< r0 goto l1_16;",
            "l0_16:",
            "r0 = 0;",
            "exit;",
            "l1_16:",
            "r0 -= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deducing_bounds_from_non_const_18
extern "C" fn deducing_bounds_from_non_const_18() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "if r0 s> 4 goto l0_17;",
            "r2 = 5;",
            "if r2 s<= r0 goto l1_17;",
            "l0_17:",
            "r0 = 0;",
            "exit;",
            "l1_17:",
            "r0 -= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deducing_bounds_from_non_const_19
extern "C" fn deducing_bounds_from_non_const_19() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "if r0 < 3 goto l0_18;",
            "r2 = 2;",
            "if r2 != r0 goto l0_18;",
            "goto l1_18;",
            "l0_18:",
            "r0 = 0;",
            "exit;",
            "l1_18:",
            "r0 -= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deducing_bounds_from_non_const_20
extern "C" fn deducing_bounds_from_non_const_20() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "w2 = 0;",
            "if w2 > w0 goto l0_19;",
            "r0 = 0;",
            "exit;",
            "l0_19:",
            "r0 -= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deducing_bounds_from_non_const_21
extern "C" fn deducing_bounds_from_non_const_21() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "if w0 < 4 goto l0_20;",
            "w2 = 4;",
            "if w2 > w0 goto l1_20;",
            "l0_20:",
            "r0 = 0;",
            "exit;",
            "l1_20:",
            "r0 -= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deducing_bounds_from_non_const_22
extern "C" fn deducing_bounds_from_non_const_22() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "if w0 < 4 goto l0_21;",
            "w2 = 3;",
            "if w2 >= w0 goto l1_21;",
            "l0_21:",
            "r0 = 0;",
            "exit;",
            "l1_21:",
            "r0 -= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deducing_bounds_from_non_const_23
extern "C" fn deducing_bounds_from_non_const_23() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "if w0 > 4 goto l0_22;",
            "w2 = 4;",
            "if w2 < w0 goto l1_22;",
            "l0_22:",
            "r0 = 0;",
            "exit;",
            "l1_22:",
            "r0 -= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deducing_bounds_from_non_const_24
extern "C" fn deducing_bounds_from_non_const_24() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "if w0 >= 4 goto l0_23;",
            "w2 = 4;",
            "if w2 <= w0 goto l1_23;",
            "l0_23:",
            "r0 = 0;",
            "exit;",
            "l1_23:",
            "r0 -= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deducing_bounds_from_non_const_25
extern "C" fn deducing_bounds_from_non_const_25() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "if w0 < 4 goto l0_24;",
            "w2 = 3;",
            "if w2 == w0 goto l1_24;",
            "l0_24:",
            "r0 = 0;",
            "exit;",
            "l1_24:",
            "r0 -= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deducing_bounds_from_non_const_26
extern "C" fn deducing_bounds_from_non_const_26() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "if w0 s< 4 goto l0_25;",
            "w2 = 4;",
            "if w2 s> w0 goto l1_25;",
            "l0_25:",
            "r0 = 0;",
            "exit;",
            "l1_25:",
            "r0 -= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deducing_bounds_from_non_const_27
extern "C" fn deducing_bounds_from_non_const_27() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "if w0 s< 4 goto l0_26;",
            "w2 = 3;",
            "if w2 s>= w0 goto l1_26;",
            "l0_26:",
            "r0 = 0;",
            "exit;",
            "l1_26:",
            "r0 -= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deducing_bounds_from_non_const_28
extern "C" fn deducing_bounds_from_non_const_28() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "if w0 s> 4 goto l0_27;",
            "w2 = 5;",
            "if w2 s< w0 goto l1_27;",
            "l0_27:",
            "r0 = 0;",
            "exit;",
            "l1_27:",
            "r0 -= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deducing_bounds_from_non_const_29
extern "C" fn deducing_bounds_from_non_const_29() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "if w0 s>= 4 goto l0_28;",
            "w2 = 4;",
            "if w2 s<= w0 goto l1_28;",
            "l0_28:",
            "r0 = 0;",
            "exit;",
            "l1_28:",
            "r0 -= r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: deducing_bounds_from_non_const_30
extern "C" fn deducing_bounds_from_non_const_30() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "if w0 < 3 goto l0_29;",
            "w2 = 2;",
            "if w2 != w0 goto l0_29;",
            "goto l1_29;",
            "l0_29:",
            "r0 = 0;",
            "exit;",
            "l1_29:",
            "r0 -= r1;",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
