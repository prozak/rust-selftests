// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_masking.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_masking` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: test_out_of_bounds_1 test_out_of_bounds_2 test_out_of_bounds_3 test_out_of_bounds_4 test_out_of_bounds_5 test_out_of_bounds_6 test_out_of_bounds_7 test_out_of_bounds_8 test_out_of_bounds_9 test_out_of_bounds_10 test_out_of_bounds_11 test_out_of_bounds_12 masking_test_in_bounds_1 masking_test_in_bounds_2 masking_test_in_bounds_3 masking_test_in_bounds_4 masking_test_in_bounds_5 masking_test_in_bounds_6 masking_test_in_bounds_7 masking_test_in_bounds_8

use bpf_rs_core::{bpf_object, test_tags};

test_tags! {
    test_out_of_bounds_1:
        __description("masking, test out of bounds 1"),
        __success,
        __success_unpriv,
        __retval("0");
    test_out_of_bounds_2:
        __description("masking, test out of bounds 2"),
        __success,
        __success_unpriv,
        __retval("0");
    test_out_of_bounds_3:
        __description("masking, test out of bounds 3"),
        __success,
        __success_unpriv,
        __retval("0");
    test_out_of_bounds_4:
        __description("masking, test out of bounds 4"),
        __success,
        __success_unpriv,
        __retval("0");
    test_out_of_bounds_5:
        __description("masking, test out of bounds 5"),
        __success,
        __success_unpriv,
        __retval("0");
    test_out_of_bounds_6:
        __description("masking, test out of bounds 6"),
        __success,
        __success_unpriv,
        __retval("0");
    test_out_of_bounds_7:
        __description("masking, test out of bounds 7"),
        __success,
        __success_unpriv,
        __retval("0");
    test_out_of_bounds_8:
        __description("masking, test out of bounds 8"),
        __success,
        __success_unpriv,
        __retval("0");
    test_out_of_bounds_9:
        __description("masking, test out of bounds 9"),
        __success,
        __success_unpriv,
        __retval("0");
    test_out_of_bounds_10:
        __description("masking, test out of bounds 10"),
        __success,
        __success_unpriv,
        __retval("0");
    test_out_of_bounds_11:
        __description("masking, test out of bounds 11"),
        __success,
        __success_unpriv,
        __retval("0");
    test_out_of_bounds_12:
        __description("masking, test out of bounds 12"),
        __success,
        __success_unpriv,
        __retval("0");
    masking_test_in_bounds_1:
        __description("masking, test in bounds 1"),
        __success,
        __success_unpriv,
        __retval("4");
    masking_test_in_bounds_2:
        __description("masking, test in bounds 2"),
        __success,
        __success_unpriv,
        __retval("0");
    masking_test_in_bounds_3:
        __description("masking, test in bounds 3"),
        __success,
        __success_unpriv,
        __retval("0xfffffffe");
    masking_test_in_bounds_4:
        __description("masking, test in bounds 4"),
        __success,
        __success_unpriv,
        __retval("0xabcde");
    masking_test_in_bounds_5:
        __description("masking, test in bounds 5"),
        __success,
        __success_unpriv,
        __retval("0");
    masking_test_in_bounds_6:
        __description("masking, test in bounds 6"),
        __success,
        __success_unpriv,
        __retval("46");
    masking_test_in_bounds_7:
        __description("masking, test in bounds 7"),
        __success,
        __success_unpriv,
        __retval("46");
    masking_test_in_bounds_8:
        __description("masking, test in bounds 8"),
        __success,
        __success_unpriv,
        __retval("0");
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: test_out_of_bounds_1
extern "C" fn test_out_of_bounds_1() {
    unsafe {
        core::arch::asm!(
            "w1 = 5;",
            "w2 = 4;",
            "r2 -= r1;",
            "r2 |= r1;",
            "r2 = -r2;",
            "r2 s>>= 63;",
            "r1 &= r2;",
            "r0 = r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: test_out_of_bounds_2
extern "C" fn test_out_of_bounds_2() {
    unsafe {
        core::arch::asm!(
            "w1 = 1;",
            "w2 = 0;",
            "r2 -= r1;",
            "r2 |= r1;",
            "r2 = -r2;",
            "r2 s>>= 63;",
            "r1 &= r2;",
            "r0 = r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: test_out_of_bounds_3
extern "C" fn test_out_of_bounds_3() {
    unsafe {
        core::arch::asm!(
            "w1 = 0xffffffff;",
            "w2 = -2;",
            "r2 -= r1;",
            "r2 |= r1;",
            "r2 = -r2;",
            "r2 s>>= 63;",
            "r1 &= r2;",
            "r0 = r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: test_out_of_bounds_4
extern "C" fn test_out_of_bounds_4() {
    unsafe {
        core::arch::asm!(
            "w1 = 0xffffffff;",
            "w2 = 0;",
            "r2 -= r1;",
            "r2 |= r1;",
            "r2 = -r2;",
            "r2 s>>= 63;",
            "r1 &= r2;",
            "r0 = r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: test_out_of_bounds_5
extern "C" fn test_out_of_bounds_5() {
    unsafe {
        core::arch::asm!(
            "w1 = -1;",
            "w2 = 0;",
            "r2 -= r1;",
            "r2 |= r1;",
            "r2 = -r2;",
            "r2 s>>= 63;",
            "r1 &= r2;",
            "r0 = r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: test_out_of_bounds_6
extern "C" fn test_out_of_bounds_6() {
    unsafe {
        core::arch::asm!(
            "w1 = -1;",
            "w2 = -2;",
            "r2 -= r1;",
            "r2 |= r1;",
            "r2 = -r2;",
            "r2 s>>= 63;",
            "r1 &= r2;",
            "r0 = r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: test_out_of_bounds_7
extern "C" fn test_out_of_bounds_7() {
    unsafe {
        core::arch::asm!(
            "r1 = 5;",
            "w2 = 4;",
            "r2 -= r1;",
            "r2 |= r1;",
            "r2 = -r2;",
            "r2 s>>= 63;",
            "r1 &= r2;",
            "r0 = r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: test_out_of_bounds_8
extern "C" fn test_out_of_bounds_8() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "w2 = 0;",
            "r2 -= r1;",
            "r2 |= r1;",
            "r2 = -r2;",
            "r2 s>>= 63;",
            "r1 &= r2;",
            "r0 = r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: test_out_of_bounds_9
extern "C" fn test_out_of_bounds_9() {
    unsafe {
        core::arch::asm!(
            "r1 = 0xffffffff;",
            "w2 = -2;",
            "r2 -= r1;",
            "r2 |= r1;",
            "r2 = -r2;",
            "r2 s>>= 63;",
            "r1 &= r2;",
            "r0 = r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: test_out_of_bounds_10
extern "C" fn test_out_of_bounds_10() {
    unsafe {
        core::arch::asm!(
            "r1 = 0xffffffff;",
            "w2 = 0;",
            "r2 -= r1;",
            "r2 |= r1;",
            "r2 = -r2;",
            "r2 s>>= 63;",
            "r1 &= r2;",
            "r0 = r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: test_out_of_bounds_11
extern "C" fn test_out_of_bounds_11() {
    unsafe {
        core::arch::asm!(
            "r1 = -1;",
            "w2 = 0;",
            "r2 -= r1;",
            "r2 |= r1;",
            "r2 = -r2;",
            "r2 s>>= 63;",
            "r1 &= r2;",
            "r0 = r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: test_out_of_bounds_12
extern "C" fn test_out_of_bounds_12() {
    unsafe {
        core::arch::asm!(
            "r1 = -1;",
            "w2 = -2;",
            "r2 -= r1;",
            "r2 |= r1;",
            "r2 = -r2;",
            "r2 s>>= 63;",
            "r1 &= r2;",
            "r0 = r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: masking_test_in_bounds_1
extern "C" fn masking_test_in_bounds_1() {
    unsafe {
        core::arch::asm!(
            "w1 = 4;",
            "w2 = 4;",
            "r2 -= r1;",
            "r2 |= r1;",
            "r2 = -r2;",
            "r2 s>>= 63;",
            "r1 &= r2;",
            "r0 = r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: masking_test_in_bounds_2
extern "C" fn masking_test_in_bounds_2() {
    unsafe {
        core::arch::asm!(
            "w1 = 0;",
            "w2 = -2;",
            "r2 -= r1;",
            "r2 |= r1;",
            "r2 = -r2;",
            "r2 s>>= 63;",
            "r1 &= r2;",
            "r0 = r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: masking_test_in_bounds_3
extern "C" fn masking_test_in_bounds_3() {
    unsafe {
        core::arch::asm!(
            "w1 = 0xfffffffe;",
            "w2 = -2;",
            "r2 -= r1;",
            "r2 |= r1;",
            "r2 = -r2;",
            "r2 s>>= 63;",
            "r1 &= r2;",
            "r0 = r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: masking_test_in_bounds_4
extern "C" fn masking_test_in_bounds_4() {
    unsafe {
        core::arch::asm!(
            "w1 = 0xabcde;",
            "w2 = 11259374;",
            "r2 -= r1;",
            "r2 |= r1;",
            "r2 = -r2;",
            "r2 s>>= 63;",
            "r1 &= r2;",
            "r0 = r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: masking_test_in_bounds_5
extern "C" fn masking_test_in_bounds_5() {
    unsafe {
        core::arch::asm!(
            "w1 = 0;",
            "w2 = 0;",
            "r2 -= r1;",
            "r2 |= r1;",
            "r2 = -r2;",
            "r2 s>>= 63;",
            "r1 &= r2;",
            "r0 = r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: masking_test_in_bounds_6
extern "C" fn masking_test_in_bounds_6() {
    unsafe {
        core::arch::asm!(
            "w1 = 46;",
            "w2 = 46;",
            "r2 -= r1;",
            "r2 |= r1;",
            "r2 = -r2;",
            "r2 s>>= 63;",
            "r1 &= r2;",
            "r0 = r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: masking_test_in_bounds_7
extern "C" fn masking_test_in_bounds_7() {
    unsafe {
        core::arch::asm!(
            "r3 = -46;",
            "r3 *= -1;",
            "w2 = 46;",
            "r2 -= r3;",
            "r2 |= r3;",
            "r2 = -r2;",
            "r2 s>>= 63;",
            "r3 &= r2;",
            "r0 = r3;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: masking_test_in_bounds_8
extern "C" fn masking_test_in_bounds_8() {
    unsafe {
        core::arch::asm!(
            "r3 = -47;",
            "r3 *= -1;",
            "w2 = 46;",
            "r2 -= r3;",
            "r2 |= r3;",
            "r2 = -r2;",
            "r2 s>>= 63;",
            "r3 &= r2;",
            "r0 = r3;",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
