// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_subreg.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_subreg` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: add32_reg_zero_extend_check add32_imm_zero_extend_check sub32_reg_zero_extend_check sub32_imm_zero_extend_check mul32_reg_zero_extend_check mul32_imm_zero_extend_check div32_reg_zero_extend_check div32_imm_zero_extend_check or32_reg_zero_extend_check or32_imm_zero_extend_check and32_reg_zero_extend_check and32_imm_zero_extend_check lsh32_reg_zero_extend_check lsh32_imm_zero_extend_check rsh32_reg_zero_extend_check rsh32_imm_zero_extend_check neg32_reg_zero_extend_check mod32_reg_zero_extend_check mod32_imm_zero_extend_check xor32_reg_zero_extend_check xor32_imm_zero_extend_check mov32_reg_zero_extend_check mov32_imm_zero_extend_check arsh32_reg_zero_extend_check arsh32_imm_zero_extend_check arsh32_imm_sign_extend_positive_check arsh32_imm_sign_extend_negative_check arsh32_imm_sign_extend_check le_reg_zero_extend_check_1 le_reg_zero_extend_check_2 be_reg_zero_extend_check_1 be_reg_zero_extend_check_2 ldx_b_zero_extend_check ldx_h_zero_extend_check ldx_w_zero_extend_check arsh_31_and arsh_63_and arsh_31_or arsh_63_or arsh32_imm1_value lsh32_reg0_zero_extend_check rsh32_reg0_zero_extend_check arsh32_reg0_zero_extend_check lsh32_imm31_value rsh32_imm31_value arsh32_imm31_value lsh32_unknown_precise_bounds rsh32_unknown_bounds

use bpf_rs_core::{bpf_object, test_tags};

test_tags! {
    add32_reg_zero_extend_check:
        __description("add32 reg zero extend check"),
        __success,
        __success_unpriv,
        __retval("0");
    add32_imm_zero_extend_check:
        __description("add32 imm zero extend check"),
        __success,
        __success_unpriv,
        __retval("0");
    sub32_reg_zero_extend_check:
        __description("sub32 reg zero extend check"),
        __success,
        __success_unpriv,
        __retval("0");
    sub32_imm_zero_extend_check:
        __description("sub32 imm zero extend check"),
        __success,
        __success_unpriv,
        __retval("0");
    mul32_reg_zero_extend_check:
        __description("mul32 reg zero extend check"),
        __success,
        __success_unpriv,
        __retval("0");
    mul32_imm_zero_extend_check:
        __description("mul32 imm zero extend check"),
        __success,
        __success_unpriv,
        __retval("0");
    div32_reg_zero_extend_check:
        __description("div32 reg zero extend check"),
        __success,
        __success_unpriv,
        __retval("0");
    div32_imm_zero_extend_check:
        __description("div32 imm zero extend check"),
        __success,
        __success_unpriv,
        __retval("0");
    or32_reg_zero_extend_check:
        __description("or32 reg zero extend check"),
        __success,
        __success_unpriv,
        __retval("0");
    or32_imm_zero_extend_check:
        __description("or32 imm zero extend check"),
        __success,
        __success_unpriv,
        __retval("0");
    and32_reg_zero_extend_check:
        __description("and32 reg zero extend check"),
        __success,
        __success_unpriv,
        __retval("0");
    and32_imm_zero_extend_check:
        __description("and32 imm zero extend check"),
        __success,
        __success_unpriv,
        __retval("0");
    lsh32_reg_zero_extend_check:
        __description("lsh32 reg zero extend check"),
        __success,
        __success_unpriv,
        __retval("0");
    lsh32_imm_zero_extend_check:
        __description("lsh32 imm zero extend check"),
        __success,
        __success_unpriv,
        __retval("0");
    rsh32_reg_zero_extend_check:
        __description("rsh32 reg zero extend check"),
        __success,
        __success_unpriv,
        __retval("0");
    rsh32_imm_zero_extend_check:
        __description("rsh32 imm zero extend check"),
        __success,
        __success_unpriv,
        __retval("0");
    neg32_reg_zero_extend_check:
        __description("neg32 reg zero extend check"),
        __success,
        __success_unpriv,
        __retval("0");
    mod32_reg_zero_extend_check:
        __description("mod32 reg zero extend check"),
        __success,
        __success_unpriv,
        __retval("0");
    mod32_imm_zero_extend_check:
        __description("mod32 imm zero extend check"),
        __success,
        __success_unpriv,
        __retval("0");
    xor32_reg_zero_extend_check:
        __description("xor32 reg zero extend check"),
        __success,
        __success_unpriv,
        __retval("0");
    xor32_imm_zero_extend_check:
        __description("xor32 imm zero extend check"),
        __success,
        __success_unpriv,
        __retval("0");
    mov32_reg_zero_extend_check:
        __description("mov32 reg zero extend check"),
        __success,
        __success_unpriv,
        __retval("0");
    mov32_imm_zero_extend_check:
        __description("mov32 imm zero extend check"),
        __success,
        __success_unpriv,
        __retval("0");
    arsh32_reg_zero_extend_check:
        __description("arsh32 reg zero extend check"),
        __success,
        __success_unpriv,
        __retval("0");
    arsh32_imm_zero_extend_check:
        __description("arsh32 imm zero extend check"),
        __success,
        __success_unpriv,
        __retval("0");
    arsh32_imm_sign_extend_positive_check:
        __description("arsh32 imm sign positive extend check"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("2: (57) r6 &= 4095                    ; R6=scalar(smin=smin32=0,smax=umax=smax32=umax32=4095,var_off=(0x0; 0xfff))"),
        __msg("3: (67) r6 <<= 32                     ; R6=scalar(smin=smin32=0,smax=umax=0xfff00000000,smax32=umax32=0,var_off=(0x0; 0xfff00000000))"),
        __msg("4: (c7) r6 s>>= 32                    ; R6=scalar(smin=smin32=0,smax=umax=smax32=umax32=4095,var_off=(0x0; 0xfff))");
    arsh32_imm_sign_extend_negative_check:
        __description("arsh32 imm sign negative extend check"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("3: (17) r6 -= 4095                    ; R6=scalar(smin=smin32=-4095,smax=smax32=0)"),
        __msg("4: (67) r6 <<= 32                     ; R6=scalar(smin=0xfffff00100000000,smax=smax32=umax32=0,smin32=0,var_off=(0x0; 0xffffffff00000000))"),
        __msg("5: (c7) r6 s>>= 32                    ; R6=scalar(smin=smin32=-4095,smax=smax32=0)");
    arsh32_imm_sign_extend_check:
        __description("arsh32 imm sign extend check"),
        __success,
        __retval("0"),
        __log_level("2"),
        __msg("3: (17) r6 -= 2047                    ; R6=scalar(smin=smin32=-2047,smax=smax32=2048)"),
        __msg("4: (67) r6 <<= 32                     ; R6=scalar(smin=0xfffff80100000000,smax=0x80000000000,smin32=0,smax32=umax32=0,var_off=(0x0; 0xffffffff00000000))"),
        __msg("5: (c7) r6 s>>= 32                    ; R6=scalar(smin=smin32=-2047,smax=smax32=2048)");
    le_reg_zero_extend_check_1:
        __description("end16 (to_le) reg zero extend check"),
        __success,
        __success_unpriv,
        __retval("0");
    le_reg_zero_extend_check_2:
        __description("end32 (to_le) reg zero extend check"),
        __success,
        __success_unpriv,
        __retval("0");
    be_reg_zero_extend_check_1:
        __description("end16 (to_be) reg zero extend check"),
        __success,
        __success_unpriv,
        __retval("0");
    be_reg_zero_extend_check_2:
        __description("end32 (to_be) reg zero extend check"),
        __success,
        __success_unpriv,
        __retval("0");
    ldx_b_zero_extend_check:
        __description("ldx_b zero extend check"),
        __success,
        __success_unpriv,
        __retval("0");
    ldx_h_zero_extend_check:
        __description("ldx_h zero extend check"),
        __success,
        __success_unpriv,
        __retval("0");
    ldx_w_zero_extend_check:
        __description("ldx_w zero extend check"),
        __success,
        __success_unpriv,
        __retval("0");
    arsh_31_and:
        __success,
        __success_unpriv,
        __retval("0");
    arsh_63_and:
        __success,
        __success_unpriv,
        __retval("0");
    arsh_31_or:
        __success,
        __success_unpriv,
        __retval("0");
    arsh_63_or:
        __success,
        __success_unpriv,
        __retval("0");
    arsh32_imm1_value:
        __success,
        __retval("42");
    lsh32_reg0_zero_extend_check:
        __success,
        __retval("1");
    rsh32_reg0_zero_extend_check:
        __success,
        __retval("1");
    arsh32_reg0_zero_extend_check:
        __success,
        __retval("1");
    lsh32_imm31_value:
        __success,
        __retval("42");
    rsh32_imm31_value:
        __success,
        __retval("42");
    arsh32_imm31_value:
        __success,
        __retval("42");
    lsh32_unknown_precise_bounds:
        __success,
        __retval("1");
    rsh32_unknown_bounds:
        __success,
        __retval("1");
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: add32_reg_zero_extend_check
extern "C" fn add32_reg_zero_extend_check() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = r0;",
            "r0 = 0x100000000 ll;",
            "w0 += w1;",
            "r0 >>= 32;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: add32_imm_zero_extend_check
extern "C" fn add32_imm_zero_extend_check() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = 0x1000000000 ll;",
            "r0 |= r1;",
            "w0 += 0;",
            "r0 >>= 32;",
            "r6 = r0;",
            "call 7;",
            "r1 = 0x1000000000 ll;",
            "r0 |= r1;",
            "w0 += -2;",
            "r0 >>= 32;",
            "r0 |= r6;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sub32_reg_zero_extend_check
extern "C" fn sub32_reg_zero_extend_check() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = r0;",
            "r0 = 0x1ffffffff ll;",
            "w0 -= w1;",
            "r0 >>= 32;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sub32_imm_zero_extend_check
extern "C" fn sub32_imm_zero_extend_check() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = 0x1000000000 ll;",
            "r0 |= r1;",
            "w0 -= 0;",
            "r0 >>= 32;",
            "r6 = r0;",
            "call 7;",
            "r1 = 0x1000000000 ll;",
            "r0 |= r1;",
            "w0 -= 1;",
            "r0 >>= 32;",
            "r0 |= r6;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mul32_reg_zero_extend_check
extern "C" fn mul32_reg_zero_extend_check() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = r0;",
            "r0 = 0x100000001 ll;",
            "w0 *= w1;",
            "r0 >>= 32;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mul32_imm_zero_extend_check
extern "C" fn mul32_imm_zero_extend_check() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = 0x1000000000 ll;",
            "r0 |= r1;",
            "w0 *= 1;",
            "r0 >>= 32;",
            "r6 = r0;",
            "call 7;",
            "r1 = 0x1000000000 ll;",
            "r0 |= r1;",
            "w0 *= -1;",
            "r0 >>= 32;",
            "r0 |= r6;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: div32_reg_zero_extend_check
extern "C" fn div32_reg_zero_extend_check() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = r0;",
            "r0 = -1;",
            "w0 /= w1;",
            "r0 >>= 32;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: div32_imm_zero_extend_check
extern "C" fn div32_imm_zero_extend_check() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = 0x1000000000 ll;",
            "r0 |= r1;",
            "w0 /= 1;",
            "r0 >>= 32;",
            "r6 = r0;",
            "call 7;",
            "r1 = 0x1000000000 ll;",
            "r0 |= r1;",
            "w0 /= 2;",
            "r0 >>= 32;",
            "r0 |= r6;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: or32_reg_zero_extend_check
extern "C" fn or32_reg_zero_extend_check() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = r0;",
            "r0 = 0x100000001 ll;",
            "w0 |= w1;",
            "r0 >>= 32;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: or32_imm_zero_extend_check
extern "C" fn or32_imm_zero_extend_check() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = 0x1000000000 ll;",
            "r0 |= r1;",
            "w0 |= 0;",
            "r0 >>= 32;",
            "r6 = r0;",
            "call 7;",
            "r1 = 0x1000000000 ll;",
            "r0 |= r1;",
            "w0 |= 1;",
            "r0 >>= 32;",
            "r0 |= r6;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: and32_reg_zero_extend_check
extern "C" fn and32_reg_zero_extend_check() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = 0x100000000 ll;",
            "r1 |= r0;",
            "r0 = 0x1ffffffff ll;",
            "w0 &= w1;",
            "r0 >>= 32;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: and32_imm_zero_extend_check
extern "C" fn and32_imm_zero_extend_check() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = 0x1000000000 ll;",
            "r0 |= r1;",
            "w0 &= -1;",
            "r0 >>= 32;",
            "r6 = r0;",
            "call 7;",
            "r1 = 0x1000000000 ll;",
            "r0 |= r1;",
            "w0 &= -2;",
            "r0 >>= 32;",
            "r0 |= r6;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: lsh32_reg_zero_extend_check
extern "C" fn lsh32_reg_zero_extend_check() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = 0x100000000 ll;",
            "r0 |= r1;",
            "r1 = 1;",
            "w0 <<= w1;",
            "r0 >>= 32;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: lsh32_imm_zero_extend_check
extern "C" fn lsh32_imm_zero_extend_check() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = 0x1000000000 ll;",
            "r0 |= r1;",
            "w0 <<= 0;",
            "r0 >>= 32;",
            "r6 = r0;",
            "call 7;",
            "r1 = 0x1000000000 ll;",
            "r0 |= r1;",
            "w0 <<= 1;",
            "r0 >>= 32;",
            "r0 |= r6;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: rsh32_reg_zero_extend_check
extern "C" fn rsh32_reg_zero_extend_check() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = 0x1000000000 ll;",
            "r0 |= r1;",
            "r1 = 1;",
            "w0 >>= w1;",
            "r0 >>= 32;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: rsh32_imm_zero_extend_check
extern "C" fn rsh32_imm_zero_extend_check() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = 0x1000000000 ll;",
            "r0 |= r1;",
            "w0 >>= 0;",
            "r0 >>= 32;",
            "r6 = r0;",
            "call 7;",
            "r1 = 0x1000000000 ll;",
            "r0 |= r1;",
            "w0 >>= 1;",
            "r0 >>= 32;",
            "r0 |= r6;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: neg32_reg_zero_extend_check
extern "C" fn neg32_reg_zero_extend_check() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = 0x1000000000 ll;",
            "r0 |= r1;",
            "w0 = -w0;",
            "r0 >>= 32;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mod32_reg_zero_extend_check
extern "C" fn mod32_reg_zero_extend_check() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = r0;",
            "r0 = -1;",
            "w0 %= w1;",
            "r0 >>= 32;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mod32_imm_zero_extend_check
extern "C" fn mod32_imm_zero_extend_check() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = 0x1000000000 ll;",
            "r0 |= r1;",
            "w0 %= 1;",
            "r0 >>= 32;",
            "r6 = r0;",
            "call 7;",
            "r1 = 0x1000000000 ll;",
            "r0 |= r1;",
            "w0 %= 2;",
            "r0 >>= 32;",
            "r0 |= r6;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: xor32_reg_zero_extend_check
extern "C" fn xor32_reg_zero_extend_check() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = r0;",
            "r0 = 0x100000000 ll;",
            "w0 ^= w1;",
            "r0 >>= 32;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: xor32_imm_zero_extend_check
extern "C" fn xor32_imm_zero_extend_check() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = 0x1000000000 ll;",
            "r0 |= r1;",
            "w0 ^= 1;",
            "r0 >>= 32;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mov32_reg_zero_extend_check
extern "C" fn mov32_reg_zero_extend_check() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = 0x100000000 ll;",
            "r1 |= r0;",
            "r0 = 0x100000000 ll;",
            "w0 = w1;",
            "r0 >>= 32;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mov32_imm_zero_extend_check
extern "C" fn mov32_imm_zero_extend_check() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = 0x1000000000 ll;",
            "r0 |= r1;",
            "w0 = 0;",
            "r0 >>= 32;",
            "r6 = r0;",
            "call 7;",
            "r1 = 0x1000000000 ll;",
            "r0 |= r1;",
            "w0 = 1;",
            "r0 >>= 32;",
            "r0 |= r6;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: arsh32_reg_zero_extend_check
extern "C" fn arsh32_reg_zero_extend_check() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = 0x1000000000 ll;",
            "r0 |= r1;",
            "r1 = 1;",
            "w0 s>>= w1;",
            "r0 >>= 32;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: arsh32_imm_zero_extend_check
extern "C" fn arsh32_imm_zero_extend_check() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = 0x1000000000 ll;",
            "r0 |= r1;",
            "w0 s>>= 0;",
            "r0 >>= 32;",
            "r6 = r0;",
            "call 7;",
            "r1 = 0x1000000000 ll;",
            "r0 |= r1;",
            "w0 s>>= 1;",
            "r0 >>= 32;",
            "r0 |= r6;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: arsh32_imm_sign_extend_positive_check
extern "C" fn arsh32_imm_sign_extend_positive_check() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r6 = r0;",
            "r6 &= 4095;",
            "r6 <<= 32;",
            "r6 s>>= 32;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: arsh32_imm_sign_extend_negative_check
extern "C" fn arsh32_imm_sign_extend_negative_check() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r6 = r0;",
            "r6 &= 4095;",
            "r6 -= 4095;",
            "r6 <<= 32;",
            "r6 s>>= 32;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: arsh32_imm_sign_extend_check
extern "C" fn arsh32_imm_sign_extend_check() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r6 = r0;",
            "r6 &= 4095;",
            "r6 -= 2047;",
            "r6 <<= 32;",
            "r6 s>>= 32;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: le_reg_zero_extend_check_1
extern "C" fn le_reg_zero_extend_check_1() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r6 = r0;",
            "r6 <<= 32;",
            "call 7;",
            "r0 |= r6;",
            "r0 = le16 r0;",
            "r0 >>= 32;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: le_reg_zero_extend_check_2
extern "C" fn le_reg_zero_extend_check_2() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r6 = r0;",
            "r6 <<= 32;",
            "call 7;",
            "r0 |= r6;",
            "r0 = le32 r0;",
            "r0 >>= 32;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: be_reg_zero_extend_check_1
extern "C" fn be_reg_zero_extend_check_1() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r6 = r0;",
            "r6 <<= 32;",
            "call 7;",
            "r0 |= r6;",
            "r0 = be16 r0;",
            "r0 >>= 32;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: be_reg_zero_extend_check_2
extern "C" fn be_reg_zero_extend_check_2() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r6 = r0;",
            "r6 <<= 32;",
            "call 7;",
            "r0 |= r6;",
            "r0 = be32 r0;",
            "r0 >>= 32;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ldx_b_zero_extend_check
extern "C" fn ldx_b_zero_extend_check() {
    unsafe {
        core::arch::asm!(
            "r6 = r10;",
            "r6 += -4;",
            "r7 = 0xfaceb00c;",
            "*(u32*)(r6 + 0) = r7;",
            "call 7;",
            "r1 = 0x1000000000 ll;",
            "r0 |= r1;",
            "r0 = *(u8*)(r6 + 0);",
            "r0 >>= 32;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ldx_h_zero_extend_check
extern "C" fn ldx_h_zero_extend_check() {
    unsafe {
        core::arch::asm!(
            "r6 = r10;",
            "r6 += -4;",
            "r7 = 0xfaceb00c;",
            "*(u32*)(r6 + 0) = r7;",
            "call 7;",
            "r1 = 0x1000000000 ll;",
            "r0 |= r1;",
            "r0 = *(u16*)(r6 + 0);",
            "r0 >>= 32;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ldx_w_zero_extend_check
extern "C" fn ldx_w_zero_extend_check() {
    unsafe {
        core::arch::asm!(
            "r6 = r10;",
            "r6 += -4;",
            "r7 = 0xfaceb00c;",
            "*(u32*)(r6 + 0) = r7;",
            "call 7;",
            "r1 = 0x1000000000 ll;",
            "r0 |= r1;",
            "r0 = *(u32*)(r6 + 0);",
            "r0 >>= 32;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: arsh_31_and
extern "C" fn arsh_31_and() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w2 = w0;",
            "w2 s>>= 31;",
            "w2 &= -134;",
            "if w2 s> -1 goto +2;",
            "if w2 != -136 goto +1;",
            "w0 /= 0;",
            "w0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: arsh_63_and
extern "C" fn arsh_63_and() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r2 = r0;",
            "r2 <<= 32;",
            "r2 s>>= 63;",
            "r2 &= -134;",
            "if r2 s> -1 goto +2;",
            "if r2 != -136 goto +1;",
            "r0 /= 0;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: arsh_31_or
extern "C" fn arsh_31_or() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w2 = w0;",
            "w2 s>>= 31;",
            "w2 |= 134;",
            "if w2 s> -1 goto +2;",
            "if w2 == -1 goto +1;",
            "w0 /= 0;",
            "w0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: arsh_63_or
extern "C" fn arsh_63_or() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r2 = r0;",
            "r2 <<= 32;",
            "r2 s>>= 63;",
            "r2 |= 134;",
            "if r2 s> -1 goto +2;",
            "if r2 == -1 goto +1;",
            "r0 /= 0;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: arsh32_imm1_value
extern "C" fn arsh32_imm1_value() {
    unsafe {
        core::arch::asm!(
            "r0 = 42;",
            "r1 = -2147483648;",
            "w1 s>>= 1;",
            "r2 = 0xC0000000 ll;",
            "if r1 == r2 goto l0_2;",
            "r0 /= 0;",
            "l0_2:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: lsh32_reg0_zero_extend_check
extern "C" fn lsh32_reg0_zero_extend_check() {
    unsafe {
        core::arch::asm!(
            "r6 = 1;",
            "call 7;",
            "r1 = 0x1000000000 ll;",
            "r0 |= r1;",
            "w1 = 0;",
            "w0 <<= w1;",
            "r0 >>= 32;",
            "if r0 == 0 goto l0_3;",
            "r6 /= 0;",
            "l0_3:",
            "r0 = r6;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: rsh32_reg0_zero_extend_check
extern "C" fn rsh32_reg0_zero_extend_check() {
    unsafe {
        core::arch::asm!(
            "r6 = 1;",
            "call 7;",
            "r1 = 0x1000000000 ll;",
            "r0 |= r1;",
            "w1 = 0;",
            "w0 >>= w1;",
            "r0 >>= 32;",
            "if r0 == 0 goto l0_4;",
            "r6 /= 0;",
            "l0_4:",
            "r0 = r6;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: arsh32_reg0_zero_extend_check
extern "C" fn arsh32_reg0_zero_extend_check() {
    unsafe {
        core::arch::asm!(
            "r6 = 1;",
            "call 7;",
            "r1 = 0x1000000000 ll;",
            "r0 |= r1;",
            "w1 = 0;",
            "w0 s>>= w1;",
            "r0 >>= 32;",
            "if r0 == 0 goto l0_5;",
            "r6 /= 0;",
            "l0_5:",
            "r0 = r6;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: lsh32_imm31_value
extern "C" fn lsh32_imm31_value() {
    unsafe {
        core::arch::asm!(
            "r0 = 42;",
            "r1 = 1;",
            "w1 <<= 31;",
            "r2 = 0x80000000 ll;",
            "if r1 == r2 goto l0_6;",
            "r0 /= 0;",
            "l0_6:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: rsh32_imm31_value
extern "C" fn rsh32_imm31_value() {
    unsafe {
        core::arch::asm!(
            "r0 = 42;",
            "r1 = -2147483648;",
            "w1 >>= 31;",
            "if r1 == 1 goto l0_7;",
            "r0 /= 0;",
            "l0_7:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: arsh32_imm31_value
extern "C" fn arsh32_imm31_value() {
    unsafe {
        core::arch::asm!(
            "r0 = 42;",
            "r1 = -2147483648;",
            "w1 s>>= 31;",
            "r2 = 0xFFFFFFFF ll;",
            "if r1 == r2 goto l0_8;",
            "r0 /= 0;",
            "l0_8:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: lsh32_unknown_precise_bounds
extern "C" fn lsh32_unknown_precise_bounds() {
    unsafe {
        core::arch::asm!(
            "r6 = 1;",
            "call 7;",
            "w0 &= 3;",
            "w0 <<= 1;",
            "if w0 < 7 goto l0_9;",
            "r6 /= 0;",
            "l0_9:",
            "r0 = r6;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: rsh32_unknown_bounds
extern "C" fn rsh32_unknown_bounds() {
    unsafe {
        core::arch::asm!(
            "r6 = 1;",
            "call 7;",
            "w0 >>= 28;",
            "if w0 < 16 goto l0_10;",
            "r6 /= 0;",
            "l0_10:",
            "r0 = r6;",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
