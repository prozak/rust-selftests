// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_bswap.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_bswap` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: bswap_16 bswap_32 bswap_64 bswap16_range bswap32_range bswap64_range be16_range be32_range be64_range le16_range le32_range le64_range bswap_reset_reg_id

use bpf_rs_core::{bpf_object, test_tags};

test_tags! {
    bswap_16:
        __description("BSWAP, 16"),
        __success,
        __success_unpriv,
        __retval("0x23ff");
    bswap_32:
        __description("BSWAP, 32"),
        __success,
        __success_unpriv,
        __retval("0x23ff0000");
    bswap_64:
        __description("BSWAP, 64"),
        __success,
        __success_unpriv,
        __retval("0x34ff12ff");
    bswap16_range:
        __success,
        __log_level("2"),
        __msg("r0 &= {{.*}}; R0=scalar({{.*}},var_off=(0x0; 0x3f00))"),
        __msg("r0 = bswap16 r0 {{.*}}; R0=scalar({{.*}},var_off=(0x0; 0x3f))");
    bswap32_range:
        __success,
        __log_level("2"),
        __msg("r0 &= {{.*}}; R0=scalar({{.*}},var_off=(0x0; 0x3f00))"),
        __msg("r0 = bswap32 r0 {{.*}}; R0=scalar({{.*}},var_off=(0x0; 0x3f0000))");
    bswap64_range:
        __success,
        __log_level("2"),
        __msg("r0 &= {{.*}}; R0=scalar({{.*}},var_off=(0x0; 0x3f00))"),
        __msg("r0 = bswap64 r0 {{.*}}; R0=scalar({{.*}},var_off=(0x0; 0x3f000000000000))");
    be16_range:
        __success,
        __log_level("2"),
        __msg("r0 &= {{.*}}; R0=scalar({{.*}},var_off=(0x0; 0x3f00))"),
        __msg("r0 = be16 r0 {{.*}}; R0=scalar({{.*}},var_off=(0x0; 0x3f))");
    be32_range:
        __success,
        __log_level("2"),
        __msg("r0 &= {{.*}}; R0=scalar({{.*}},var_off=(0x0; 0x3f00))"),
        __msg("r0 = be32 r0 {{.*}}; R0=scalar({{.*}},var_off=(0x0; 0x3f0000))");
    be64_range:
        __success,
        __log_level("2"),
        __msg("r0 &= {{.*}}; R0=scalar({{.*}},var_off=(0x0; 0x3f00))"),
        __msg("r0 = be64 r0 {{.*}}; R0=scalar({{.*}},var_off=(0x0; 0x3f000000000000))");
    le16_range:
        __success,
        __log_level("2"),
        __msg("r0 &= {{.*}}; R0=scalar({{.*}},var_off=(0x0; 0x3f00))"),
        __msg("r0 = le16 r0 {{.*}}; R0=scalar({{.*}},var_off=(0x0; 0x3f00))");
    le32_range:
        __success,
        __log_level("2"),
        __msg("r0 &= {{.*}}; R0=scalar({{.*}},var_off=(0x0; 0x3f00))"),
        __msg("r0 = le32 r0 {{.*}}; R0=scalar({{.*}},var_off=(0x0; 0x3f00))");
    le64_range:
        __success,
        __log_level("2"),
        __msg("r0 &= {{.*}}; R0=scalar({{.*}},var_off=(0x0; 0x3f00))"),
        __msg("r0 = le64 r0 {{.*}}; R0=scalar({{.*}},var_off=(0x0; 0x3f00))");
    bswap_reset_reg_id:
        __description("BSWAP, reset reg id"),
        __failure,
        __msg("math between fp pointer and register with unbounded min value is not allowed");
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bswap_16
extern "C" fn bswap_16() {
    unsafe {
        core::arch::asm!(
            "r0 = 0xff23;",
            "r0 = bswap16 r0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bswap_32
extern "C" fn bswap_32() {
    unsafe {
        core::arch::asm!(
            "r0 = 0xff23;",
            "r0 = bswap32 r0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bswap_64
extern "C" fn bswap_64() {
    unsafe {
        core::arch::asm!(
            "r0 = -66710441369862280 ll;",
            "r0 = bswap64 r0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bswap16_range
extern "C" fn bswap16_range() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 0x3f00;",
            "r0 = bswap16 r0;",
            "r2 = 0x3f ll;",
            "if r0 > r2 goto trap_0;",
            "r0 = 0;",
            "exit;",
            "trap_0:",
            "r1 = 42;",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bswap32_range
extern "C" fn bswap32_range() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 0x3f00;",
            "r0 = bswap32 r0;",
            "r2 = 0x3f0000 ll;",
            "if r0 > r2 goto trap_1;",
            "r0 = 0;",
            "exit;",
            "trap_1:",
            "r1 = 42;",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bswap64_range
extern "C" fn bswap64_range() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 0x3f00;",
            "r0 = bswap64 r0;",
            "r2 = 0x3f000000000000 ll;",
            "if r0 > r2 goto trap_2;",
            "r0 = 0;",
            "exit;",
            "trap_2:",
            "r1 = 42;",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: be16_range
extern "C" fn be16_range() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 0x3f00;",
            "r0 = be16 r0;",
            "r2 = 0x3f ll;",
            "if r0 > r2 goto trap_3;",
            "r0 = 0;",
            "exit;",
            "trap_3:",
            "r1 = 42;",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: be32_range
extern "C" fn be32_range() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 0x3f00;",
            "r0 = be32 r0;",
            "r2 = 0x3f0000 ll;",
            "if r0 > r2 goto trap_4;",
            "r0 = 0;",
            "exit;",
            "trap_4:",
            "r1 = 42;",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: be64_range
extern "C" fn be64_range() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 0x3f00;",
            "r0 = be64 r0;",
            "r2 = 0x3f000000000000 ll;",
            "if r0 > r2 goto trap_5;",
            "r0 = 0;",
            "exit;",
            "trap_5:",
            "r1 = 42;",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: le16_range
extern "C" fn le16_range() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 0x3f00;",
            "r0 = le16 r0;",
            "r2 = 0x3f00 ll;",
            "if r0 > r2 goto trap_6;",
            "r0 = 0;",
            "exit;",
            "trap_6:",
            "r1 = 42;",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: le32_range
extern "C" fn le32_range() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 0x3f00;",
            "r0 = le32 r0;",
            "r2 = 0x3f00 ll;",
            "if r0 > r2 goto trap_7;",
            "r0 = 0;",
            "exit;",
            "trap_7:",
            "r1 = 42;",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: le64_range
extern "C" fn le64_range() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 0x3f00;",
            "r0 = le64 r0;",
            "r2 = 0x3f00 ll;",
            "if r0 > r2 goto trap_8;",
            "r0 = 0;",
            "exit;",
            "trap_8:",
            "r1 = 42;",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bswap_reset_reg_id
extern "C" fn bswap_reset_reg_id() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "r1 = r0;",
            "r0 = be16 r0;",
            "if r0 != 1 goto l0_9;",
            "r2 = r10;",
            "r2 += -512;",
            "r2 += r1;",
            "*(u8 *)(r2 + 0) = 0;",
            "l0_9:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
