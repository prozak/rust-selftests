// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_ringbuf.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_ringbuf` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: ringbuf_invalid_reservation_offset_1 ringbuf_invalid_reservation_offset_2 passing_rb_mem_to_helpers

use bpf_rs_core::{bpf_map, bpf_object, test_tags};

test_tags! {
    ringbuf_invalid_reservation_offset_1:
        __description("ringbuf: invalid reservation offset 1"),
        __failure,
        __msg("R1 must have zero offset when passed to release func"),
        __failure_unpriv;
    ringbuf_invalid_reservation_offset_2:
        __description("ringbuf: invalid reservation offset 2"),
        __failure,
        __msg("R7 min value is outside of the allowed memory range"),
        __failure_unpriv;
    passing_rb_mem_to_helpers:
        __description("ringbuf: check passing rb mem to helpers"),
        __success,
        __retval("0");
}

bpf_map! {
    map_ringbuf {
        r#type: *const [i32; 27],
        max_entries: *const [i32; 4096],
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ringbuf_invalid_reservation_offset_1
extern "C" fn ringbuf_invalid_reservation_offset_1() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r1 = {map_ringbuf} ll;",
            "r2 = 8;",
            "r3 = 0;",
            "call 131;",
            "r6 = r0;",
            "if r0 == 0 goto l0_0;",
            "*(u64*)(r10 - 8) = r6;",
            "r7 = *(u64*)(r10 - 8);",
            "r1 = 0;",
            "*(u64*)(r7 + 0) = r1;",
            "r1 = r7;",
            "r1 += 0xcafe;",
            "r2 = 0;",
            "call 132;",
            "l0_0:",
            "r0 = 0;",
            "exit;",
            map_ringbuf = sym map_ringbuf,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ringbuf_invalid_reservation_offset_2
extern "C" fn ringbuf_invalid_reservation_offset_2() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r1 = {map_ringbuf} ll;",
            "r2 = 8;",
            "r3 = 0;",
            "call 131;",
            "r6 = r0;",
            "if r0 == 0 goto l0_1;",
            "*(u64*)(r10 - 8) = r6;",
            "r7 = *(u64*)(r10 - 8);",
            "r7 += 0xcafe;",
            "r1 = 0;",
            "*(u64*)(r7 + 0) = r1;",
            "r1 = r7;",
            "r2 = 0;",
            "call 132;",
            "l0_1:",
            "r0 = 0;",
            "exit;",
            map_ringbuf = sym map_ringbuf,
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: passing_rb_mem_to_helpers
extern "C" fn passing_rb_mem_to_helpers() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r1 = {map_ringbuf} ll;",
            "r2 = 8;",
            "r3 = 0;",
            "call 131;",
            "r7 = r0;",
            "if r0 != 0 goto l0_2;",
            "exit;",
            "l0_2:",
            "r1 = r6;",
            "r2 = r0;",
            "r3 = 8;",
            "r4 = 0;",
            "call 69;",
            "r1 = r7;",
            "r2 = 0;",
            "call 132;",
            "r0 = 0;",
            "exit;",
            map_ringbuf = sym map_ringbuf,
            options(nostack)
        );
    }
}

bpf_object!("GPL");
