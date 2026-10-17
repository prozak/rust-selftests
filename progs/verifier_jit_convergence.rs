// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_jit_convergence.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_jit_convergence` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

use bpf_rs_core::{bpf_map, bpf_object, test_tags};

test_tags! {
    btf_jit_convergence_je_jmp:
        __description("bpf_jit_convergence je <-> jmp"),
        __success,
        __retval("0"),
        __arch_x86_64,
        __jited("\tpushq\t%rbp");
}

// Map key/value types, shaped like the C object's BTF (the kernel
// checks some of them member by member, so no explicit padding).
// translint: allow(padding)
#[allow(non_camel_case_types)]
#[repr(C)]
struct value_t {
    a: [i64; 32],
}

bpf_map! {
    map_hash {
        r#type: *const [i32; 1],
        max_entries: *const [i32; 1],
        key: *const i64,
        value: *const value_t,
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: btf_jit_convergence_je_jmp
extern "C" fn btf_jit_convergence_je_jmp() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "if r0 == 0 goto l20_0;",
            "if r0 == 1 goto l21_0;",
            "if r0 == 2 goto l22_0;",
            "if r0 == 3 goto l23_0;",
            "if r0 == 4 goto l24_0;",
            "call 7;",
            "call 7;",
            "l20_0:",
            "l21_0:",
            "l22_0:",
            "l23_0:",
            "l24_0:",
            "r1 = 0;",
            "*(u64 *)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash} ll;",
            "call 1;",
            "if r0 == 0 goto l1_0;",
            "r6 = r0;",
            "call 7;",
            "r7 = r0;",
            "r5 = r6;",
            "if r0 != 0x0 goto l12_0;",
            "call 7;",
            "r1 = r0;",
            "r2 = r6;",
            "if r1 == 0x0 goto l0_0;",
            "l9_0:",
            "r2 = *(u64 *)(r6 + 0x0);",
            "r2 += 0x1;",
            "*(u64 *)(r6 + 0x0) = r2;",
            "goto l1_0;",
            "l12_0:",
            "r1 = r7;",
            "r1 += 0x98;",
            "r2 = r5;",
            "r2 += 0x90;",
            "r2 = *(u32 *)(r2 + 0x0);",
            "r3 = r7;",
            "r3 &= 0x1;",
            "r2 *= 0xa8;",
            "if r3 == 0x0 goto l2_0;",
            "r3 = 0x1234;",
            "r1 += r2;",
            "r1 -= r7;",
            "r1 += 0x8;",
            "if r1 <= 0xb20 goto l3_0;",
            "r1 = 0x0;",
            "goto l4_0;",
            "l3_0:",
            "r1 += r7;",
            "l4_0:",
            "if r1 == 0x0 goto l8_0;",
            "goto l9_0;",
            "l2_0:",
            "r1 += r2;",
            "r1 -= r7;",
            "r1 += 0x10;",
            "if r1 <= 0xb20 goto l6_0;",
            "r1 = 0x0;",
            "goto l7_0;",
            "l6_0:",
            "r1 += r7;",
            "l7_0:",
            "if r1 == 0x0 goto l8_0;",
            "goto l9_0;",
            "l0_0:",
            "r1 = 0x3;",
            "*(u64 *)(r10 - 0x10) = r1;",
            "r2 = r1;",
            "goto l1_0;",
            "l8_0:",
            "r1 = r5;",
            "r1 += 0x4;",
            "r1 = *(u32 *)(r1 + 0x0);",
            "*(u64 *)(r10 - 0x8) = r1;",
            "l1_0:",
            "r0 = 0;",
            "exit;",
            map_hash = sym map_hash,
            options(nostack)
        );
    }
}

bpf_object!("GPL");
