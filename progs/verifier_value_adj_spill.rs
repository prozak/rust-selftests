// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_value_adj_spill.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_value_adj_spill` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: is_preserved_across_register_spilling is_marked_on_register_spilling

use bpf_rs_core::{bpf_map, bpf_object, test_tags};

test_tags! {
    is_preserved_across_register_spilling:
        __description("map element value is preserved across register spilling"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R0 leaks addr"),
        __retval("0");
    is_marked_on_register_spilling:
        __description("map element value or null is marked on register spilling"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R0 leaks addr"),
        __retval("0");
}

// Map key/value types, shaped like the C object's BTF (the kernel
// checks some of them member by member, so no explicit padding).
// translint: allow(padding)
#[allow(non_camel_case_types)]
#[repr(C)]
struct test_val {
    index: u32,
    foo: [i32; 11],
}

bpf_map! {
    map_hash_48b {
        r#type: *const [i32; 1],
        max_entries: *const [i32; 1],
        key: *const i64,
        value: *const test_val,
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: is_preserved_across_register_spilling
extern "C" fn is_preserved_across_register_spilling() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_0;",
            "r1 = 42;",
            "*(u64*)(r0 + 0) = r1;",
            "r1 = r10;",
            "r1 += -184;",
            "*(u64*)(r1 + 0) = r0;",
            "r3 = *(u64*)(r1 + 0);",
            "r1 = 42;",
            "*(u64*)(r3 + 0) = r1;",
            "l0_0:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: is_marked_on_register_spilling
extern "C" fn is_marked_on_register_spilling() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "r1 = r10;",
            "r1 += -152;",
            "*(u64*)(r1 + 0) = r0;",
            "if r0 == 0 goto l0_1;",
            "r3 = *(u64*)(r1 + 0);",
            "r1 = 42;",
            "*(u64*)(r3 + 0) = r1;",
            "l0_1:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

bpf_object!("GPL");
