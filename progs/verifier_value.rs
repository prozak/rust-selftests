// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_value.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_value` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: store_of_cleared_call_register element_value_with_unaligned_store element_value_with_unaligned_load is_preserved_across_register_spilling

use bpf_rs_core::{bpf_map, bpf_object, test_tags};

test_tags! {
    store_of_cleared_call_register:
        __description("map element value store of cleared call register"),
        __failure,
        __msg("R1 !read_ok"),
        __failure_unpriv,
        __msg_unpriv("R1 !read_ok");
    element_value_with_unaligned_store:
        __description("map element value with unaligned store"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R0 leaks addr"),
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    element_value_with_unaligned_load:
        __description("map element value with unaligned load"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R0 leaks addr"),
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    is_preserved_across_register_spilling:
        __description("map element value is preserved across register spilling"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R0 leaks addr"),
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
}

// Map key/value types, shaped like the C object's BTF (the kernel
// checks some of them member by member, so no explicit padding).
// translint: allow(padding)
#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
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
// BPF_NAKED: store_of_cleared_call_register
extern "C" fn store_of_cleared_call_register() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_0;",
            "*(u64*)(r0 + 0) = r1;",
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
// BPF_NAKED: element_value_with_unaligned_store
extern "C" fn element_value_with_unaligned_store() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_1;",
            "r0 += 3;",
            "r1 = 42;",
            "*(u64*)(r0 + 0) = r1;",
            "r1 = 43;",
            "*(u64*)(r0 + 2) = r1;",
            "r1 = 44;",
            "*(u64*)(r0 - 2) = r1;",
            "r8 = r0;",
            "r1 = 32;",
            "*(u64*)(r8 + 0) = r1;",
            "r1 = 33;",
            "*(u64*)(r8 + 2) = r1;",
            "r1 = 34;",
            "*(u64*)(r8 - 2) = r1;",
            "r8 += 5;",
            "r1 = 22;",
            "*(u64*)(r8 + 0) = r1;",
            "r1 = 23;",
            "*(u64*)(r8 + 4) = r1;",
            "r1 = 24;",
            "*(u64*)(r8 - 7) = r1;",
            "r7 = r8;",
            "r7 += 3;",
            "r1 = 22;",
            "*(u64*)(r7 + 0) = r1;",
            "r1 = 23;",
            "*(u64*)(r7 + 4) = r1;",
            "r1 = 24;",
            "*(u64*)(r7 - 4) = r1;",
            "l0_1:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: element_value_with_unaligned_load
extern "C" fn element_value_with_unaligned_load() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_2;",
            "r1 = *(u32*)(r0 + 0);",
            "if r1 >= 11 goto l0_2;",
            "r0 += 3;",
            "r7 = *(u64*)(r0 + 0);",
            "r7 = *(u64*)(r0 + 2);",
            "r8 = r0;",
            "r7 = *(u64*)(r8 + 0);",
            "r7 = *(u64*)(r8 + 2);",
            "r0 += 5;",
            "r7 = *(u64*)(r0 + 0);",
            "r7 = *(u64*)(r0 + 4);",
            "l0_2:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
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
            "if r0 == 0 goto l0_3;",
            "r0 += 4;",
            "r1 = 42;",
            "*(u64*)(r0 + 0) = r1;",
            "r1 = r10;",
            "r1 += -184;",
            "*(u64*)(r1 + 0) = r0;",
            "r3 = *(u64*)(r1 + 0);",
            "r1 = 42;",
            "*(u64*)(r3 + 0) = r1;",
            "l0_3:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

bpf_object!("GPL");
