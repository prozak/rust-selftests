// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_map_ptr.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_map_ptr` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: read_with_negative_offset_rejected bpf_map_ptr_write_rejected read_non_existent_field_rejected read_beyond_sha_field_rejected ptr_read_ops_field_accepted map_ptr_map_ptr_r _0_r_r_map_ptr

use bpf_rs_core::{bpf_map, bpf_object, test_tags};

test_tags! {
    read_with_negative_offset_rejected:
        __description("bpf_map_ptr: read with negative offset rejected"),
        __failure,
        __msg("R1 is bpf_array invalid negative access: off=-8"),
        __failure_unpriv,
        __msg_unpriv("access is allowed only to CAP_PERFMON and CAP_SYS_ADMIN");
    bpf_map_ptr_write_rejected:
        __description("bpf_map_ptr: write rejected"),
        __failure,
        __msg("only read from bpf_array is supported"),
        __failure_unpriv,
        __msg_unpriv("access is allowed only to CAP_PERFMON and CAP_SYS_ADMIN");
    read_non_existent_field_rejected:
        __description("bpf_map_ptr: read non-existent field rejected"),
        __failure,
        __msg("cannot access ptr member inner_map_meta with moff 40 in struct bpf_map with off 41 size 4"),
        __failure_unpriv,
        __msg_unpriv("access is allowed only to CAP_PERFMON and CAP_SYS_ADMIN"),
        __flag("BPF_F_ANY_ALIGNMENT");
    read_beyond_sha_field_rejected:
        __description("bpf_map_ptr: read beyond sha field rejected"),
        __failure,
        __msg("access beyond the end of member sha (mend:32) in struct bpf_map with off 30 size 4"),
        __failure_unpriv,
        __msg_unpriv("access is allowed only to CAP_PERFMON and CAP_SYS_ADMIN"),
        __flag("BPF_F_ANY_ALIGNMENT");
    ptr_read_ops_field_accepted:
        __description("bpf_map_ptr: read ops field accepted"),
        __success,
        __failure_unpriv,
        __msg_unpriv("access is allowed only to CAP_PERFMON and CAP_SYS_ADMIN"),
        __retval("1");
    map_ptr_map_ptr_r:
        __description("bpf_map_ptr: r = 0, map_ptr = map_ptr + r"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R1 has pointer with unsupported alu operation"),
        __retval("0");
    _0_r_r_map_ptr:
        __description("bpf_map_ptr: r = 0, r = r + map_ptr"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R0 has pointer with unsupported alu operation"),
        __retval("0");
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

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct other_val {
    foo: i64,
    bar: i64,
}

bpf_map! {
    map_array_48b {
        r#type: *const [i32; 2],
        max_entries: *const [i32; 1],
        key: *const i32,
        value: *const test_val,
    }
}

bpf_map! {
    map_hash_16b {
        r#type: *const [i32; 1],
        max_entries: *const [i32; 1],
        key: *const i64,
        value: *const other_val,
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: read_with_negative_offset_rejected
extern "C" fn read_with_negative_offset_rejected() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 = {map_array_48b} ll;",
            "r6 = *(u64*)(r1 - 8);",
            "r0 = 1;",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bpf_map_ptr_write_rejected
extern "C" fn bpf_map_ptr_write_rejected() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "*(u64*)(r10 - 8) = r0;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_array_48b} ll;",
            "*(u64*)(r1 + 0) = r2;",
            "r0 = 1;",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: read_non_existent_field_rejected
extern "C" fn read_non_existent_field_rejected() {
    unsafe {
        core::arch::asm!(
            "r6 = 0;",
            "r1 = {map_array_48b} ll;",
            "r6 = *(u32*)(r1 + 41);",
            "r0 = 1;",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: read_beyond_sha_field_rejected
extern "C" fn read_beyond_sha_field_rejected() {
    unsafe {
        core::arch::asm!(
            "r6 = 0;",
            "r1 = {map_array_48b} ll;",
            "r6 = *(u32*)(r1 + 30);",
            "r0 = 1;",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_read_ops_field_accepted
extern "C" fn ptr_read_ops_field_accepted() {
    unsafe {
        core::arch::asm!(
            "r6 = 0;",
            "r1 = {map_array_48b} ll;",
            "r6 = *(u64*)(r1 + 32);",
            "r0 = 1;",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: map_ptr_map_ptr_r
extern "C" fn map_ptr_map_ptr_r() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "*(u64*)(r10 - 8) = r0;",
            "r2 = r10;",
            "r2 += -8;",
            "r0 = 0;",
            "r1 = {map_hash_16b} ll;",
            "r1 += r0;",
            "call 1;",
            "r0 = 0;",
            "exit;",
            map_hash_16b = sym map_hash_16b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: _0_r_r_map_ptr
extern "C" fn _0_r_r_map_ptr() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "*(u64*)(r10 - 8) = r0;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "r0 = {map_hash_16b} ll;",
            "r1 += r0;",
            "call 1;",
            "r0 = 0;",
            "exit;",
            map_hash_16b = sym map_hash_16b,
            options(nostack)
        );
    }
}

bpf_object!("GPL");
