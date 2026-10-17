// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_map_ptr_mixing.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_map_ptr_mixing` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: dummy_prog_42_socket dummy_prog_24_socket dummy_prog_loop1_socket dummy_prog_loop2_socket pointers_for_lookup_hash_array pointers_for_lookup_hash_array__1 pointers_for_lookup_hash_array__2 lookup_hash_map_in_map lookup_hash_map_in_map__1 lookup_hash_map_in_map__2 pointers_for_lookup_tail_tail_1 pointers_for_lookup_tail_tail_2

use bpf_rs_core::{bpf_map, bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    dummy_prog_42_socket:
        __auxiliary,
        __auxiliary_unpriv;
    dummy_prog_24_socket:
        __auxiliary,
        __auxiliary_unpriv;
    dummy_prog_loop1_socket:
        __auxiliary,
        __auxiliary_unpriv;
    dummy_prog_loop2_socket:
        __auxiliary,
        __auxiliary_unpriv;
    pointers_for_lookup_hash_array:
        __description("calls: two calls returning different map pointers for lookup (hash, array)"),
        __success,
        __retval("1");
    lookup_hash_map_in_map:
        __description("calls: two calls returning different map pointers for lookup (hash, map in map)"),
        __failure,
        __msg("only read from bpf_array is supported");
    pointers_for_lookup_tail_tail_1:
        __description("cond: two branches returning different map pointers for lookup (tail, tail)"),
        __success,
        __failure_unpriv,
        __msg_unpriv("tail_call abusing map_ptr"),
        __retval("42");
    pointers_for_lookup_tail_tail_2:
        __description("cond: two branches returning same map pointers for lookup (tail, tail)"),
        __success,
        __success_unpriv,
        __retval("42");
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

#[allow(non_camel_case_types)]
#[repr(C)]
struct map_in_map__inner {
    r#type: *const [i32; 2],
    max_entries: *const [i32; 1],
    key: *const i32,
    value: *const i32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct map_prog1_socket {
    r#type: *const [i32; 3],
    max_entries: *const [i32; 4],
    key_size: *const [i32; 4],
    values: [*const c_void; 3],
}
unsafe impl Sync for map_prog1_socket {}

#[link_section = ".maps"]
#[no_mangle]
static map_prog1_socket: map_prog1_socket = map_prog1_socket {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key_size: core::ptr::null(),
    values: [dummy_prog_42_socket as extern "C" fn() as *const c_void, dummy_prog_loop1_socket as extern "C" fn() as *const c_void, dummy_prog_24_socket as extern "C" fn() as *const c_void],
};

#[allow(non_camel_case_types)]
#[repr(C)]
struct map_prog2_socket {
    r#type: *const [i32; 3],
    max_entries: *const [i32; 8],
    key_size: *const [i32; 4],
    values: [*const c_void; 8],
}
unsafe impl Sync for map_prog2_socket {}

#[link_section = ".maps"]
#[no_mangle]
static map_prog2_socket: map_prog2_socket = map_prog2_socket {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key_size: core::ptr::null(),
    values: [core::ptr::null(), dummy_prog_loop2_socket as extern "C" fn() as *const c_void, dummy_prog_24_socket as extern "C" fn() as *const c_void, core::ptr::null(), core::ptr::null(), core::ptr::null(), core::ptr::null(), dummy_prog_42_socket as extern "C" fn() as *const c_void],
};

bpf_map! {
    map_hash_48b {
        r#type: *const [i32; 1],
        max_entries: *const [i32; 1],
        key: *const i64,
        value: *const test_val,
    }
}

bpf_map! {
    map_array_48b {
        r#type: *const [i32; 2],
        max_entries: *const [i32; 1],
        key: *const i32,
        value: *const test_val,
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct map_in_map {
    r#type: *const [i32; 12],
    max_entries: *const [i32; 1],
    key: *const i32,
    value: *const i32,
    values: [*const map_in_map__inner; 0],
}
unsafe impl Sync for map_in_map {}

#[link_section = ".maps"]
#[no_mangle]
static map_in_map: map_in_map = map_in_map {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
    values: [],
};

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: dummy_prog_42_socket
extern "C" fn dummy_prog_42_socket() {
    unsafe {
        core::arch::asm!(
            "r0 = 42;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: dummy_prog_24_socket
extern "C" fn dummy_prog_24_socket() {
    unsafe {
        core::arch::asm!(
            "r0 = 24;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: dummy_prog_loop1_socket
extern "C" fn dummy_prog_loop1_socket() {
    unsafe {
        core::arch::asm!(
            "r3 = 1;",
            "r2 = {map_prog1_socket} ll;",
            "call 12;",
            "r0 = 41;",
            "exit;",
            map_prog1_socket = sym map_prog1_socket,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: dummy_prog_loop2_socket
extern "C" fn dummy_prog_loop2_socket() {
    unsafe {
        core::arch::asm!(
            "r3 = 1;",
            "r2 = {map_prog2_socket} ll;",
            "call 12;",
            "r0 = 41;",
            "exit;",
            map_prog2_socket = sym map_prog2_socket,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pointers_for_lookup_hash_array
extern "C" fn pointers_for_lookup_hash_array() {
    unsafe {
        core::arch::asm!(
            "if r1 != 0 goto l0_0;",
            "call {pointers_for_lookup_hash_array__1};",
            "goto l1_0;",
            "l0_0:",
            "call {pointers_for_lookup_hash_array__2};",
            "l1_0:",
            "r1 = r0;",
            "r2 = 0;",
            "*(u64*)(r10 - 8) = r2;",
            "r2 = r10;",
            "r2 += -8;",
            "call 1;",
            "if r0 == 0 goto l2_0;",
            "r1 = 4;",
            "*(u64*)(r0 + 0) = r1;",
            "r0 = 1;",
            "l2_0:",
            "exit;",
            pointers_for_lookup_hash_array__1 = sym pointers_for_lookup_hash_array__1,
            pointers_for_lookup_hash_array__2 = sym pointers_for_lookup_hash_array__2,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: pointers_for_lookup_hash_array__1
extern "C" fn pointers_for_lookup_hash_array__1() {
    unsafe {
        core::arch::asm!(
            "r0 = {map_hash_48b} ll;",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: pointers_for_lookup_hash_array__2
extern "C" fn pointers_for_lookup_hash_array__2() {
    unsafe {
        core::arch::asm!(
            "r0 = {map_array_48b} ll;",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: lookup_hash_map_in_map
extern "C" fn lookup_hash_map_in_map() {
    unsafe {
        core::arch::asm!(
            "if r1 != 0 goto l0_1;",
            "call {lookup_hash_map_in_map__1};",
            "goto l1_1;",
            "l0_1:",
            "call {lookup_hash_map_in_map__2};",
            "l1_1:",
            "r1 = r0;",
            "r2 = 0;",
            "*(u64*)(r10 - 8) = r2;",
            "r2 = r10;",
            "r2 += -8;",
            "call 1;",
            "if r0 == 0 goto l2_1;",
            "r1 = 4;",
            "*(u64*)(r0 + 0) = r1;",
            "r0 = 1;",
            "l2_1:",
            "exit;",
            lookup_hash_map_in_map__1 = sym lookup_hash_map_in_map__1,
            lookup_hash_map_in_map__2 = sym lookup_hash_map_in_map__2,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: lookup_hash_map_in_map__1
extern "C" fn lookup_hash_map_in_map__1() {
    unsafe {
        core::arch::asm!(
            "r0 = {map_array_48b} ll;",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: lookup_hash_map_in_map__2
extern "C" fn lookup_hash_map_in_map__2() {
    unsafe {
        core::arch::asm!(
            "r0 = {map_in_map} ll;",
            "exit;",
            map_in_map = sym map_in_map,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pointers_for_lookup_tail_tail_1
extern "C" fn pointers_for_lookup_tail_tail_1() {
    unsafe {
        core::arch::asm!(
            "r6 = *(u32*)(r1 + 8);",
            "if r6 != 0 goto l0_2;",
            "r2 = {map_prog2_socket} ll;",
            "goto l1_2;",
            "l0_2:",
            "r2 = {map_prog1_socket} ll;",
            "l1_2:",
            "r3 = 7;",
            "call 12;",
            "r0 = 1;",
            "exit;",
            map_prog1_socket = sym map_prog1_socket,
            map_prog2_socket = sym map_prog2_socket,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pointers_for_lookup_tail_tail_2
extern "C" fn pointers_for_lookup_tail_tail_2() {
    unsafe {
        core::arch::asm!(
            "r6 = *(u32*)(r1 + 8);",
            "if r6 == 0 goto l0_3;",
            "r2 = {map_prog2_socket} ll;",
            "goto l1_3;",
            "l0_3:",
            "r2 = {map_prog2_socket} ll;",
            "l1_3:",
            "r3 = 7;",
            "call 12;",
            "r0 = 1;",
            "exit;",
            map_prog2_socket = sym map_prog2_socket,
            options(nostack)
        );
    }
}

bpf_object!("GPL");
