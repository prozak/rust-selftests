// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_map_in_map.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_map_in_map.rs
// (include!d below): __rb_event_submit, map_ptr_is_never_null_rb.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_map_in_map` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: map_in_map_access map_in_map_dynamic_inner_array_lookup_is_nullable map_in_map_state_pruning invalid_inner_map_pointer on_the_inner_map_pointer map_ptr_is_never_null map_ptr_is_never_null_inner map_ptr_is_never_null_inner_spill_fill __rb_event_submit map_ptr_is_never_null_rb

use bpf_rs_core::{bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    map_in_map_access:
        __description("map in map access"),
        __success,
        __success_unpriv,
        __retval("0");
    map_in_map_dynamic_inner_array_lookup_is_nullable:
        __description("map in map dynamic inner array lookup is nullable"),
        __failure,
        __msg("invalid mem access 'map_value_or_null'");
    map_in_map_state_pruning:
        __description("map in map state pruning"),
        __success,
        __msg("processed 15 insns"),
        __log_level("2"),
        __retval("0"),
        __flag("BPF_F_TEST_STATE_FREQ");
    invalid_inner_map_pointer:
        __description("invalid inner map pointer"),
        __failure,
        __msg("R1 pointer arithmetic on map_ptr prohibited"),
        __failure_unpriv;
    on_the_inner_map_pointer:
        __description("forgot null checking on the inner map pointer"),
        __failure,
        __msg("Possibly NULL pointer passed to trusted R1"),
        __failure_unpriv;
    map_ptr_is_never_null:
        __description("map_ptr is never null"),
        __success;
    map_ptr_is_never_null_inner:
        __description("map_ptr is never null inner"),
        __success;
    map_ptr_is_never_null_inner_spill_fill:
        __description("map_ptr is never null inner spill fill"),
        __success;
}

// Map key/value types, shaped like the C object's BTF (the kernel
// checks some of them member by member, so no explicit padding).
// translint: allow(padding)
#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct bpf_dynptr {
    __opaque: [u64; 2],
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct rb_ctx {
    rb: *mut c_void,
    dptr: bpf_dynptr,
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
struct map_in_map_dyn__inner {
    r#type: *const [i32; 2],
    map_flags: *const [i32; 4096],
    max_entries: *const [i32; 8],
    key: *const i32,
    value: *const i64,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct rb_in_map__inner {
    r#type: *const [i32; 27],
    max_entries: *const [i32; 65536],
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

#[allow(non_camel_case_types)]
#[repr(C)]
struct map_in_map_dyn {
    r#type: *const [i32; 12],
    max_entries: *const [i32; 1],
    key: *const i32,
    value: *const i32,
    values: [*const map_in_map_dyn__inner; 0],
}
unsafe impl Sync for map_in_map_dyn {}

#[link_section = ".maps"]
#[no_mangle]
static map_in_map_dyn: map_in_map_dyn = map_in_map_dyn {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
    values: [],
};

#[allow(non_camel_case_types)]
#[repr(C)]
struct rb_in_map {
    r#type: *const [i32; 12],
    max_entries: *const [i32; 1],
    key: *const i32,
    value: *const i32,
    values: [*const rb_in_map__inner; 0],
}
unsafe impl Sync for rb_in_map {}

#[link_section = ".maps"]
#[no_mangle]
static rb_in_map: rb_in_map = rb_in_map {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
    values: [],
};

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: map_in_map_access
extern "C" fn map_in_map_access() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u32*)(r10 - 4) = r1;",
            "r2 = r10;",
            "r2 += -4;",
            "r1 = {map_in_map} ll;",
            "call 1;",
            "if r0 == 0 goto l0_0;",
            "r1 = 0;",
            "*(u32*)(r10 - 4) = r1;",
            "r2 = r10;",
            "r2 += -4;",
            "r1 = r0;",
            "call 1;",
            "l0_0:",
            "r0 = 0;",
            "exit;",
            map_in_map = sym map_in_map,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: map_in_map_dynamic_inner_array_lookup_is_nullable
extern "C" fn map_in_map_dynamic_inner_array_lookup_is_nullable() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u32*)(r10 - 4) = r1;",
            "r2 = r10;",
            "r2 += -4;",
            "r1 = {map_in_map_dyn} ll;",
            "call 1;",
            "if r0 == 0 goto l0_1;",
            "*(u32*)(r10 - 8) = 4;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = r0;",
            "call 1;",
            "r0 = *(u64 *)(r0 + 0);",
            "l0_1:",
            "exit;",
            map_in_map_dyn = sym map_in_map_dyn,
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: map_in_map_state_pruning
extern "C" fn map_in_map_state_pruning() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u32*)(r10 - 4) = r1;",
            "r6 = r10;",
            "r6 += -4;",
            "r2 = r6;",
            "r1 = {map_in_map} ll;",
            "call 1;",
            "if r0 != 0 goto l0_2;",
            "exit;",
            "l0_2:",
            "r2 = r6;",
            "r1 = r0;",
            "call 1;",
            "if r0 != 0 goto l1_2;",
            "r2 = r6;",
            "r1 = {map_in_map} ll;",
            "call 1;",
            "if r0 != 0 goto l2_2;",
            "exit;",
            "l2_2:",
            "r2 = r6;",
            "r1 = r0;",
            "call 1;",
            "if r0 != 0 goto l1_2;",
            "exit;",
            "l1_2:",
            "r0 = *(u32*)(r0 + 0);",
            "exit;",
            map_in_map = sym map_in_map,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: invalid_inner_map_pointer
extern "C" fn invalid_inner_map_pointer() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u32*)(r10 - 4) = r1;",
            "r2 = r10;",
            "r2 += -4;",
            "r1 = {map_in_map} ll;",
            "call 1;",
            "if r0 == 0 goto l0_3;",
            "r1 = 0;",
            "*(u32*)(r10 - 4) = r1;",
            "r2 = r10;",
            "r2 += -4;",
            "r1 = r0;",
            "r1 += 8;",
            "call 1;",
            "l0_3:",
            "r0 = 0;",
            "exit;",
            map_in_map = sym map_in_map,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: on_the_inner_map_pointer
extern "C" fn on_the_inner_map_pointer() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u32*)(r10 - 4) = r1;",
            "r2 = r10;",
            "r2 += -4;",
            "r1 = {map_in_map} ll;",
            "call 1;",
            "r1 = 0;",
            "*(u32*)(r10 - 4) = r1;",
            "r2 = r10;",
            "r2 += -4;",
            "r1 = r0;",
            "call 1;",
            "r0 = 0;",
            "exit;",
            map_in_map = sym map_in_map,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: map_ptr_is_never_null
extern "C" fn map_ptr_is_never_null() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "r1 = {map_in_map} ll;",
            "if r1 != 0 goto l0_4;",
            "r10 = 42;",
            "l0_4:",
            "exit;",
            map_in_map = sym map_in_map,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: map_ptr_is_never_null_inner
extern "C" fn map_ptr_is_never_null_inner() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u32*)(r10 - 4) = r1;",
            "r2 = r10;",
            "r2 += -4;",
            "r1 = {map_in_map} ll;",
            "call 1;",
            "if r0 == 0 goto l0_5;",
            "if r0 != 0 goto l0_5;",
            "r10 = 42;",
            "l0_5:",
            "exit;",
            map_in_map = sym map_in_map,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: map_ptr_is_never_null_inner_spill_fill
extern "C" fn map_ptr_is_never_null_inner_spill_fill() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u32*)(r10 - 4) = r1;",
            "r2 = r10;",
            "r2 += -4;",
            "r1 = {map_in_map} ll;",
            "call 1;",
            "if r0 != 0 goto l0_6;",
            "exit;",
            "l0_6:",
            "*(u64 *)(r10 -16) = r0;",
            "r1 = *(u64 *)(r10 -16);",
            "if r1 == 0 goto l1_6;",
            "exit;",
            "l1_6:",
            "r10 = 42;",
            "exit;",
            map_in_map = sym map_in_map,
            options(nostack)
        );
    }
}

include!("hand/verifier_map_in_map.rs");

bpf_object!("GPL");
