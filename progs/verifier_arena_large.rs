// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]
#![allow(function_casts_as_integer)]

// Translation of tools/testing/selftests/bpf/progs/verifier_arena_large.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_arena_large.rs
// (include!d below): big_alloc1, access_reserved, request_partially_reserved, free_reserved, alloc_pages, big_alloc2, big_alloc3, big_alloc4.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_arena_large` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: big_alloc1 access_reserved request_partially_reserved free_reserved alloc_pages big_alloc2 big_alloc3 big_alloc4

// a `*mut c_void` is the C's `void *` in BTF (scripts/btf_rename.py)
// BTF_C_VOID: c_void

use bpf_rs_core::{bpf_map, bpf_object, btf_type_tags, test_tags};
use core::ffi::c_void;

test_tags! {
    big_alloc1:
        __success,
        __retval("0");
    access_reserved:
        __success,
        __retval("0");
    request_partially_reserved:
        __success,
        __retval("0");
    free_reserved:
        __success,
        __retval("0");
    big_alloc2:
        __success,
        __retval("0");
    big_alloc3:
        __success,
        __retval("0");
    big_alloc4:
        __success,
        __retval("0");
}

btf_type_tags! {
    base: arena;
}

bpf_map! {
    arena {
        r#type: *const [i32; 33],
        map_flags: *const [i32; 1024],
        max_entries: *const [i32; 1048576],
    }
}

#[link_section = ".addr_space.1"]
#[no_mangle]
#[allow(non_upper_case_globals)]
static mut page: [*mut u8; 100] = [core::ptr::null_mut(); 100];

#[no_mangle]
#[allow(non_upper_case_globals)]
static mut zero: i32 = 0;

#[no_mangle]
#[allow(non_upper_case_globals)]
static mut base: *mut u8 = core::ptr::null_mut();

extern "C" {
    fn bpf_arena_alloc_pages(a0: *mut c_void, a1: *mut c_void, a2: u32, a3: i32, a4: u64) -> *mut c_void;
    fn bpf_arena_free_pages(a0: *mut c_void, a1: *mut c_void, a2: u32);
    fn bpf_arena_reserve_pages(a0: *mut c_void, a1: *mut c_void, a2: u32) -> i32;
}

include!("hand/verifier_arena_large.rs");

bpf_object!("GPL");
