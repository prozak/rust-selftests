// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_arena_globals2.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_arena_globals2.rs
// (include!d below): check_reserve2.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_arena_globals2` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// a `*mut c_void` is the C's `void *` in BTF (scripts/btf_rename.py)
// BTF_C_VOID: c_void

use bpf_rs_core::{bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    check_reserve2:
        __success,
        __retval("0");
}

// Map key/value types, shaped like the C object's BTF (the kernel
// checks some of them member by member, so no explicit padding).
// translint: allow(padding)
#[allow(non_camel_case_types)]
#[repr(u64)]
enum arena__map_extra {
    __unique_value = 0x1000fffe0000,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct arena {
    r#type: *const [i32; 33],
    map_flags: *const [i32; 1024],
    max_entries: *const [i32; 32],
    map_extra: arena__map_extra,
}
unsafe impl Sync for arena {}

#[link_section = ".maps"]
#[no_mangle]
static arena: arena = arena {
    r#type: core::ptr::null(),
    map_flags: core::ptr::null(),
    max_entries: core::ptr::null(),
    map_extra: arena__map_extra::__unique_value,
};

#[link_section = ".addr_space.1"]
#[no_mangle]
#[allow(non_upper_case_globals)]
static mut global_data: [[i8; 4096]; 32] = [[0; 4096]; 32];

extern "C" {
    fn bpf_arena_reserve_pages(a0: *mut c_void, a1: *mut c_void, a2: u32) -> i32;
}

include!("hand/verifier_arena_globals2.rs");

bpf_object!("GPL");
