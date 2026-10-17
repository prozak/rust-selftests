// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Translation of tools/testing/selftests/bpf/progs/verifier_bits_iter.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_bits_iter.rs
// (include!d below): no_destroy, next_uninit, destroy_uninit, null_pointer, bits_copy, bits_memalloc, bit_index, bits_too_big, fewer_words, zero_words, huge_words, max_words, bad_words.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_bits_iter` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: no_destroy next_uninit destroy_uninit null_pointer bits_copy bits_memalloc bit_index bits_too_big fewer_words zero_words huge_words max_words bad_words

use bpf_rs_core::{bpf_map, bpf_object, btf_type_tags, test_tags};
use btf_macros::btf;
use core::ffi::c_void;

test_tags! {
    no_destroy:
        __description("bits iter without destroy"),
        __failure,
        __msg("Unreleased reference");
    next_uninit:
        __description("uninitialized iter in ->next()"),
        __failure,
        __msg("expected an initialized iter_bits as R1");
    destroy_uninit:
        __description("uninitialized iter in ->destroy()"),
        __failure,
        __msg("expected an initialized iter_bits as R1");
    null_pointer:
        __description("null pointer"),
        __success,
        __retval("0");
    bits_copy:
        __description("bits copy"),
        __success,
        __retval("10");
    bits_memalloc:
        __description("bits memalloc"),
        __success,
        __retval("64");
    bit_index:
        __description("bit index"),
        __success,
        __retval("8");
    bits_too_big:
        __description("bits too big"),
        __success,
        __retval("0");
    fewer_words:
        __description("fewer words"),
        __success,
        __retval("1");
    zero_words:
        __description("zero words"),
        __success,
        __retval("0");
    huge_words:
        __description("huge words"),
        __success,
        __retval("0");
    max_words:
        __description("max words"),
        __success,
        __retval("4");
    bad_words:
        __description("bad words"),
        __success,
        __retval("0");
}

// Map key/value types, shaped like the C object's BTF (the kernel
// checks some of them member by member, so no explicit padding).
// translint: allow(padding)
btf_type_tags! {
    __tasks_kfunc_map_value.task: kptr;
    task_kptr_lock_value.task: kptr;
}

/// An opaque stand-in for the kernel's: only pointed at.
#[allow(non_camel_case_types)]
#[btf]
struct task_struct {}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct __tasks_kfunc_map_value {
    task: *mut task_struct,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct bpf_spin_lock {
    val: u32,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct task_kptr_lock_value {
    lock: bpf_spin_lock,
    task: *mut task_struct,
}

bpf_map! {
    __tasks_kfunc_map {
        r#type: *const [i32; 1],
        key: *const i32,
        value: *const __tasks_kfunc_map_value,
        max_entries: *const [i32; 1],
    }
}

bpf_map! {
    task_kptr_lock_map {
        r#type: *const [i32; 2],
        key: *const i32,
        value: *const task_kptr_lock_value,
        max_entries: *const [i32; 1],
    }
}

#[no_mangle]
#[allow(non_upper_case_globals)]
static mut bits_array: [u64; 511] = [0; 511];

extern "C" {
    fn bpf_iter_bits_new(a0: *mut c_void, a1: *mut c_void, a2: u32) -> i32;
    fn bpf_iter_bits_next(a0: *mut c_void) -> *mut c_void;
    fn bpf_iter_bits_destroy(a0: *mut c_void);
}

include!("hand/verifier_bits_iter.rs");

bpf_object!("GPL");
