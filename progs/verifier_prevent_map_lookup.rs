// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_prevent_map_lookup.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_prevent_map_lookup` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: map_lookup_in_stack_trace map_lookup_in_prog_array

use bpf_rs_core::{bpf_map, bpf_object, test_tags};

test_tags! {
    map_lookup_in_stack_trace:
        __description("prevent map lookup in stack trace"),
        __failure,
        __msg("cannot pass map_type 7 into func bpf_map_lookup_elem");
    map_lookup_in_prog_array:
        __description("prevent map lookup in prog array"),
        __failure,
        __msg("cannot pass map_type 3 into func bpf_map_lookup_elem"),
        __failure_unpriv;
}

bpf_map! {
    map_stacktrace {
        r#type: *const [i32; 7],
        max_entries: *const [i32; 1],
        key: *const u32,
        value: *const u64,
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct map_prog2_socket {
    r#type: *const [i32; 3],
    max_entries: *const [i32; 8],
    key_size: *const [i32; 4],
    values: [extern "C" fn(); 0],
}
unsafe impl Sync for map_prog2_socket {}

#[link_section = ".maps"]
#[no_mangle]
static map_prog2_socket: map_prog2_socket = map_prog2_socket {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key_size: core::ptr::null(),
    values: [],
};

#[link_section = "perf_event"]
#[no_mangle]
// BPF_NAKED: map_lookup_in_stack_trace
extern "C" fn map_lookup_in_stack_trace() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_stacktrace} ll;",
            "call 1;",
            "exit;",
            map_stacktrace = sym map_stacktrace,
            options(noreturn)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
// BPF_NAKED: map_lookup_in_prog_array
extern "C" fn map_lookup_in_prog_array() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_prog2_socket} ll;",
            "call 1;",
            "exit;",
            map_prog2_socket = sym map_prog2_socket,
            options(noreturn)
        );
    }
}

bpf_object!("GPL");
