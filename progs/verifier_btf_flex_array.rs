// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Translation of tools/testing/selftests/bpf/progs/verifier_btf_flex_array.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_btf_flex_array.rs
// (include!d below): stash_and_peek.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_btf_flex_array` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// (from the hand file)
// BTF_TYPE_ID: test_flex_batch_id local struct test_flex_batch

use bpf_rs_core::{bpf_map, bpf_object, btf_type_tags, test_tags};
use core::ffi::c_void;

test_tags! {
    stash_and_peek:
        __description("btf walk into flexible array of zero-sized elements"),
        __failure,
        __msg("access beyond struct test_flex_batch at off 4 size 1");
}

// Map key/value types, shaped like the C object's BTF (the kernel
// checks some of them member by member, so no explicit padding).
// translint: allow(padding)
btf_type_tags! {
    map_value.batch: kptr;
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct test_empty_event {

}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct test_flex_batch {
    nr: i32,
    events: [test_empty_event; 0],
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct map_value {
    batch: *mut test_flex_batch,
}

bpf_map! {
    batches {
        r#type: *const [i32; 2],
        key: *const i32,
        value: *const map_value,
        max_entries: *const [i32; 1],
    }
}

extern "C" {
    fn bpf_obj_new(a0: u64) -> *mut c_void;
    fn bpf_obj_drop(a0: *mut c_void);
}

include!("hand/verifier_btf_flex_array.rs");

bpf_object!("GPL");
