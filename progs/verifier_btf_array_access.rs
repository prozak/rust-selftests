// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_btf_array_access.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_btf_array_access.rs
// (include!d below): arr_field_in_bounds, arr_field_out_of_bounds, long_array_in_bounds, byte_array_size_spanning, byte_array_in_bounds, arr_unaligned_step, grid_outer_dim, grid_inner_dim, ptr_array_in_bounds, ptr_array_out_of_bounds, kernel_btf_array_in_bounds, kernel_btf_array_out_of_bounds, nested_struct_in_bounds, nested_struct_out_of_bounds, flex_array_field, flex_array_unaligned_step, flex_array_inner_array_out_of_bounds, typedef_array_in_bounds.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_btf_array_access` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: arr_field_in_bounds arr_field_out_of_bounds long_array_in_bounds byte_array_size_spanning byte_array_in_bounds arr_unaligned_step grid_outer_dim grid_inner_dim ptr_array_in_bounds ptr_array_out_of_bounds kernel_btf_array_in_bounds kernel_btf_array_out_of_bounds nested_struct_in_bounds nested_struct_out_of_bounds flex_array_field flex_array_unaligned_step flex_array_inner_array_out_of_bounds typedef_array_in_bounds

// (from the hand file)
// BTF_TYPE_ID: outer_id local struct outer
// BTF_TYPE_ID: with_ptrs_id local struct with_ptrs
// BTF_TYPE_ID: nest_id local struct nest
// BTF_TYPE_ID: typedef_array_id local struct typedef_array
// BTF_TYPE_ID: tid_vring_used struct vring_used
// BTF_TYPE_ID: tid_unix_address struct unix_address

use bpf_rs_core::{bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    arr_field_in_bounds:
        __success;
    arr_field_out_of_bounds:
        __failure,
        __msg("invalid variable offset access into struct outer");
    long_array_in_bounds:
        __success;
    byte_array_size_spanning:
        __failure,
        __flag("BPF_F_ANY_ALIGNMENT"),
        __msg("invalid variable offset access into struct outer");
    byte_array_in_bounds:
        __success;
    arr_unaligned_step:
        __failure,
        __msg("invalid variable offset access into struct outer");
    grid_outer_dim:
        __success;
    grid_inner_dim:
        __success;
    ptr_array_in_bounds:
        __success;
    ptr_array_out_of_bounds:
        __failure,
        __msg("invalid variable offset access into struct with_ptrs");
    kernel_btf_array_in_bounds:
        __success;
    kernel_btf_array_out_of_bounds:
        __failure,
        __msg("invalid variable offset access into struct task_struct");
    nested_struct_in_bounds:
        __success;
    nested_struct_out_of_bounds:
        __failure,
        __msg("invalid variable offset access into struct nest");
    flex_array_field:
        __success;
    flex_array_unaligned_step:
        __failure,
        __msg("invalid variable offset access into struct vring_used");
    flex_array_inner_array_out_of_bounds:
        __failure,
        __msg("invalid variable offset access into struct unix_address");
    typedef_array_in_bounds:
        __success;
}

extern "C" {
    fn bpf_obj_new(a0: u64) -> *mut c_void;
    fn bpf_obj_drop(a0: *mut c_void);
    fn bpf_rdonly_cast(a0: *mut c_void, a1: u32) -> *mut c_void;
}

include!("hand/verifier_btf_array_access.rs");

bpf_object!("GPL");
