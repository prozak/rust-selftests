// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Translation of tools/testing/selftests/bpf/progs/verifier_lsm_init_xattr.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_lsm_init_xattr.rs
// (include!d below): reject_count_write, allow_count_read, reject_unchecked_xattrs, reject_unchecked_qstr, allow_spilled_count, reject_forged_count, reject_stack_count, reject_other_ctx_arg, reject_null_count, reject_shifted_count, reject_var_shifted_count, reject_ctx_forged_count, claim_via_subprog, allow_count_via_subprog, reject_shifted_xattrs, reject_sleepable, reject_lsm_cgroup, reject_wrong_hook.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_lsm_init_xattr` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: reject_count_write allow_count_read reject_unchecked_xattrs reject_unchecked_qstr allow_spilled_count reject_forged_count reject_stack_count reject_other_ctx_arg reject_null_count reject_shifted_count reject_var_shifted_count reject_ctx_forged_count claim_via_subprog allow_count_via_subprog reject_shifted_xattrs reject_sleepable reject_lsm_cgroup reject_wrong_hook

use bpf_rs_core::{bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    reject_count_write:
        __failure,
        __msg("cannot write into rdonly_trusted_mem");
    allow_count_read:
        __success;
    reject_unchecked_xattrs:
        __failure,
        __msg("Possibly NULL pointer passed to trusted");
    reject_unchecked_qstr:
        __failure,
        __msg("invalid mem access 'trusted_ptr_or_null_'");
    allow_spilled_count:
        __success;
    reject_forged_count:
        __failure,
        __msg("expected=rdonly_trusted_mem");
    reject_stack_count:
        __failure,
        __msg("expected=rdonly_trusted_mem");
    reject_other_ctx_arg:
        __failure,
        __msg("expected=rdonly_trusted_mem");
    reject_null_count:
        __failure,
        __msg("Possibly NULL pointer passed to trusted");
    reject_shifted_count:
        __failure,
        __msg("dereference of modified rdonly_trusted_mem ptr");
    reject_var_shifted_count:
        __failure,
        __msg("variable rdonly_trusted_mem access var_off=");
    reject_ctx_forged_count:
        __failure,
        __msg("invalid bpf_context access");
    allow_count_via_subprog:
        __success;
    reject_shifted_xattrs:
        __failure,
        __msg("access beyond struct xattr at off 24");
    reject_sleepable:
        __failure,
        __msg("bpf_lsm_inode_init_security is not sleepable");
    reject_lsm_cgroup:
        __failure,
        __msg("calling kernel function bpf_inode_init_xattr is not allowed");
    reject_wrong_hook:
        __failure,
        __msg("calling kernel function bpf_inode_init_xattr is not allowed");
}

// Map key/value types, shaped like the C object's BTF (the kernel
// checks some of them member by member, so no explicit padding).
// translint: allow(padding)
#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct xattr {
    name: *mut i8,
    value: *mut c_void,
    value_len: u64,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct bpf_dynptr {
    __opaque: [u64; 2],
}

#[no_mangle]
#[allow(non_upper_case_globals)]
static mut scratch_count: i32 = 0;

#[no_mangle]
#[allow(non_upper_case_globals)]
static mut value_buf: [i8; 8] = [122, 0, 0, 0, 0, 0, 0, 0];

#[no_mangle]
#[allow(non_upper_case_globals)]
static xattr_zone: [i8; 18] = [115, 101, 99, 117, 114, 105, 116, 121, 46, 98, 112, 102, 46, 122, 111, 110, 101, 0];

extern "C" {
    fn bpf_inode_init_xattr(a0: *mut c_void, a1: *mut c_void, a2: *mut c_void, a3: *mut c_void) -> i32;
}

include!("hand/verifier_lsm_init_xattr.rs");

bpf_object!("GPL");
