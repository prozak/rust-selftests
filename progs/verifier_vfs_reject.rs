// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Translation of tools/testing/selftests/bpf/progs/verifier_vfs_reject.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_vfs_reject.rs
// (include!d below): get_task_exe_file_kfunc_null, get_task_exe_file_kfunc_fp, get_task_exe_file_kfunc_untrusted, get_task_exe_file_kfunc_unreleased, put_file_kfunc_unacquired, path_d_path_kfunc_null, path_d_path_kfunc_untrusted_from_argument, path_d_path_kfunc_untrusted_from_current, path_d_path_kfunc_type_mismatch, path_d_path_kfunc_invalid_buf_sz, path_d_path_kfunc_non_lsm, inode_rename.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_vfs_reject` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: get_task_exe_file_kfunc_null get_task_exe_file_kfunc_fp get_task_exe_file_kfunc_untrusted get_task_exe_file_kfunc_unreleased put_file_kfunc_unacquired path_d_path_kfunc_null path_d_path_kfunc_untrusted_from_argument path_d_path_kfunc_untrusted_from_current path_d_path_kfunc_type_mismatch path_d_path_kfunc_invalid_buf_sz path_d_path_kfunc_non_lsm inode_rename

use bpf_rs_core::{bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    get_task_exe_file_kfunc_null:
        __failure,
        __msg("Possibly NULL pointer passed to trusted R1");
    get_task_exe_file_kfunc_fp:
        __failure,
        __msg("R1 type=fp expected=ptr_, trusted_ptr_, rcu_ptr_");
    get_task_exe_file_kfunc_untrusted:
        __failure,
        __msg("R1 must be referenced or trusted");
    get_task_exe_file_kfunc_unreleased:
        __failure,
        __msg("Unreleased reference");
    put_file_kfunc_unacquired:
        __failure,
        __msg("release function bpf_put_file expects referenced PTR_TO_BTF_ID passed to R1");
    path_d_path_kfunc_null:
        __failure,
        __msg("Possibly NULL pointer passed to trusted R1");
    path_d_path_kfunc_untrusted_from_argument:
        __failure,
        __msg("dereference of modified untrusted_ptr_");
    path_d_path_kfunc_untrusted_from_current:
        __failure,
        __msg("dereference of modified untrusted_ptr_");
    path_d_path_kfunc_type_mismatch:
        __failure,
        __msg("bpf_path_d_path R1 expected pointer to STRUCT path but R1 has a pointer to STRUCT file");
    path_d_path_kfunc_invalid_buf_sz:
        __failure,
        __msg("invalid access to map value, value_size=4096 off=0 size=8192");
    path_d_path_kfunc_non_lsm:
        __failure,
        __msg("calling kernel function bpf_path_d_path is not allowed");
    inode_rename:
        __failure,
        __msg("invalid mem access 'trusted_ptr_or_null_'");
}

#[no_mangle]
#[allow(non_upper_case_globals)]
static mut buf: [i8; 4096] = [0; 4096];

extern "C" {
    fn bpf_get_task_exe_file(a0: *mut c_void) -> *mut c_void;
    fn bpf_put_file(a0: *mut c_void);
    fn bpf_path_d_path(a0: *mut c_void, a1: *mut c_void, a2: u64) -> i32;
}

include!("hand/verifier_vfs_reject.rs");

bpf_object!("GPL");
