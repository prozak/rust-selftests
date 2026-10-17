// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_vfs_accept.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_vfs_accept.rs
// (include!d below): get_task_exe_file_and_put_kfunc_from_current_sleepable, get_task_exe_file_and_put_kfunc_from_current_non_sleepable, get_task_exe_file_and_put_kfunc_from_argument, path_d_path_from_path_argument, path_d_path_from_file_argument, inode_rename.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_vfs_accept` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: get_task_exe_file_and_put_kfunc_from_current_sleepable get_task_exe_file_and_put_kfunc_from_current_non_sleepable get_task_exe_file_and_put_kfunc_from_argument path_d_path_from_path_argument path_d_path_from_file_argument inode_rename

use bpf_rs_core::{bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    get_task_exe_file_and_put_kfunc_from_current_sleepable:
        __success;
    get_task_exe_file_and_put_kfunc_from_current_non_sleepable:
        __success;
    get_task_exe_file_and_put_kfunc_from_argument:
        __success;
    path_d_path_from_path_argument:
        __success;
    path_d_path_from_file_argument:
        __success;
    inode_rename:
        __success;
}

#[no_mangle]
static mut buf: [i8; 64] = [0; 64];

extern "C" {
    fn bpf_get_task_exe_file(a0: *mut c_void) -> *mut c_void;
    fn bpf_put_file(a0: *mut c_void);
    fn bpf_path_d_path(a0: *mut c_void, a1: *mut c_void, a2: u64) -> i32;
}

include!("hand/verifier_vfs_accept.rs");

bpf_object!("GPL");
