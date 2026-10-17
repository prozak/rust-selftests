// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Translation of tools/testing/selftests/bpf/progs/verifier_default_trusted_ptr.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_default_trusted_ptr.rs
// (include!d below): test_default_trusted_ptr.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_default_trusted_ptr` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

use bpf_rs_core::{bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    test_default_trusted_ptr:
        __success,
        __retval("0");
}

extern "C" {
    fn bpf_kfunc_get_default_trusted_ptr_test() -> *mut c_void;
    fn bpf_kfunc_put_default_trusted_ptr_test(a0: *mut c_void);
}

include!("hand/verifier_default_trusted_ptr.rs");

bpf_object!("GPL");
