// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_set_retval.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_set_retval.rs
// (include!d below): lsm_cgroup_set_retval_zero_valid, lsm_cgroup_set_retval_negative_valid, lsm_cgroup_set_retval_negative_invalid, lsm_cgroup_set_retval_positive_invalid, cgroup_dev_set_retval_0, cgroup_dev_set_retval_neg_maxerrno, cgroup_dev_set_retval_1, cgroup_dev_set_retval_neg_4096.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_set_retval` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: lsm_cgroup_set_retval_zero_valid lsm_cgroup_set_retval_negative_valid lsm_cgroup_set_retval_negative_invalid lsm_cgroup_set_retval_positive_invalid cgroup_dev_set_retval_0 cgroup_dev_set_retval_neg_maxerrno cgroup_dev_set_retval_1 cgroup_dev_set_retval_neg_4096 cgroup_dev_set_retval_pruning_bypass

use bpf_rs_core::{bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    lsm_cgroup_set_retval_zero_valid:
        __description("lsm_cgroup bpf_set_retval success"),
        __success;
    lsm_cgroup_set_retval_negative_valid:
        __description("lsm_cgroup bpf_set_retval valid errno"),
        __success;
    lsm_cgroup_set_retval_negative_invalid:
        __description("lsm_cgroup bpf_set_retval invalid negative value"),
        __failure,
        __msg("should have been in [-4095, 0]");
    lsm_cgroup_set_retval_positive_invalid:
        __description("lsm_cgroup bpf_set_retval invalid positive value"),
        __failure,
        __msg("should have been in [-4095, 0]");
    cgroup_dev_set_retval_0:
        __description("cgroup_device bpf_set_retval success"),
        __success;
    cgroup_dev_set_retval_neg_maxerrno:
        __description("cgroup_device bpf_set_retval valid errno"),
        __success;
    cgroup_dev_set_retval_1:
        __description("cgroup_device bpf_set_retval invalid positive value"),
        __failure,
        __msg("should have been in [-4095, 0]");
    cgroup_dev_set_retval_neg_4096:
        __description("cgroup_device bpf_set_retval invalid negative value"),
        __failure,
        __msg("should have been in [-4095, 0]");
    cgroup_dev_set_retval_pruning_bypass:
        __description("bpf_set_retval bounds check survives state pruning"),
        __failure,
        __msg("should have been in [-4095, 0]");
}

// Map key/value types, shaped like the C object's BTF (the kernel
// checks some of them member by member, so no explicit padding).
// translint: allow(padding)
#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct bpf_cgroup_dev_ctx {
    access_type: u32,
    major: u32,
    minor: u32,
}

#[link_section = "cgroup/dev"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: cgroup_dev_set_retval_pruning_bypass
extern "C" fn cgroup_dev_set_retval_pruning_bypass(_ctx: *mut c_void) -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "call 7;",
            "if r0 != 0 goto 1f;",
            "r0 = r0;",
            "r0 = r0;",
            "r0 = r0;",
            "r0 = r0;",
            "goto 2f;",
            "1:",
            "call 7;",
            "2:",
            "r1 = r0;",
            "call 187;",
            "r0 = 1;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

include!("hand/verifier_set_retval.rs");

bpf_object!("GPL");
