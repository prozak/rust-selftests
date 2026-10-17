// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_netfilter_ctx.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_netfilter_ctx.rs
// (include!d below): with_invalid_ctx_access_test5, with_valid_ctx_access_test6, skb_len_write, skb_data_write, with_dynptr_write, with_dynptr_rdwr, with_dynptr_store.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_netfilter_ctx` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: with_invalid_ctx_access_test1 with_invalid_ctx_access_test2 with_invalid_ctx_access_test3 with_invalid_ctx_access_test4 with_invalid_ctx_access_test5 with_valid_ctx_access_test6 skb_len_write skb_data_write with_dynptr_write with_dynptr_rdwr with_dynptr_store

use bpf_rs_core::{bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    with_invalid_ctx_access_test1:
        __description("netfilter invalid context access, size too short"),
        __failure,
        __msg("invalid bpf_context access");
    with_invalid_ctx_access_test2:
        __description("netfilter invalid context access, size too short"),
        __failure,
        __msg("invalid bpf_context access");
    with_invalid_ctx_access_test3:
        __description("netfilter invalid context access, past end of ctx"),
        __failure,
        __msg("invalid bpf_context access");
    with_invalid_ctx_access_test4:
        __description("netfilter invalid context, write"),
        __failure,
        __msg("invalid bpf_context access");
    with_invalid_ctx_access_test5:
        __description("netfilter valid context read and invalid write"),
        __failure,
        __msg("only read is supported");
    with_valid_ctx_access_test6:
        __description("netfilter test prog with skb and state read access"),
        __success,
        __failure_unpriv,
        __retval("0");
    skb_len_write:
        __description("netfilter test prog with skb write access"),
        __failure,
        __msg("only read is supported");
    skb_data_write:
        __description("netfilter test prog with skb data write access"),
        __failure,
        __msg("cannot write into rdonly_untrusted_mem");
    with_dynptr_write:
        __description("netfilter test prog with bpf_dynptr_write"),
        __success,
        __failure_unpriv,
        __retval("0");
    with_dynptr_rdwr:
        __description("netfilter test prog with bpf_dynptr_slice_rdwr"),
        __failure,
        __msg("the prog does not allow writes to packet data");
    with_dynptr_store:
        __description("netfilter test prog with bpf_dynptr_slice + write"),
        __failure,
        __msg("cannot write into rdonly_mem");
}

extern "C" {
    fn bpf_dynptr_from_skb(a0: *mut c_void, a1: u64, a2: *mut c_void) -> i32;
    fn bpf_dynptr_slice(a0: *mut c_void, a1: u64, a2: *mut c_void, a3: u64) -> *mut c_void;
    fn bpf_dynptr_slice_rdwr(a0: *mut c_void, a1: u64, a2: *mut c_void, a3: u64) -> *mut c_void;
}

#[link_section = "netfilter"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: with_invalid_ctx_access_test1
extern "C" fn with_invalid_ctx_access_test1() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u8*)(r1 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "netfilter"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: with_invalid_ctx_access_test2
extern "C" fn with_invalid_ctx_access_test2() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u16*)(r1 + 8);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "netfilter"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: with_invalid_ctx_access_test3
extern "C" fn with_invalid_ctx_access_test3() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u64*)(r1 + 16);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "netfilter"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: with_invalid_ctx_access_test4
extern "C" fn with_invalid_ctx_access_test4() {
    unsafe {
        core::arch::asm!(
            "r2 = r1;",
            "*(u64*)(r2 + 0) = r1;",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

include!("hand/verifier_netfilter_ctx.rs");

bpf_object!("GPL");
