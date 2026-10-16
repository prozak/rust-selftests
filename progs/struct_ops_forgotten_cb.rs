// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/struct_ops_forgotten_cb.c
// (bpf-rs-core idiom).
//
// The ops map deliberately leaves test_1 NULL (C: `struct bpf_testmod_ops
// ops = { /* we forgot to reference test_1_forgotten above, oops */ }`), so
// prog_tests/test_struct_ops_module.c expects the first load to fail with
// libbpf's "SEC("struct_ops") program isn't referenced anywhere", then sets
// `skel->struct_ops.ops->test_1 = skel->progs.test_1_forgotten` and loads
// again. For that the skeleton needs test_1 as a function-pointer member;
// a Rust fn cannot be null, so the member is a `*const c_void` and
// scripts/btf_fn_ptrs.py gives it test_1_forgotten's FUNC_PROTO in BTF.

// BTF_FN_PTR: bpf_testmod_ops.test_1 = test_1_forgotten

use bpf_rs_core::bpf_object;
use core::ffi::c_void;

#[link_section = "struct_ops/test_1"]
#[no_mangle]
extern "C" fn test_1_forgotten(_ctx: *const u64) -> i32 {
    0
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_testmod_ops {
    test_1: *const c_void,
}
unsafe impl Sync for bpf_testmod_ops {}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static ops: bpf_testmod_ops = bpf_testmod_ops {
    /* we forgot to reference test_1_forgotten above, oops */
    test_1: core::ptr::null(),
};

bpf_object!("GPL");
