// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/struct_ops_arena_fail.c
// (bpf-rs-core idiom).
//
// No arena in the program: attaching to test_arena must be rejected
// (prog_tests/test_struct_ops_arena.c expects open_and_load to fail). Only
// the bpf_testmod_ops3 member the C initializes is declared; libbpf matches
// struct_ops members by name (struct_ops_arena.rs).

use bpf_rs_core::bpf_object;

#[link_section = "struct_ops/test_arena"]
#[no_mangle]
extern "C" fn test_arena_no_arena(_ctx: *const u64) -> i32 {
    0
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_testmod_ops3 {
    test_arena: extern "C" fn(*const u64) -> i32,
}
unsafe impl Sync for bpf_testmod_ops3 {}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static testmod_arena_fail: bpf_testmod_ops3 = bpf_testmod_ops3 {
    test_arena: test_arena_no_arena,
};

bpf_object!("GPL");
