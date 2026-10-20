// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/tracing_multi_verifier.c,
// bpf-rs-core idiom.
//
// Three NEGATIVE verifier tests on multi-attach tracing programs
// (prog_tests/tracing_multi.c RUN_TESTS this object): a fentry.multi /
// fexit.multi / fsession.multi program's context is the generic
// bpf_multi_func, so a direct ctx[i] argument load is rejected with the
// messages declared below. BPF_PROG(..., int a) reads ctx[0]; the fexit
// `ret` is ctx[3] (after char a, int b, __u64 c); the fsession `c` is
// ctx[2].

use bpf_rs_core::bpf_object;
use bpf_rs_core::progs::fentry_arg as arg;
use bpf_rs_core::test_tags;

test_tags! {
    fentry_direct_access: __failure, __msg("func 'bpf_multi_func' doesn't have 1-th argument");
    fexit_direct_access: __failure, __msg("invalid bpf_context access off=24 size=8");
    fsession_direct_access: __failure, __msg("invalid bpf_context access off=16 size=8");
}

#[link_section = "fentry.multi/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn fentry_direct_access(ctx: *const u64) -> i32 {
    arg(ctx, 0) as i32
}

#[link_section = "fexit.multi/bpf_fentry_test3"]
#[no_mangle]
extern "C" fn fexit_direct_access(ctx: *const u64) -> i32 {
    arg(ctx, 3) as i32
}

#[link_section = "fsession.multi/bpf_fentry_test4"]
#[no_mangle]
extern "C" fn fsession_direct_access(ctx: *const u64) -> i32 {
    arg(ctx, 2) as i32
}

bpf_object!("GPL");
