// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_tp_btf_nullable.c,
// bpf-rs-core idiom.
//
// A NEGATIVE verifier test (prog_tests/tp_btf_nullable.c RUN_TESTS this
// object): bpf_testmod's bpf_testmod_test_nullable_bare_tp tracepoint
// declares its context argument nullable (the module's BTF stub names it
// `ctx__nullable`), so the first program's unchecked `nullable_ctx->len`
// is a load through a trusted_ptr_or_null_ and is rejected with the message
// declared below; the second program null-checks first and loads.

use bpf_rs_core::bpf_object;
use bpf_rs_core::progs::fentry_arg as arg;
use bpf_rs_core::test_tags;
use btf_macros::btf;

test_tags! {
    handle_tp_btf_nullable_bare1: __failure, __msg("R1 invalid mem access 'trusted_ptr_or_null_'");
}

// bpf_testmod.h's bpf_testmod_test_read_ctx, read via CO-RE against the
// module's split BTF (see test_module_attach.rs).
#[btf]
struct bpf_testmod_test_read_ctx {
    len: u64,
}

#[link_section = "tp_btf/bpf_testmod_test_nullable_bare_tp"]
#[no_mangle]
extern "C" fn handle_tp_btf_nullable_bare1(ctx: *const u64) -> i32 {
    let nullable_ctx = arg(ctx, 0) as *const bpf_testmod_test_read_ctx;
    *unsafe { &*nullable_ctx }.len().get().unwrap() as i32
}

#[link_section = "tp_btf/bpf_testmod_test_nullable_bare_tp"]
#[no_mangle]
extern "C" fn handle_tp_btf_nullable_bare2(ctx: *const u64) -> i32 {
    let nullable_ctx = arg(ctx, 0) as *const bpf_testmod_test_read_ctx;
    if !nullable_ctx.is_null() {
        return *unsafe { &*nullable_ctx }.len().get().unwrap() as i32;
    }
    0
}

bpf_object!("GPL");
