// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// translint allow(kconfig): the C object's LINUX_HAS_BPF_COOKIE .kconfig
// extern is read only by usdt.bpf.h's library functions (bpf_usdt_arg & co.)
// in .text, which none of its programs call; the translation has no such dead
// code to read it from
// translint: allow(kconfig)

// Direct translation of
// tools/testing/selftests/bpf/progs/kprobe_multi_verifier.c (bpf-rs-core
// idiom). RUN_TESTS(kprobe_multi_verifier) in prog_tests/kprobe_multi_test.c
// loads each program through test_loader: a kprobe.session program may
// return only 0 or 1, so the third one must fail with the C's message
// (test_tags! mirrors the C's __success/__failure/__msg decl tags).

use bpf_rs_core::{bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    kprobe_session_return_0: __success;
    kprobe_session_return_1: __success;
    kprobe_session_return_2:
        __failure,
        __msg("At program exit the register R0 has smin=2 smax=2 should have been in [0, 1]");
}

#[link_section = "kprobe.session"]
#[no_mangle]
extern "C" fn kprobe_session_return_0(_ctx: *const c_void) -> i32 {
    0
}

#[link_section = "kprobe.session"]
#[no_mangle]
extern "C" fn kprobe_session_return_1(_ctx: *const c_void) -> i32 {
    1
}

#[link_section = "kprobe.session"]
#[no_mangle]
extern "C" fn kprobe_session_return_2(_ctx: *const c_void) -> i32 {
    2
}

bpf_object!("GPL");
