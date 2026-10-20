// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/stream_fail.c,
// bpf-rs-core idiom.
//
// Three NEGATIVE verifier tests on bpf_stream_vprintk's arguments
// (prog_tests/stream.c RUN_TESTS this object): a NULL `args` pointer, a
// scalar `args` pointer, and the program context where the format string
// (a .rodata map value) is expected. bpf_stream_vprintk is a
// KF_IMPLICIT_ARGS kfunc (see stream.rs): the call site omits the trailing
// bpf_prog_aux argument the verifier appends.

use bpf_rs_core::bpf_object;
use bpf_rs_core::test_tags;
use core::ffi::c_void;

test_tags! {
    stream_vprintk_null_arg: __failure, __msg("Possibly NULL pointer passed");
    stream_vprintk_scalar_arg: __failure, __msg("R3 type=scalar expected=");
    stream_vprintk_string_arg: __failure, __msg("R2 type=ctx expected=map_value");
}

const BPF_STDOUT: i32 = 1;
// C's "" literal: a one-byte string constant in .rodata.
const EMPTY: [u8; 1] = *b"\0";

extern "C" {
    fn bpf_stream_vprintk(stream_id: i32, fmt: *const u8, args: *const c_void, len: u32) -> i32;
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn stream_vprintk_null_arg(_ctx: *mut c_void) -> i32 {
    unsafe { bpf_stream_vprintk(BPF_STDOUT, EMPTY.as_ptr(), core::ptr::null(), 0) };
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn stream_vprintk_scalar_arg(_ctx: *mut c_void) -> i32 {
    unsafe { bpf_stream_vprintk(BPF_STDOUT, EMPTY.as_ptr(), 46 as *const c_void, 0) };
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn stream_vprintk_string_arg(ctx: *mut c_void) -> i32 {
    unsafe { bpf_stream_vprintk(BPF_STDOUT, ctx as *const u8, core::ptr::null(), 0) };
    0
}

bpf_object!("GPL");
