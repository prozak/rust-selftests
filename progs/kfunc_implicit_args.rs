// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Translation of tools/testing/selftests/bpf/progs/kfunc_implicit_args.c,
// bpf-rs-core idiom.
//
// bpf_testmod's KF_IMPLICIT_ARGS kfuncs take a trailing `struct bpf_prog_aux
// *aux` the verifier supplies, so a program calls them without it
// (bpf_kfunc_implicit_arg(5) returns 5, _legacy(3, 4) returns 7), while the
// explicit `_legacy_impl(5, 6, NULL)` variant is a plain kfunc (11). The
// NEGATIVE program calls `bpf_kfunc_implicit_arg_impl`, a name the module's
// BTF has but exports no address for, so the load fails with the message
// declared below. The three positives carry the C's __retval expectations.
// Kfunc prototypes are mirrored from the kernel BTF; `bpf_prog_aux` is only
// pointed at, so it stays opaque. Sibling: kfunc_implicit_args_tracing.rs.

use bpf_rs_core::bpf_object;
use bpf_rs_core::test_tags;
use core::ffi::c_void;

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_prog_aux {
    _opaque: [u8; 0],
}

extern "C" {
    fn bpf_kfunc_implicit_arg(a: i32) -> i32;
    fn bpf_kfunc_implicit_arg_impl(a: i32, aux: *mut bpf_prog_aux) -> i32; /* illegal */
    fn bpf_kfunc_implicit_arg_legacy(a: i32, b: i32) -> i32;
    fn bpf_kfunc_implicit_arg_legacy_impl(a: i32, b: i32, aux: *mut bpf_prog_aux) -> i32;
}

test_tags! {
    test_kfunc_implicit_arg: __retval(5);
    test_kfunc_implicit_arg_impl_illegal: __failure, __msg("cannot find address for kernel function bpf_kfunc_implicit_arg_impl");
    test_kfunc_implicit_arg_legacy: __retval(7);
    test_kfunc_implicit_arg_legacy_impl: __retval(11);
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_kfunc_implicit_arg(_ctx: *mut c_void) -> i32 {
    unsafe { bpf_kfunc_implicit_arg(5) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_kfunc_implicit_arg_impl_illegal(_ctx: *mut c_void) -> i32 {
    unsafe { bpf_kfunc_implicit_arg_impl(5, core::ptr::null_mut()) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_kfunc_implicit_arg_legacy(_ctx: *mut c_void) -> i32 {
    unsafe { bpf_kfunc_implicit_arg_legacy(3, 4) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_kfunc_implicit_arg_legacy_impl(_ctx: *mut c_void) -> i32 {
    unsafe { bpf_kfunc_implicit_arg_legacy_impl(5, 6, core::ptr::null_mut()) }
}

bpf_object!("GPL");
