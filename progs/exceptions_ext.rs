// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/exceptions_ext.c
// bpf-rs-core idiom.
//
// throwing_exception_cb_extension and throwing_extension carry C's
// __exception_cb(exception_cb), the decl tag "exception_callback:exception_cb"
// on the program's FUNC, through rust-bpf's #[btf_tag]. bpf_throw() in them
// therefore unwinds to exception_cb, whose `cookie + 64` becomes the
// extension's return value (prog_tests/exceptions.c checks it through the
// programs the extensions replace into: RUN_SUCCESS(..., 131) and
// RUN_SUCCESS(..., 128)).

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use btf_macros::btf_tag;

extern "C" {
    fn bpf_throw(cookie: u64);
}

#[link_section = "?fentry"]
#[no_mangle]
extern "C" fn pfentry(_ctx: *const u64) -> i32 {
    0
}

#[link_section = "?fentry"]
#[no_mangle]
extern "C" fn throwing_fentry(_ctx: *const u64) -> i32 {
    unsafe { bpf_throw(0) };
    0
}

#[no_mangle]
extern "C" fn exception_cb(cookie: u64) -> i32 {
    (cookie + 64) as i32
}

#[link_section = "?freplace"]
#[no_mangle]
extern "C" fn extension(_ctx: *const __sk_buff) -> i32 {
    0
}

#[btf_tag(decl_tag = "exception_callback:exception_cb")]
#[link_section = "?freplace"]
#[no_mangle]
extern "C" fn throwing_exception_cb_extension(_cookie: u64) -> i32 {
    unsafe { bpf_throw(32) };
    0
}

#[btf_tag(decl_tag = "exception_callback:exception_cb")]
#[link_section = "?freplace"]
#[no_mangle]
extern "C" fn throwing_extension(_ctx: *const __sk_buff) -> i32 {
    unsafe { bpf_throw(64) };
    0
}

#[link_section = "?fexit"]
#[no_mangle]
extern "C" fn pfexit(_ctx: *const u64) -> i32 {
    0
}

#[link_section = "?fexit"]
#[no_mangle]
extern "C" fn throwing_fexit(_ctx: *const u64) -> i32 {
    unsafe { bpf_throw(0) };
    0
}

#[link_section = "?fmod_ret"]
#[no_mangle]
extern "C" fn pfmod_ret(_ctx: *const u64) -> i32 {
    0
}

#[link_section = "?fmod_ret"]
#[no_mangle]
extern "C" fn throwing_fmod_ret(_ctx: *const u64) -> i32 {
    unsafe { bpf_throw(0) };
    0
}

bpf_object!("GPL");
