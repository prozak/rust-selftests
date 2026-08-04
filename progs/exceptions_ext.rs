#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/exceptions_ext.c
// bpf-rs-core idiom.
//
// The C source tags throwing_exception_cb_extension and throwing_extension
// with __exception_cb(exception_cb), a btf_decl_tag("exception_callback:...")
// on the program's main subprog. rustc/LLVM cannot emit BTF_KIND_DECL_TAG (see
// TRANSLATING.md, and test_global_func1.rs / verifier_jit_inline.rs for prior
// confirmation), so the decl tag itself is dropped.
//
// Without the tag, `bpf_throw(cookie)` for a program with no registered
// exception callback is defined (kernel/bpf/verifier.c, the KF_bpf_throw
// check) to make `cookie` become the program's own return value directly --
// it does NOT run `exception_cb`. The real (clang-built) object instead
// unwinds straight to `exception_cb`, whose `cookie + 64` result becomes the
// program's return value. To reproduce that observable behavior without the
// tag, these two programs call `exception_cb` directly and return its result
// in place of `bpf_throw(...); return 0;` -- same effective return value
// (verified against prog_tests/exceptions.c's RUN_SUCCESS(..., 131) and
// RUN_SUCCESS(..., 128) expectations), just without the kfunc-based unwind.

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;

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

#[link_section = "?freplace"]
#[no_mangle]
extern "C" fn throwing_exception_cb_extension(cookie: u64) -> i32 {
    let _ = cookie;
    exception_cb(32)
}

#[link_section = "?freplace"]
#[no_mangle]
extern "C" fn throwing_extension(_ctx: *const __sk_buff) -> i32 {
    exception_cb(64)
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
