#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/get_func_ip_fsession_test.c
// bpf-rs-core idiom.
//
// BLOCKED: see TRANSLATION-FAIL note at the bottom of this file / the final
// chat report. `bpf_session_is_return` must be a genuine kfunc call (the
// verifier only allows the ctx[-1] trampoline-flags read it inlines to as a
// fixup keyed on recognizing that exact kfunc call; a hand-written raw read
// at a negative ctx offset is rejected: "invalid bpf_context access
// off=-8 size=8"). Resolving any kfunc call requires libbpf's BTF
// func_proto compat check to succeed, but this pipeline's add_ksyms.py
// unconditionally emits a `void ()` DISubroutineType for every extern
// function declaration regardless of its real Rust signature, so the
// vlen check (0 vs the kfunc's real arity) always fails. Same issue blocks
// resolving `&bpf_fentry_test1`'s address via a func-kind ksym extern.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_func_ip;
use core::ffi::c_void;

extern "C" {
    fn bpf_fentry_test1(a: i32) -> i32;
    fn bpf_session_is_return(ctx: *mut c_void) -> bool;
}

#[no_mangle]
static mut test1_entry_result: u64 = 0;
#[no_mangle]
static mut test1_exit_result: u64 = 0;

#[link_section = "fsession/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test1(ctx: *const u64) -> i32 {
    let addr = bpf_get_func_ip(ctx as *const c_void);
    let matches = (addr == bpf_fentry_test1 as usize as u64) as u64;

    if unsafe { bpf_session_is_return(ctx as *mut c_void) } {
        unsafe { test1_exit_result = matches };
    } else {
        unsafe { test1_entry_result = matches };
    }
    0
}

bpf_object!("GPL");
