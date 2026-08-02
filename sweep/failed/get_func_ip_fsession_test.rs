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
// off=-8 size=8"). Its real kernel BTF proto is
// `bool bpf_session_is_return(void *ctx)` — a genuine untyped `void *`
// argument (pointee BTF type_id 0). The pipeline's add_ksyms.py mirrors the
// kernel FUNC_PROTO for this into LLVM debug info as a baseType-less
// DIDerivedType pointer, which this LLVM's llvm-as hard-rejects at the
// `make` ksyms step: "error: missing required field 'baseType'". This is
// out-of-file-scope (add_ksyms.py lives outside rust-selftests/) and
// unfixable via the Rust-side extern declaration, since add_ksyms.py picks
// the mirrored proto by kernel-BTF function-name match, not by the local
// declared signature.

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
