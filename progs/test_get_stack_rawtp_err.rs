#![no_std]
#![no_main]

// Translation of
// tools/testing/selftests/bpf/progs/test_get_stack_rawtp_err.c,
// bpf-rs-core idiom.
//
// This is a genuine negative *load* test (get_stack_raw_tp.c's
// bpf_prog_test_load(file_err, ...) asserts err < 0), not a __failure/__msg
// test_loader tag test: the C original deliberately calls bpf_get_stack()
// with flags that always evaluate to -EINVAL, then spins in an unbounded
// `while (1) error++;` on that branch so the verifier can never prove the
// program terminates and rejects the load. Rust's `loop {}` has the same
// defined (non-UB) infinite-loop semantics as C `volatile`-free `while(1)`
// used here for the same purpose, so the same shape reproduces the
// rejection.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_stack;
use core::ffi::c_void;

const MAX_STACK_RAWTP: usize = 10;

#[link_section = "raw_tracepoint/sys_enter"]
#[no_mangle]
extern "C" fn bpf_prog2(ctx: *const c_void) -> i32 {
    let mut stack = [0u64; MAX_STACK_RAWTP];

    // C: bpf_get_stack(ctx, stack, 0, -1) — size 0, flags -1: always -EINVAL.
    let mut error = bpf_get_stack(ctx, stack.as_mut_ptr() as *mut c_void, 0, -1i64 as u64) as i32;

    if error < 0 {
        loop {
            error += 1;
        }
    }

    error
}

bpf_object!("GPL");
