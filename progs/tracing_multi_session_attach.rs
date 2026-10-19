// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(non_upper_case_globals)]

// Direct translation of
// tools/testing/selftests/bpf/progs/tracing_multi_session_attach.c
// (bpf-rs-core idiom). The attach half of tracing_multi_session.skel.h
// (Makefile.skel: `tracing_multi_session.skel.h-deps :=
// tracing_multi_session_attach.bpf.o tracing_multi_check.bpf.o`):
// prog_tests/tracing_multi.c's session subtest attaches the fsession.multi
// programs to bpf_fentry_test* (and the testmod's), and expects the exit
// count to include one extra per function for the session cookie the
// entry stored. `tracing_multi_arg_check` is tracing_multi_check.c's
// global function, `__hidden extern` here (`// BTF_EXTERN:` + `.hidden`,
// see tracing_multi_attach.rs). The cookie slot is `volatile __u64 *` in
// the C: read_volatile/write_volatile. The three programs share one body
// (`session`), inlined into each as the C's are compiled.

use core::ffi::c_void;
use core::ptr::{addr_of_mut, read_volatile, write_volatile};

use bpf_rs_core::bpf_object;

// BTF_EXTERN: tracing_multi_arg_check
extern "C" {
    fn tracing_multi_arg_check(ctx: *mut u64, test_result: *mut u64, is_return: bool) -> i32;
    fn bpf_session_is_return(ctx: *mut c_void) -> bool;
    fn bpf_session_cookie(ctx: *mut c_void) -> *mut u64;
}
core::arch::global_asm!(".hidden tracing_multi_arg_check");

#[no_mangle]
static mut test_result_fentry: u64 = 0;
#[no_mangle]
static mut test_result_fexit: u64 = 0;

#[inline(always)]
unsafe fn session(ctx: *mut u64) -> i32 {
    let cookie = bpf_session_cookie(ctx as *mut c_void);

    if bpf_session_is_return(ctx as *mut c_void) {
        if tracing_multi_arg_check(ctx, addr_of_mut!(test_result_fexit), true) != 0 {
            return 0;
        }
        /* extra count for test_result_fexit cookie */
        test_result_fexit += (read_volatile(cookie) == 0xbeafbeafbeafbeaf) as u64;
    } else {
        if tracing_multi_arg_check(ctx, addr_of_mut!(test_result_fentry), false) != 0 {
            return 0;
        }
        write_volatile(cookie, 0xbeafbeafbeafbeaf);
    }
    0
}

#[link_section = "fsession.multi/bpf_fentry_test*"]
#[no_mangle]
extern "C" fn test_session_1(ctx: *mut u64) -> i32 {
    unsafe { session(ctx) }
}

#[link_section = "fsession.multi.s/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test_fsession_s(ctx: *mut u64) -> i32 {
    unsafe { session(ctx) }
}

#[link_section = "fsession.multi/bpf_testmod:bpf_testmod_fentry_test*"]
#[no_mangle]
extern "C" fn test_session_2(ctx: *mut u64) -> i32 {
    unsafe { session(ctx) }
}

bpf_object!("GPL");
