// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![allow(non_upper_case_globals)]

// Direct translation of tools/testing/selftests/bpf/progs/test_subskeleton.c
// (bpf-rs-core idiom). The main half of test_subskeleton.skel.h
// (Makefile.skel: `test_subskeleton.skel.h-deps := test_subskeleton_lib2.bpf.o
// test_subskeleton_lib.bpf.o test_subskeleton.bpf.o`): prog_tests/
// subskeleton.c sets `rovar1` and the library's inputs through the
// skeleton and the subskeleton, triggers the raw tracepoint and checks
// `out1` against the library's `libout1` times `rovar1`.
//
// `lib_routine` is test_subskeleton_lib.c's global function, an extern
// here (`// BTF_EXTERN:`, scripts/ksym_vars.py mirrors the C object's
// declaration for the static linker). `var5` is the strong definition
// that overrides the library's weak one. CONFIG_BPF_SYSCALL is the
// `.kconfig` extern (`// BTF_KCONFIG:`), `extern volatile bool` in the C
// so `(void) CONFIG_BPF_SYSCALL;` is a real load; `rovar1` is `const
// volatile`, read with read_volatile. The C names its license global
// `LICENSE` (bpftool_ringbuf.rs).

use core::ffi::c_void;
use core::ptr::{addr_of, read_volatile};

use bpf_rs_core::bpf_object;

/* volatile to force a read, compiler may assume 0 otherwise */
#[link_section = ".rodata"]
#[no_mangle]
static rovar1: i32 = 0;
#[no_mangle]
static mut out1: i32 = 0;

/* Override weak symbol in test_subskeleton_lib */
#[no_mangle]
static mut var5: i32 = 5;

// BTF_KCONFIG: CONFIG_BPF_SYSCALL
extern "C" {
    static CONFIG_BPF_SYSCALL: u8;
}

// BTF_EXTERN: lib_routine
extern "C" {
    fn lib_routine() -> i32;
}

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn handler1(_ctx: *const c_void) -> i32 {
    unsafe {
        read_volatile(addr_of!(CONFIG_BPF_SYSCALL));

        out1 = lib_routine().wrapping_mul(read_volatile(addr_of!(rovar1)));
    }
    0
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 4] = bpf_rs_core::__lic_bytes::<4>("GPL");

bpf_object!("GPL");
