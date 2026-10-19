// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_core_extern.c
// (bpf-rs-core idiom).
//
// Every `.kconfig` extern type libbpf accepts: each `// BTF_KCONFIG:` line
// below selects a Rust extern whose declaration scripts/ksym_vars.py
// mirrors from the C object (int, bool, char, uint16_t, uint64_t, the
// libbpf_tristate enum, a const char[8], the weak ones weak), so the
// consumer's open-time `.kconfig` strings (prog_tests/core_extern.c) fill
// them exactly as they fill the C object's. The program stores every value
// into a `.data` u64 the consumer reads back as one uint64_t array, so the
// `.data` layout is the C's (`// C_LAYOUT: .data`) and `char str_val[8]` is
// `char` (`// BTF_C_CHAR: u8`). Conversions follow C: int, char -> sign
// extension; bool, enum, uint16_t -> zero extension.
//
// `bpf_missing_helper` is C's non-existing helper #999, called only in the
// `if (CONFIG_MISSING)` arm that libbpf's resolution of the missing weak
// extern (0) makes dead code the verifier eliminates; the call stays in
// the object as in C.
// BTF_C_CHAR: u8
// C_LAYOUT: .data
// translint: allow(big-hex) -- 0xDEADC0DE is stored into a u64 as in C, no 32-bit arithmetic

use bpf_rs_core::bpf_object;
use core::ffi::c_void;

// BTF_KCONFIG: LINUX_KERNEL_VERSION
// BTF_KCONFIG: LINUX_UNKNOWN_VIRTUAL_EXTERN
// BTF_KCONFIG: CONFIG_BPF_SYSCALL
// BTF_KCONFIG: CONFIG_TRISTATE
// BTF_KCONFIG: CONFIG_BOOL
// BTF_KCONFIG: CONFIG_CHAR
// BTF_KCONFIG: CONFIG_USHORT
// BTF_KCONFIG: CONFIG_INT
// BTF_KCONFIG: CONFIG_ULONG
// BTF_KCONFIG: CONFIG_STR
// BTF_KCONFIG: CONFIG_MISSING
extern "C" {
    static LINUX_KERNEL_VERSION: i32;
    static LINUX_UNKNOWN_VIRTUAL_EXTERN: i32;
    static CONFIG_BPF_SYSCALL: u8; // bool (strong)
    static CONFIG_TRISTATE: u32; // enum libbpf_tristate
    static CONFIG_BOOL: u8; // bool
    static CONFIG_CHAR: i8; // char
    static CONFIG_USHORT: u16;
    static CONFIG_INT: i32;
    static CONFIG_ULONG: u64;
    static CONFIG_STR: [u8; 8]; // const char[8]
    static CONFIG_MISSING: u64;
}

#[no_mangle]
static mut kern_ver: u64 = u64::MAX;
#[no_mangle]
static mut unkn_virt_val: u64 = u64::MAX;
#[no_mangle]
static mut bpf_syscall: u64 = u64::MAX;
#[no_mangle]
static mut tristate_val: u64 = u64::MAX;
#[no_mangle]
static mut bool_val: u64 = u64::MAX;
#[no_mangle]
static mut char_val: u64 = u64::MAX;
#[no_mangle]
static mut ushort_val: u64 = u64::MAX;
#[no_mangle]
static mut int_val: u64 = u64::MAX;
#[no_mangle]
static mut ulong_val: u64 = u64::MAX;
#[no_mangle]
static mut str_val: [u8; 8] = [0xff; 8];
#[no_mangle]
static mut missing_val: u64 = u64::MAX;

/// C: `static int (*bpf_missing_helper)(const void *arg1, int arg2) = (void *) 999;`
#[inline(always)]
fn bpf_missing_helper(arg1: *const c_void, arg2: i32) -> i32 {
    let f: extern "C" fn(*const c_void, i32) -> i32 = unsafe { core::mem::transmute(999usize) };
    f(arg1, arg2)
}

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn handle_sys_enter(ctx: *const c_void) -> i32 {
    unsafe {
        kern_ver = LINUX_KERNEL_VERSION as i64 as u64;
        unkn_virt_val = LINUX_UNKNOWN_VIRTUAL_EXTERN as i64 as u64;
        bpf_syscall = CONFIG_BPF_SYSCALL as u64;
        tristate_val = CONFIG_TRISTATE as u64;
        bool_val = CONFIG_BOOL as u64;
        char_val = CONFIG_CHAR as i64 as u64;
        ushort_val = CONFIG_USHORT as u64;
        int_val = CONFIG_INT as i64 as u64;
        ulong_val = CONFIG_ULONG;

        let mut i = 0;
        while i < CONFIG_STR.len() {
            str_val[i] = CONFIG_STR[i];
            i += 1;
        }

        if CONFIG_MISSING != 0 {
            // invalid, but dead code - never executed
            missing_val = bpf_missing_helper(ctx, 123) as i64 as u64;
        } else {
            missing_val = 0xDEADC0DE;
        }
    }

    0
}

bpf_object!("GPL");
