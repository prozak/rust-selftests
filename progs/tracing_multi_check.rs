// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![allow(non_upper_case_globals)]

// Direct translation of
// tools/testing/selftests/bpf/progs/tracing_multi_check.c (bpf-rs-core
// idiom). The shared half of four linked skeletons (Makefile.skel:
// tracing_multi, tracing_multi_module, tracing_multi_intersect,
// tracing_multi_session, each `<attach half>.bpf.o tracing_multi_check.bpf.o`):
// it defines no program, only the global function `tracing_multi_arg_check`
// in .text that every attach half declares `__hidden extern` and calls
// from its fentry.multi/fexit.multi/fsession.multi programs.
// prog_tests/tracing_multi.c sets `pid` (and `test_cookies` for the cookies
// subtest), attaches the halves to bpf_fentry_test1..10 or the testmod's
// bpf_testmod_fentry_test* and counts the matched calls in the attach
// half's test_result_* globals through `*test_result += ...`.
//
// The traced function is identified by bpf_get_func_ip against the
// address-only ksyms (`extern const void X __ksym` -> `// BTF_KSYM:`,
// scripts/ksym_vars.py; bpf_link_fops in linked_vars1.rs); bpf_fentry_test1
// is the kfunc vmlinux.h declares, so its address is the function's
// (get_func_ip_fsession_test.rs). The C compiles `if (test_cookies)` as
// `w != 1` and the `x ? cond : 0` ternaries on `test_cookies` and
// `is_return` as `cond & flag`: mirrored per site (translint bool-global,
// lesson 32). `pid` is an int compared against the u64 tgid, so it is
// sign-extended first, as in the C.

use core::ffi::c_void;
use core::ptr::addr_of;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_get_attach_cookie, bpf_get_current_pid_tgid, bpf_get_func_arg, bpf_get_func_ip,
    bpf_get_func_ret,
};

#[no_mangle]
static mut pid: i32 = 0;
#[no_mangle]
static mut test_cookies: u8 = 0;

/* bpf_fentry_test1 is exported as kfunc via vmlinux.h */
extern "C" {
    fn bpf_fentry_test1(a: i32) -> i32;
}

// BTF_KSYM: bpf_fentry_test2
// BTF_KSYM: bpf_fentry_test3
// BTF_KSYM: bpf_fentry_test4
// BTF_KSYM: bpf_fentry_test5
// BTF_KSYM: bpf_fentry_test6
// BTF_KSYM: bpf_fentry_test7
// BTF_KSYM: bpf_fentry_test8
// BTF_KSYM: bpf_fentry_test9
// BTF_KSYM: bpf_fentry_test10
// BTF_KSYM: bpf_testmod_fentry_test1
// BTF_KSYM: bpf_testmod_fentry_test2
// BTF_KSYM: bpf_testmod_fentry_test3
// BTF_KSYM: bpf_testmod_fentry_test7
// BTF_KSYM: bpf_testmod_fentry_test11
extern "C" {
    static bpf_fentry_test2: u8;
    static bpf_fentry_test3: u8;
    static bpf_fentry_test4: u8;
    static bpf_fentry_test5: u8;
    static bpf_fentry_test6: u8;
    static bpf_fentry_test7: u8;
    static bpf_fentry_test8: u8;
    static bpf_fentry_test9: u8;
    static bpf_fentry_test10: u8;

    static bpf_testmod_fentry_test1: u8;
    static bpf_testmod_fentry_test2: u8;
    static bpf_testmod_fentry_test3: u8;
    static bpf_testmod_fentry_test7: u8;
    static bpf_testmod_fentry_test11: u8;
}

#[no_mangle]
pub extern "C" fn tracing_multi_arg_check(ctx: *mut u64, test_result: *mut u64, is_return: bool) -> i32 {
    let vctx = ctx as *const c_void;
    let ip = bpf_get_func_ip(vctx);
    let mut value: u64 = 0;
    let mut ret: u64 = 0;
    let mut cookie: u64 = 0;
    let mut err: i64 = 0;
    let is_return = is_return as i64;

    unsafe {
        if bpf_get_current_pid_tgid() >> 32 != pid as i64 as u64 {
            return 1;
        }

        if is_return != 0 {
            err |= bpf_get_func_ret(vctx, &mut ret);
        }
        if test_cookies == 1 {
            cookie = bpf_get_attach_cookie(vctx);
        }
        let cookies = test_cookies as i64;

        if ip == bpf_fentry_test1 as usize as u64 {
            err |= bpf_get_func_arg(vctx, 0, &mut value);
            let a = value as i32;

            err |= ((ret != 2) as i64) & is_return;
            err |= ((cookie != 8) as i64) & cookies;

            *test_result += (err == 0 && a == 1) as u64;
        } else if ip == addr_of!(bpf_fentry_test2) as u64 {
            err |= bpf_get_func_arg(vctx, 0, &mut value);
            let a = value as i32;
            err |= bpf_get_func_arg(vctx, 1, &mut value);
            let b: u64 = value;

            err |= ((ret != 5) as i64) & is_return;
            err |= ((cookie != 9) as i64) & cookies;

            *test_result += (err == 0 && a == 2 && b == 3) as u64;
        } else if ip == addr_of!(bpf_fentry_test3) as u64 {
            err |= bpf_get_func_arg(vctx, 0, &mut value);
            let a = value as i8;
            err |= bpf_get_func_arg(vctx, 1, &mut value);
            let b = value as i32;
            err |= bpf_get_func_arg(vctx, 2, &mut value);
            let c: u64 = value;

            err |= ((ret != 15) as i64) & is_return;
            err |= ((cookie != 7) as i64) & cookies;

            *test_result += (err == 0 && a == 4 && b == 5 && c == 6) as u64;
        } else if ip == addr_of!(bpf_fentry_test4) as u64 {
            err |= bpf_get_func_arg(vctx, 0, &mut value);
            let a = value as *const c_void;
            err |= bpf_get_func_arg(vctx, 1, &mut value);
            let b = value as i8;
            err |= bpf_get_func_arg(vctx, 2, &mut value);
            let c = value as i32;
            err |= bpf_get_func_arg(vctx, 3, &mut value);
            let d: u64 = value;

            err |= ((ret != 34) as i64) & is_return;
            err |= ((cookie != 5) as i64) & cookies;

            *test_result +=
                (err == 0 && a == 7 as *const c_void && b == 8 && c == 9 && d == 10) as u64;
        } else if ip == addr_of!(bpf_fentry_test5) as u64 {
            err |= bpf_get_func_arg(vctx, 0, &mut value);
            let a: u64 = value;
            err |= bpf_get_func_arg(vctx, 1, &mut value);
            let b = value as *const c_void;
            err |= bpf_get_func_arg(vctx, 2, &mut value);
            let c = value as i16;
            err |= bpf_get_func_arg(vctx, 3, &mut value);
            let d = value as i32;
            err |= bpf_get_func_arg(vctx, 4, &mut value);
            let e: u64 = value;

            err |= ((ret != 65) as i64) & is_return;
            err |= ((cookie != 4) as i64) & cookies;

            *test_result += (err == 0
                && a == 11
                && b == 12 as *const c_void
                && c == 13
                && d == 14
                && e == 15) as u64;
        } else if ip == addr_of!(bpf_fentry_test6) as u64 {
            err |= bpf_get_func_arg(vctx, 0, &mut value);
            let a: u64 = value;
            err |= bpf_get_func_arg(vctx, 1, &mut value);
            let b = value as *const c_void;
            err |= bpf_get_func_arg(vctx, 2, &mut value);
            let c = value as i16;
            err |= bpf_get_func_arg(vctx, 3, &mut value);
            let d = value as i32;
            err |= bpf_get_func_arg(vctx, 4, &mut value);
            let e = value as *const c_void;
            err |= bpf_get_func_arg(vctx, 5, &mut value);
            let f: u64 = value;

            err |= ((ret != 111) as i64) & is_return;
            err |= ((cookie != 2) as i64) & cookies;

            *test_result += (err == 0
                && a == 16
                && b == 17 as *const c_void
                && c == 18
                && d == 19
                && e == 20 as *const c_void
                && f == 21) as u64;
        } else if ip == addr_of!(bpf_fentry_test7) as u64 {
            err |= ((ret != 0) as i64) & is_return;
            err |= ((cookie != 3) as i64) & cookies;

            *test_result += if err == 0 { 1 } else { 0 };
        } else if ip == addr_of!(bpf_fentry_test8) as u64 {
            err |= ((ret != 0) as i64) & is_return;
            err |= ((cookie != 1) as i64) & cookies;

            *test_result += if err == 0 { 1 } else { 0 };
        } else if ip == addr_of!(bpf_fentry_test9) as u64 {
            err |= ((ret != 0) as i64) & is_return;
            err |= ((cookie != 10) as i64) & cookies;

            *test_result += if err == 0 { 1 } else { 0 };
        } else if ip == addr_of!(bpf_fentry_test10) as u64 {
            err |= ((ret != 0) as i64) & is_return;
            err |= ((cookie != 6) as i64) & cookies;

            *test_result += if err == 0 { 1 } else { 0 };
        } else if ip == addr_of!(bpf_testmod_fentry_test1) as u64 {
            err |= bpf_get_func_arg(vctx, 0, &mut value);
            let a = value as i32;

            err |= ((ret != 2) as i64) & is_return;

            *test_result += (err == 0 && a == 1) as u64;
        } else if ip == addr_of!(bpf_testmod_fentry_test2) as u64 {
            err |= bpf_get_func_arg(vctx, 0, &mut value);
            let a = value as i32;
            err |= bpf_get_func_arg(vctx, 1, &mut value);
            let b: u64 = value;

            err |= ((ret != 5) as i64) & is_return;

            *test_result += (err == 0 && a == 2 && b == 3) as u64;
        } else if ip == addr_of!(bpf_testmod_fentry_test3) as u64 {
            err |= bpf_get_func_arg(vctx, 0, &mut value);
            let a = value as i8;
            err |= bpf_get_func_arg(vctx, 1, &mut value);
            let b = value as i32;
            err |= bpf_get_func_arg(vctx, 2, &mut value);
            let c: u64 = value;

            err |= ((ret != 15) as i64) & is_return;

            *test_result += (err == 0 && a == 4 && b == 5 && c == 6) as u64;
        } else if ip == addr_of!(bpf_testmod_fentry_test7) as u64 {
            err |= ((ret != 133) as i64) & is_return;

            *test_result += (err == 0) as u64;
        } else if ip == addr_of!(bpf_testmod_fentry_test11) as u64 {
            err |= ((ret != 231) as i64) & is_return;

            *test_result += (err == 0) as u64;
        }
    }

    0
}

bpf_object!("GPL");
