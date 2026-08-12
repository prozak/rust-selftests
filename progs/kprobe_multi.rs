#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/kprobe_multi.c
// bpf-rs-core idiom.
//
// `extern const void bpf_fentry_test{1..8}/bpf_testmod_fentry_test{1..3}
// __ksym;` in the C source are address-only data ksyms, but every one of
// them names a real kernel/module *function* (bpf_fentry_test1 is itself a
// fentry attach target elsewhere, see fentry_test.rs). Per the
// extern-ksym-data-to-func-workaround: rustc emits no BTF for `extern "C" {
// static X: T; }` (libbpf then fails object open with "failed to find BTF
// for extern"), but redeclaring the ksym as an extern *function* and taking
// its address (never calling it) round-trips fine -- add_ksyms.py mirrors a
// BTF FUNC entry from the kernel's own BTF by name regardless of the
// declared signature, and libbpf resolves a FUNC-kind ksym extern into
// BPF_PSEUDO_BTF_ID for an address-taking RELO_EXTERN_LD64 site just as it
// does for a call site.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_get_attach_cookie, bpf_get_current_pid_tgid, bpf_get_func_ip};
use core::ffi::c_void;

extern "C" {
    fn bpf_fentry_test1();
    fn bpf_fentry_test2();
    fn bpf_fentry_test3();
    fn bpf_fentry_test4();
    fn bpf_fentry_test5();
    fn bpf_fentry_test6();
    fn bpf_fentry_test7();
    fn bpf_fentry_test8();

    fn bpf_testmod_fentry_test1();
    fn bpf_testmod_fentry_test2();
    fn bpf_testmod_fentry_test3();
}

#[no_mangle]
static mut pid: i32 = 0;
#[no_mangle]
// C declares this `bool`; clang compiles every `test_cookie`/`!test_cookie`
// test as `!= 1` (jne 1), so it's true only for the byte value 1. Mirror
// that with u8 + explicit `== 1` compares (a Rust `if bool` would test
// `!= 0` and diverge for out-of-range bytes).
static mut test_cookie: u8 = 0;

#[no_mangle]
static mut kprobe_test1_result: u64 = 0;
#[no_mangle]
static mut kprobe_test2_result: u64 = 0;
#[no_mangle]
static mut kprobe_test3_result: u64 = 0;
#[no_mangle]
static mut kprobe_test4_result: u64 = 0;
#[no_mangle]
static mut kprobe_test5_result: u64 = 0;
#[no_mangle]
static mut kprobe_test6_result: u64 = 0;
#[no_mangle]
static mut kprobe_test7_result: u64 = 0;
#[no_mangle]
static mut kprobe_test8_result: u64 = 0;

#[no_mangle]
static mut kretprobe_test1_result: u64 = 0;
#[no_mangle]
static mut kretprobe_test2_result: u64 = 0;
#[no_mangle]
static mut kretprobe_test3_result: u64 = 0;
#[no_mangle]
static mut kretprobe_test4_result: u64 = 0;
#[no_mangle]
static mut kretprobe_test5_result: u64 = 0;
#[no_mangle]
static mut kretprobe_test6_result: u64 = 0;
#[no_mangle]
static mut kretprobe_test7_result: u64 = 0;
#[no_mangle]
static mut kretprobe_test8_result: u64 = 0;

#[no_mangle]
static mut kprobe_testmod_test1_result: u64 = 0;
#[no_mangle]
static mut kprobe_testmod_test2_result: u64 = 0;
#[no_mangle]
static mut kprobe_testmod_test3_result: u64 = 0;

#[no_mangle]
static mut kretprobe_testmod_test1_result: u64 = 0;
#[no_mangle]
static mut kretprobe_testmod_test2_result: u64 = 0;
#[no_mangle]
static mut kretprobe_testmod_test3_result: u64 = 0;

#[inline(always)]
fn matches(addr: u64, target: u64, cookie: u64, want_cookie: u64) -> bool {
    addr == target && (unsafe { test_cookie } != 1 || cookie == want_cookie)
}

#[inline(never)]
fn kprobe_multi_check(ctx: *const c_void, is_return: bool) {
    if (bpf_get_current_pid_tgid() >> 32) as i32 != unsafe { pid } {
        return;
    }

    let cookie = if unsafe { test_cookie } == 1 {
        bpf_get_attach_cookie(ctx)
    } else {
        0
    };
    let addr = bpf_get_func_ip(ctx);

    if is_return {
        if matches(addr, bpf_fentry_test1 as usize as u64, cookie, 8) {
            unsafe { kretprobe_test1_result = 1 };
        }
        if matches(addr, bpf_fentry_test2 as usize as u64, cookie, 2) {
            unsafe { kretprobe_test2_result = 1 };
        }
        if matches(addr, bpf_fentry_test3 as usize as u64, cookie, 7) {
            unsafe { kretprobe_test3_result = 1 };
        }
        if matches(addr, bpf_fentry_test4 as usize as u64, cookie, 6) {
            unsafe { kretprobe_test4_result = 1 };
        }
        if matches(addr, bpf_fentry_test5 as usize as u64, cookie, 5) {
            unsafe { kretprobe_test5_result = 1 };
        }
        if matches(addr, bpf_fentry_test6 as usize as u64, cookie, 4) {
            unsafe { kretprobe_test6_result = 1 };
        }
        if matches(addr, bpf_fentry_test7 as usize as u64, cookie, 3) {
            unsafe { kretprobe_test7_result = 1 };
        }
        if matches(addr, bpf_fentry_test8 as usize as u64, cookie, 1) {
            unsafe { kretprobe_test8_result = 1 };
        }
    } else {
        if matches(addr, bpf_fentry_test1 as usize as u64, cookie, 1) {
            unsafe { kprobe_test1_result = 1 };
        }
        if matches(addr, bpf_fentry_test2 as usize as u64, cookie, 7) {
            unsafe { kprobe_test2_result = 1 };
        }
        if matches(addr, bpf_fentry_test3 as usize as u64, cookie, 2) {
            unsafe { kprobe_test3_result = 1 };
        }
        if matches(addr, bpf_fentry_test4 as usize as u64, cookie, 3) {
            unsafe { kprobe_test4_result = 1 };
        }
        if matches(addr, bpf_fentry_test5 as usize as u64, cookie, 4) {
            unsafe { kprobe_test5_result = 1 };
        }
        if matches(addr, bpf_fentry_test6 as usize as u64, cookie, 5) {
            unsafe { kprobe_test6_result = 1 };
        }
        if matches(addr, bpf_fentry_test7 as usize as u64, cookie, 6) {
            unsafe { kprobe_test7_result = 1 };
        }
        if matches(addr, bpf_fentry_test8 as usize as u64, cookie, 8) {
            unsafe { kprobe_test8_result = 1 };
        }
    }
}

#[inline(never)]
fn kprobe_multi_testmod_check(ctx: *const c_void, is_return: bool) {
    if (bpf_get_current_pid_tgid() >> 32) as i32 != unsafe { pid } {
        return;
    }

    let addr = bpf_get_func_ip(ctx);

    if is_return {
        if addr == bpf_testmod_fentry_test1 as usize as u64 {
            unsafe { kretprobe_testmod_test1_result = 1 };
        }
        if addr == bpf_testmod_fentry_test2 as usize as u64 {
            unsafe { kretprobe_testmod_test2_result = 1 };
        }
        if addr == bpf_testmod_fentry_test3 as usize as u64 {
            unsafe { kretprobe_testmod_test3_result = 1 };
        }
    } else {
        if addr == bpf_testmod_fentry_test1 as usize as u64 {
            unsafe { kprobe_testmod_test1_result = 1 };
        }
        if addr == bpf_testmod_fentry_test2 as usize as u64 {
            unsafe { kprobe_testmod_test2_result = 1 };
        }
        if addr == bpf_testmod_fentry_test3 as usize as u64 {
            unsafe { kprobe_testmod_test3_result = 1 };
        }
    }
}

// No tests in here, just to trigger 'bpf_fentry_test*' through tracing
// test_run.
#[link_section = "fentry/bpf_modify_return_test"]
#[no_mangle]
extern "C" fn trigger(_ctx: *const u64) -> i32 {
    0
}

#[link_section = "kprobe.multi/bpf_fentry_tes??"]
#[no_mangle]
extern "C" fn test_kprobe(ctx: *const c_void) -> i32 {
    kprobe_multi_check(ctx, false);
    0
}

#[link_section = "kretprobe.multi/bpf_fentry_test*"]
#[no_mangle]
extern "C" fn test_kretprobe(ctx: *const c_void) -> i32 {
    kprobe_multi_check(ctx, true);
    0
}

#[link_section = "kprobe.multi"]
#[no_mangle]
extern "C" fn test_kprobe_manual(ctx: *const c_void) -> i32 {
    kprobe_multi_check(ctx, false);
    0
}

#[link_section = "kretprobe.multi"]
#[no_mangle]
extern "C" fn test_kretprobe_manual(ctx: *const c_void) -> i32 {
    kprobe_multi_check(ctx, true);
    0
}

#[link_section = "kprobe.multi"]
#[no_mangle]
extern "C" fn test_kprobe_testmod(ctx: *const c_void) -> i32 {
    kprobe_multi_testmod_check(ctx, false);
    0
}

#[link_section = "kretprobe.multi"]
#[no_mangle]
extern "C" fn test_kretprobe_testmod(ctx: *const c_void) -> i32 {
    kprobe_multi_testmod_check(ctx, true);
    0
}

bpf_object!("GPL");
