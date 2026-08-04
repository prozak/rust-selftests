#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/kprobe_multi_session.c
// bpf-rs-core idiom. ctx (`struct pt_regs *`) is only forwarded to
// bpf_get_func_ip, never dereferenced, so it stays opaque (same pattern as
// kprobe_multi_override.rs). Each `extern const void bpf_fentry_testN __ksym;`
// (address-only ksym) is redeclared as an extern fn and only address-taken,
// per get_func_ip_fsession_test.rs -- rustc emits no BTF for extern statics,
// so an extern function is the only way to get a resolvable ksym relocation.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_get_current_pid_tgid, bpf_get_func_ip};
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
}

#[no_mangle]
static mut pid: i32 = 0;

#[no_mangle]
static mut kprobe_session_result: [u64; 8] = [0; 8];

unsafe fn session_check(ctx: *const c_void) -> i32 {
    let kfuncs = [
        bpf_fentry_test1 as usize as u64,
        bpf_fentry_test2 as usize as u64,
        bpf_fentry_test3 as usize as u64,
        bpf_fentry_test4 as usize as u64,
        bpf_fentry_test5 as usize as u64,
        bpf_fentry_test6 as usize as u64,
        bpf_fentry_test7 as usize as u64,
        bpf_fentry_test8 as usize as u64,
    ];

    if (bpf_get_current_pid_tgid() >> 32) as i32 != pid {
        return 1;
    }

    let addr = bpf_get_func_ip(ctx);

    let mut i = 0usize;
    while i < kfuncs.len() {
        if kfuncs[i] == addr {
            let p = core::ptr::addr_of_mut!(kprobe_session_result) as *mut u64;
            *p.add(i) += 1;
            break;
        }
        i += 1;
    }

    // Force probes for function bpf_fentry_test[5-8] not to install and
    // execute the return probe.
    if addr == kfuncs[4] || addr == kfuncs[5] || addr == kfuncs[6] || addr == kfuncs[7] {
        return 1;
    }

    0
}

/*
 * No tests in here, just to trigger 'bpf_fentry_test*'
 * through tracing test_run
 */
#[link_section = "fentry/bpf_modify_return_test"]
#[no_mangle]
extern "C" fn trigger(_ctx: *const u64) -> i32 {
    0
}

#[link_section = "kprobe.session/bpf_fentry_test*"]
#[no_mangle]
extern "C" fn test_kprobe(ctx: *const c_void) -> i32 {
    unsafe { session_check(ctx) }
}

/*
 * Exact function name (no wildcards) - exercises the fast syms[] path
 * in bpf_program__attach_kprobe_multi_opts() which bypasses kallsyms parsing.
 */
#[link_section = "kprobe.session/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test_kprobe_syms(ctx: *const c_void) -> i32 {
    unsafe { session_check(ctx) }
}

bpf_object!("GPL");
