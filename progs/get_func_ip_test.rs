// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/get_func_ip_test.c
// (bpf-rs-core idiom). prog_tests/get_func_ip_test.c attaches everything,
// test_run()s test1/test5, calls its own uprobe_trigger() and reads the
// `testN_result` globals; the body test enables test6 (`?kprobe`) and
// attaches it at an offset that depends on CONFIG_X86_KERNEL_IBT, read
// through `skel->kconfig`.
//
// CONFIG_X86_KERNEL_IBT is the C's weak `__kconfig` bool (`// BTF_KCONFIG:`
// below, scripts/ksym_vars.py mirrors the C object's declaration); like the
// C, the global `unused()` subprog is the only reader, kept so the extern
// lands in the object's BTF. The `extern const void bpf_fentry_testN
// __ksym` address-only ksyms are extern fns that are only address-taken
// (kprobe_multi_session.rs); the two kfunc protos follow the C.
// `uprobe_trigger` is the C's `unsigned long` the consumer fills in.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_func_ip;
use bpf_rs_core::progs::fentry_arg as arg;
use core::ffi::c_void;

extern "C" {
    fn bpf_fentry_test1(a: i32) -> i32;
    fn bpf_modify_return_test(a: i32, b: *mut i32) -> i32;

    fn bpf_fentry_test2();
    fn bpf_fentry_test3();
    fn bpf_fentry_test4();
}

// BTF_KCONFIG: CONFIG_X86_KERNEL_IBT
extern "C" {
    static CONFIG_X86_KERNEL_IBT: u8;
}

/* This function is here to have CONFIG_X86_KERNEL_IBT
 * used and added to object BTF.
 */
#[no_mangle]
pub extern "C" fn unused() -> i32 {
    if unsafe { CONFIG_X86_KERNEL_IBT } != 0 {
        0
    } else {
        1
    }
}

#[no_mangle]
static mut test1_result: u64 = 0;
#[link_section = "fentry/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test1(ctx: *const u64) -> i32 {
    let addr = bpf_get_func_ip(ctx as *const c_void);

    unsafe { test1_result = (addr == bpf_fentry_test1 as usize as u64) as u64 };
    0
}

#[no_mangle]
static mut test2_result: u64 = 0;
#[link_section = "fexit/bpf_fentry_test2"]
#[no_mangle]
extern "C" fn test2(ctx: *const u64) -> i32 {
    let addr = bpf_get_func_ip(ctx as *const c_void);

    unsafe { test2_result = (addr == bpf_fentry_test2 as usize as u64) as u64 };
    0
}

#[no_mangle]
static mut test3_result: u64 = 0;
#[link_section = "kprobe/bpf_fentry_test3"]
#[no_mangle]
extern "C" fn test3(ctx: *const c_void) -> i32 {
    let addr = bpf_get_func_ip(ctx);

    unsafe { test3_result = (addr == bpf_fentry_test3 as usize as u64) as u64 };
    0
}

#[no_mangle]
static mut test4_result: u64 = 0;
#[link_section = "kretprobe/bpf_fentry_test4"]
#[no_mangle]
extern "C" fn test4(ctx: *const c_void) -> i32 {
    let addr = bpf_get_func_ip(ctx);

    unsafe { test4_result = (addr == bpf_fentry_test4 as usize as u64) as u64 };
    0
}

#[no_mangle]
static mut test5_result: u64 = 0;
#[link_section = "fmod_ret/bpf_modify_return_test"]
#[no_mangle]
extern "C" fn test5(ctx: *const u64) -> i32 {
    let addr = bpf_get_func_ip(ctx as *const c_void);

    unsafe { test5_result = (addr == bpf_modify_return_test as usize as u64) as u64 };
    arg(ctx, 2) as i32
}

#[no_mangle]
static mut test6_result: u64 = 0;
#[link_section = "?kprobe"]
#[no_mangle]
extern "C" fn test6(ctx: *const c_void) -> i32 {
    let addr = bpf_get_func_ip(ctx);

    unsafe { test6_result = (addr == 0) as u64 };
    0
}

#[no_mangle]
static mut uprobe_trigger: usize = 0;

#[no_mangle]
static mut test7_result: u64 = 0;
#[link_section = "uprobe//proc/self/exe:uprobe_trigger"]
#[no_mangle]
extern "C" fn test7(ctx: *const u64) -> i32 {
    let addr = bpf_get_func_ip(ctx as *const c_void);

    unsafe { test7_result = (addr as usize == uprobe_trigger) as u64 };
    0
}

#[no_mangle]
static mut test8_result: u64 = 0;
#[link_section = "uretprobe//proc/self/exe:uprobe_trigger"]
#[no_mangle]
extern "C" fn test8(ctx: *const u64) -> i32 {
    let addr = bpf_get_func_ip(ctx as *const c_void);

    unsafe { test8_result = (addr as usize == uprobe_trigger) as u64 };
    0
}

bpf_object!("GPL");
