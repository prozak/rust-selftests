// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_fill_link_info.c
// (bpf-rs-core idiom). prog_tests/fill_link_info.c attaches each empty
// program by hand and checks what bpf_link_get_info_by_fd() reports; the
// kprobe address check depends on CONFIG_X86_KERNEL_IBT and the three PPC
// options, read through `skel->kconfig`.
//
// The four bools are the C's weak `__kconfig` externs (`// BTF_KCONFIG:`
// below, scripts/ksym_vars.py mirrors the C object's declarations); like
// the C, the global `unused()` subprog is their only reader, kept so the
// externs land in the object's BTF.

use bpf_rs_core::bpf_object;
use core::ffi::c_void;

// BTF_KCONFIG: CONFIG_X86_KERNEL_IBT
// BTF_KCONFIG: CONFIG_PPC_FTRACE_OUT_OF_LINE
// BTF_KCONFIG: CONFIG_KPROBES_ON_FTRACE
// BTF_KCONFIG: CONFIG_PPC64
extern "C" {
    static CONFIG_X86_KERNEL_IBT: u8;
    static CONFIG_PPC_FTRACE_OUT_OF_LINE: u8;
    static CONFIG_KPROBES_ON_FTRACE: u8;
    static CONFIG_PPC64: u8;
}

/* This function is here to have CONFIG_X86_KERNEL_IBT,
 * CONFIG_PPC_FTRACE_OUT_OF_LINE, CONFIG_KPROBES_ON_FTRACE,
 * CONFIG_PPC64 used and added to object BTF.
 */
#[no_mangle]
pub extern "C" fn unused() -> i32 {
    if unsafe {
        CONFIG_X86_KERNEL_IBT != 0
            || CONFIG_PPC_FTRACE_OUT_OF_LINE != 0
            || CONFIG_KPROBES_ON_FTRACE != 0
            || CONFIG_PPC64 != 0
    } {
        0
    } else {
        1
    }
}

#[link_section = "kprobe"]
#[no_mangle]
extern "C" fn kprobe_run(_ctx: *const c_void) -> i32 {
    0
}

#[link_section = "uprobe"]
#[no_mangle]
extern "C" fn uprobe_run(_ctx: *const c_void) -> i32 {
    0
}

#[link_section = "tracepoint"]
#[no_mangle]
extern "C" fn tp_run(_ctx: *const c_void) -> i32 {
    0
}

#[link_section = "perf_event"]
#[no_mangle]
extern "C" fn event_run(_ctx: *const c_void) -> i32 {
    0
}

#[link_section = "kprobe.multi"]
#[no_mangle]
extern "C" fn kmulti_run(_ctx: *const c_void) -> i32 {
    0
}

#[link_section = "uprobe.multi"]
#[no_mangle]
extern "C" fn umulti_run(_ctx: *const c_void) -> i32 {
    0
}

#[link_section = "fentry.multi"]
#[no_mangle]
extern "C" fn tmulti_run(_ctx: *const c_void) -> i32 {
    0
}

bpf_object!("GPL");
