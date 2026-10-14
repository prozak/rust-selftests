// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Direct translation of
// tools/testing/selftests/bpf/progs/pro_epilogue_goto_start.c, bpf-rs-core
// idiom.
//
// The three struct_ops programs are `__naked` hand-written BPF asm in the
// C: a loop of backward gotos whose last one targets the first insn of the
// program. The kernel's st_ops_gen_prologue/st_ops_gen_epilogue callbacks
// (bpf_testmod.c) splice a prologue and/or an epilogue in, keyed on the
// struct_ops member name, and must retarget that goto to the start of the
// main prog rather than the prologue. The C's `__xlated` tags assert the
// rewritten listing line by line, so the bodies are carried verbatim as raw
// asm (// BPF_NAKED:, scripts/naked_abi.py) and every tag is mirrored by
// test_tags! below.
//
// Keep the C object's order of the syscall programs, so test_loader runs
// the subtests in the same order.
// BPF_PROGRAM_ORDER: syscall_prologue_goto_start syscall_epilogue_goto_start syscall_pro_epilogue_goto_start

use bpf_rs_core::{bpf_object, test_tags};
use core::ffi::c_void;

// The C's tag comments: in each listing the kernel's prologue comes first
// (the four lines ending in `r7 += 1000`), then `*(u64 *)(r10 -8) = r1`
// saving the __u64 *ctx for the epilogue, then the main prog, then the
// epilogue (`r6 += 10000` ... `exit`). The __retval comments: 20000 =
// (EPILOGUE_A [10000]) * 2; 22000 = (PROLOGUE_A [1000] + EPILOGUE_A
// [10000]) * 2.
test_tags! {
    test_prologue_goto_start: __success,
        __xlated("0: r6 = *(u64 *)(r1 +0)"),
        __xlated("1: r7 = *(u64 *)(r6 +0)"),
        __xlated("2: r7 += 1000"),
        __xlated("3: *(u64 *)(r6 +0) = r7"),
        __xlated("4: if r1 == 0x0 goto pc+5"),
        __xlated("5: if r1 == 0x1 goto pc+2"),
        __xlated("6: r1 = 1"),
        __xlated("7: goto pc-3"),
        __xlated("8: r1 = 0"),
        __xlated("9: goto pc-6"),
        __xlated("10: r0 = 0"),
        __xlated("11: exit");
    test_epilogue_goto_start: __success,
        __xlated("0: *(u64 *)(r10 -8) = r1"),
        __xlated("1: if r1 == 0x0 goto pc+5"),
        __xlated("2: if r1 == 0x1 goto pc+2"),
        __xlated("3: r1 = 1"),
        __xlated("4: goto pc-3"),
        __xlated("5: r1 = 0"),
        __xlated("6: goto pc-6"),
        __xlated("7: r0 = 0"),
        __xlated("8: r1 = *(u64 *)(r10 -8)"),
        __xlated("9: r1 = *(u64 *)(r1 +0)"),
        __xlated("10: r6 = *(u64 *)(r1 +0)"),
        __xlated("11: r6 += 10000"),
        __xlated("12: *(u64 *)(r1 +0) = r6"),
        __xlated("13: r0 = r6"),
        __xlated("14: r0 *= 2"),
        __xlated("15: exit");
    test_pro_epilogue_goto_start: __success,
        __xlated("0: r6 = *(u64 *)(r1 +0)"),
        __xlated("1: r7 = *(u64 *)(r6 +0)"),
        __xlated("2: r7 += 1000"),
        __xlated("3: *(u64 *)(r6 +0) = r7"),
        __xlated("4: *(u64 *)(r10 -8) = r1"),
        __xlated("5: if r1 == 0x0 goto pc+5"),
        __xlated("6: if r1 == 0x1 goto pc+2"),
        __xlated("7: r1 = 1"),
        __xlated("8: goto pc-3"),
        __xlated("9: r1 = 0"),
        __xlated("10: goto pc-6"),
        __xlated("11: r0 = 0"),
        __xlated("12: r1 = *(u64 *)(r10 -8)"),
        __xlated("13: r1 = *(u64 *)(r1 +0)"),
        __xlated("14: r6 = *(u64 *)(r1 +0)"),
        __xlated("15: r6 += 10000"),
        __xlated("16: *(u64 *)(r1 +0) = r6"),
        __xlated("17: r0 = r6"),
        __xlated("18: r0 *= 2"),
        __xlated("19: exit");
    syscall_prologue_goto_start: __retval(0);
    syscall_epilogue_goto_start: __retval(20000);
    syscall_pro_epilogue_goto_start: __retval(22000);
}

#[repr(C)]
struct st_ops_args {
    a: u64,
}

extern "C" {
    fn bpf_kfunc_st_ops_test_prologue(args: *mut st_ops_args) -> i32;
    fn bpf_kfunc_st_ops_test_epilogue(args: *mut st_ops_args) -> i32;
    fn bpf_kfunc_st_ops_test_pro_epilogue(args: *mut st_ops_args) -> i32;
}

#[link_section = "struct_ops/test_prologue_goto_start"]
#[no_mangle]
// BPF_NAKED: test_prologue_goto_start
extern "C" fn test_prologue_goto_start() -> i32 {
    unsafe {
        core::arch::asm!(
            "if r1 == 0 goto +5;",
            "if r1 == 1 goto +2;",
            "r1 = 1;",
            "goto -3;",
            "r1 = 0;",
            "goto -6;",
            "r0 = 0;",
            "exit;",
            options(noreturn)
        );
    }
}

#[link_section = "struct_ops/test_epilogue_goto_start"]
#[no_mangle]
// BPF_NAKED: test_epilogue_goto_start
extern "C" fn test_epilogue_goto_start() -> i32 {
    unsafe {
        core::arch::asm!(
            "if r1 == 0 goto +5;",
            "if r1 == 1 goto +2;",
            "r1 = 1;",
            "goto -3;",
            "r1 = 0;",
            "goto -6;",
            "r0 = 0;",
            "exit;",
            options(noreturn)
        );
    }
}

#[link_section = "struct_ops/test_pro_epilogue_goto_start"]
#[no_mangle]
// BPF_NAKED: test_pro_epilogue_goto_start
extern "C" fn test_pro_epilogue_goto_start() -> i32 {
    unsafe {
        core::arch::asm!(
            "if r1 == 0 goto +5;",
            "if r1 == 1 goto +2;",
            "r1 = 1;",
            "goto -3;",
            "r1 = 0;",
            "goto -6;",
            "r0 = 0;",
            "exit;",
            options(noreturn)
        );
    }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn syscall_prologue_goto_start(_ctx: *const c_void) -> i32 {
    let mut args = st_ops_args { a: 0 };
    unsafe { bpf_kfunc_st_ops_test_prologue(&mut args as *mut st_ops_args) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn syscall_epilogue_goto_start(_ctx: *const c_void) -> i32 {
    let mut args = st_ops_args { a: 0 };
    unsafe { bpf_kfunc_st_ops_test_epilogue(&mut args as *mut st_ops_args) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn syscall_pro_epilogue_goto_start(_ctx: *const c_void) -> i32 {
    let mut args = st_ops_args { a: 0 };
    unsafe { bpf_kfunc_st_ops_test_pro_epilogue(&mut args as *mut st_ops_args) }
}

// struct bpf_testmod_st_ops (bpf_testmod.h): only the members this program
// initializes are declared — libbpf's struct_ops relocation matches local
// struct members against the kernel type by name (see
// struct_ops_maybe_null.rs / pro_epilogue_with_kfunc.rs).
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_testmod_st_ops {
    test_prologue: extern "C" fn() -> i32,
    test_epilogue: extern "C" fn() -> i32,
    test_pro_epilogue: extern "C" fn() -> i32,
}

unsafe impl Sync for bpf_testmod_st_ops {}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static epilogue_goto_start: bpf_testmod_st_ops = bpf_testmod_st_ops {
    test_prologue: test_prologue_goto_start,
    test_epilogue: test_epilogue_goto_start,
    test_pro_epilogue: test_pro_epilogue_goto_start,
};

bpf_object!("GPL");
