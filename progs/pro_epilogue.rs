// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Direct translation of tools/testing/selftests/bpf/progs/pro_epilogue.c
// (bpf-rs-core idiom).
//
// The three struct_ops programs are `__naked` hand-written BPF asm in the
// C: load the args ptr, call the bpf_kfunc_st_ops_inc10 kfunc, call the
// noinline `subprog` (args->a += 1; return args->a), exit. The kernel's
// st_ops_gen_prologue/st_ops_gen_epilogue callbacks (bpf_testmod.c) splice
// a prologue (args->a += 1000) and/or an epilogue (args->a += 10000, return
// args->a * 2) around that body, keyed on the struct_ops member name. The
// C's `__xlated` tags assert the rewritten listing line by line, so the
// bodies are carried verbatim as raw asm (// BPF_NAKED:,
// scripts/naked_abi.py) and every tag is mirrored by test_tags! below.
//
// __kfunc_btf_root is a plain (non-SEC, never-called) global function in
// the C source whose only purpose is giving the compiler/relocator a
// reachable use of bpf_kfunc_st_ops_inc10 for BTF/relocation purposes; it
// is a GLOBAL FUNC symbol in the clang-built object (confirmed via
// llvm-readelf -sW), so the internalize keep-list requires it verbatim.

use bpf_rs_core::{bpf_object, test_tags};
use core::ffi::c_void;

// The C's tag comments: in each listing the kernel's prologue comes first
// (the four lines ending in `r7 += 1000`), then `*(u64 *)(r10 -8) = r1`
// saving the __u64 *ctx for the epilogue, then the main prog, then the
// epilogue (`r6 += 10000` ... `exit`). The __retval comments: 1011 =
// PROLOGUE_A [1000] + KFUNC_INC10 + SUBPROG_A [1]; 20022 = (KFUNC_INC10 +
// SUBPROG_A [1] + EPILOGUE_A [10000]) * 2; 22022 = (PROLOGUE_A [1000] +
// KFUNC_INC10 + SUBPROG_A [1] + EPILOGUE_A [10000]) * 2.
test_tags! {
    test_prologue: __success,
        __xlated("0: r6 = *(u64 *)(r1 +0)"),
        __xlated("1: r7 = *(u64 *)(r6 +0)"),
        __xlated("2: r7 += 1000"),
        __xlated("3: *(u64 *)(r6 +0) = r7"),
        __xlated("4: r1 = *(u64 *)(r1 +0)"),
        __xlated("5: r6 = r1"),
        __xlated("6: call kernel-function"),
        __xlated("7: r1 = r6"),
        __xlated("8: call pc+1"),
        __xlated("9: exit");
    test_epilogue: __success,
        __xlated("0: *(u64 *)(r10 -8) = r1"),
        __xlated("1: r1 = *(u64 *)(r1 +0)"),
        __xlated("2: r6 = r1"),
        __xlated("3: call kernel-function"),
        __xlated("4: r1 = r6"),
        __xlated("5: call pc+"),
        __xlated("6: r1 = *(u64 *)(r10 -8)"),
        __xlated("7: r1 = *(u64 *)(r1 +0)"),
        __xlated("8: r6 = *(u64 *)(r1 +0)"),
        __xlated("9: r6 += 10000"),
        __xlated("10: *(u64 *)(r1 +0) = r6"),
        __xlated("11: r0 = r6"),
        __xlated("12: r0 *= 2"),
        __xlated("13: exit");
    test_pro_epilogue: __success,
        __xlated("0: r6 = *(u64 *)(r1 +0)"),
        __xlated("1: r7 = *(u64 *)(r6 +0)"),
        __xlated("2: r7 += 1000"),
        __xlated("3: *(u64 *)(r6 +0) = r7"),
        __xlated("4: *(u64 *)(r10 -8) = r1"),
        __xlated("5: r1 = *(u64 *)(r1 +0)"),
        __xlated("6: r6 = r1"),
        __xlated("7: call kernel-function"),
        __xlated("8: r1 = r6"),
        __xlated("9: call pc+"),
        __xlated("10: r1 = *(u64 *)(r10 -8)"),
        __xlated("11: r1 = *(u64 *)(r1 +0)"),
        __xlated("12: r6 = *(u64 *)(r1 +0)"),
        __xlated("13: r6 += 10000"),
        __xlated("14: *(u64 *)(r1 +0) = r6"),
        __xlated("15: r0 = r6"),
        __xlated("16: r0 *= 2"),
        __xlated("17: exit");
    syscall_prologue: __retval(1011);
    syscall_epilogue: __retval(20022);
    syscall_pro_epilogue: __retval(22022);
}
#[allow(non_camel_case_types)]
#[repr(C)]
struct st_ops_args {
    a: u64,
}

extern "C" {
    fn bpf_kfunc_st_ops_inc10(args: *mut st_ops_args) -> i32;
    fn bpf_kfunc_st_ops_test_prologue(args: *mut st_ops_args) -> i32;
    fn bpf_kfunc_st_ops_test_epilogue(args: *mut st_ops_args) -> i32;
    fn bpf_kfunc_st_ops_test_pro_epilogue(args: *mut st_ops_args) -> i32;
}

#[no_mangle]
extern "C" fn __kfunc_btf_root() {
    unsafe {
        bpf_kfunc_st_ops_inc10(core::ptr::null_mut());
    }
}

#[no_mangle]
#[inline(never)]
extern "C" fn subprog(args: *mut st_ops_args) -> i32 {
    unsafe {
        (*args).a += 1;
        (*args).a as i32
    }
}

#[link_section = "struct_ops/test_prologue"]
#[no_mangle]
// BPF_NAKED: test_prologue
extern "C" fn test_prologue() -> i32 {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64 *)(r1 +0);",
            "r6 = r1;",
            "call {bpf_kfunc_st_ops_inc10};",
            "r1 = r6;",
            "call {subprog};",
            "exit;",
            bpf_kfunc_st_ops_inc10 = sym bpf_kfunc_st_ops_inc10,
            subprog = sym subprog,
            options(noreturn)
        );
    }
}

#[link_section = "struct_ops/test_epilogue"]
#[no_mangle]
// BPF_NAKED: test_epilogue
extern "C" fn test_epilogue() -> i32 {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64 *)(r1 +0);",
            "r6 = r1;",
            "call {bpf_kfunc_st_ops_inc10};",
            "r1 = r6;",
            "call {subprog};",
            "exit;",
            bpf_kfunc_st_ops_inc10 = sym bpf_kfunc_st_ops_inc10,
            subprog = sym subprog,
            options(noreturn)
        );
    }
}

#[link_section = "struct_ops/test_pro_epilogue"]
#[no_mangle]
// BPF_NAKED: test_pro_epilogue
extern "C" fn test_pro_epilogue() -> i32 {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64 *)(r1 +0);",
            "r6 = r1;",
            "call {bpf_kfunc_st_ops_inc10};",
            "r1 = r6;",
            "call {subprog};",
            "exit;",
            bpf_kfunc_st_ops_inc10 = sym bpf_kfunc_st_ops_inc10,
            subprog = sym subprog,
            options(noreturn)
        );
    }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn syscall_prologue(_ctx: *const c_void) -> i32 {
    let mut args = st_ops_args { a: 0 };
    unsafe { bpf_kfunc_st_ops_test_prologue(&mut args) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn syscall_epilogue(_ctx: *const c_void) -> i32 {
    let mut args = st_ops_args { a: 0 };
    unsafe { bpf_kfunc_st_ops_test_epilogue(&mut args) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn syscall_pro_epilogue(_ctx: *const c_void) -> i32 {
    let mut args = st_ops_args { a: 0 };
    unsafe { bpf_kfunc_st_ops_test_pro_epilogue(&mut args) }
}

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
static pro_epilogue: bpf_testmod_st_ops = bpf_testmod_st_ops {
    test_prologue,
    test_epilogue,
    test_pro_epilogue,
};

bpf_object!("GPL");
