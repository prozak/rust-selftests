// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Direct translation of
// tools/testing/selftests/bpf/progs/pro_epilogue_with_kfunc.c, bpf-rs-core
// idiom.
//
// test_kfunc_pro_epilogue is `__naked` hand-written BPF asm in the C: load
// the args ptr, call the bpf_kfunc_st_ops_inc10 kfunc, call the noinline
// `subprog` (args->a += 1; return args->a), exit. The kernel's
// st_ops_gen_prologue/st_ops_gen_epilogue callbacks (bpf_testmod.c) splice
// in a prologue and an epilogue that themselves call kfuncs, keyed on the
// `test_pro_epilogue` struct_ops member. The C's `__xlated` tags assert the
// rewritten listing line by line, so the body is carried verbatim as raw
// asm (// BPF_NAKED:, scripts/naked_abi.py) and every tag is mirrored by
// test_tags! below.
//
// __kfunc_btf_root is a plain (non-SEC, never-called) global function in
// the C source whose only purpose is a reachable use of
// bpf_kfunc_st_ops_inc10 for BTF/relocation purposes.

use bpf_rs_core::{bpf_object, test_tags};
use core::ffi::c_void;

// The C's tag comments: 0-11 are the kernel's prologue (with its own kfunc
// calls), 12 saves the __u64 *ctx to the stack, 13-17 are the main prog
// and 18-32 the epilogue. The __retval comment: 22022 = (PROLOGUE_A [1000]
// + KFUNC_INC10 + SUBPROG_A [1] + EPILOGUE_A [10000]) * 2.
test_tags! {
    test_kfunc_pro_epilogue: __success,
        __xlated("0: r8 = r1"),
        __xlated("1: r1 = 0"),
        __xlated("2: call kernel-function"),
        __xlated("3: if r0 != 0x0 goto pc+5"),
        __xlated("4: r6 = *(u64 *)(r8 +0)"),
        __xlated("5: r7 = *(u64 *)(r6 +0)"),
        __xlated("6: r7 += 1000"),
        __xlated("7: *(u64 *)(r6 +0) = r7"),
        __xlated("8: goto pc+2"),
        __xlated("9: r1 = r0"),
        __xlated("10: call kernel-function"),
        __xlated("11: r1 = r8"),
        __xlated("12: *(u64 *)(r10 -8) = r1"),
        __xlated("13: r1 = *(u64 *)(r1 +0)"),
        __xlated("14: r6 = r1"),
        __xlated("15: call kernel-function"),
        __xlated("16: r1 = r6"),
        __xlated("17: call pc+"),
        __xlated("18: r1 = 0"),
        __xlated("19: r6 = 0"),
        __xlated("20: call kernel-function"),
        __xlated("21: if r0 != 0x0 goto pc+6"),
        __xlated("22: r1 = *(u64 *)(r10 -8)"),
        __xlated("23: r1 = *(u64 *)(r1 +0)"),
        __xlated("24: r6 = *(u64 *)(r1 +0)"),
        __xlated("25: r6 += 10000"),
        __xlated("26: *(u64 *)(r1 +0) = r6"),
        __xlated("27: goto pc+2"),
        __xlated("28: r1 = r0"),
        __xlated("29: call kernel-function"),
        __xlated("30: r0 = r6"),
        __xlated("31: r0 *= 2"),
        __xlated("32: exit");
    syscall_pro_epilogue: __retval(22022);
}

#[repr(C)]
struct st_ops_args {
    a: u64,
}

extern "C" {
    fn bpf_kfunc_st_ops_inc10(args: *mut st_ops_args) -> i32;
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

#[link_section = "struct_ops/test_pro_epilogue"]
#[no_mangle]
// BPF_NAKED: test_kfunc_pro_epilogue
extern "C" fn test_kfunc_pro_epilogue() -> i32 {
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
extern "C" fn syscall_pro_epilogue(_ctx: *const c_void) -> i32 {
    let mut args = st_ops_args { a: 0 };
    unsafe { bpf_kfunc_st_ops_test_pro_epilogue(&mut args as *mut st_ops_args) }
}

// struct bpf_testmod_st_ops (bpf_testmod.h): only the member this program
// initializes is declared — libbpf's struct_ops relocation matches local
// struct members against the kernel type by name (see
// struct_ops_maybe_null.rs / bpf_tcp_nogpl.rs).
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_testmod_st_ops {
    test_pro_epilogue: extern "C" fn() -> i32,
}

unsafe impl Sync for bpf_testmod_st_ops {}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static pro_epilogue_with_kfunc: bpf_testmod_st_ops = bpf_testmod_st_ops {
    test_pro_epilogue: test_kfunc_pro_epilogue,
};

bpf_object!("GPL");
