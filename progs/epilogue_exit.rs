// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Direct translation of tools/testing/selftests/bpf/progs/epilogue_exit.c
// (bpf-rs-core idiom).
//
// test_epilogue_exit is `__naked` in the C source: hand-written BPF asm with
// two `exit;` instructions. The struct_ops "test_epilogue" member makes the
// kernel's gen_epilogue callback (bpf_testmod.c) splice its epilogue in at
// the first exit and turn the second into a jump back to it. The C's
// `__xlated` tags assert that rewritten listing line by line, so the body
// is carried verbatim as raw asm (// BPF_NAKED:, scripts/naked_abi.py) and
// every tag is mirrored by test_tags! below.

use bpf_rs_core::{bpf_object, test_tags};
use core::ffi::c_void;

// The C's tag comments: 0 saves the __u64 *ctx to the stack; 1-7 are the
// main prog; 8-15 the spliced epilogue; 16-19 the second part of the main
// prog after the first exit, where 18 clears r1 so an off-by-1 jump would
// show, and 19 jumps back to the start of the epilogue, which reloads r1.
test_tags! {
    test_epilogue_exit: __success,
        __xlated("0: *(u64 *)(r10 -8) = r1"),
        __xlated("1: r1 = *(u64 *)(r1 +0)"),
        __xlated("2: r2 = *(u64 *)(r1 +0)"),
        __xlated("3: r3 = 0"),
        __xlated("4: r4 = 1"),
        __xlated("5: if r2 == 0x0 goto pc+10"),
        __xlated("6: r0 = 0"),
        __xlated("7: *(u64 *)(r1 +0) = r3"),
        __xlated("8: r1 = *(u64 *)(r10 -8)"),
        __xlated("9: r1 = *(u64 *)(r1 +0)"),
        __xlated("10: r6 = *(u64 *)(r1 +0)"),
        __xlated("11: r6 += 10000"),
        __xlated("12: *(u64 *)(r1 +0) = r6"),
        __xlated("13: r0 = r6"),
        __xlated("14: r0 *= 2"),
        __xlated("15: exit"),
        __xlated("16: *(u64 *)(r1 +0) = r4"),
        __xlated("17: r0 = 1"),
        __xlated("18: r1 = 0"),
        __xlated("19: gotol pc-12");
    syscall_epilogue_exit0: __retval(20000);
    syscall_epilogue_exit1: __retval(20002);
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct st_ops_args {
    a: u64,
}

extern "C" {
    fn bpf_kfunc_st_ops_test_epilogue(args: *mut st_ops_args) -> i32;
}

#[link_section = "struct_ops/test_epilogue_exit"]
#[no_mangle]
// BPF_NAKED: test_epilogue_exit
extern "C" fn test_epilogue_exit() -> i32 {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64 *)(r1 +0);",
            "r2 = *(u64 *)(r1 +0);",
            "r3 = 0;",
            "r4 = 1;",
            "if r2 == 0 goto +3;",
            "r0 = 0;",
            "*(u64 *)(r1 + 0) = r3;",
            "exit;",
            "*(u64 *)(r1 + 0) = r4;",
            "r0 = 1;",
            "r1 = 0;",
            "exit;",
            options(noreturn)
        );
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_testmod_st_ops {
    test_epilogue: extern "C" fn() -> i32,
}

unsafe impl Sync for bpf_testmod_st_ops {}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static epilogue_exit: bpf_testmod_st_ops = bpf_testmod_st_ops {
    test_epilogue: test_epilogue_exit,
};

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn syscall_epilogue_exit0(_ctx: *const c_void) -> i32 {
    let mut args = st_ops_args { a: 1 };
    unsafe { bpf_kfunc_st_ops_test_epilogue(&mut args) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn syscall_epilogue_exit1(_ctx: *const c_void) -> i32 {
    let mut args = st_ops_args { a: 0 };
    unsafe { bpf_kfunc_st_ops_test_epilogue(&mut args) }
}

bpf_object!("GPL");
