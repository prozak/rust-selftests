// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Direct translation of tools/testing/selftests/bpf/progs/iters_looping.c
// (bpf-rs-core idiom). The C drives the bpf_iter_num kfuncs from
// `asm volatile` blocks inside ordinary functions, with the iterator a
// stack local passed in as `__imm_ptr(iter)` and r0-r5 clobbered; the same
// blocks are `asm!` here with the iterator's address as an `in(reg)`
// operand and the kfuncs as `sym` operands. iterator_with_diff_stack_depth
// reads its parameter straight from r1 inside the asm and touches r10-128
// behind the compiler's back, so it is carried as `// BPF_NAKED:` raw asm
// (the C object's instruction sequence), as is the __naked
// widening_stack_size_bug that calls it. The test_loader decl tags are
// declared with test_tags! (scripts/btf_test_tags.py).

use bpf_rs_core::bpf_object;
use bpf_rs_core::test_tags;
use core::ffi::c_void;
use core::mem::MaybeUninit;

// struct bpf_iter_num { __u64 __opaque[1]; } __attribute__((aligned(8)));
#[repr(C, align(8))]
struct bpf_iter_num {
    __opaque: [u64; 1],
}

extern "C" {
    fn bpf_iter_num_new(it: *mut bpf_iter_num, start: i32, end: i32) -> i32;
    fn bpf_iter_num_next(it: *mut bpf_iter_num) -> *mut i32;
    fn bpf_iter_num_destroy(it: *mut bpf_iter_num);
}

test_tags! {
    force_clang_to_emit_btf_for_externs: __success;
    consume_first_item_only: __success;
    missing_null_check_fail: __failure, __msg("R0 invalid mem access 'scalar'");
    wrong_sized_read_fail: __failure, __msg("invalid access to memory, mem_size=4 off=0 size=8"), __msg("R0 min value is outside of the allowed memory range");
    simplest_loop: __success, __log_level(2), __flag(BPF_F_TEST_STATE_FREQ);
    widening_stack_size_bug: __success;
}

#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn force_clang_to_emit_btf_for_externs(_ctx: *mut c_void) -> i32 {
    /* we need this as a workaround to enforce compiler emitting BTF
     * information for bpf_iter_num_{new,next,destroy}() kfuncs,
     * as, apparently, it doesn't emit it for symbols only referenced from
     * assembly (or cleanup attribute, for that matter, as well)
     */
    // C: bpf_repeat(0);
    let mut it = MaybeUninit::<bpf_iter_num>::uninit();
    unsafe {
        bpf_iter_num_new(it.as_mut_ptr(), 0, 0);
        while !bpf_iter_num_next(it.as_mut_ptr()).is_null() {}
        bpf_iter_num_destroy(it.as_mut_ptr());
    }

    0
}

#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn consume_first_item_only(_ctx: *mut c_void) -> i32 {
    let mut iter = MaybeUninit::<bpf_iter_num>::uninit();

    unsafe {
        core::arch::asm!(
            /* create iterator */
            "r1 = {iter};",
            "r2 = 0;",
            "r3 = 1000;",
            "call {bpf_iter_num_new};",

            /* consume first item */
            "r1 = {iter};",
            "call {bpf_iter_num_next};",

            "if r0 == 0 goto +1;",
            "r0 = *(u32 *)(r0 + 0);",

            /* destroy iterator */
            "r1 = {iter};",
            "call {bpf_iter_num_destroy};",
            iter = in(reg) iter.as_mut_ptr(),
            bpf_iter_num_new = sym bpf_iter_num_new,
            bpf_iter_num_next = sym bpf_iter_num_next,
            bpf_iter_num_destroy = sym bpf_iter_num_destroy,
            out("r0") _,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
        );
    }

    0
}

#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn missing_null_check_fail(_ctx: *mut c_void) -> i32 {
    let mut iter = MaybeUninit::<bpf_iter_num>::uninit();

    unsafe {
        core::arch::asm!(
            /* create iterator */
            "r1 = {iter};",
            "r2 = 0;",
            "r3 = 1000;",
            "call {bpf_iter_num_new};",

            /* consume first element */
            "r1 = {iter};",
            "call {bpf_iter_num_next};",

            /* FAIL: deref with no NULL check */
            "r1 = *(u32 *)(r0 + 0);",

            /* destroy iterator */
            "r1 = {iter};",
            "call {bpf_iter_num_destroy};",
            iter = in(reg) iter.as_mut_ptr(),
            bpf_iter_num_new = sym bpf_iter_num_new,
            bpf_iter_num_next = sym bpf_iter_num_next,
            bpf_iter_num_destroy = sym bpf_iter_num_destroy,
            out("r0") _,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
        );
    }

    0
}

#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn wrong_sized_read_fail(_ctx: *mut c_void) -> i32 {
    let mut iter = MaybeUninit::<bpf_iter_num>::uninit();

    unsafe {
        core::arch::asm!(
            /* create iterator */
            "r1 = {iter};",
            "r2 = 0;",
            "r3 = 1000;",
            "call {bpf_iter_num_new};",

            /* consume first element */
            "r1 = {iter};",
            "call {bpf_iter_num_next};",

            "if r0 == 0 goto +1;",
            /* FAIL: deref more than available 4 bytes */
            "r0 = *(u64 *)(r0 + 0);",

            /* destroy iterator */
            "r1 = {iter};",
            "call {bpf_iter_num_destroy};",
            iter = in(reg) iter.as_mut_ptr(),
            bpf_iter_num_new = sym bpf_iter_num_new,
            bpf_iter_num_next = sym bpf_iter_num_next,
            bpf_iter_num_destroy = sym bpf_iter_num_destroy,
            out("r0") _,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
        );
    }

    0
}

#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn simplest_loop(_ctx: *mut c_void) -> i32 {
    let mut iter = MaybeUninit::<bpf_iter_num>::uninit();

    unsafe {
        core::arch::asm!(
            "r6 = 0;", /* init sum */

            /* create iterator */
            "r1 = {iter};",
            "r2 = 0;",
            "r3 = 10;",
            "call {bpf_iter_num_new};",

            "1:",
            /* consume next item */
            "r1 = {iter};",
            "call {bpf_iter_num_next};",

            "if r0 == 0 goto 2f;",
            "r0 = *(u32 *)(r0 + 0);",
            "r6 += r0;", /* accumulate sum */
            "goto 1b;",

            "2:",
            /* destroy iterator */
            "r1 = {iter};",
            "call {bpf_iter_num_destroy};",
            iter = in(reg) iter.as_mut_ptr(),
            bpf_iter_num_new = sym bpf_iter_num_new,
            bpf_iter_num_next = sym bpf_iter_num_next,
            bpf_iter_num_destroy = sym bpf_iter_num_destroy,
            out("r0") _,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
            out("r6") _,
        );
    }

    0
}

// C: __used static void iterator_with_diff_stack_depth(int x) -- the asm
// tests the parameter in r1 directly and writes r10-128 on one path, so the
// subprogram's stack depth is 8 or 128 bytes depending on the argument.
// Carried as the C object's instruction sequence (clang keeps &iter in r7).
#[no_mangle]
#[inline(never)]
// BPF_NAKED: iterator_with_diff_stack_depth
extern "C" fn iterator_with_diff_stack_depth(_x: i32) {
    unsafe {
        core::arch::asm!(
            "r7 = r10;",
            "r7 += -8;",
            "if r1 == 42 goto 0f;",
            "*(u64 *)(r10 - 128) = 0;",
            "0:",
            /* create iterator */
            "r1 = r7;",
            "r2 = 0;",
            "r3 = 10;",
            "call {bpf_iter_num_new};",
            "1:",
            /* consume next item */
            "r1 = r7;",
            "call {bpf_iter_num_next};",
            "if r0 == 0 goto 2f;",
            "goto 1b;",
            "2:",
            /* destroy iterator */
            "r1 = r7;",
            "call {bpf_iter_num_destroy};",
            "exit;",
            bpf_iter_num_new = sym bpf_iter_num_new,
            bpf_iter_num_next = sym bpf_iter_num_next,
            bpf_iter_num_destroy = sym bpf_iter_num_destroy,
            options(noreturn)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: widening_stack_size_bug
extern "C" fn widening_stack_size_bug() -> i32 {
    /*
     * Depending on iterator_with_diff_stack_depth() parameter value,
     * subprogram stack depth is either 8 or 128 bytes. Arrange values so
     * that it is 128 on a first call and 8 on a second. This triggered a
     * bug in verifier's widen_imprecise_scalars() logic.
     */
    unsafe {
        core::arch::asm!(
            "r6 = 0;",
            "r1 = 0;",
            "1:",
            "call {iterator_with_diff_stack_depth};",
            "r1 = 42;",
            "r6 += 1;",
            "if r6 < 2 goto 1b;",
            "r0 = 0;",
            "exit;",
            iterator_with_diff_stack_depth = sym iterator_with_diff_stack_depth,
            options(noreturn)
        );
    }
}

bpf_object!("GPL");
