// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Direct translation of tools/testing/selftests/bpf/progs/iters_state_safety.c
// (bpf-rs-core idiom): the verifier's bookkeeping of a bpf_iter_num on the
// stack -- create/destroy pairing, leaked references, direct and helper
// writes over the iterator slots, reuse of the slots, reads of the opaque
// state, and the stack-spill vs iterator confusion. As in iters_looping.rs
// the C drives the kfuncs from `asm volatile` blocks inside ordinary
// functions with the iterator a stack local passed as `__imm_ptr(iter)`
// and r0-r5 clobbered: the same blocks are `asm!` here with the iterator's
// address as an `in(reg)` operand and the kfuncs as `sym` operands; helpers
// are called by number (bpf_probe_read_kernel 113, bpf_get_prandom_u32 7).
// read_from_iter_slot_fail is the C's __naked body as `// BPF_NAKED:`. The
// C's `bad:` / `skip_bad:` labels are the numeric `1:` / `2:`; the unused
// `__imm_addr(zero)` / `__imm(bpf_dynptr_from_mem)` operands have no
// counterpart (asm! rejects operands the template does not use) and `zero`
// stays a .bss global as in the C object. The test_loader decl tags are
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
    create_and_destroy: __success, __log_level(2), __msg("fp-8=iter_num(id=1,state=active,depth=0)");
    destroy_fp0_fail: __failure, __msg("cannot pass in iter at an offset=0");
    create_and_forget_to_destroy_fail: __failure, __msg("Unreleased reference id=1");
    destroy_without_creating_fail: __failure, __msg("expected an initialized iter_num as R1");
    compromise_iter_w_direct_write_fail: __failure, __msg("expected an initialized iter_num as R1");
    compromise_iter_w_direct_write_and_skip_destroy_fail: __failure, __msg("Unreleased reference id=1");
    compromise_iter_w_helper_write_fail: __failure, __msg("expected an initialized iter_num as R1");
    leak_iter_from_subprog_fail: __failure, __msg("returning from callee:"), __msg("Unreleased reference id=1");
    valid_stack_reuse: __success, __log_level(2), __msg("fp-8=iter_num(id=1,state=active,depth=0)");
    double_create_fail: __failure, __msg("expected uninitialized iter_num as R1");
    double_destroy_fail: __failure, __msg("expected an initialized iter_num as R1");
    next_without_new_fail: __failure, __msg("expected an initialized iter_num as R1");
    next_after_destroy_fail: __failure, __msg("expected an initialized iter_num as R1");
    read_from_iter_slot_fail: __failure, __msg("invalid read from stack"), __msg("Verification failed: Memory Safety: Direct read of iterator stack state"), __msg("verifier-managed iterator state"), __msg("Use iterator kfuncs");
    stacksafe_should_not_conflate_stack_spill_and_iter: __failure, __flag(BPF_F_TEST_STATE_FREQ), __msg("Unreleased reference");
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
extern "C" fn create_and_destroy(_ctx: *mut c_void) -> i32 {
    let mut iter = MaybeUninit::<bpf_iter_num>::uninit();

    unsafe {
        core::arch::asm!(
            /* create iterator */
            "r1 = {iter};",
            "r2 = 0;",
            "r3 = 1000;",
            "call {bpf_iter_num_new};",
            /* destroy iterator */
            "r1 = {iter};",
            "call {bpf_iter_num_destroy};",
            iter = in(reg) iter.as_mut_ptr(),
            bpf_iter_num_new = sym bpf_iter_num_new,
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

/* fp+0 is not a stack slot. bpf_get_spi(0) used to alias spi 0 (fp-8). */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn destroy_fp0_fail(_ctx: *mut c_void) -> i32 {
    let mut iter = MaybeUninit::<bpf_iter_num>::uninit();

    unsafe {
        core::arch::asm!(
            "r1 = {iter};",
            "r2 = 0;",
            "r3 = 1000;",
            "call {bpf_iter_num_new};",
            /* r10 is fp+0, one byte above the top of the BPF stack */
            "r1 = r10;",
            "call {bpf_iter_num_destroy};",
            iter = in(reg) iter.as_mut_ptr(),
            bpf_iter_num_new = sym bpf_iter_num_new,
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
extern "C" fn create_and_forget_to_destroy_fail(_ctx: *mut c_void) -> i32 {
    let mut iter = MaybeUninit::<bpf_iter_num>::uninit();

    unsafe {
        core::arch::asm!(
            /* create iterator */
            "r1 = {iter};",
            "r2 = 0;",
            "r3 = 1000;",
            "call {bpf_iter_num_new};",
            iter = in(reg) iter.as_mut_ptr(),
            bpf_iter_num_new = sym bpf_iter_num_new,
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
extern "C" fn destroy_without_creating_fail(_ctx: *mut c_void) -> i32 {
    /* init with zeros to stop verifier complaining about uninit stack */
    let mut iter = MaybeUninit::<bpf_iter_num>::uninit();

    unsafe {
        core::arch::asm!(
            "r1 = {iter};",
            "call {bpf_iter_num_destroy};",
            iter = in(reg) iter.as_mut_ptr(),
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
extern "C" fn compromise_iter_w_direct_write_fail(_ctx: *mut c_void) -> i32 {
    let mut iter = MaybeUninit::<bpf_iter_num>::uninit();

    unsafe {
        core::arch::asm!(
            /* create iterator */
            "r1 = {iter};",
            "r2 = 0;",
            "r3 = 1000;",
            "call {bpf_iter_num_new};",

            /* directly write over first half of iter state */
            "*(u64 *)({iter} + 0) = r0;",

            /* (attempt to) destroy iterator */
            "r1 = {iter};",
            "call {bpf_iter_num_destroy};",
            iter = in(reg) iter.as_mut_ptr(),
            bpf_iter_num_new = sym bpf_iter_num_new,
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
extern "C" fn compromise_iter_w_direct_write_and_skip_destroy_fail(_ctx: *mut c_void) -> i32 {
    let mut iter = MaybeUninit::<bpf_iter_num>::uninit();

    unsafe {
        core::arch::asm!(
            /* create iterator */
            "r1 = {iter};",
            "r2 = 0;",
            "r3 = 1000;",
            "call {bpf_iter_num_new};",

            /* directly write over first half of iter state */
            "*(u64 *)({iter} + 0) = r0;",

            /* don't destroy iter, leaking ref, which should fail */
            iter = in(reg) iter.as_mut_ptr(),
            bpf_iter_num_new = sym bpf_iter_num_new,
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
extern "C" fn compromise_iter_w_helper_write_fail(_ctx: *mut c_void) -> i32 {
    let mut iter = MaybeUninit::<bpf_iter_num>::uninit();

    unsafe {
        core::arch::asm!(
            /* create iterator */
            "r1 = {iter};",
            "r2 = 0;",
            "r3 = 1000;",
            "call {bpf_iter_num_new};",

            /* overwrite 8th byte with bpf_probe_read_kernel() */
            "r1 = {iter};",
            "r1 += 7;",
            "r2 = 1;",
            "r3 = 0;", /* NULL */
            "call 113;", /* bpf_probe_read_kernel */

            /* (attempt to) destroy iterator */
            "r1 = {iter};",
            "call {bpf_iter_num_destroy};",
            iter = in(reg) iter.as_mut_ptr(),
            bpf_iter_num_new = sym bpf_iter_num_new,
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

// C: static __noinline void subprog_with_iter(void)
#[inline(never)]
fn subprog_with_iter() {
    let mut iter = MaybeUninit::<bpf_iter_num>::uninit();

    unsafe {
        bpf_iter_num_new(iter.as_mut_ptr(), 0, 1);
    }
}

#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn leak_iter_from_subprog_fail(_ctx: *mut c_void) -> i32 {
    subprog_with_iter();

    0
}

#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn valid_stack_reuse(_ctx: *mut c_void) -> i32 {
    let mut iter = MaybeUninit::<bpf_iter_num>::uninit();

    unsafe {
        core::arch::asm!(
            /* create iterator */
            "r1 = {iter};",
            "r2 = 0;",
            "r3 = 1000;",
            "call {bpf_iter_num_new};",
            /* destroy iterator */
            "r1 = {iter};",
            "call {bpf_iter_num_destroy};",

            /* now reuse same stack slots */

            /* create iterator */
            "r1 = {iter};",
            "r2 = 0;",
            "r3 = 1000;",
            "call {bpf_iter_num_new};",
            /* destroy iterator */
            "r1 = {iter};",
            "call {bpf_iter_num_destroy};",
            iter = in(reg) iter.as_mut_ptr(),
            bpf_iter_num_new = sym bpf_iter_num_new,
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
extern "C" fn double_create_fail(_ctx: *mut c_void) -> i32 {
    let mut iter = MaybeUninit::<bpf_iter_num>::uninit();

    unsafe {
        core::arch::asm!(
            /* create iterator */
            "r1 = {iter};",
            "r2 = 0;",
            "r3 = 1000;",
            "call {bpf_iter_num_new};",
            /* (attempt to) create iterator again */
            "r1 = {iter};",
            "r2 = 0;",
            "r3 = 1000;",
            "call {bpf_iter_num_new};",
            /* destroy iterator */
            "r1 = {iter};",
            "call {bpf_iter_num_destroy};",
            iter = in(reg) iter.as_mut_ptr(),
            bpf_iter_num_new = sym bpf_iter_num_new,
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
extern "C" fn double_destroy_fail(_ctx: *mut c_void) -> i32 {
    let mut iter = MaybeUninit::<bpf_iter_num>::uninit();

    unsafe {
        core::arch::asm!(
            /* create iterator */
            "r1 = {iter};",
            "r2 = 0;",
            "r3 = 1000;",
            "call {bpf_iter_num_new};",
            /* destroy iterator */
            "r1 = {iter};",
            "call {bpf_iter_num_destroy};",
            /* (attempt to) destroy iterator again */
            "r1 = {iter};",
            "call {bpf_iter_num_destroy};",
            iter = in(reg) iter.as_mut_ptr(),
            bpf_iter_num_new = sym bpf_iter_num_new,
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
extern "C" fn next_without_new_fail(_ctx: *mut c_void) -> i32 {
    let mut iter = MaybeUninit::<bpf_iter_num>::uninit();

    unsafe {
        core::arch::asm!(
            /* don't create iterator and try to iterate*/
            "r1 = {iter};",
            "call {bpf_iter_num_next};",
            /* destroy iterator */
            "r1 = {iter};",
            "call {bpf_iter_num_destroy};",
            iter = in(reg) iter.as_mut_ptr(),
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
extern "C" fn next_after_destroy_fail(_ctx: *mut c_void) -> i32 {
    let mut iter = MaybeUninit::<bpf_iter_num>::uninit();

    unsafe {
        core::arch::asm!(
            /* create iterator */
            "r1 = {iter};",
            "r2 = 0;",
            "r3 = 1000;",
            "call {bpf_iter_num_new};",
            /* destroy iterator */
            "r1 = {iter};",
            "call {bpf_iter_num_destroy};",
            /* don't create iterator and try to iterate*/
            "r1 = {iter};",
            "call {bpf_iter_num_next};",
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

// C: int __naked read_from_iter_slot_fail(void) -- the whole body is the
// asm block (r6 holds &iter = fp-24, r7/r8 the leaked state words).
#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: read_from_iter_slot_fail
extern "C" fn read_from_iter_slot_fail() -> i32 {
    unsafe {
        core::arch::asm!(
            /* r6 points to struct bpf_iter_num on the stack */
            "r6 = r10;",
            "r6 += -24;",

            /* create iterator */
            "r1 = r6;",
            "r2 = 0;",
            "r3 = 1000;",
            "call {bpf_iter_num_new};",

            /* attempt to leak bpf_iter_num state */
            "r7 = *(u64 *)(r6 + 0);",
            "r8 = *(u64 *)(r6 + 8);",

            /* destroy iterator */
            "r1 = r6;",
            "call {bpf_iter_num_destroy};",

            /* leak bpf_iter_num state */
            "r0 = r7;",
            "if r7 > r8 goto +1;",
            "r0 = r8;",
            "exit;",
            bpf_iter_num_new = sym bpf_iter_num_new,
            bpf_iter_num_destroy = sym bpf_iter_num_destroy,
            options(noreturn)
        );
    }
}

// C: int zero; -- named only by the last program's unused __imm_addr operand.
#[allow(non_upper_case_globals)]
#[no_mangle]
static mut zero: i32 = 0;

#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn stacksafe_should_not_conflate_stack_spill_and_iter(_ctx: *mut c_void) -> i32 {
    let mut iter = MaybeUninit::<bpf_iter_num>::uninit();

    unsafe {
        core::arch::asm!(
            /* Create a fork in logic, with general setup as follows:
             *   - fallthrough (first) path is valid;
             *   - branch (second) path is invalid.
             * Then depending on what we do in fallthrough vs branch path,
             * we try to detect bugs in func_states_equal(), regsafe(),
             * refsafe(), stack_safe(), and similar by tricking verifier
             * into believing that branch state is a valid subset of
             * a fallthrough state. Verifier should reject overall
             * validation, unless there is a bug somewhere in verifier
             * logic.
             */
            "call 7;", /* bpf_get_prandom_u32 */
            "r6 = r0;",
            "call 7;", /* bpf_get_prandom_u32 */
            "r7 = r0;",

            "if r6 > r7 goto 1f;", /* fork */

            /* spill r6 into stack slot of bpf_iter_num var */
            "*(u64 *)({iter} + 0) = r6;",

            "goto 2f;",

            "1:", /* bad: */
            /* create iterator in the same stack slot */
            "r1 = {iter};",
            "r2 = 0;",
            "r3 = 1000;",
            "call {bpf_iter_num_new};",

            /* but then forget about it and overwrite it back to r6 spill */
            "*(u64 *)({iter} + 0) = r6;",

            "2:", /* skip_bad: */
            "goto +0;", /* force checkpoint */

            /* corrupt stack slots, if they are really dynptr */
            "*(u64 *)({iter} + 0) = r6;",
            iter = in(reg) iter.as_mut_ptr(),
            bpf_iter_num_new = sym bpf_iter_num_new,
            out("r0") _,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
            out("r6") _,
            out("r7") _,
        );
    }

    0
}

bpf_object!("GPL");
