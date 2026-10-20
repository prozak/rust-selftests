// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/iters.c, translated
// by hand; include!d by the generated progs/iters.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

// The C bodies: the num-iterator programs (open-coded bpf_iter_num loops,
// libbpf's bpf_for / bpf_repeat / bpf_for_each macros, bpf_printk),
// their static subprograms, and loop_cb5 (the bpf_loop callback of the
// naked iter_remake). The Rust-level calls of the three bpf_iter_num kfuncs
// also give them their BTF prototype (llc emits one only for a real call;
// the asm `sym` references of the naked programs alone leave libbpf with
// "failed to find BTF info for global/extern symbol").
// MY_PID_GUARD() is empty outside REAL_TEST and has no counterpart here.
// Array accesses index through raw pointers (no Rust bounds check: the C
// has none, and the expected messages are about the index's bounds).
// bpf_printk1(fmt, args...) is bpf_trace_printk2(fmt, sizeof(fmt), args...)
// on the C object's own format strings (the `<prog>.____fmt` statics of
// the generated file); int arguments are sign-extended as clang does.

use bpf_rs_core::helpers::sink;
use core::hint::black_box;
use core::mem::MaybeUninit;
use core::ptr::{addr_of, addr_of_mut, read_volatile};

// HAND: iter_err_unsafe_c_loop
//   SEC("?raw_tp")
//   __failure __msg("math between map_value pointer and register with unbounded min value is not allowed")
//   int iter_err_unsafe_c_loop(const void *ctx)
//   {
//       struct bpf_iter_num it;
//       int *v, i = zero; /* obscure initial value of i */
//
//       MY_PID_GUARD();
//
//       bpf_iter_num_new(&it, 0, 1000);
//       while ((v = bpf_iter_num_next(&it))) {
//           i++;
//       }
//       bpf_iter_num_destroy(&it);
//
//       small_arr[i] = 123; /* invalid */
//
//       return 0;
//   }
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn iter_err_unsafe_c_loop(_ctx: *mut c_void) -> i32 {
    let mut it = MaybeUninit::<bpf_iter_num>::uninit();
    let mut i: i32 = unsafe { read_volatile(addr_of!(zero)) }; /* obscure initial value of i */

    unsafe {
        bpf_iter_num_new(it.as_mut_ptr() as *mut c_void, 0, 1000);
        while !bpf_iter_num_next(it.as_mut_ptr() as *mut c_void).is_null() {
            i = i.wrapping_add(1);
        }
        bpf_iter_num_destroy(it.as_mut_ptr() as *mut c_void);

        addr_of_mut!(small_arr).cast::<i32>().wrapping_offset(i as isize).write(123); /* invalid */
    }

    0
}

// HAND: loop_cb5
//   __used
//   static int loop_cb5(int i, __u64 *ctx)
//   {
//       /* unsafe on a second iteration */
//       small_arr[*ctx] = i;
//       *ctx = 100500;
//       return 0;
//   }
// `small_arr[*ctx]` is a raw pointer store (no Rust bounds check: the
// C has none and the expected message is about the second iteration's
// out-of-bounds index).
#[no_mangle]
#[inline(never)]
extern "C" fn loop_cb5(i: i32, ctx: *mut u64) -> i32 {
    unsafe {
        /* unsafe on a second iteration */
        let idx = *ctx;
        core::ptr::addr_of_mut!(small_arr).cast::<i32>().wrapping_add(idx as usize).write(i);
        *ctx = 100500;
    }
    0
}

// bpf_printk1(fmt, args...) with 0-3 arguments is a bpf_trace_printk0()
// (helper 6) call with exactly those arguments (libbpf's ___bpf_pick_printk);
// the arity-exact thunks keep clang's argument setup (no r4/r5 = 0 for the
// missing ones) and keep LLVM from merging two calls of different arity
// into one (iter_search_loop's found / not-found branches).
#[inline(always)]
unsafe fn printk0<const N: usize>(fmt: &'static [i8; N]) {
    let f: extern "C" fn(*const c_void, u32) -> i64 = core::mem::transmute(6usize);
    f(fmt.as_ptr() as *const c_void, N as u32);
}

#[inline(always)]
unsafe fn printk1<const N: usize>(fmt: &'static [i8; N], a1: u64) {
    let f: extern "C" fn(*const c_void, u32, u64) -> i64 = core::mem::transmute(6usize);
    f(fmt.as_ptr() as *const c_void, N as u32, a1);
}

#[inline(always)]
unsafe fn printk2<const N: usize>(fmt: &'static [i8; N], a1: u64, a2: u64) {
    let f: extern "C" fn(*const c_void, u32, u64, u64) -> i64 = core::mem::transmute(6usize);
    f(fmt.as_ptr() as *const c_void, N as u32, a1, a2);
}

#[inline(always)]
unsafe fn printk3<const N: usize>(fmt: &'static [i8; N], a1: u64, a2: u64, a3: u64) {
    let f: extern "C" fn(*const c_void, u32, u64, u64, u64) -> i64 = core::mem::transmute(6usize);
    f(fmt.as_ptr() as *const c_void, N as u32, a1, a2, a3);
}

/// `bpf_for(i, start, end)` of bpf_helpers.h: bpf_iter_num_new() once, then per
/// step bpf_iter_num_next() and the termination and bounds check
/// `___t && ((i) = *___t, (i) >= (start) && (i) < (end))`; bpf_iter_num_destroy()
/// on every exit (the C's cleanup attribute), so `break` and `continue` in the
/// body behave as in the C.
macro_rules! bpf_for {
    ($i:ident, $start:expr, $end:expr, $body:block) => {{
        let mut ___it = MaybeUninit::<bpf_iter_num>::uninit();
        let ___start: i32 = $start;
        let ___end: i32 = $end;
        bpf_iter_num_new(___it.as_mut_ptr() as *mut c_void, ___start, ___end);
        loop {
            let ___t = bpf_iter_num_next(___it.as_mut_ptr() as *mut c_void) as *mut i32;
            if ___t.is_null() {
                break;
            }
            let $i: i32 = *___t;
            if !($i >= ___start && $i < ___end) {
                break;
            }
            $body
        }
        bpf_iter_num_destroy(___it.as_mut_ptr() as *mut c_void);
    }};
}

/// `bpf_repeat(N)` of bpf_helpers.h: bpf_iter_num_new(&it, 0, N), a step per
/// non-NULL bpf_iter_num_next(), bpf_iter_num_destroy() on every exit.
macro_rules! bpf_repeat {
    ($n:expr, $body:block) => {{
        let mut ___it = MaybeUninit::<bpf_iter_num>::uninit();
        bpf_iter_num_new(___it.as_mut_ptr() as *mut c_void, 0, $n);
        while !bpf_iter_num_next(___it.as_mut_ptr() as *mut c_void).is_null() $body
        bpf_iter_num_destroy(___it.as_mut_ptr() as *mut c_void);
    }};
}

// HAND: iter_err_unsafe_asm_loop
//   SEC("?raw_tp")
//   __failure __msg("unbounded memory access")
//   int iter_err_unsafe_asm_loop(const void *ctx)
//   {
//       struct bpf_iter_num it;
//
//       MY_PID_GUARD();
//
//       asm volatile (
//           "r6 = %[zero];" /* iteration counter */
//           "r1 = %[it];" /* iterator state */
//           "r2 = 0;"
//           "r3 = 1000;"
//           "r4 = 1;"
//           "call %[bpf_iter_num_new];"
//       "loop:"
//           "r1 = %[it];"
//           "call %[bpf_iter_num_next];"
//           "if r0 == 0 goto out;"
//           "r6 += 1;"
//           "goto loop;"
//       "out:"
//           "r1 = %[it];"
//           "call %[bpf_iter_num_destroy];"
//           "r1 = %[small_arr];"
//           "r2 = r6;"
//           "r2 <<= 2;"
//           "r1 += r2;"
//           "*(u32 *)(r1 + 0) = r6;" /* invalid */
//           :
//           : [it]"r"(&it),
//             [small_arr]"r"(small_arr),
//             [zero]"r"(zero),
//             __imm(bpf_iter_num_new),
//             __imm(bpf_iter_num_next),
//             __imm(bpf_iter_num_destroy)
//           : __clobber_common, "r6"
//       );
//
//       return 0;
//   }
// The C's `asm volatile` inside an ordinary function: the same block as
// `asm!` with the iterator's address, small_arr's address and the value
// of `zero` as `in(reg)` operands, the kfuncs as `sym`, r0-r5 and r6
// clobbered; the `loop:` / `out:` labels are the numeric `1:` / `2:`.
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn iter_err_unsafe_asm_loop(_ctx: *mut c_void) -> i32 {
    let mut it = MaybeUninit::<bpf_iter_num>::uninit();

    unsafe {
        core::arch::asm!(
            "r6 = {zero};", /* iteration counter */
            "r1 = {it};", /* iterator state */
            "r2 = 0;",
            "r3 = 1000;",
            "r4 = 1;",
            "call {bpf_iter_num_new};",
            "1:",
            "r1 = {it};",
            "call {bpf_iter_num_next};",
            "if r0 == 0 goto 2f;",
            "r6 += 1;",
            "goto 1b;",
            "2:",
            "r1 = {it};",
            "call {bpf_iter_num_destroy};",
            "r1 = {small_arr};",
            "r2 = r6;",
            "r2 <<= 2;",
            "r1 += r2;",
            "*(u32 *)(r1 + 0) = r6;", /* invalid */
            it = in(reg) it.as_mut_ptr(),
            small_arr = in(reg) addr_of_mut!(small_arr) as *mut i32,
            zero = in(reg) read_volatile(addr_of!(zero)),
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

// HAND: iter_while_loop
//   SEC("raw_tp")
//   __success
//   int iter_while_loop(const void *ctx)
//   {
//       struct bpf_iter_num it;
//       int *v;
//
//       MY_PID_GUARD();
//
//       bpf_iter_num_new(&it, 0, 3);
//       while ((v = bpf_iter_num_next(&it))) {
//           bpf_printk1("ITER_BASIC: E1 VAL: v=%d", *v);
//       }
//       bpf_iter_num_destroy(&it);
//
//       return 0;
//   }
#[link_section = "raw_tp"]
#[no_mangle]
extern "C" fn iter_while_loop(_ctx: *mut c_void) -> i32 {
    let mut it = MaybeUninit::<bpf_iter_num>::uninit();

    unsafe {
        bpf_iter_num_new(it.as_mut_ptr() as *mut c_void, 0, 3);
        loop {
            let v = bpf_iter_num_next(it.as_mut_ptr() as *mut c_void) as *mut i32;
            if v.is_null() {
                break;
            }
            printk1(&iter_while_loop_____fmt, *v as i64 as u64);
        }
        bpf_iter_num_destroy(it.as_mut_ptr() as *mut c_void);
    }

    0
}

// HAND: iter_while_loop_auto_cleanup
//   SEC("raw_tp")
//   __success
//   int iter_while_loop_auto_cleanup(const void *ctx)
//   {
//       __attribute__((cleanup(bpf_iter_num_destroy))) struct bpf_iter_num it;
//       int *v;
//
//       MY_PID_GUARD();
//
//       bpf_iter_num_new(&it, 0, 3);
//       while ((v = bpf_iter_num_next(&it))) {
//           bpf_printk1("ITER_BASIC: E1 VAL: v=%d", *v);
//       }
//       /* (!) no explicit bpf_iter_num_destroy() */
//
//       return 0;
//   }
// The cleanup attribute's bpf_iter_num_destroy() runs at the return: the
// explicit call below is that.
#[link_section = "raw_tp"]
#[no_mangle]
extern "C" fn iter_while_loop_auto_cleanup(_ctx: *mut c_void) -> i32 {
    let mut it = MaybeUninit::<bpf_iter_num>::uninit();

    unsafe {
        bpf_iter_num_new(it.as_mut_ptr() as *mut c_void, 0, 3);
        loop {
            let v = bpf_iter_num_next(it.as_mut_ptr() as *mut c_void) as *mut i32;
            if v.is_null() {
                break;
            }
            printk1(&iter_while_loop_auto_cleanup_____fmt, *v as i64 as u64);
        }
        /* (!) no explicit bpf_iter_num_destroy() -- the cleanup attribute's */
        bpf_iter_num_destroy(it.as_mut_ptr() as *mut c_void);
    }

    0
}

// HAND: iter_for_loop
//   SEC("raw_tp")
//   __success
//   int iter_for_loop(const void *ctx)
//   {
//       struct bpf_iter_num it;
//       int *v;
//
//       MY_PID_GUARD();
//
//       bpf_iter_num_new(&it, 5, 10);
//       for (v = bpf_iter_num_next(&it); v; v = bpf_iter_num_next(&it)) {
//           bpf_printk1("ITER_BASIC: E2 VAL: v=%d", *v);
//       }
//       bpf_iter_num_destroy(&it);
//
//       return 0;
//   }
#[link_section = "raw_tp"]
#[no_mangle]
extern "C" fn iter_for_loop(_ctx: *mut c_void) -> i32 {
    let mut it = MaybeUninit::<bpf_iter_num>::uninit();

    unsafe {
        bpf_iter_num_new(it.as_mut_ptr() as *mut c_void, 5, 10);
        let mut v = bpf_iter_num_next(it.as_mut_ptr() as *mut c_void) as *mut i32;
        while !v.is_null() {
            printk1(&iter_for_loop_____fmt, *v as i64 as u64);
            v = bpf_iter_num_next(it.as_mut_ptr() as *mut c_void) as *mut i32;
        }
        bpf_iter_num_destroy(it.as_mut_ptr() as *mut c_void);
    }

    0
}

// HAND: iter_bpf_for_each_macro
//   SEC("raw_tp")
//   __success
//   int iter_bpf_for_each_macro(const void *ctx)
//   {
//       int *v;
//
//       MY_PID_GUARD();
//
//       bpf_for_each(num, v, 5, 10) {
//           bpf_printk1("ITER_BASIC: E2 VAL: v=%d", *v);
//       }
//
//       return 0;
//   }
// bpf_for_each(num, v, 5, 10): bpf_iter_num_new(&it, 5, 10) once, a step per
// non-NULL `v = bpf_iter_num_next(&it)`, destroy at the exit.
#[link_section = "raw_tp"]
#[no_mangle]
extern "C" fn iter_bpf_for_each_macro(_ctx: *mut c_void) -> i32 {
    let mut it = MaybeUninit::<bpf_iter_num>::uninit();

    unsafe {
        bpf_iter_num_new(it.as_mut_ptr() as *mut c_void, 5, 10);
        loop {
            let v = bpf_iter_num_next(it.as_mut_ptr() as *mut c_void) as *mut i32;
            if v.is_null() {
                break;
            }
            printk1(&iter_bpf_for_each_macro_____fmt, *v as i64 as u64);
        }
        bpf_iter_num_destroy(it.as_mut_ptr() as *mut c_void);
    }

    0
}

// HAND: iter_bpf_for_macro
//   SEC("raw_tp")
//   __success
//   int iter_bpf_for_macro(const void *ctx)
//   {
//       int i;
//
//       MY_PID_GUARD();
//
//       bpf_for(i, 5, 10) {
//           bpf_printk1("ITER_BASIC: E2 VAL: v=%d", i);
//       }
//
//       return 0;
//   }
#[link_section = "raw_tp"]
#[no_mangle]
extern "C" fn iter_bpf_for_macro(_ctx: *mut c_void) -> i32 {
    unsafe {
        bpf_for!(i, 5, 10, {
            printk1(&iter_bpf_for_macro_____fmt, i as i64 as u64);
        });
    }

    0
}

// HAND: iter_pragma_unroll_loop
//   SEC("raw_tp")
//   __success
//   int iter_pragma_unroll_loop(const void *ctx)
//   {
//       struct bpf_iter_num it;
//       int *v, i;
//
//       MY_PID_GUARD();
//
//       bpf_iter_num_new(&it, 0, 2);
//       __pragma_loop_no_unroll
//       for (i = 0; i < 3; i++) {
//           v = bpf_iter_num_next(&it);
//           bpf_printk2("ITER_BASIC: E3 VAL: i=%d v=%d", i, v ? *v : -1);
//       }
//       bpf_iter_num_destroy(&it);
//
//       return 0;
//   }
// `__pragma_loop_no_unroll` is clang's `#pragma clang loop unroll(disable)`:
// the trip count goes through an 8-byte black_box (a stack spill LLVM does
// not see through, so the loop stays a loop as in the C object, while the
// verifier still reads the spilled constant 3 back precisely).
#[link_section = "raw_tp"]
#[no_mangle]
extern "C" fn iter_pragma_unroll_loop(_ctx: *mut c_void) -> i32 {
    let mut it = MaybeUninit::<bpf_iter_num>::uninit();

    unsafe {
        bpf_iter_num_new(it.as_mut_ptr() as *mut c_void, 0, 2);
        let n: i64 = black_box(3); /* __pragma_loop_no_unroll */
        let mut i: i32 = 0;
        while (i as i64) < n {
            let v = bpf_iter_num_next(it.as_mut_ptr() as *mut c_void) as *mut i32;
            printk2(&iter_pragma_unroll_loop_____fmt, i as i64 as u64, (if v.is_null() { -1 } else { *v }) as i64 as u64);
            i += 1;
        }
        bpf_iter_num_destroy(it.as_mut_ptr() as *mut c_void);
    }

    0
}

// HAND: iter_manual_unroll_loop
//   SEC("raw_tp")
//   __success
//   int iter_manual_unroll_loop(const void *ctx)
//   {
//       struct bpf_iter_num it;
//       int *v;
//
//       MY_PID_GUARD();
//
//       bpf_iter_num_new(&it, 100, 200);
//       v = bpf_iter_num_next(&it);
//       bpf_printk1("ITER_BASIC: E4 VAL: v=%d", v ? *v : -1);
//       v = bpf_iter_num_next(&it);
//       bpf_printk1("ITER_BASIC: E4 VAL: v=%d", v ? *v : -1);
//       v = bpf_iter_num_next(&it);
//       bpf_printk1("ITER_BASIC: E4 VAL: v=%d", v ? *v : -1);
//       v = bpf_iter_num_next(&it);
//       bpf_printk1("ITER_BASIC: E4 VAL: v=%d\n", v ? *v : -1);
//       bpf_iter_num_destroy(&it);
//
//       return 0;
//   }
#[link_section = "raw_tp"]
#[no_mangle]
extern "C" fn iter_manual_unroll_loop(_ctx: *mut c_void) -> i32 {
    let mut it = MaybeUninit::<bpf_iter_num>::uninit();

    unsafe {
        bpf_iter_num_new(it.as_mut_ptr() as *mut c_void, 100, 200);
        let v = bpf_iter_num_next(it.as_mut_ptr() as *mut c_void) as *mut i32;
        printk1(&iter_manual_unroll_loop_____fmt, (if v.is_null() { -1 } else { *v }) as i64 as u64);
        let v = bpf_iter_num_next(it.as_mut_ptr() as *mut c_void) as *mut i32;
        printk1(&iter_manual_unroll_loop_____fmt_1, (if v.is_null() { -1 } else { *v }) as i64 as u64);
        let v = bpf_iter_num_next(it.as_mut_ptr() as *mut c_void) as *mut i32;
        printk1(&iter_manual_unroll_loop_____fmt_2, (if v.is_null() { -1 } else { *v }) as i64 as u64);
        let v = bpf_iter_num_next(it.as_mut_ptr() as *mut c_void) as *mut i32;
        printk1(&iter_manual_unroll_loop_____fmt_3, (if v.is_null() { -1 } else { *v }) as i64 as u64);
        bpf_iter_num_destroy(it.as_mut_ptr() as *mut c_void);
    }

    0
}

// HAND: iter_multiple_sequential_loops
//   SEC("raw_tp")
//   __success
//   int iter_multiple_sequential_loops(const void *ctx)
//   {
//       struct bpf_iter_num it;
//       int *v, i;
//
//       MY_PID_GUARD();
//
//       bpf_iter_num_new(&it, 0, 3);
//       while ((v = bpf_iter_num_next(&it))) {
//           bpf_printk1("ITER_BASIC: E1 VAL: v=%d", *v);
//       }
//       bpf_iter_num_destroy(&it);
//
//       bpf_iter_num_new(&it, 5, 10);
//       for (v = bpf_iter_num_next(&it); v; v = bpf_iter_num_next(&it)) {
//           bpf_printk1("ITER_BASIC: E2 VAL: v=%d", *v);
//       }
//       bpf_iter_num_destroy(&it);
//
//       bpf_iter_num_new(&it, 0, 2);
//       __pragma_loop_no_unroll
//       for (i = 0; i < 3; i++) {
//           v = bpf_iter_num_next(&it);
//           bpf_printk2("ITER_BASIC: E3 VAL: i=%d v=%d", i, v ? *v : -1);
//       }
//       bpf_iter_num_destroy(&it);
//
//       bpf_iter_num_new(&it, 100, 200);
//       v = bpf_iter_num_next(&it);
//       bpf_printk1("ITER_BASIC: E4 VAL: v=%d", v ? *v : -1);
//       v = bpf_iter_num_next(&it);
//       bpf_printk1("ITER_BASIC: E4 VAL: v=%d", v ? *v : -1);
//       v = bpf_iter_num_next(&it);
//       bpf_printk1("ITER_BASIC: E4 VAL: v=%d", v ? *v : -1);
//       v = bpf_iter_num_next(&it);
//       bpf_printk1("ITER_BASIC: E4 VAL: v=%d\n", v ? *v : -1);
//       bpf_iter_num_destroy(&it);
//
//       return 0;
//   }
#[link_section = "raw_tp"]
#[no_mangle]
extern "C" fn iter_multiple_sequential_loops(_ctx: *mut c_void) -> i32 {
    let mut it = MaybeUninit::<bpf_iter_num>::uninit();
    let p = it.as_mut_ptr() as *mut c_void;

    unsafe {
        bpf_iter_num_new(p, 0, 3);
        loop {
            let v = bpf_iter_num_next(p) as *mut i32;
            if v.is_null() {
                break;
            }
            printk1(&iter_multiple_sequential_loops_____fmt, *v as i64 as u64);
        }
        bpf_iter_num_destroy(p);

        bpf_iter_num_new(p, 5, 10);
        let mut v = bpf_iter_num_next(p) as *mut i32;
        while !v.is_null() {
            printk1(&iter_multiple_sequential_loops_____fmt_4, *v as i64 as u64);
            v = bpf_iter_num_next(p) as *mut i32;
        }
        bpf_iter_num_destroy(p);

        bpf_iter_num_new(p, 0, 2);
        let n: i64 = black_box(3); /* __pragma_loop_no_unroll */
        let mut i: i32 = 0;
        while (i as i64) < n {
            let v = bpf_iter_num_next(p) as *mut i32;
            printk2(&iter_multiple_sequential_loops_____fmt_5, i as i64 as u64, (if v.is_null() { -1 } else { *v }) as i64 as u64);
            i += 1;
        }
        bpf_iter_num_destroy(p);

        bpf_iter_num_new(p, 100, 200);
        let v = bpf_iter_num_next(p) as *mut i32;
        printk1(&iter_multiple_sequential_loops_____fmt_6, (if v.is_null() { -1 } else { *v }) as i64 as u64);
        let v = bpf_iter_num_next(p) as *mut i32;
        printk1(&iter_multiple_sequential_loops_____fmt_7, (if v.is_null() { -1 } else { *v }) as i64 as u64);
        let v = bpf_iter_num_next(p) as *mut i32;
        printk1(&iter_multiple_sequential_loops_____fmt_8, (if v.is_null() { -1 } else { *v }) as i64 as u64);
        let v = bpf_iter_num_next(p) as *mut i32;
        printk1(&iter_multiple_sequential_loops_____fmt_9, (if v.is_null() { -1 } else { *v }) as i64 as u64);
        bpf_iter_num_destroy(p);
    }

    0
}

// HAND: iter_limit_cond_break_loop
//   SEC("raw_tp")
//   __success
//   int iter_limit_cond_break_loop(const void *ctx)
//   {
//       struct bpf_iter_num it;
//       int *v, i = 0, sum = 0;
//
//       MY_PID_GUARD();
//
//       bpf_iter_num_new(&it, 0, 10);
//       while ((v = bpf_iter_num_next(&it))) {
//           bpf_printk2("ITER_SIMPLE: i=%d v=%d", i, *v);
//           sum += *v;
//
//           i++;
//           if (i > 3)
//               break;
//       }
//       bpf_iter_num_destroy(&it);
//
//       bpf_printk1("ITER_SIMPLE: sum=%d\n", sum);
//
//       return 0;
//   }
#[link_section = "raw_tp"]
#[no_mangle]
extern "C" fn iter_limit_cond_break_loop(_ctx: *mut c_void) -> i32 {
    let mut it = MaybeUninit::<bpf_iter_num>::uninit();
    let mut i: i32 = 0;
    let mut sum: i32 = 0;

    unsafe {
        bpf_iter_num_new(it.as_mut_ptr() as *mut c_void, 0, 10);
        loop {
            let v = bpf_iter_num_next(it.as_mut_ptr() as *mut c_void) as *mut i32;
            if v.is_null() {
                break;
            }
            printk2(&iter_limit_cond_break_loop_____fmt, i as i64 as u64, *v as i64 as u64);
            sum = sum.wrapping_add(*v);

            i += 1;
            if i > 3 {
                break;
            }
        }
        bpf_iter_num_destroy(it.as_mut_ptr() as *mut c_void);

        printk1(&iter_limit_cond_break_loop_____fmt_10, sum as i64 as u64);
    }

    0
}

// HAND: iter_obfuscate_counter
//   SEC("raw_tp")
//   __success
//   int iter_obfuscate_counter(const void *ctx)
//   {
//       struct bpf_iter_num it;
//       int *v, sum = 0;
//       /* Make i's initial value unknowable for verifier to prevent it from
//        * pruning if/else branch inside the loop body and marking i as precise.
//        */
//       int i = zero;
//
//       MY_PID_GUARD();
//
//       bpf_iter_num_new(&it, 0, 10);
//       while ((v = bpf_iter_num_next(&it))) {
//           int x;
//
//           i += 1;
//
//           /* If we initialized i as `int i = 0;` above, verifier would
//            * track that i becomes 1 on first iteration after increment
//            * above, and here verifier would eagerly prune else branch
//            * and mark i as precise, ruining open-coded iterator logic
//            * completely, as each next iteration would have a different
//            * *precise* value of i, and thus there would be no
//            * convergence of state. This would result in reaching maximum
//            * instruction limit, no matter what the limit is.
//            */
//           if (i == 1)
//               x = 123;
//           else
//               x = i * 3 + 1;
//
//           bpf_printk3("ITER_OBFUSCATE_COUNTER: i=%d v=%d x=%d", i, *v, x);
//
//           sum += x;
//       }
//       bpf_iter_num_destroy(&it);
//
//       bpf_printk1("ITER_OBFUSCATE_COUNTER: sum=%d\n", sum);
//
//       return 0;
//   }
#[link_section = "raw_tp"]
#[no_mangle]
extern "C" fn iter_obfuscate_counter(_ctx: *mut c_void) -> i32 {
    let mut it = MaybeUninit::<bpf_iter_num>::uninit();
    let mut sum: i32 = 0;
    /* Make i's initial value unknowable for verifier to prevent it from
     * pruning if/else branch inside the loop body and marking i as precise.
     */
    let mut i: i32 = unsafe { read_volatile(addr_of!(zero)) };

    unsafe {
        bpf_iter_num_new(it.as_mut_ptr() as *mut c_void, 0, 10);
        loop {
            let v = bpf_iter_num_next(it.as_mut_ptr() as *mut c_void) as *mut i32;
            if v.is_null() {
                break;
            }
            let x: i32;

            i = i.wrapping_add(1);

            /* see the C comment: `int i = 0` would make i precise and the
             * loop state never converge */
            if i == 1 {
                x = 123;
            } else {
                x = i.wrapping_mul(3).wrapping_add(1);
            }

            printk3(&iter_obfuscate_counter_____fmt, i as i64 as u64, *v as i64 as u64, x as i64 as u64);

            sum = sum.wrapping_add(x);
        }
        bpf_iter_num_destroy(it.as_mut_ptr() as *mut c_void);

        printk1(&iter_obfuscate_counter_____fmt_11, sum as i64 as u64);
    }

    0
}

// HAND: iter_search_loop
//   SEC("raw_tp")
//   __success
//   int iter_search_loop(const void *ctx)
//   {
//       struct bpf_iter_num it;
//       int *v, *elem = NULL;
//       bool found = false;
//
//       MY_PID_GUARD();
//
//       bpf_iter_num_new(&it, 0, 10);
//
//       while ((v = bpf_iter_num_next(&it))) {
//           bpf_printk1("ITER_SEARCH_LOOP: v=%d", *v);
//
//           if (*v == 2) {
//               found = true;
//               elem = v;
//               barrier_var(elem);
//           }
//       }
//
//       /* should fail to verify if bpf_iter_num_destroy() is here */
//
//       if (found)
//           /* here found element will be wrong, we should have copied
//            * value to a variable, but here we want to make sure we can
//            * access memory after the loop anyways
//            */
//           bpf_printk1("ITER_SEARCH_LOOP: FOUND IT = %d!\n", *elem);
//       else
//           bpf_printk0("ITER_SEARCH_LOOP: NOT FOUND IT!\n");
//
//       bpf_iter_num_destroy(&it);
//
//       return 0;
//   }
// barrier_var(elem) is helpers::sink (the same `asm volatile("" : "+r")`).
#[link_section = "raw_tp"]
#[no_mangle]
extern "C" fn iter_search_loop(_ctx: *mut c_void) -> i32 {
    let mut it = MaybeUninit::<bpf_iter_num>::uninit();
    let mut elem: *mut i32 = core::ptr::null_mut();
    let mut found = false;

    unsafe {
        bpf_iter_num_new(it.as_mut_ptr() as *mut c_void, 0, 10);

        loop {
            let v = bpf_iter_num_next(it.as_mut_ptr() as *mut c_void) as *mut i32;
            if v.is_null() {
                break;
            }
            printk1(&iter_search_loop_____fmt, *v as i64 as u64);

            if *v == 2 {
                found = true;
                elem = v;
                sink(&mut elem);
            }
        }

        /* should fail to verify if bpf_iter_num_destroy() is here */

        if found {
            /* here found element will be wrong, we should have copied
             * value to a variable, but here we want to make sure we can
             * access memory after the loop anyways
             */
            printk1(&iter_search_loop_____fmt_12, *elem as i64 as u64);
        } else {
            printk0(&iter_search_loop_____fmt_13);
        }

        bpf_iter_num_destroy(it.as_mut_ptr() as *mut c_void);
    }

    0
}

// HAND: iter_array_fill
//   SEC("raw_tp")
//   __success
//   int iter_array_fill(const void *ctx)
//   {
//       int sum, i;
//
//       MY_PID_GUARD();
//
//       bpf_for(i, 0, ARRAY_SIZE(arr)) {
//           arr[i] = i * 2;
//       }
//
//       sum = 0;
//       bpf_for(i, 0, ARRAY_SIZE(arr)) {
//           sum += arr[i];
//       }
//
//       bpf_printk2("ITER_ARRAY_FILL: sum=%d (should be %d)\n", sum, 255 * 256);
//
//       return 0;
//   }
#[link_section = "raw_tp"]
#[no_mangle]
extern "C" fn iter_array_fill(_ctx: *mut c_void) -> i32 {
    let mut sum: i32;

    unsafe {
        let arr_p = addr_of_mut!(arr).cast::<i32>();
        bpf_for!(i, 0, 256, {
            arr_p.wrapping_offset(i as isize).write(i.wrapping_mul(2));
        });

        sum = 0;
        bpf_for!(i, 0, 256, {
            sum = sum.wrapping_add(arr_p.wrapping_offset(i as isize).read());
        });

        printk2(&iter_array_fill_____fmt, sum as i64 as u64, (255 * 256) as u64);
    }

    0
}
