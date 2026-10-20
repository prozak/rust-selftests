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

use bpf_rs_core::helpers::{bpf_get_current_comm, bpf_get_prandom_u32, bpf_map_lookup_elem, bpf_probe_read_kernel, sink};
use core::hint::black_box;
use core::mem::MaybeUninit;
use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};

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

// The %s argument of two bpf_printk()s below: the C's "\n" / "" literals.
#[link_section = ".rodata.str"]
static NEWLINE_STR: [i8; 2] = [10, 0];
#[link_section = ".rodata.str"]
static EMPTY_STR: [i8; 1] = [0];

// HAND: iter_nested_iters
//   static int arr2d[4][5];
//   static int arr2d_row_sums[4];
//   static int arr2d_col_sums[5];
//
//   SEC("raw_tp")
//   __success
//   int iter_nested_iters(const void *ctx)
//   {
//       int sum, row, col;
//
//       MY_PID_GUARD();
//
//       bpf_for(row, 0, ARRAY_SIZE(arr2d)) {
//           bpf_for( col, 0, ARRAY_SIZE(arr2d[0])) {
//               arr2d[row][col] = row * col;
//           }
//       }
//
//       /* zero-initialize sums */
//       sum = 0;
//       bpf_for(row, 0, ARRAY_SIZE(arr2d)) {
//           arr2d_row_sums[row] = 0;
//       }
//       bpf_for(col, 0, ARRAY_SIZE(arr2d[0])) {
//           arr2d_col_sums[col] = 0;
//       }
//
//       /* calculate sums */
//       bpf_for(row, 0, ARRAY_SIZE(arr2d)) {
//           bpf_for(col, 0, ARRAY_SIZE(arr2d[0])) {
//               sum += arr2d[row][col];
//               arr2d_row_sums[row] += arr2d[row][col];
//               arr2d_col_sums[col] += arr2d[row][col];
//           }
//       }
//
//       bpf_printk("ITER_NESTED_ITERS: total sum=%d", sum);
//       bpf_for(row, 0, ARRAY_SIZE(arr2d)) {
//           bpf_printk("ITER_NESTED_ITERS: row #%d sum=%d", row, arr2d_row_sums[row]);
//       }
//       bpf_for(col, 0, ARRAY_SIZE(arr2d[0])) {
//           bpf_printk("ITER_NESTED_ITERS: col #%d sum=%d%s",
//                  col, arr2d_col_sums[col],
//                  col == ARRAY_SIZE(arr2d[0]) - 1 ? "\n" : "");
//       }
//
//       return 0;
//   }
// arr2d[row][col] is the row-major element row * 5 + col of the static.
#[link_section = "raw_tp"]
#[no_mangle]
extern "C" fn iter_nested_iters(_ctx: *mut c_void) -> i32 {
    let mut sum: i32;

    unsafe {
        let a2d = addr_of_mut!(arr2d).cast::<i32>();
        let rows = addr_of_mut!(arr2d_row_sums).cast::<i32>();
        let cols = addr_of_mut!(arr2d_col_sums).cast::<i32>();

        bpf_for!(row, 0, 4, {
            bpf_for!(col, 0, 5, {
                a2d.wrapping_offset((row * 5 + col) as isize).write(row.wrapping_mul(col));
            });
        });

        /* zero-initialize sums */
        sum = 0;
        bpf_for!(row, 0, 4, {
            rows.wrapping_offset(row as isize).write(0);
        });
        bpf_for!(col, 0, 5, {
            cols.wrapping_offset(col as isize).write(0);
        });

        /* calculate sums */
        bpf_for!(row, 0, 4, {
            bpf_for!(col, 0, 5, {
                let v = a2d.wrapping_offset((row * 5 + col) as isize).read();
                sum = sum.wrapping_add(v);
                let rp = rows.wrapping_offset(row as isize);
                rp.write(rp.read().wrapping_add(v));
                let cp = cols.wrapping_offset(col as isize);
                cp.write(cp.read().wrapping_add(v));
            });
        });

        printk1(&iter_nested_iters_____fmt, sum as i64 as u64);
        bpf_for!(row, 0, 4, {
            printk2(
                &iter_nested_iters_____fmt_14,
                row as i64 as u64,
                rows.wrapping_offset(row as isize).read() as i64 as u64,
            );
        });
        bpf_for!(col, 0, 5, {
            printk3(
                &iter_nested_iters_____fmt_15,
                col as i64 as u64,
                cols.wrapping_offset(col as isize).read() as i64 as u64,
                (if col == 5 - 1 { NEWLINE_STR.as_ptr() } else { EMPTY_STR.as_ptr() }) as u64,
            );
        });
    }

    0
}

// HAND: iter_nested_deeply_iters
//   SEC("raw_tp")
//   __success
//   int iter_nested_deeply_iters(const void *ctx)
//   {
//       int sum = 0;
//
//       MY_PID_GUARD();
//
//       bpf_repeat(10) {
//           bpf_repeat(10) {
//               bpf_repeat(10) {
//                   bpf_repeat(10) {
//                       bpf_repeat(10) {
//                           sum += 1;
//                       }
//                   }
//               }
//           }
//           /* validate that we can break from inside bpf_repeat() */
//           break;
//       }
//
//       return sum;
//   }
#[link_section = "raw_tp"]
#[no_mangle]
extern "C" fn iter_nested_deeply_iters(_ctx: *mut c_void) -> i32 {
    let mut sum: i32 = 0;

    unsafe {
        bpf_repeat!(10, {
            bpf_repeat!(10, {
                bpf_repeat!(10, {
                    bpf_repeat!(10, {
                        bpf_repeat!(10, {
                            sum = sum.wrapping_add(1);
                        });
                    });
                });
            });
            /* validate that we can break from inside bpf_repeat() */
            break;
        });
    }

    sum
}

// HAND: fill_inner_dimension
//   static __noinline void fill_inner_dimension(int row)
//   {
//       int col;
//
//       bpf_for(col, 0, ARRAY_SIZE(arr2d[0])) {
//           arr2d[row][col] = row * col;
//       }
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn fill_inner_dimension(row: i32) {
    unsafe {
        let a2d = addr_of_mut!(arr2d).cast::<i32>();

        bpf_for!(col, 0, 5, {
            a2d.wrapping_offset((row * 5 + col) as isize).write(row.wrapping_mul(col));
        });
    }
}

// HAND: sum_inner_dimension
//   static __noinline int sum_inner_dimension(int row)
//   {
//       int sum = 0, col;
//
//       bpf_for(col, 0, ARRAY_SIZE(arr2d[0])) {
//           sum += arr2d[row][col];
//           arr2d_row_sums[row] += arr2d[row][col];
//           arr2d_col_sums[col] += arr2d[row][col];
//       }
//
//       return sum;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn sum_inner_dimension(row: i32) -> i32 {
    let mut sum: i32 = 0;

    unsafe {
        let a2d = addr_of_mut!(arr2d).cast::<i32>();
        let rows = addr_of_mut!(arr2d_row_sums).cast::<i32>();
        let cols = addr_of_mut!(arr2d_col_sums).cast::<i32>();

        bpf_for!(col, 0, 5, {
            let v = a2d.wrapping_offset((row * 5 + col) as isize).read();
            sum = sum.wrapping_add(v);
            let rp = rows.wrapping_offset(row as isize);
            rp.write(rp.read().wrapping_add(v));
            let cp = cols.wrapping_offset(col as isize);
            cp.write(cp.read().wrapping_add(v));
        });
    }

    sum
}

// HAND: iter_subprog_iters
//   SEC("raw_tp")
//   __success
//   int iter_subprog_iters(const void *ctx)
//   {
//       int sum, row, col;
//
//       MY_PID_GUARD();
//
//       bpf_for(row, 0, ARRAY_SIZE(arr2d)) {
//           fill_inner_dimension(row);
//       }
//
//       /* zero-initialize sums */
//       sum = 0;
//       bpf_for(row, 0, ARRAY_SIZE(arr2d)) {
//           arr2d_row_sums[row] = 0;
//       }
//       bpf_for(col, 0, ARRAY_SIZE(arr2d[0])) {
//           arr2d_col_sums[col] = 0;
//       }
//
//       /* calculate sums */
//       bpf_for(row, 0, ARRAY_SIZE(arr2d)) {
//           sum += sum_inner_dimension(row);
//       }
//
//       bpf_printk("ITER_SUBPROG_ITERS: total sum=%d", sum);
//       bpf_for(row, 0, ARRAY_SIZE(arr2d)) {
//           bpf_printk("ITER_SUBPROG_ITERS: row #%d sum=%d",
//                  row, arr2d_row_sums[row]);
//       }
//       bpf_for(col, 0, ARRAY_SIZE(arr2d[0])) {
//           bpf_printk("ITER_SUBPROG_ITERS: col #%d sum=%d%s",
//                  col, arr2d_col_sums[col],
//                  col == ARRAY_SIZE(arr2d[0]) - 1 ? "\n" : "");
//       }
//
//       return 0;
//   }
#[link_section = "raw_tp"]
#[no_mangle]
extern "C" fn iter_subprog_iters(_ctx: *mut c_void) -> i32 {
    let mut sum: i32;

    unsafe {
        let rows = addr_of_mut!(arr2d_row_sums).cast::<i32>();
        let cols = addr_of_mut!(arr2d_col_sums).cast::<i32>();

        bpf_for!(row, 0, 4, {
            fill_inner_dimension(row);
        });

        /* zero-initialize sums */
        sum = 0;
        bpf_for!(row, 0, 4, {
            rows.wrapping_offset(row as isize).write(0);
        });
        bpf_for!(col, 0, 5, {
            cols.wrapping_offset(col as isize).write(0);
        });

        /* calculate sums */
        bpf_for!(row, 0, 4, {
            sum = sum.wrapping_add(sum_inner_dimension(row));
        });

        printk1(&iter_subprog_iters_____fmt, sum as i64 as u64);
        bpf_for!(row, 0, 4, {
            printk2(
                &iter_subprog_iters_____fmt_17,
                row as i64 as u64,
                rows.wrapping_offset(row as isize).read() as i64 as u64,
            );
        });
        bpf_for!(col, 0, 5, {
            printk3(
                &iter_subprog_iters_____fmt_18,
                col as i64 as u64,
                cols.wrapping_offset(col as isize).read() as i64 as u64,
                (if col == 5 - 1 { NEWLINE_STR.as_ptr() } else { EMPTY_STR.as_ptr() }) as u64,
            );
        });
    }

    0
}

// The map_val stores of the four hash_map programs are write_volatile: the
// expected messages are about the pointer's state at the store, and a plain
// store through a pointer LLVM can see is NULL on a path is one it may fold
// (the path would be undefined behaviour); the C compiles the store as is.

// HAND: iter_err_too_permissive1
//   SEC("?raw_tp")
//   __failure __msg("invalid mem access 'scalar'")
//   int iter_err_too_permissive1(const void *ctx)
//   {
//       int *map_val = NULL;
//       int key = 0;
//
//       MY_PID_GUARD();
//
//       map_val = bpf_map_lookup_elem(&hash_map, &key);
//       if (!map_val)
//           return 0;
//
//       bpf_repeat(1000000) {
//           map_val = NULL;
//       }
//
//       *map_val = 123;
//
//       return 0;
//   }
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn iter_err_too_permissive1(_ctx: *mut c_void) -> i32 {
    let mut map_val: *mut i32;
    let key: i32 = 0;

    unsafe {
        map_val = bpf_map_lookup_elem(&hash_map, &key) as *mut i32;
        if map_val.is_null() {
            return 0;
        }

        bpf_repeat!(1000000, {
            map_val = core::ptr::null_mut();
        });

        write_volatile(map_val, 123);
    }

    0
}

// HAND: iter_err_too_permissive2
//   SEC("?raw_tp")
//   __failure __msg("invalid mem access 'map_value_or_null'")
//   int iter_err_too_permissive2(const void *ctx)
//   {
//       int *map_val = NULL;
//       int key = 0;
//
//       MY_PID_GUARD();
//
//       map_val = bpf_map_lookup_elem(&hash_map, &key);
//       if (!map_val)
//           return 0;
//
//       bpf_repeat(1000000) {
//           map_val = bpf_map_lookup_elem(&hash_map, &key);
//       }
//
//       *map_val = 123;
//
//       return 0;
//   }
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn iter_err_too_permissive2(_ctx: *mut c_void) -> i32 {
    let mut map_val: *mut i32;
    let key: i32 = 0;

    unsafe {
        map_val = bpf_map_lookup_elem(&hash_map, &key) as *mut i32;
        if map_val.is_null() {
            return 0;
        }

        bpf_repeat!(1000000, {
            map_val = bpf_map_lookup_elem(&hash_map, &key) as *mut i32;
        });

        write_volatile(map_val, 123);
    }

    0
}

// HAND: iter_err_too_permissive3
//   SEC("?raw_tp")
//   __failure __msg("invalid mem access 'map_value_or_null'")
//   int iter_err_too_permissive3(const void *ctx)
//   {
//       int *map_val = NULL;
//       int key = 0;
//       bool found = false;
//
//       MY_PID_GUARD();
//
//       bpf_repeat(1000000) {
//           map_val = bpf_map_lookup_elem(&hash_map, &key);
//           found = true;
//       }
//
//       if (found)
//           *map_val = 123;
//
//       return 0;
//   }
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn iter_err_too_permissive3(_ctx: *mut c_void) -> i32 {
    let mut map_val: *mut i32 = core::ptr::null_mut();
    let key: i32 = 0;
    let mut found = false;

    unsafe {
        bpf_repeat!(1000000, {
            map_val = bpf_map_lookup_elem(&hash_map, &key) as *mut i32;
            found = true;
        });

        if found {
            write_volatile(map_val, 123);
        }
    }

    0
}

// HAND: iter_tricky_but_fine
//   SEC("raw_tp")
//   __success
//   int iter_tricky_but_fine(const void *ctx)
//   {
//       int *map_val = NULL;
//       int key = 0;
//       bool found = false;
//
//       MY_PID_GUARD();
//
//       bpf_repeat(1000000) {
//           map_val = bpf_map_lookup_elem(&hash_map, &key);
//           if (map_val) {
//               found = true;
//               break;
//           }
//       }
//
//       if (found)
//           *map_val = 123;
//
//       return 0;
//   }
#[link_section = "raw_tp"]
#[no_mangle]
extern "C" fn iter_tricky_but_fine(_ctx: *mut c_void) -> i32 {
    let mut map_val: *mut i32 = core::ptr::null_mut();
    let key: i32 = 0;
    let mut found = false;

    unsafe {
        bpf_repeat!(1000000, {
            map_val = bpf_map_lookup_elem(&hash_map, &key) as *mut i32;
            if !map_val.is_null() {
                found = true;
                break;
            }
        });

        if found {
            write_volatile(map_val, 123);
        }
    }

    0
}

// HAND: iter_stack_array_loop
//   #define __bpf_memzero(p, sz) bpf_probe_read_kernel((p), (sz), 0)
//
//   SEC("raw_tp")
//   __success
//   int iter_stack_array_loop(const void *ctx)
//   {
//       long arr1[16], arr2[16], sum = 0;
//       int i;
//
//       MY_PID_GUARD();
//
//       /* zero-init arr1 and arr2 in such a way that verifier doesn't know
//        * it's all zeros; if we don't do that, we'll make BPF verifier track
//        * all combination of zero/non-zero stack slots for arr1/arr2, which
//        * will lead to O(2^(ARRAY_SIZE(arr1)+ARRAY_SIZE(arr2))) different
//        * states
//        */
//       __bpf_memzero(arr1, sizeof(arr1));
//       __bpf_memzero(arr2, sizeof(arr1));
//
//       /* validate that we can break and continue when using bpf_for() */
//       bpf_for(i, 0, ARRAY_SIZE(arr1)) {
//           if (i & 1) {
//               arr1[i] = i;
//               continue;
//           } else {
//               arr2[i] = i;
//               break;
//           }
//       }
//
//       bpf_for(i, 0, ARRAY_SIZE(arr1)) {
//           sum += arr1[i] + arr2[i];
//       }
//
//       return sum;
//   }
#[link_section = "raw_tp"]
#[no_mangle]
extern "C" fn iter_stack_array_loop(_ctx: *mut c_void) -> i32 {
    let mut arr1 = MaybeUninit::<[i64; 16]>::uninit();
    let mut arr2 = MaybeUninit::<[i64; 16]>::uninit();
    let mut sum: i64 = 0;

    unsafe {
        /* zero-init arr1 and arr2 in such a way that verifier doesn't know
         * it's all zeros (see the C comment): bpf_probe_read_kernel() from
         * address 0 fails and zero-fills the destination
         */
        bpf_probe_read_kernel(&mut arr1, 128, core::ptr::null());
        bpf_probe_read_kernel(&mut arr2, 128, core::ptr::null());

        let p1 = arr1.as_mut_ptr().cast::<i64>();
        let p2 = arr2.as_mut_ptr().cast::<i64>();

        /* validate that we can break and continue when using bpf_for() */
        bpf_for!(i, 0, 16, {
            if i & 1 != 0 {
                p1.wrapping_offset(i as isize).write(i as i64);
                continue;
            } else {
                p2.wrapping_offset(i as isize).write(i as i64);
                break;
            }
        });

        bpf_for!(i, 0, 16, {
            sum = sum.wrapping_add(
                p1.wrapping_offset(i as isize).read().wrapping_add(p2.wrapping_offset(i as isize).read()),
            );
        });
    }

    sum as i32
}

// HAND: fill
//   static __noinline void fill(struct bpf_iter_num *it, int *arr, __u32 n, int mul)
//   {
//       int *t, i;
//
//       while ((t = bpf_iter_num_next(it))) {
//           i = *t;
//           if (i >= n)
//               break;
//           arr[i] =  i * mul;
//       }
//   }
// `i >= n` compares int against __u32: unsigned, as the C's usual arithmetic
// conversions do. The `arr` parameter is `a` here: a Rust parameter cannot
// shadow the `arr` static (E0530); the BTF keeps the C's parameter name
// only through the debug info, so the name differs.
#[no_mangle]
#[inline(never)]
extern "C" fn fill(it: *mut bpf_iter_num, a: *mut i32, n: u32, mul: i32) {
    unsafe {
        loop {
            let t = bpf_iter_num_next(it as *mut c_void) as *mut i32;
            if t.is_null() {
                break;
            }
            let i = *t;
            if (i as u32) >= n {
                break;
            }
            a.wrapping_offset(i as isize).write(i.wrapping_mul(mul));
        }
    }
}

// HAND: sum
//   static __noinline int sum(struct bpf_iter_num *it, int *arr, __u32 n)
//   {
//       int *t, i, sum = 0;
//
//       while ((t = bpf_iter_num_next(it))) {
//           i = *t;
//           if ((__u32)i >= n)
//               break;
//           sum += arr[i];
//       }
//
//       return sum;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn sum(it: *mut bpf_iter_num, a: *mut i32, n: u32) -> i32 {
    let mut sum: i32 = 0;

    unsafe {
        loop {
            let t = bpf_iter_num_next(it as *mut c_void) as *mut i32;
            if t.is_null() {
                break;
            }
            let i = *t;
            if (i as u32) >= n {
                break;
            }
            sum = sum.wrapping_add(a.wrapping_offset(i as isize).read());
        }
    }

    sum
}

// HAND: iter_pass_iter_ptr_to_subprog
//   SEC("raw_tp")
//   __success
//   int iter_pass_iter_ptr_to_subprog(const void *ctx)
//   {
//       int arr1[16], arr2[32];
//       struct bpf_iter_num it;
//       int n, sum1, sum2;
//
//       MY_PID_GUARD();
//
//       /* fill arr1 */
//       n = ARRAY_SIZE(arr1);
//       bpf_iter_num_new(&it, 0, n);
//       fill(&it, arr1, n, 2);
//       bpf_iter_num_destroy(&it);
//
//       /* fill arr2 */
//       n = ARRAY_SIZE(arr2);
//       bpf_iter_num_new(&it, 0, n);
//       fill(&it, arr2, n, 10);
//       bpf_iter_num_destroy(&it);
//
//       /* sum arr1 */
//       n = ARRAY_SIZE(arr1);
//       bpf_iter_num_new(&it, 0, n);
//       sum1 = sum(&it, arr1, n);
//       bpf_iter_num_destroy(&it);
//
//       /* sum arr2 */
//       n = ARRAY_SIZE(arr2);
//       bpf_iter_num_new(&it, 0, n);
//       sum2 = sum(&it, arr2, n);
//       bpf_iter_num_destroy(&it);
//
//       bpf_printk("sum1=%d, sum2=%d", sum1, sum2);
//
//       return 0;
//   }
#[link_section = "raw_tp"]
#[no_mangle]
extern "C" fn iter_pass_iter_ptr_to_subprog(_ctx: *mut c_void) -> i32 {
    let mut arr1 = MaybeUninit::<[i32; 16]>::uninit();
    let mut arr2 = MaybeUninit::<[i32; 32]>::uninit();
    let mut it = MaybeUninit::<bpf_iter_num>::uninit();
    let sum1: i32;
    let sum2: i32;

    unsafe {
        let p = it.as_mut_ptr();
        let a1 = arr1.as_mut_ptr().cast::<i32>();
        let a2 = arr2.as_mut_ptr().cast::<i32>();

        /* fill arr1 */
        let n = 16;
        bpf_iter_num_new(p as *mut c_void, 0, n);
        fill(p, a1, n as u32, 2);
        bpf_iter_num_destroy(p as *mut c_void);

        /* fill arr2 */
        let n = 32;
        bpf_iter_num_new(p as *mut c_void, 0, n);
        fill(p, a2, n as u32, 10);
        bpf_iter_num_destroy(p as *mut c_void);

        /* sum arr1 */
        let n = 16;
        bpf_iter_num_new(p as *mut c_void, 0, n);
        sum1 = sum(p, a1, n as u32);
        bpf_iter_num_destroy(p as *mut c_void);

        /* sum arr2 */
        let n = 32;
        bpf_iter_num_new(p as *mut c_void, 0, n);
        sum2 = sum(p, a2, n as u32);
        bpf_iter_num_destroy(p as *mut c_void);

        printk2(&iter_pass_iter_ptr_to_subprog_____fmt, sum1 as i64 as u64, sum2 as i64 as u64);
    }

    0
}

// HAND: iter_arr_with_actual_elem_count
//   struct {
//       int data[32];
//       int n;
//   } loop_data;
//
//   SEC("raw_tp")
//   __success
//   int iter_arr_with_actual_elem_count(const void *ctx)
//   {
//       int i, n = loop_data.n, sum = 0;
//
//       if (n > ARRAY_SIZE(loop_data.data))
//           return 0;
//
//       bpf_for(i, 0, n) {
//           /* no rechecking of i against ARRAY_SIZE(loop_data.n) */
//           sum += loop_data.data[i];
//       }
//
//       return sum;
//   }
// `n > ARRAY_SIZE(...)` compares int against size_t: unsigned, so a negative
// n returns 0 too.
#[link_section = "raw_tp"]
#[no_mangle]
extern "C" fn iter_arr_with_actual_elem_count(_ctx: *mut c_void) -> i32 {
    let n: i32 = unsafe { (*addr_of!(loop_data)).n };
    let mut sum: i32 = 0;

    if (n as i64 as u64) > 32 {
        return 0;
    }

    unsafe {
        let data = addr_of_mut!(loop_data).cast::<i32>();
        bpf_for!(i, 0, n, {
            /* no rechecking of i against ARRAY_SIZE(loop_data.n) */
            sum = sum.wrapping_add(data.wrapping_offset(i as isize).read());
        });
    }

    sum
}

// HAND: nest_2
//   static __noinline bool nest_2(char *str)
//   {
//       /* some insns (including branch insns) to ensure stacksafe() is triggered
//        * in nest_2(). This way, stacksafe() can compare frame associated with nest_1().
//        */
//       if (str[0] == 't')
//           return true;
//       if (str[1] == 'e')
//           return true;
//       if (str[2] == 's')
//           return true;
//       if (str[3] == 't')
//           return true;
//       return false;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn nest_2(str: *mut i8) -> bool {
    /* some insns (including branch insns) to ensure stacksafe() is triggered
     * in nest_2(). This way, stacksafe() can compare frame associated with nest_1().
     */
    unsafe {
        if str.wrapping_offset(0).read() == b't' as i8 {
            return true;
        }
        if str.wrapping_offset(1).read() == b'e' as i8 {
            return true;
        }
        if str.wrapping_offset(2).read() == b's' as i8 {
            return true;
        }
        if str.wrapping_offset(3).read() == b't' as i8 {
            return true;
        }
    }
    false
}

// HAND: nest_1
//   static __noinline bool nest_1(int n)
//   {
//       /* case 0: allocate stack, case 1: no allocate stack */
//       switch (n) {
//       case 0: {
//           char comm[16];
//
//           if (bpf_get_current_comm(comm, 16))
//               return false;
//           return nest_2(comm);
//       }
//       case 1:
//           return nest_2((char *)&global);
//       default:
//           return false;
//       }
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn nest_1(n: i32) -> bool {
    /* case 0: allocate stack, case 1: no allocate stack */
    match n {
        0 => {
            let mut comm = MaybeUninit::<[i8; 16]>::uninit();

            unsafe {
                if bpf_get_current_comm(comm.as_mut_ptr() as *mut c_void, 16) != 0 {
                    return false;
                }
                nest_2(comm.as_mut_ptr().cast::<i8>())
            }
        }
        1 => unsafe { nest_2(addr_of_mut!(global).cast::<i8>()) },
        _ => false,
    }
}

// HAND: iter_subprog_check_stacksafe
//   __u32 upper, select_n, result;
//   __u64 global;
//
//   SEC("raw_tp")
//   __success
//   int iter_subprog_check_stacksafe(const void *ctx)
//   {
//       long i;
//
//       bpf_for(i, 0, upper) {
//           if (!nest_1(select_n)) {
//               result = 1;
//               return 0;
//           }
//       }
//
//       result = 2;
//       return 0;
//   }
// bpf_for() spelled out: the loop variable is a long and `upper` is re-read at
// every step's bounds check (nest_1 is an opaque call), and the `return 0`
// inside the loop destroys the iterator first (the C's cleanup attribute).
#[link_section = "raw_tp"]
#[no_mangle]
extern "C" fn iter_subprog_check_stacksafe(_ctx: *mut c_void) -> i32 {
    let mut it = MaybeUninit::<bpf_iter_num>::uninit();

    unsafe {
        bpf_iter_num_new(it.as_mut_ptr() as *mut c_void, 0, (*addr_of!(upper)) as i32);
        loop {
            let t = bpf_iter_num_next(it.as_mut_ptr() as *mut c_void) as *mut i32;
            if t.is_null() {
                break;
            }
            let i: i64 = *t as i64;
            if !(i >= 0 && i < (*addr_of!(upper)) as i64) {
                break;
            }
            if !nest_1((*addr_of!(select_n)) as i32) {
                result = 1;
                bpf_iter_num_destroy(it.as_mut_ptr() as *mut c_void);
                return 0;
            }
        }
        bpf_iter_num_destroy(it.as_mut_ptr() as *mut c_void);

        result = 2;
    }
    0
}

// HAND: iter_new_bad_arg
//   struct bpf_iter_num global_it;
//
//   SEC("raw_tp")
//   __failure __msg("R1 type=map_value expected=fp")
//   int iter_new_bad_arg(const void *ctx)
//   {
//       bpf_iter_num_new(&global_it, 0, 1);
//       return 0;
//   }
#[link_section = "raw_tp"]
#[no_mangle]
extern "C" fn iter_new_bad_arg(_ctx: *mut c_void) -> i32 {
    unsafe {
        bpf_iter_num_new(addr_of_mut!(global_it) as *mut c_void, 0, 1);
    }
    0
}

// HAND: iter_next_bad_arg
//   SEC("raw_tp")
//   __failure __msg("R1 type=map_value expected=fp")
//   int iter_next_bad_arg(const void *ctx)
//   {
//       bpf_iter_num_next(&global_it);
//       return 0;
//   }
#[link_section = "raw_tp"]
#[no_mangle]
extern "C" fn iter_next_bad_arg(_ctx: *mut c_void) -> i32 {
    unsafe {
        bpf_iter_num_next(addr_of_mut!(global_it) as *mut c_void);
    }
    0
}

// HAND: iter_destroy_bad_arg
//   SEC("raw_tp")
//   __failure __msg("R1 type=map_value expected=fp")
//   int iter_destroy_bad_arg(const void *ctx)
//   {
//       bpf_iter_num_destroy(&global_it);
//       return 0;
//   }
#[link_section = "raw_tp"]
#[no_mangle]
extern "C" fn iter_destroy_bad_arg(_ctx: *mut c_void) -> i32 {
    unsafe {
        bpf_iter_num_destroy(addr_of_mut!(global_it) as *mut c_void);
    }
    0
}

// HAND: clean_live_states
//   SEC("raw_tp")
//   __success
//   int clean_live_states(const void *ctx)
//   {
//       char buf[1];
//       int i, j, k, l, m, n, o;
//
//       bpf_for(i, 0, 10)
//       bpf_for(j, 0, 10)
//       bpf_for(k, 0, 10)
//       bpf_for(l, 0, 10)
//       bpf_for(m, 0, 10)
//       bpf_for(n, 0, 10)
//       bpf_for(o, 0, 10) {
//           if (unlikely(bpf_get_prandom_u32()))
//               buf[0] = 42;
//           bpf_printk("%s", buf);
//       }
//       return 0;
//   }
#[link_section = "raw_tp"]
#[no_mangle]
extern "C" fn clean_live_states(_ctx: *mut c_void) -> i32 {
    let mut buf = MaybeUninit::<[i8; 1]>::uninit();

    unsafe {
        bpf_for!(_i, 0, 10, {
            bpf_for!(_j, 0, 10, {
                bpf_for!(_k, 0, 10, {
                    bpf_for!(_l, 0, 10, {
                        bpf_for!(_m, 0, 10, {
                            bpf_for!(_n, 0, 10, {
                                bpf_for!(_o, 0, 10, {
                                    if bpf_get_prandom_u32() != 0 {
                                        buf.as_mut_ptr().cast::<i8>().write(42);
                                    }
                                    printk1(&clean_live_states_____fmt, buf.as_ptr() as u64);
                                });
                            });
                        });
                    });
                });
            });
        });
    }
    0
}

// HAND: iter_nested_remake
//   /* The inner iterator is created in every iteration of the outer loop */
//   SEC("socket")
//   __description("iter: nested loops")
//   __success __retval(12)
//   int iter_nested_remake(void *ctx)
//   {
//       int i, j, sum = 0;
//
//       bpf_for(i, 0, 3) {
//           bpf_for(j, 0, 4)
//               sum++;
//       }
//       return sum;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn iter_nested_remake(_ctx: *mut c_void) -> i32 {
    let mut sum: i32 = 0;

    unsafe {
        bpf_for!(_i, 0, 3, {
            bpf_for!(_j, 0, 4, {
                sum = sum.wrapping_add(1);
            });
        });
    }
    sum
}
