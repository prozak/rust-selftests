// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_stack_arg.c, translated
// by hand; include!d by the generated progs/verifier_stack_arg.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

// HAND: subprog_6args -- translate the C below (see the file comment)
//   __noinline __used
//   static int subprog_6args(int a, int b, int c, int d, int e, int f)
//   {
//       return a + b + c + d + e + f;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn subprog_6args(a: i32, b: i32, c: i32, d: i32, e: i32, f: i32) -> i32 {
    a.wrapping_add(b).wrapping_add(c).wrapping_add(d).wrapping_add(e).wrapping_add(f)
}

// HAND: subprog_7args -- translate the C below (see the file comment)
//   __noinline __used
//   static int subprog_7args(int a, int b, int c, int d, int e, int f, int g)
//   {
//       return a + b + c + d + e + f + g;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn subprog_7args(a: i32, b: i32, c: i32, d: i32, e: i32, f: i32, g: i32) -> i32 {
    a.wrapping_add(b).wrapping_add(c).wrapping_add(d).wrapping_add(e).wrapping_add(f).wrapping_add(g)
}

// HAND: subprog_deref_arg6 -- translate the C below (see the file comment)
//   __noinline __used
//   static long subprog_deref_arg6(long a, long b, long c, long d, long e, long *f)
//   {
//       return *f;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn subprog_deref_arg6(_a: i64, _b: i64, _c: i64, _d: i64, _e: i64, f: *mut i64) -> i64 {
    unsafe { *f }
}
