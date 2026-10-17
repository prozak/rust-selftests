// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_gotox.c, translated
// by hand; include!d by the generated progs/verifier_gotox.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

// HAND: terminal_gotox_subprog2 -- translate the C below (see the file comment)
//   static __noinline __used int terminal_gotox_subprog2(void)
//   {
//       return 0;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn terminal_gotox_subprog2() -> i32 {
    0
}

// HAND: test_subprog -- translate the C below (see the file comment)
//   __used static int test_subprog(void)
//   {
//       return 0;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn test_subprog() -> i32 {
    0
}
