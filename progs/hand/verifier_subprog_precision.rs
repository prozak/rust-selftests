// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_subprog_precision.c, translated
// by hand; include!d by the generated progs/verifier_subprog_precision.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

// HAND: global_identity_subprog -- translate the C below (see the file comment)
//   __noinline __used
//   unsigned long global_identity_subprog(__u64 x)
//   {
//       /* the simplest *global* 64-bit identity function */
//       return x;
//   }
// the simplest *global* 64-bit identity function
#[no_mangle]
#[inline(never)]
extern "C" fn global_identity_subprog(x: u64) -> u64 {
    x
}

// HAND: subprog_with_precise_arg -- translate the C below (see the file comment)
//   __noinline __used
//   static __u64 subprog_with_precise_arg(__u64 x)
//   {
//       return vals[x]; /* x is forced to be precise */
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn subprog_with_precise_arg(x: u64) -> u64 {
    // `return vals[x]`, unchecked as in C: x is forced to be precise
    unsafe { *core::ptr::addr_of!(vals).cast::<i32>().add(x as usize) as i64 as u64 }
}
