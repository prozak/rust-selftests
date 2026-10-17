// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_scev.c, translated
// by hand; include!d by the generated progs/verifier_scev.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

// HAND: global_noop_counter -- translate the C below (see the file comment)
//   /* Even a no-op global callee can be freplaced with one that writes to *p. */
//   __noinline int global_noop_counter(__u64 *p)
//   {
//       return 0;
//   }
// `__noinline int global_noop_counter(__u64 *p)`: a global subprogram, its
// argument typed `__u64 *` in BTF.
#[no_mangle]
#[inline(never)]
extern "C" fn global_noop_counter(_p: *mut u64) -> i32 {
    0
}

// HAND: no_widen_dynptr_kfunc_arg -- translate the C below (see the file comment)
//   /*
//    * A dynptr/iter/irq/res_spin_lock call initializes a stack object through a
//    * pointer argument, which acts like a spill base: the induction variable
//    * computing that argument's varying stack offset must not be widened, otherwise
//    * the slot can't be resolved. Here each iteration constructs an xdp dynptr at
//    * &dptrs[i].
//    */
//   SEC("xdp")
//   __success
//   __log_level(2)
//   __flag(BPF_F_TEST_STATE_FREQ)
//   __msg("can't widen {{.*}}, requires exact stack-offset tracking")
//   #ifndef __clang__
//   /* The issue is unrelated to SCEV */
//   __skip("GCC emits a stack-pointer loop condition the verifier cannot resolve")
//   #endif
//   int no_widen_dynptr_kfunc_arg(struct xdp_md *ctx)
//   {
//       struct bpf_dynptr dptrs[4];
//       int i;
//
//   #ifdef __clang__
//   #pragma clang loop unroll(disable)
//   #else
//   #pragma GCC unroll 0
//   #endif
//       for (i = 0; i < 4; i++)
//           bpf_dynptr_from_xdp(ctx, 0, &dptrs[i]);
//
//       return 0;
//   }
#[link_section = "xdp"]
#[no_mangle]
extern "C" fn no_widen_dynptr_kfunc_arg(ctx: *mut c_void) -> i32 {
    // struct bpf_dynptr dptrs[4] (two __u64 each). The C disables unrolling
    // (#pragma clang loop unroll(disable)) so the verifier sees the loop:
    // the trip count is read back through a volatile to keep LLVM from
    // unrolling it, bounded by the array for the verifier.
    let mut dptrs: [u64; 8] = [0; 8];
    let n = unsafe { core::ptr::read_volatile(&4usize) };
    let mut i = 0usize;
    while i < n && i < 4 {
        unsafe { bpf_dynptr_from_xdp(ctx, 0, dptrs.as_mut_ptr().add(2 * i) as *mut c_void) };
        i += 1;
    }
    0
}
