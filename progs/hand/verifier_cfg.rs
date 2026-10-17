// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_cfg.c, translated
// by hand; include!d by the generated progs/verifier_cfg.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

use bpf_rs_core::helpers::bpf_tail_call;

// HAND: tail_call_or_throw_subprog -- translate the C below (see the file comment)
//   /*
//    * The subprogram leaves through the tail call or the exception and never
//    * reaches an exit insn, so the hidden edge of the tail call has no exit to
//    * point at. The stack access makes the liveness pass walk the subprogram,
//    * and the loop compiles to a single jump back onto itself.
//    */
//   __noinline __used
//   static int tail_call_or_throw_subprog(void *ctx)
//   {
//       volatile __u32 idx = 0;
//
//       bpf_tail_call(ctx, &map_array, idx);
//       bpf_throw(0);
//       for (;;) {}
//       return 0;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn tail_call_or_throw_subprog(ctx: *mut c_void) -> i32 {
    // `volatile __u32 idx = 0`: the index is read back from the stack
    let idx: u32 = 0;
    let i = unsafe { core::ptr::read_volatile(&idx) };
    bpf_tail_call(ctx, &map_array, i);
    unsafe { bpf_throw(0) };
    loop {}
}
