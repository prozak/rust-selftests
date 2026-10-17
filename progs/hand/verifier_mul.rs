// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_mul.c, translated
// by hand; include!d by the generated progs/verifier_mul.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

// HAND: mul_precise -- translate the C below (see the file comment)
//   /* Intended to test the abstract multiplication technique(s) used by
//    * the verifier. Using assembly to avoid compiler optimizations.
//    */
//   SEC("fentry/bpf_fentry_test1")
//   void BPF_PROG(mul_precise, int x)
//   {
//       /* First, force the verifier to be uncertain about the value:
//        *     unsigned int a = (bpf_get_prandom_u32() & 0x2) | 0x1;
//        *
//        * Assuming the verifier is using tnum, a must be tnum{.v=0x1, .m=0x2}.
//        * Then a * 0x3 would be m0m1 (m for uncertain). Added imprecision
//        * would cause the following to fail, because the required return value
//        * is 0:
//        *     return (a * 0x3) & 0x4);
//        */
//       asm volatile ("\
//       call %[bpf_get_prandom_u32];\
//       r0 &= 0x2;\
//       r0 |= 0x1;\
//       r0 *= 0x3;\
//       r0 &= 0x4;\
//       if r0 != 0 goto l0_%=;\
//       r0 = 0;\
//       goto l1_%=;\
//   l0_%=:\
//       r0 = 1;\
//   l1_%=:\
//   "    :
//       : __imm(bpf_get_prandom_u32)
//       : __clobber_all);
//   }
// BPF_PROG(mul_precise, int x), void: the asm leaves the result in r0.
// bpf_get_prandom_u32 is helper 7.
#[link_section = "fentry/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn mul_precise(_ctx: *mut u64) {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 0x2;",
            "r0 |= 0x1;",
            "r0 *= 0x3;",
            "r0 &= 0x4;",
            "if r0 != 0 goto 1f;",
            "r0 = 0;",
            "goto 2f;",
            "1:",
            "r0 = 1;",
            "2:",
            out("r0") _, out("r1") _, out("r2") _, out("r3") _, out("r4") _, out("r5") _, out("r6") _, out("r7") _, out("r8") _, out("r9") _,
            options(nostack)
        );
    }
}
