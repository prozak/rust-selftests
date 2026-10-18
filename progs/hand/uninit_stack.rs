// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/uninit_stack.c, translated
// by hand; include!d by the generated progs/uninit_stack.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

// HAND: dummy -- translate the C below (see the file comment)
//   static __noinline void dummy(void) {}
// A static subprogram helper_uninit_to_misc calls so that the verifier
// prints the caller's stack state (the __msg it expects).
#[no_mangle]
#[inline(never)]
extern "C" fn dummy() {}
