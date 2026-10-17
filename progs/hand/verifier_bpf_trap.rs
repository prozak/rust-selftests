// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_bpf_trap.c, translated
// by hand; include!d by the generated progs/verifier_bpf_trap.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

// HAND: bpf_trap_with_simple_c -- translate the C below (see the file comment)
//   SEC("socket")
//   __description("__bpf_trap with simple c code")
//   __failure __msg("unexpected __bpf_trap() due to uninitialized variable?")
//   void bpf_trap_with_simple_c(void)
//   {
//       __bpf_trap();
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn bpf_trap_with_simple_c() {
    unsafe { __bpf_trap() }
}
