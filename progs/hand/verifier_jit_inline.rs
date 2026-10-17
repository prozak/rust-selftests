// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_jit_inline.c, translated
// by hand; include!d by the generated progs/verifier_jit_inline.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

use bpf_rs_core::helpers::{bpf_get_current_task, bpf_get_smp_processor_id};

// HAND: inline_bpf_get_current_task -- translate the C below (see the file comment)
//   SEC("fentry/bpf_fentry_test1")
//   __success __retval(0)
//   __arch_x86_64
//   __jited("    addq    %gs:{{.*}}, %rax")
//   __arch_arm64
//   __jited("    mrs    x8, SP_EL0")
//   __arch_riscv64
//   __jited("    mv    t6, tp")
//   __arch_loongarch
//   __jited("    move    $a5, $tp")
//   int inline_bpf_get_current_task(void)
//   {
//       bpf_get_current_task();
//
//       return 0;
//   }
#[link_section = "fentry/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn inline_bpf_get_current_task() -> i32 {
    bpf_get_current_task();
    0
}

// HAND: inline_bpf_get_smp_processor_id -- translate the C below (see the file comment)
//   SEC("fentry/bpf_fentry_test2")
//   __success __retval(0)
//   __arch_loongarch
//   __jited("    ld.wu    $a5, $tp, 16")
//   int inline_bpf_get_smp_processor_id(void)
//   {
//       bpf_get_smp_processor_id();
//
//       return 0;
//   }
#[link_section = "fentry/bpf_fentry_test2"]
#[no_mangle]
extern "C" fn inline_bpf_get_smp_processor_id() -> i32 {
    bpf_get_smp_processor_id();
    0
}
