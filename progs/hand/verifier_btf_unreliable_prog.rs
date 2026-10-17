// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_btf_unreliable_prog.c, translated
// by hand; include!d by the generated progs/verifier_btf_unreliable_prog.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

// HAND: btf_unreliable_kprobe -- translate the C below (see the file comment)
//   SEC("kprobe")
//   __success __log_level(2)
//   /* context type is wrong, making it impossible to freplace this program */
//   int btf_unreliable_kprobe(struct whatever *ctx)
//   {
//       return 0;
//   }
// the context type is wrong, making it impossible to freplace this program
#[link_section = "kprobe"]
#[no_mangle]
extern "C" fn btf_unreliable_kprobe(_ctx: *mut whatever) -> i32 {
    0
}
