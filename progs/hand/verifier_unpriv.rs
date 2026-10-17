// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_unpriv.c, translated
// by hand; include!d by the generated progs/verifier_unpriv.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

use bpf_rs_core::helpers::bpf_loop;

// HAND: pseudo_func_callback -- translate the C below (see the file comment)
//   static int pseudo_func_callback(__u32 index, void *ctx)
//   {
//       return 0;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn pseudo_func_callback(_index: u64, _ctx: *mut c_void) -> i64 {
    0
}

// HAND: unpriv_pseudo_func_policy -- translate the C below (see the file comment)
//   SEC("socket")
//   __description("unpriv: pseudo function policy diagnostic")
//   __success __failure_unpriv
//   __msg_unpriv("loading/calling other bpf or kernel functions")
//   __not_msg_unpriv("BPF-to-BPF function call")
//   __msg_unpriv("policy check failed for BPF function reference")
//   __msg_unpriv("avoid BPF function references in unprivileged")
//   int unpriv_pseudo_func_policy(void *ctx)
//   {
//       bpf_loop(1, pseudo_func_callback, NULL, 0);
//       return 0;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn unpriv_pseudo_func_policy(_ctx: *mut c_void) -> i32 {
    bpf_loop(1, pseudo_func_callback, core::ptr::null_mut::<c_void>(), 0);
    0
}

// HAND: nospec_global_func -- translate the C below (see the file comment)
//   __noinline int nospec_global_func(int x)
//   {
//       return x + 1;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn nospec_global_func(x: i32) -> i32 {
    x.wrapping_add(1)
}
