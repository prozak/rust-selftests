// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_live_stack.c, translated
// by hand; include!d by the generated progs/verifier_live_stack.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

// HAND: global_noop_arg -- translate the C below (see the file comment)
//   __noinline int global_noop_arg(struct cnt8 *p)
//   {
//       return 0;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn global_noop_arg(_p: *mut cnt8) -> i32 {
    0
}

// HAND: global_int_arg -- translate the C below (see the file comment)
//   __noinline int global_int_arg(int x)
//   {
//       return 0;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn global_int_arg(_x: i32) -> i32 {
    0
}

// HAND: global_noop_dynptr_arg -- translate the C below (see the file comment)
//   __noinline int global_noop_dynptr_arg(struct bpf_dynptr *p)
//   {
//       return 0;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn global_noop_dynptr_arg(_p: *mut bpf_dynptr) -> i32 {
    0
}

// HAND: global_noop_btf_arg -- translate the C below (see the file comment)
//   __noinline int global_noop_btf_arg(struct task_struct *p __arg_untrusted)
//   {
//       return 0;
//   }
// `struct task_struct *p __arg_untrusted` (the arg_tags! declaration)
#[no_mangle]
#[inline(never)]
extern "C" fn global_noop_btf_arg(_p: *mut task_struct) -> i32 {
    0
}
