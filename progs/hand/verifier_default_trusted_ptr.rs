// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_default_trusted_ptr.c, translated
// by hand; include!d by the generated progs/verifier_default_trusted_ptr.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

// HAND: test_default_trusted_ptr -- translate the C below (see the file comment)
//   SEC("syscall")
//   __success __retval(0)
//   int test_default_trusted_ptr(void *ctx)
//   {
//       struct prog_test_member *trusted_ptr;
//
//       trusted_ptr = bpf_kfunc_get_default_trusted_ptr_test();
//       /*
//        * Test BPF kfunc bpf_get_default_trusted_ptr_test() returns a
//        * PTR_TO_BTF_ID | PTR_TRUSTED, therefore it should be accepted when
//        * passed to a BPF kfunc only accepting KF_TRUSTED_ARGS.
//        */
//       bpf_kfunc_put_default_trusted_ptr_test(trusted_ptr);
//       return 0;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_default_trusted_ptr(_ctx: *mut c_void) -> i32 {
    unsafe {
        let trusted_ptr = bpf_kfunc_get_default_trusted_ptr_test();
        // a PTR_TO_BTF_ID | PTR_TRUSTED, accepted by a kfunc that takes only
        // KF_TRUSTED_ARGS
        bpf_kfunc_put_default_trusted_ptr_test(trusted_ptr);
    }
    0
}
