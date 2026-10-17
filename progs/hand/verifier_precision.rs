// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_precision.c, translated
// by hand; include!d by the generated progs/verifier_precision.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

use bpf_rs_core::ctx::__sk_buff;

// HAND: subprog_mem_arg -- translate the C below (see the file comment)
//   __weak int subprog_mem_arg(int *p)
//   {
//       if (p)
//           return *p;
//       return 0;
//   }
// `__weak int subprog_mem_arg(int *p)`: a global subprogram, its argument
// typed `int *` in BTF for the verifier's global-function argument check.
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn subprog_mem_arg(p: *mut i32) -> i32 {
    if !p.is_null() {
        return unsafe { *p };
    }
    0
}

// HAND: null_kfunc_arg_dynptr_slice -- translate the C below (see the file comment)
//   /* Same as above, check that path with r3 == 0 does not prune the path with r3 != 0 */
//   SEC("?tc")
//   __flag(BPF_F_TEST_STATE_FREQ)
//   __failure __msg("R3 type=scalar expected=fp")
//   int null_kfunc_arg_dynptr_slice(struct __sk_buff *skb)
//   {
//       struct bpf_dynptr ptr;
//
//       bpf_dynptr_from_skb(skb, 0, &ptr);
//       asm volatile (
//           "call %[bpf_get_prandom_u32];"
//           "r3 = 42;"
//           "if r0 > 42 goto 1f;"
//           "r3 = 0;"
//       "1:"
//           "r1 = %[ptr];"
//           "r2 = 0;"
//           "r4 = 8;"
//           "call %[bpf_dynptr_slice];"
//           :
//           : __imm_ptr(ptr),
//             __imm(bpf_get_prandom_u32),
//             __imm(bpf_dynptr_slice)
//           : __clobber_common);
//       return 0;
//   }
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn null_kfunc_arg_dynptr_slice(skb: *const __sk_buff) -> i32 {
    // struct bpf_dynptr { __u64 __opaque[2]; }
    let mut ptr: [u64; 2] = [0; 2];
    unsafe {
        bpf_dynptr_from_skb(skb as *mut c_void, 0, ptr.as_mut_ptr() as *mut c_void);
        // the C's asm: bpf_get_prandom_u32 is helper 7
        core::arch::asm!(
            "call 7;",
            "r3 = 42;",
            "if r0 > 42 goto 1f;",
            "r3 = 0;",
            "1:",
            "r1 = {ptr};",
            "r2 = 0;",
            "r4 = 8;",
            "call {bpf_dynptr_slice};",
            ptr = in(reg) ptr.as_mut_ptr(),
            bpf_dynptr_slice = sym bpf_dynptr_slice,
            out("r0") _,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
            options(nostack)
        );
    }
    0
}
