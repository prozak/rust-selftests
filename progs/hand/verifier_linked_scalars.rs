// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_linked_scalars.c, translated
// by hand; include!d by the generated progs/verifier_linked_scalars.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

use bpf_rs_core::helpers::bpf_get_prandom_u32;

// HAND: alu32_negative_offset -- translate the C below (see the file comment)
//   SEC("socket")
//   __success
//   void alu32_negative_offset(void)
//   {
//       volatile char path[5];
//       volatile int offset = bpf_get_prandom_u32();
//       int off = offset;
//
//       if (off >= 5 && off < 10)
//           path[off - 5] = '.';
//
//       /* So compiler doesn't say: error: variable 'path' set but not used */
//       __sink(path[0]);
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn alu32_negative_offset() {
    // volatile char path[5]; volatile int offset = bpf_get_prandom_u32();
    let mut path: [u8; 5] = [0; 5];
    let mut offset: i32 = 0;
    unsafe {
        core::ptr::write_volatile(&mut offset, bpf_get_prandom_u32() as i32);
        let off = core::ptr::read_volatile(&offset);
        if off >= 5 && off < 10 {
            core::ptr::write_volatile(path.as_mut_ptr().add((off - 5) as usize), b'.');
        }
        // __sink(path[0]): a real instruction (an empty asm leaves two
        // line infos at one offset, which the kernel rejects)
        let mut p0 = core::ptr::read_volatile(path.as_ptr()) as u64;
        core::arch::asm!("{0} = {0}", inout(reg) p0, options(nostack, preserves_flags));
    }
}

// HAND: spurious_precision_marks -- translate the C below (see the file comment)
//   SEC("socket")
//   __success
//   __flag(BPF_F_TEST_STATE_FREQ)
//   int spurious_precision_marks(void *ctx)
//   {
//       struct bpf_iter_num iter;
//
//       asm volatile(
//           "r1 = %[iter];"
//           "r2 = 0;"
//           "r3 = 10;"
//           "call %[bpf_iter_num_new];"
//       "1:"
//           "r1 = %[iter];"
//           "call %[bpf_iter_num_next];"
//           "if r0 == 0 goto 4f;"
//           "r7 = *(u32 *)(r0 + 0);"
//           "r8 = *(u32 *)(r0 + 0);"
//           /* This jump can't be predicted and does not change r7 or r8 state. */
//           "if r7 > r8 goto 2f;"
//           /* Branch explored first ties r2 and r7 as having the same id. */
//           "r2 = r7;"
//           "goto 3f;"
//       "2:"
//           /* Branch explored second does not tie r2 and r7 but has a function call. */
//           "call %[bpf_get_prandom_u32];"
//       "3:"
//           /*
//            * A checkpoint.
//            * When first branch is explored, this would inject linked registers
//            * r2 and r7 into the jump history.
//            * When second branch is explored, this would be a cache hit point,
//            * triggering propagate_precision().
//            */
//           "if r7 <= 42 goto +0;"
//           /*
//            * Mark r7 as precise using an if condition that is always true.
//            * When reached via the second branch, this triggered a bug in the backtrack_insn()
//            * because r2 (tied to r7) was propagated as precise to a call.
//            */
//           "if r7 <= 0xffffFFFF goto +0;"
//           "goto 1b;"
//       "4:"
//           "r1 = %[iter];"
//           "call %[bpf_iter_num_destroy];"
//           :
//           : __imm_ptr(iter),
//             __imm(bpf_iter_num_new),
//             __imm(bpf_iter_num_next),
//             __imm(bpf_iter_num_destroy),
//             __imm(bpf_get_prandom_u32)
//           : __clobber_common, "r7", "r8"
//       );
//
//       return 0;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn spurious_precision_marks(_ctx: *mut c_void) -> i32 {
    // struct bpf_iter_num iter (one __u64); the C's asm with its operands:
    // bpf_get_prandom_u32 is helper 7, the iterator kfuncs are `sym`
    let mut iter: [u64; 1] = [0];
    unsafe {
        core::arch::asm!(
            "r1 = {iter};",
            "r2 = 0;",
            "r3 = 10;",
            "call {bpf_iter_num_new};",
            "1:",
            "r1 = {iter};",
            "call {bpf_iter_num_next};",
            "if r0 == 0 goto 4f;",
            "r7 = *(u32 *)(r0 + 0);",
            "r8 = *(u32 *)(r0 + 0);",
            "if r7 > r8 goto 2f;",
            "r2 = r7;",
            "goto 3f;",
            "2:",
            "call 7;",
            "3:",
            "if r7 <= 42 goto +0;",
            "if r7 <= 0xffffFFFF goto +0;",
            "goto 1b;",
            "4:",
            "r1 = {iter};",
            "call {bpf_iter_num_destroy};",
            iter = in(reg) iter.as_mut_ptr(),
            bpf_iter_num_new = sym bpf_iter_num_new,
            bpf_iter_num_next = sym bpf_iter_num_next,
            bpf_iter_num_destroy = sym bpf_iter_num_destroy,
            out("r0") _,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
            out("r7") _,
            out("r8") _,
            options(nostack)
        );
    }
    0
}
