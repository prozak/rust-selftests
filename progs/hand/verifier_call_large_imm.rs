// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_call_large_imm.c, translated
// by hand; include!d by the generated progs/verifier_call_large_imm.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

// HAND: padding_subprog -- translate the C below (see the file comment)
//   /*
//    * 32765 is the exact minimum number of padding instructions needed to
//    * trigger the verifier failure, because:
//    * 1. Counting the wrapper instructions around the padding block (one
//    *    "r0=0" and two "exit" instructions), the actual jump distance
//    *    evaluates to N + 3.
//    * 2. To overflow the s16 max bound (32767), we need N + 3 > 32767.
//    * Thus, N = 32765 is the exact minimum padding size required.
//    */
//   static __attribute__((noinline)) void padding_subprog(void)
//   {
//       asm volatile (
//       "r0 = 0;"
//       ".rept 32765;"
//       "r0 += 0;"
//       ".endr;"
//       ::: __clobber_all);
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn padding_subprog() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            ".rept 32765;",
            "r0 += 0;",
            ".endr;",
            out("r0") _, out("r1") _, out("r2") _, out("r3") _, out("r4") _, out("r5") _, out("r6") _, out("r7") _, out("r8") _, out("r9") _,
            options(nostack)
        );
    }
}

// HAND: target_subprog -- translate the C below (see the file comment)
//   static __attribute__((noinline)) int target_subprog(void)
//   {
//       /* Use volatile variable here to prevent optimization. */
//       volatile int magic_ret = 3;
//       return magic_ret;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn target_subprog() -> i32 {
    // a volatile variable prevents optimization
    let mut magic_ret: i32 = 0;
    unsafe {
        core::ptr::write_volatile(&mut magic_ret, 3);
        core::ptr::read_volatile(&magic_ret)
    }
}

// HAND: call_large_imm_test -- translate the C below (see the file comment)
//   SEC("syscall")
//   __success __retval(3)
//   int call_large_imm_test(void *ctx)
//   {
//       /*
//        * Landing pad to handle call error on kernel without the fix,
//        * preventing kernel panic.
//        */
//       asm volatile (
//       "r0 = 0;"
//       ".rept 32768;"
//       "r0 += 0;"
//       ".endr;"
//       ::: __clobber_all);
//
//       /*
//        * The call_happened variable is 1 only when the call insn wrongly
//        * go back to the landing pad above.
//        */
//       if (call_happened == 1) {
//           /* Use volatile variable here to prevent optimization. */
//           volatile int flag = -1;
//           return flag;
//       }
//
//       call_happened = 1;
//
//       padding_subprog();
//
//       return target_subprog();
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn call_large_imm_test(_ctx: *mut c_void) -> i32 {
    // a landing pad to handle a call error on a kernel without the fix,
    // preventing a kernel panic
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            ".rept 32768;",
            "r0 += 0;",
            ".endr;",
            out("r0") _, out("r1") _, out("r2") _, out("r3") _, out("r4") _, out("r5") _, out("r6") _, out("r7") _, out("r8") _, out("r9") _,
            options(nostack)
        );
    }

    // call_happened is 1 only when the call insn wrongly goes back to the
    // landing pad above
    if unsafe { call_happened } == 1 {
        let mut flag: i32 = 0;
        unsafe {
            core::ptr::write_volatile(&mut flag, -1);
            return core::ptr::read_volatile(&flag);
        }
    }

    unsafe { call_happened = 1 };

    padding_subprog();

    target_subprog()
}
