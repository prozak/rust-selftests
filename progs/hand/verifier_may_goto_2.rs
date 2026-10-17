// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_may_goto_2.c, translated
// by hand; include!d by the generated progs/verifier_may_goto_2.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

/// bpf_experimental.h's `can_loop`: a may_goto (opcode 0xe5) to the asm's
/// label block (the arena_htab_asm.rs encoding).
#[inline(always)]
unsafe fn can_loop() -> bool {
    let mut ret = true;
    core::arch::asm!(
        "1:",
        ".byte 0xe5",
        ".byte 0",
        ".long (({0} - 1b - 8) / 8) & 0xffff",
        ".short 0",
        label {
            ret = false;
        },
    );
    ret
}

// HAND: may_goto_c_code -- translate the C below (see the file comment)
//   SEC("raw_tp")
//   __description("C code with may_goto 0")
//   __success
//   int may_goto_c_code(void)
//   {
//       int i, tmp[3];
//
//       for (i = 0; i < 3 && can_loop; i++)
//           tmp[i] = 0;
//
//       for (i = 0; i < 3 && can_loop; i++)
//           tmp[i] = gvar - i;
//
//       for (i = 0; i < 3 && can_loop; i++)
//           gvar += tmp[i];
//
//       return 0;
//   }
#[link_section = "raw_tp"]
#[no_mangle]
extern "C" fn may_goto_c_code() -> i32 {
    let mut tmp = core::mem::MaybeUninit::<[i32; 3]>::uninit();
    let t = tmp.as_mut_ptr() as *mut i32;
    unsafe {
        let mut i: usize = 0;
        while i < 3 && can_loop() {
            *t.add(i) = 0;
            i += 1;
        }
        let mut i: usize = 0;
        while i < 3 && can_loop() {
            *t.add(i) = gvar.wrapping_sub(i as i32);
            i += 1;
        }
        let mut i: usize = 0;
        while i < 3 && can_loop() {
            gvar = gvar.wrapping_add(*t.add(i));
            i += 1;
        }
    }
    0
}
