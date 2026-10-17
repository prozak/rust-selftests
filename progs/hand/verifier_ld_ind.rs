// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_ld_ind.c, translated
// by hand; include!d by the generated progs/verifier_ld_ind.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

// (`struct __sk_buff` is the generated file's, from the C object's BTF)
use bpf_rs_core::helpers::bpf_loop;

// HAND: ld_abs_callback_reject -- translate the C below (see the file comment)
//   SEC("socket")
//   __description("ld_abs: reject in callback")
//   __failure __msg("cannot use BPF_LD_[ABS|IND] within callback")
//   int ld_abs_callback_reject(struct __sk_buff *skb)
//   {
//       bpf_loop(1, ld_abs_callback, &skb, 0);
//       return 0;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn ld_abs_callback_reject(mut skb: *mut __sk_buff) -> i32 {
    // bpf_loop with a naked callback (the C passes the function, which
    // has no Rust signature bpf_rs_core's wrapper could take)
    let bpf_loop_raw: extern "C" fn(u32, usize, *mut c_void, u64) -> i64 =
        unsafe { core::mem::transmute(181usize) };
    bpf_loop_raw(1, ld_abs_callback as usize, &mut skb as *mut *mut __sk_buff as *mut c_void, 0);
    0
}

// HAND: ld_ind_callback_subprog_reject -- translate the C below (see the file comment)
//   SEC("socket")
//   __description("ld_ind: reject in callback subprog")
//   __failure __msg("cannot use BPF_LD_[ABS|IND] within callback")
//   int ld_ind_callback_subprog_reject(struct __sk_buff *skb)
//   {
//       bpf_loop(1, ld_ind_callback, &skb, 0);
//       return 0;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn ld_ind_callback_subprog_reject(mut skb: *mut __sk_buff) -> i32 {
    // bpf_loop with a naked callback (the C passes the function, which
    // has no Rust signature bpf_rs_core's wrapper could take)
    let bpf_loop_raw: extern "C" fn(u32, usize, *mut c_void, u64) -> i64 =
        unsafe { core::mem::transmute(181usize) };
    bpf_loop_raw(1, ld_ind_callback as usize, &mut skb as *mut *mut __sk_buff as *mut c_void, 0);
    0
}

// HAND: ld_ind_global_static -- translate the C below (see the file comment)
//   static __noinline int ld_ind_global_static(struct __sk_buff *skb)
//   {
//       asm volatile (
//       "r6 = %[skb];"
//       "r7 = 0;"
//       ".8byte %[ld_ind];"
//       :
//       : [skb] "r"(skb),
//         __imm_insn(ld_ind, BPF_LD_IND(BPF_W, BPF_REG_7, 0))
//       : __clobber_common, "r6", "r7");
//       return skb->mark;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn ld_ind_global_static(skb: *mut __sk_buff) -> i32 {
    unsafe {
        // BPF_LD_IND(BPF_W, BPF_REG_7, 0): r0 = *(u32 *)skb[r7 + 0]
        core::arch::asm!(
            "r6 = {skb};",
            "r7 = 0;",
            ".8byte {ld_ind};",
            skb = in(reg) skb,
            ld_ind = const 0x0000000000007040u64,
            out("r0") _,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
            out("r6") _,
            out("r7") _,
            options(nostack)
        );
        (*skb).mark as i32
    }
}

// HAND: ld_ind_global -- translate the C below (see the file comment)
//   __noinline int ld_ind_global(struct __sk_buff *skb)
//   {
//       return ld_ind_global_static(skb);
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn ld_ind_global(skb: *mut __sk_buff) -> i32 {
    ld_ind_global_static(skb)
}

// HAND: ld_ind_global_callback -- translate the C below (see the file comment)
//   static int ld_ind_global_callback(__u32 index, struct __sk_buff **ctx)
//   {
//       ld_ind_global(*ctx);
//       return 0;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn ld_ind_global_callback(_index: u64, ctx: *mut *mut __sk_buff) -> i64 {
    ld_ind_global(unsafe { *ctx });
    0
}

// HAND: ld_ind_global_callback_reject -- translate the C below (see the file comment)
//   SEC("socket")
//   __description("ld_ind: reject in callback global subprog")
//   __failure __msg("cannot use BPF_LD_[ABS|IND] within callback")
//   int ld_ind_global_callback_reject(struct __sk_buff *skb)
//   {
//       bpf_loop(1, ld_ind_global_callback, &skb, 0);
//       return 0;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn ld_ind_global_callback_reject(mut skb: *mut __sk_buff) -> i32 {
    bpf_loop(1, ld_ind_global_callback, &mut skb as *mut *mut __sk_buff, 0);
    0
}

// HAND: ld_ind_global_subprog_ok -- translate the C below (see the file comment)
//   SEC("socket")
//   __description("ld_ind: allow in non-callback global subprog")
//   __success
//   int ld_ind_global_subprog_ok(struct __sk_buff *skb)
//   {
//       return ld_ind_global(skb);
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn ld_ind_global_subprog_ok(skb: *mut __sk_buff) -> i32 {
    ld_ind_global(skb)
}
