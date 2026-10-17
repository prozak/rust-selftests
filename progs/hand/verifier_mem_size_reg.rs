// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_mem_size_reg.c, translated
// by hand; include!d by the generated progs/verifier_mem_size_reg.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

// HAND: dynptr_slice_null_buf_size_precise -- translate the C below (see the file comment)
//   /*
//    * The __szk size of a kfunc memory/size pair must be marked precise even when
//    * the nullable buffer is passed as NULL.
//    */
//   SEC("?tc")
//   __success __log_level(2)
//   __msg("mark_precise: frame0: regs=r4 stack= before")
//   int dynptr_slice_null_buf_size_precise(struct __sk_buff *skb)
//   {
//       struct bpf_dynptr dptr;
//       char *p;
//
//       bpf_dynptr_from_skb(skb, 0, &dptr);
//
//       p = bpf_dynptr_slice(&dptr, 0, NULL, 8);
//       if (p)
//           return p[0];
//       return 0;
//   }
// The __szk size of a kfunc memory/size pair must be marked precise even
// when the nullable buffer is passed as NULL.
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn dynptr_slice_null_buf_size_precise(skb: *mut __sk_buff) -> i32 {
    let mut dptr = core::mem::MaybeUninit::<[u64; 2]>::uninit();
    unsafe {
        bpf_dynptr_from_skb(skb as *mut c_void, 0, dptr.as_mut_ptr() as *mut c_void);
        let p = bpf_dynptr_slice(dptr.as_mut_ptr() as *mut c_void, 0, core::ptr::null_mut(), 8) as *mut i8;
        if !p.is_null() {
            return *p as i32;
        }
    }
    0
}
