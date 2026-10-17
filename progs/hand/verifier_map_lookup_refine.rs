// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_map_lookup_refine.c, translated
// by hand; include!d by the generated progs/verifier_map_lookup_refine.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

use bpf_rs_core::helpers::{bpf_csum_diff, bpf_map_lookup_elem};

// HAND: mapofmaps_value_as_kfunc_mem_buf -- translate the C below (see the file comment)
//   SEC("?tc")
//   __failure __msg("type=map_ptr_or_null expected=fp")
//   int mapofmaps_value_as_kfunc_mem_buf(struct __sk_buff *skb)
//   {
//       struct bpf_dynptr dptr;
//       __u32 key = 0;
//       void *inner;
//       char *p;
//
//       inner = bpf_map_lookup_elem(&outer_map, &key);
//       /* intentionally NOT NULL-checked: type is map_ptr_or_null */
//
//       bpf_dynptr_from_skb(skb, 0, &dptr);
//       /* arg3 is mem+size */
//       p = bpf_dynptr_slice(&dptr, 0, inner, 4);
//       if (p)
//           return p[0];
//       return 0;
//   }
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn mapofmaps_value_as_kfunc_mem_buf(skb: *mut __sk_buff) -> i32 {
    let mut dptr = core::mem::MaybeUninit::<[u64; 2]>::uninit();
    let key: u32 = 0;
    // intentionally NOT NULL-checked: type is map_ptr_or_null
    let inner = bpf_map_lookup_elem(&outer_map, &key);
    unsafe {
        bpf_dynptr_from_skb(skb as *mut c_void, 0, dptr.as_mut_ptr() as *mut c_void);
        // arg3 is mem+size
        let p = bpf_dynptr_slice(dptr.as_mut_ptr() as *mut c_void, 0, inner, 4) as *mut i8;
        if !p.is_null() {
            return *p as i32;
        }
    }
    0
}

// HAND: mapofmaps_value_as_helper_mem_buf -- translate the C below (see the file comment)
//   SEC("?tc")
//   __failure __msg("type=map_ptr_or_null expected=fp")
//   int mapofmaps_value_as_helper_mem_buf(struct __sk_buff *skb)
//   {
//       __u32 key = 0;
//       void *inner;
//
//       inner = bpf_map_lookup_elem(&outer_map, &key);
//       /* intentionally NOT NULL-checked: type is map_ptr_or_null */
//
//       /* arg1 is mem+size */
//       return bpf_csum_diff(inner, 4, NULL, 0, 0) + skb->len;
//   }
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn mapofmaps_value_as_helper_mem_buf(skb: *mut __sk_buff) -> i32 {
    let key: u32 = 0;
    // intentionally NOT NULL-checked: type is map_ptr_or_null
    let inner = bpf_map_lookup_elem(&outer_map, &key);
    // arg1 is mem+size
    (bpf_csum_diff(inner, 4, core::ptr::null(), 0, 0) as i32).wrapping_add(unsafe { (*skb).len } as i32)
}

// HAND: mapofmaps_value_as_helper_fixed_mem -- translate the C below (see the file comment)
//   SEC("?tc")
//   __failure __msg("Possibly NULL pointer passed to trusted R1")
//   int mapofmaps_value_as_helper_fixed_mem(struct __sk_buff *skb)
//   {
//       char th[sizeof(struct tcphdr)] = {};
//       __u32 key = 0;
//       void *inner;
//
//       inner = bpf_map_lookup_elem(&outer_map, &key);
//       /* intentionally NOT NULL-checked: type is map_ptr_or_null */
//
//       /* arg1 is fixed-sized mem */
//       return bpf_tcp_raw_check_syncookie_ipv4(inner, (void *)th);
//   }
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn mapofmaps_value_as_helper_fixed_mem(_skb: *mut __sk_buff) -> i32 {
    let th = [0u8; 20]; // char th[sizeof(struct tcphdr)]
    let key: u32 = 0;
    // intentionally NOT NULL-checked: type is map_ptr_or_null
    let inner = bpf_map_lookup_elem(&outer_map, &key);
    // arg1 is fixed-sized mem: bpf_tcp_raw_check_syncookie_ipv4 (helper 206)
    let f: extern "C" fn(*mut c_void, *const c_void) -> i64 = unsafe { core::mem::transmute(206usize) };
    f(inner, th.as_ptr() as *const c_void) as i32
}
