// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_btf_flex_array.c, translated
// by hand; include!d by the generated progs/verifier_btf_flex_array.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

use bpf_rs_core::helpers::{bpf_kptr_xchg, bpf_map_lookup_elem};

// BTF_TYPE_ID: test_flex_batch_id local struct test_flex_batch
extern "C" {
    fn test_flex_batch_id() -> u64;
}

// HAND: stash_and_peek -- translate the C below (see the file comment)
//   SEC("syscall")
//   __description("btf walk into flexible array of zero-sized elements")
//   __failure __msg("access beyond struct test_flex_batch at off 4 size 1")
//   int stash_and_peek(void *ctx)
//   {
//       struct test_flex_batch *b, *old;
//       struct map_value *v;
//       int key = 0;
//
//       v = bpf_map_lookup_elem(&batches, &key);
//       if (!v)
//           return 0;
//
//       b = bpf_obj_new(struct test_flex_batch);
//       if (!b)
//           return 0;
//       b->nr = 1;
//
//       old = bpf_kptr_xchg(&v->batch, b);
//       if (old)
//           bpf_obj_drop(old);
//
//       b = v->batch;
//       if (!b)
//           return 0;
//
//       return b->nr + *(char *)&b->events[0];
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn stash_and_peek(_ctx: *mut c_void) -> i32 {
    let key: i32 = 0;
    let v = bpf_map_lookup_elem(&batches, &key) as *mut map_value;
    if v.is_null() {
        return 0;
    }

    // bpf_obj_new(struct test_flex_batch): the object's own type id
    let mut b = unsafe { bpf_obj_new(test_flex_batch_id()) } as *mut test_flex_batch;
    if b.is_null() {
        return 0;
    }
    unsafe { (*b).nr = 1 };

    let old = bpf_kptr_xchg(unsafe { core::ptr::addr_of_mut!((*v).batch) } as *mut c_void, b as *mut c_void);
    if !old.is_null() {
        unsafe { bpf_obj_drop(old) };
    }

    b = unsafe { (*v).batch };
    if b.is_null() {
        return 0;
    }

    unsafe { (*b).nr.wrapping_add(*(core::ptr::addr_of!((*b).events) as *const i8) as i32) }
}
