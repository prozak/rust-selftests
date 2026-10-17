// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_spin_lock.c, translated
// by hand; include!d by the generated progs/verifier_spin_lock.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

use bpf_rs_core::helpers::{bpf_map_lookup_elem, bpf_spin_lock, bpf_spin_unlock};

// HAND: bpf_loop_inside_locked_region -- translate the C below (see the file comment)
//   SEC("tc")
//   __description("spin_lock: loop within a locked region")
//   __success __failure_unpriv __msg_unpriv("")
//   __retval(0)
//   int bpf_loop_inside_locked_region(void)
//   {
//       const int zero = 0;
//       struct val *val;
//       int i, j = 0;
//
//       val = bpf_map_lookup_elem(&map_spin_lock, &zero);
//       if (!val)
//           return -1;
//
//       bpf_spin_lock(&val->l);
//       bpf_for(i, 0, 10) {
//           j++;
//           /* Silence "unused variable" warnings. */
//           if (j == 10)
//               break;
//       }
//       bpf_spin_unlock(&val->l);
//
//       return 0;
//   }
#[link_section = "tc"]
#[no_mangle]
extern "C" fn bpf_loop_inside_locked_region() -> i32 {
    let zero: i32 = 0;
    let mut j: i32 = 0;

    let v = bpf_map_lookup_elem(&map_spin_lock, &zero) as *mut val;
    if v.is_null() {
        return -1;
    }

    unsafe {
        bpf_spin_lock(core::ptr::addr_of_mut!((*v).l));
        // bpf_for(i, 0, 10): the open-coded numeric iterator (`struct
        // bpf_iter_num { __u64 __opaque[1]; }`, the kfuncs declared above)
        let mut it: [u64; 1] = [0];
        let itp = it.as_mut_ptr() as *mut c_void;
        bpf_iter_num_new(itp, 0, 10);
        loop {
            let i = bpf_iter_num_next(itp);
            if i.is_null() {
                break;
            }
            j += 1;
            if j == 10 {
                break;
            }
        }
        bpf_iter_num_destroy(itp);
        bpf_spin_unlock(core::ptr::addr_of_mut!((*v).l));
    }

    0
}
