// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/iters.c, translated
// by hand; include!d by the generated progs/iters.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

// Commit 1 of the iters translation carries the hand-asm family of the C
// (the BPF_NAKED programs of the generated progs/iters.rs) and the two C
// bodies that family needs: loop_cb5 (the bpf_loop callback of iter_remake)
// and iter_err_unsafe_c_loop, whose Rust-level calls of the three
// bpf_iter_num kfuncs give them a BTF prototype (llc emits one only for a
// real call, the asm `sym` references alone leave libbpf with "failed to
// find BTF info for global/extern symbol"); the other C bodies follow.
// MY_PID_GUARD() is empty outside REAL_TEST and has no counterpart here.
// Array stores index through raw pointers (no Rust bounds check: the C has
// none and the expected messages are about the index's bounds).

use core::mem::MaybeUninit;
use core::ptr::{addr_of, addr_of_mut, read_volatile};

// HAND: iter_err_unsafe_c_loop
//   SEC("?raw_tp")
//   __failure __msg("math between map_value pointer and register with unbounded min value is not allowed")
//   int iter_err_unsafe_c_loop(const void *ctx)
//   {
//       struct bpf_iter_num it;
//       int *v, i = zero; /* obscure initial value of i */
//
//       MY_PID_GUARD();
//
//       bpf_iter_num_new(&it, 0, 1000);
//       while ((v = bpf_iter_num_next(&it))) {
//           i++;
//       }
//       bpf_iter_num_destroy(&it);
//
//       small_arr[i] = 123; /* invalid */
//
//       return 0;
//   }
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn iter_err_unsafe_c_loop(_ctx: *mut c_void) -> i32 {
    let mut it = MaybeUninit::<bpf_iter_num>::uninit();
    let mut i: i32 = unsafe { read_volatile(addr_of!(zero)) }; /* obscure initial value of i */

    unsafe {
        bpf_iter_num_new(it.as_mut_ptr() as *mut c_void, 0, 1000);
        while !bpf_iter_num_next(it.as_mut_ptr() as *mut c_void).is_null() {
            i = i.wrapping_add(1);
        }
        bpf_iter_num_destroy(it.as_mut_ptr() as *mut c_void);

        addr_of_mut!(small_arr).cast::<i32>().wrapping_offset(i as isize).write(123); /* invalid */
    }

    0
}

// HAND: loop_cb5
//   __used
//   static int loop_cb5(int i, __u64 *ctx)
//   {
//       /* unsafe on a second iteration */
//       small_arr[*ctx] = i;
//       *ctx = 100500;
//       return 0;
//   }
// `small_arr[*ctx]` is a raw pointer store (no Rust bounds check: the
// C has none and the expected message is about the second iteration's
// out-of-bounds index).
#[no_mangle]
#[inline(never)]
extern "C" fn loop_cb5(i: i32, ctx: *mut u64) -> i32 {
    unsafe {
        /* unsafe on a second iteration */
        let idx = *ctx;
        core::ptr::addr_of_mut!(small_arr).cast::<i32>().wrapping_add(idx as usize).write(i);
        *ctx = 100500;
    }
    0
}
