// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_arena_scalar.c, translated
// by hand; include!d by the generated progs/verifier_arena_scalar.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

use bpf_rs_core::helpers::bpf_loop;

// HAND: st_cb -- translate the C below (see the file comment)
//   static int st_cb(__u64 idx, void *ctx)
//   {
//       volatile long *p = *(volatile long **)ctx;
//
//       p[idx] = 7;
//       return 0;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn st_cb(idx: u64, ctx: *mut *mut i64) -> i64 {
    // volatile long *p = *(volatile long **)ctx; p[idx] = 7
    let p = unsafe { *ctx };
    unsafe { core::ptr::write_volatile(p.add(idx as usize), 7) };
    0
}

// HAND: st_in_callback -- translate the C below (see the file comment)
//   SEC("syscall")
//   __arena_scalar
//   __description("arena_scalar: store through a number in a callback")
//   __success __retval(0)
//   __load_if_JITed()
//   int st_in_callback(void *unused)
//   {
//       volatile long *p = bpf_arena_alloc_pages(&arena, NULL, 1, -1, 0);
//
//       if (!p)
//           return 100;
//       bpf_loop(4, st_cb, &p, 0);
//       return p[0] + p[3] + p[4] - 14;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn st_in_callback(_unused: *mut c_void) -> i32 {
    // arena pointers are scalars here (BPF_F_ARENA_SCALAR): plain accesses
    let mut p = unsafe { bpf_arena_alloc_pages(&arena as *const arena as *mut c_void, core::ptr::null_mut(), 1, -1, 0) } as *mut i64;
    if p.is_null() {
        return 100;
    }
    bpf_loop(4, st_cb, &mut p as *mut *mut i64, 0);
    unsafe {
        (core::ptr::read_volatile(p) + core::ptr::read_volatile(p.add(3)) + core::ptr::read_volatile(p.add(4)) - 14) as i32
    }
}
