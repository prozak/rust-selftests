// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_subprog_insn_stats.c, translated
// by hand; include!d by the generated progs/verifier_subprog_insn_stats.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

// HAND: stats_async_leaf -- translate the C below (see the file comment)
//   __noinline __used
//   static int stats_async_leaf(void *map, __u32 *key, struct bpf_timer *timer)
//   {
//       return 0;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn stats_async_leaf(_map: *mut c_void, _key: *mut c_void, _timer: *mut c_void) -> i32 {
    0
}

// HAND: stats_async_schedule -- translate the C below (see the file comment)
//   __noinline __used
//   static __u64 stats_async_schedule(struct bpf_map *map, __u32 *key,
//                     struct timer_value *value, void *ctx)
//   {
//       asm volatile (
//           "r1 = %[timer];"
//           "r2 = %[stats_async_leaf];"
//           "call %[bpf_timer_set_callback];"
//           :
//           : [timer] "r" (value),
//             __imm_ptr(stats_async_leaf),
//             __imm(bpf_timer_set_callback)
//           : __clobber_common
//       );
//       return 0;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn stats_async_schedule(_map: *mut c_void, _key: *mut c_void, value: *mut c_void, _ctx: *mut c_void) -> u64 {
    // the C's asm: bpf_timer_set_callback (helper 170) on the timer with
    // stats_async_leaf as the callback
    unsafe {
        core::arch::asm!(
            "r1 = {timer};",
            "r2 = {cb};",
            "call 170;",
            timer = in(reg) value,
            cb = in(reg) stats_async_leaf as usize,
            out("r0") _,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
            options(nostack)
        );
    }
    0
}

// HAND: stats_async_nested_leaf -- translate the C below (see the file comment)
//   __noinline __used
//   static int stats_async_nested_leaf(void *map, __u32 *key, struct bpf_timer *timer)
//   {
//       return 0;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn stats_async_nested_leaf(_map: *mut c_void, _key: *mut c_void, _timer: *mut c_void) -> i32 {
    0
}

// HAND: stats_async_outer -- translate the C below (see the file comment)
//   __noinline __used
//   static int stats_async_outer(void *map, __u32 *key, struct bpf_timer *timer)
//   {
//       asm volatile (
//           "r1 = %[timer];"
//           "r2 = %[stats_async_nested_leaf];"
//           "call %[bpf_timer_set_callback];"
//           :
//           : [timer] "r" (timer),
//             __imm_ptr(stats_async_nested_leaf),
//             __imm(bpf_timer_set_callback)
//           : __clobber_common
//       );
//       return 0;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn stats_async_outer(_map: *mut c_void, _key: *mut c_void, timer: *mut c_void) -> i32 {
    // the C's asm: bpf_timer_set_callback (helper 170) on the timer with
    // stats_async_nested_leaf as the callback
    unsafe {
        core::arch::asm!(
            "r1 = {timer};",
            "r2 = {cb};",
            "call 170;",
            timer = in(reg) timer,
            cb = in(reg) stats_async_nested_leaf as usize,
            out("r0") _,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
            options(nostack)
        );
    }
    0
}

// HAND: stats_async_nested_schedule -- translate the C below (see the file comment)
//   __noinline __used
//   static __u64 stats_async_nested_schedule(struct bpf_map *map, __u32 *key,
//                        struct timer_value *value, void *ctx)
//   {
//       asm volatile (
//           "r1 = %[timer];"
//           "r2 = %[stats_async_outer];"
//           "call %[bpf_timer_set_callback];"
//           :
//           : [timer] "r" (value),
//             __imm_ptr(stats_async_outer),
//             __imm(bpf_timer_set_callback)
//           : __clobber_common
//       );
//       return 0;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn stats_async_nested_schedule(_map: *mut c_void, _key: *mut c_void, value: *mut c_void, _ctx: *mut c_void) -> u64 {
    // the C's asm: bpf_timer_set_callback (helper 170) on the timer with
    // stats_async_outer as the callback
    unsafe {
        core::arch::asm!(
            "r1 = {timer};",
            "r2 = {cb};",
            "call 170;",
            timer = in(reg) value,
            cb = in(reg) stats_async_outer as usize,
            out("r0") _,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
            options(nostack)
        );
    }
    0
}
