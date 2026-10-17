// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_private_stack.c, translated
// by hand; include!d by the generated progs/verifier_private_stack.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

use bpf_rs_core::helpers::{bpf_map_lookup_elem, bpf_timer_init, bpf_timer_set_callback, bpf_timer_start};

// HAND: private_stack_exception_main_prog -- translate the C below (see the file comment)
//   SEC("fentry/bpf_fentry_test9")
//   __description("Private stack, exception in main prog")
//   __success __retval(0)
//   __arch_x86_64
//   __jited("    pushq    %r9")
//   __jited("...")
//   __jited("    callq")
//   __jited("    popq    %r9")
//   __arch_arm64
//   __jited("    stp    x29, x30, [sp, #-0x10]!")
//   __jited("    mov    x29, sp")
//   __jited("    stp    xzr, x26, [sp, #-0x10]!")
//   __jited("    mov    x26, sp")
//   __jited("    stp    x19, x20, [sp, #-0x10]!")
//   __jited("    stp    x21, x22, [sp, #-0x10]!")
//   __jited("    stp    x23, x24, [sp, #-0x10]!")
//   __jited("    stp    x25, x26, [sp, #-0x10]!")
//   __jited("    stp    x27, x28, [sp, #-0x10]!")
//   __jited("    mov    x27, {{.*}}")
//   __jited("    movk    x27, {{.*}}, lsl #16")
//   __jited("    movk    x27, {{.*}}")
//   __jited("    mrs    x10, TPIDR_EL{{[0-1]}}")
//   __jited("    add    x27, x27, x10")
//   __jited("    add    x25, x27, {{.*}}")
//   __jited("    mov    x0, #0x2a")
//   __jited("    str    x0, [x27]")
//   __jited("    mov    x0, #0x0")
//   __jited("    bl    0x{{.*}}")
//   __jited("    mov    x8, x0")
//   __jited("    ldp    x27, x28, [sp], #0x10")
//   int private_stack_exception_main_prog(void)
//   {
//       asm volatile ("            \
//       r1 = 42;            \
//       *(u64 *)(r10 - 512) = r1;    \
//   "    ::: __clobber_common);
//
//       bpf_throw(0);
//       return 0;
//   }
#[link_section = "fentry/bpf_fentry_test9"]
#[no_mangle]
extern "C" fn private_stack_exception_main_prog() -> i32 {
    unsafe {
        core::arch::asm!("r1 = 42;", out("r0") _, out("r1") _, out("r2") _, out("r3") _, out("r4") _, out("r5") _, options(nostack));
        bpf_throw(0);
    }
    0
}

// HAND: subprog_exception -- translate the C below (see the file comment)
//   __used static int subprog_exception(void)
//   {
//       bpf_throw(0);
//       return 0;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn subprog_exception() -> i32 {
    unsafe { bpf_throw(0) };
    0
}

// HAND: private_stack_exception_sub_prog -- translate the C below (see the file comment)
//   SEC("fentry/bpf_fentry_test9")
//   __description("Private stack, exception in subprog")
//   __success __retval(0)
//   __arch_x86_64
//   __jited("    movq    %rdi, -0x200(%r9)")
//   __jited("    pushq    %r9")
//   __jited("...")
//   __jited("    callq")
//   __jited("    popq    %r9")
//   __arch_arm64
//   __jited("    stp    x27, x28, [sp, #-0x10]!")
//   __jited("    mov    x27, {{.*}}")
//   __jited("    movk    x27, {{.*}}, lsl #16")
//   __jited("    movk    x27, {{.*}}")
//   __jited("    mrs    x10, TPIDR_EL{{[0-1]}}")
//   __jited("    add    x27, x27, x10")
//   __jited("    add    x25, x27, {{.*}}")
//   __jited("    mov    x0, #0x2a")
//   __jited("    str    x0, [x27]")
//   __jited("    bl    0x{{.*}}")
//   __jited("    mov    x8, x0")
//   __jited("    ldp    x27, x28, [sp], #0x10")
//   int private_stack_exception_sub_prog(void)
//   {
//       asm volatile ("            \
//       r1 = 42;            \
//       *(u64 *)(r10 - 512) = r1;    \
//       call subprog_exception;        \
//   "    ::: __clobber_common);
//
//       return 0;
//   }
#[link_section = "fentry/bpf_fentry_test9"]
#[no_mangle]
extern "C" fn private_stack_exception_sub_prog() -> i32 {
    unsafe {
        core::arch::asm!(
            "r1 = 42;",
            "call {subprog_exception};",
            subprog_exception = sym subprog_exception,
            out("r0") _, out("r1") _, out("r2") _, out("r3") _, out("r4") _, out("r5") _,
            options(nostack)
        );
    }
    0
}

// HAND: subprog2 -- translate the C below (see the file comment)
//   int glob;
//   __noinline static void subprog2(int *val)
//   {
//       glob += val[0] * 2;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn subprog2(val: *mut i32) {
    unsafe { glob = glob.wrapping_add((*val).wrapping_mul(2)) };
}

// HAND: subprog1 -- translate the C below (see the file comment)
//   __noinline static void subprog1(int *val)
//   {
//       int tmp[64] = {};
//
//       tmp[0] = *val;
//       subprog2(tmp);
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn subprog1(val: *mut i32) {
    let mut tmp = [0i32; 64];
    tmp[0] = unsafe { *val };
    subprog2(tmp.as_mut_ptr());
}

// HAND: timer_cb1 -- translate the C below (see the file comment)
//   __noinline static int timer_cb1(void *map, int *key, struct bpf_timer *timer)
//   {
//       subprog1(key);
//       return 0;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn timer_cb1(_map: *mut c_void, key: *mut i32, _timer: *mut bpf_timer) -> i64 {
    subprog1(key);
    0
}

// HAND: timer_cb2 -- translate the C below (see the file comment)
//   __noinline static int timer_cb2(void *map, int *key, struct bpf_timer *timer)
//   {
//       return 0;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn timer_cb2(_map: *mut c_void, _key: *mut i32, _timer: *mut bpf_timer) -> i64 {
    0
}

// HAND: private_stack_async_callback_1 -- translate the C below (see the file comment)
//   SEC("fentry/bpf_fentry_test9")
//   __description("Private stack, async callback, not nested")
//   __success __retval(0)
//   __arch_x86_64
//   __jited("    movabsq    $0x{{.*}}, %r9")
//   __arch_arm64
//   __jited("    mrs    x10, TPIDR_EL{{[0-1]}}")
//   __jited("    add    x27, x27, x10")
//   __jited("    add    x25, x27, {{.*}}")
//   int private_stack_async_callback_1(void)
//   {
//       struct bpf_timer *arr_timer;
//       int array_key = 0;
//
//       arr_timer = bpf_map_lookup_elem(&array, &array_key);
//       if (!arr_timer)
//           return 0;
//
//       bpf_timer_init(arr_timer, &array, 1);
//       bpf_timer_set_callback(arr_timer, timer_cb2);
//       bpf_timer_start(arr_timer, 0, 0);
//       subprog1(&array_key);
//       return 0;
//   }
#[link_section = "fentry/bpf_fentry_test9"]
#[no_mangle]
extern "C" fn private_stack_async_callback_1() -> i32 {
    let mut array_key: i32 = 0;
    let arr_timer = bpf_map_lookup_elem(&array, &array_key) as *mut bpf_timer;
    if arr_timer.is_null() {
        return 0;
    }
    bpf_timer_init(arr_timer, &array, 1);
    bpf_timer_set_callback(arr_timer, timer_cb2);
    bpf_timer_start(arr_timer, 0, 0);
    subprog1(&mut array_key);
    0
}

// HAND: private_stack_async_callback_2 -- translate the C below (see the file comment)
//   SEC("fentry/bpf_fentry_test9")
//   __description("Private stack, async callback, potential nesting")
//   __success __retval(0)
//   __load_if_JITed()
//   __log_level(4) __msg("stack depth max 272")
//   __msg("subprog 0 (private_stack_async_callback_2) main {{.*}} stack 8")
//   __msg("subprog 1 (timer_cb1) static {{.*}} stack 0")
//   __msg("subprog 2 (subprog1) static {{.*}} stack 256")
//   __msg("subprog 3 (subprog2) static {{.*}} stack 0")
//   __arch_x86_64
//   __jited("    subq    $0x100, %rsp")
//   __arch_arm64
//   __jited("    sub    sp, sp, #0x100")
//   int private_stack_async_callback_2(void)
//   {
//       struct bpf_timer *arr_timer;
//       int array_key = 0;
//
//       arr_timer = bpf_map_lookup_elem(&array, &array_key);
//       if (!arr_timer)
//           return 0;
//
//       bpf_timer_init(arr_timer, &array, 1);
//       bpf_timer_set_callback(arr_timer, timer_cb1);
//       bpf_timer_start(arr_timer, 0, 0);
//       subprog1(&array_key);
//       return 0;
//   }
#[link_section = "fentry/bpf_fentry_test9"]
#[no_mangle]
extern "C" fn private_stack_async_callback_2() -> i32 {
    let mut array_key: i32 = 0;
    let arr_timer = bpf_map_lookup_elem(&array, &array_key) as *mut bpf_timer;
    if arr_timer.is_null() {
        return 0;
    }
    bpf_timer_init(arr_timer, &array, 1);
    bpf_timer_set_callback(arr_timer, timer_cb1);
    bpf_timer_start(arr_timer, 0, 0);
    subprog1(&mut array_key);
    0
}

// HAND: private_stack_max_depth -- translate the C below (see the file comment)
//   SEC("fentry/bpf_fentry_test9")
//   __description("private stack, max stack depth is private stack")
//   __success
//   __log_level(4) __msg("stack depth max 256")
//   __msg("subprog 0 (private_stack_max_depth) main {{.*}} stack 8")
//   __msg("subprog 1 (subprog1) static insns_self {{[0-9]+}} insns_total {{[0-9]+}} stack 256")
//   __msg("subprog 2 (subprog2) static insns_self {{[0-9]+}} insns_total {{[0-9]+}} stack 0")
//   int private_stack_max_depth(void)
//   {
//       int x = 0;
//
//       subprog1(&x);
//       return 0;
//   }
#[link_section = "fentry/bpf_fentry_test9"]
#[no_mangle]
extern "C" fn private_stack_max_depth() -> i32 {
    let mut x: i32 = 0;
    subprog1(&mut x);
    0
}
