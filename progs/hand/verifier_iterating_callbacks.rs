// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_iterating_callbacks.c, translated
// by hand; include!d by the generated progs/verifier_iterating_callbacks.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

use bpf_rs_core::helpers::{bpf_find_vma, bpf_for_each_map_elem, bpf_get_current_task_btf, bpf_loop, bpf_probe_read_user, bpf_user_ringbuf_drain};

const ARR_SZ: u64 = 1000000;
const ARR2_SZ: u64 = 1000;
const ARR_LONG_SZ: u64 = 1000;

/// struct iter_limit_bug_ctx, the callback's context.
#[allow(non_camel_case_types)]
#[repr(C)]
struct iter_limit_bug_ctx {
    a: u64,
    b: u64,
    c: u64,
}

/// bpf_experimental.h's `can_loop` / `cond_break`: a may_goto (opcode 0xe5)
/// to the asm's label block (the arena_htab_asm.rs encoding).
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

/// `barrier_var(v)`: `asm volatile("" : "+r"(v))`.
#[inline(always)]
fn barrier_var(v: &mut u64) {
    unsafe { core::arch::asm!("{0} = {0}", inout(reg) *v, options(nostack, preserves_flags)) };
}

/// The C's always_inline oob_state_machine.
#[inline(always)]
fn oob_state_machine(ctx: *mut num_context) -> i64 {
    unsafe {
        match (*ctx).i {
            0 => (*ctx).i = 1,
            1 => (*ctx).i = 32,
            _ => {}
        }
    }
    0
}

// HAND: unsafe_on_2nd_iter_cb -- translate the C below (see the file comment)
//   static int unsafe_on_2nd_iter_cb(__u32 idx, struct buf_context *ctx)
//   {
//       if (idx == 0) {
//           ctx->buf = (char *)(0xDEAD);
//           return 0;
//       }
//
//       if (bpf_probe_read_user(ctx->buf, 8, (void *)(0xBADC0FFEE)))
//           return 1;
//
//       return 0;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn unsafe_on_2nd_iter_cb(idx: u64, ctx: *mut buf_context) -> i64 {
    if idx == 0 {
        unsafe { (*ctx).buf = 0xDEAD as *mut i8 };
        return 0;
    }
    if bpf_probe_read_user(unsafe { (*ctx).buf } as *mut c_void, 8, 0xBADC0FFEEusize as *const c_void) != 0 {
        return 1;
    }
    0
}

// HAND: unsafe_on_2nd_iter -- translate the C below (see the file comment)
//   SEC("?raw_tp")
//   __failure __msg("R1 type=scalar expected=fp")
//   int unsafe_on_2nd_iter(void *unused)
//   {
//       char buf[4];
//       struct buf_context loop_ctx = { .buf = buf };
//
//       bpf_loop(100, unsafe_on_2nd_iter_cb, &loop_ctx, 0);
//       return 0;
//   }
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn unsafe_on_2nd_iter(_unused: *mut c_void) -> i32 {
    let mut lbuf = core::mem::MaybeUninit::<[i8; 4]>::uninit();
    let mut loop_ctx = buf_context { buf: lbuf.as_mut_ptr() as *mut i8 };
    bpf_loop(100, unsafe_on_2nd_iter_cb, &mut loop_ctx, 0);
    0
}

// HAND: unsafe_on_zero_iter_cb -- translate the C below (see the file comment)
//   static int unsafe_on_zero_iter_cb(__u32 idx, struct num_context *ctx)
//   {
//       ctx->i = 0;
//       return 0;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn unsafe_on_zero_iter_cb(_idx: u64, ctx: *mut num_context) -> i64 {
    unsafe { (*ctx).i = 0 };
    0
}

// HAND: unsafe_on_zero_iter -- translate the C below (see the file comment)
//   SEC("?raw_tp")
//   __failure __msg("invalid access to map value, value_size=2 off=32 size=1")
//   int unsafe_on_zero_iter(void *unused)
//   {
//       struct num_context loop_ctx = { .i = 32 };
//
//       bpf_loop(100, unsafe_on_zero_iter_cb, &loop_ctx, 0);
//       return choice_arr[loop_ctx.i];
//   }
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn unsafe_on_zero_iter(_unused: *mut c_void) -> i32 {
    let mut loop_ctx = num_context { i: 32, j: 0 };
    bpf_loop(100, unsafe_on_zero_iter_cb, &mut loop_ctx, 0);
    unsafe { *core::ptr::addr_of!(choice_arr).cast::<u8>().add(loop_ctx.i as usize) as i32 }
}

// HAND: widening_cb -- translate the C below (see the file comment)
//   static int widening_cb(__u32 idx, struct num_context *ctx)
//   {
//       ++ctx->i;
//       return 0;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn widening_cb(_idx: u64, ctx: *mut num_context) -> i64 {
    unsafe { (*ctx).i = (*ctx).i.wrapping_add(1) };
    0
}

// HAND: widening -- translate the C below (see the file comment)
//   SEC("?raw_tp")
//   __success
//   int widening(void *unused)
//   {
//       struct num_context loop_ctx = { .i = 0, .j = 1 };
//
//       bpf_loop(100, widening_cb, &loop_ctx, 0);
//       /* loop_ctx.j is not changed during callback iteration,
//        * verifier should not apply widening to it.
//        */
//       return choice_arr[loop_ctx.j];
//   }
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn widening(_unused: *mut c_void) -> i32 {
    let mut loop_ctx = num_context { i: 0, j: 1 };
    bpf_loop(100, widening_cb, &mut loop_ctx, 0);
    // loop_ctx.j is not changed during callback iteration: the verifier
    // should not apply widening to it
    unsafe { *core::ptr::addr_of!(choice_arr).cast::<u8>().add(loop_ctx.j as usize) as i32 }
}

// HAND: loop_detection_cb -- translate the C below (see the file comment)
//   static int loop_detection_cb(__u32 idx, struct num_context *ctx)
//   {
//       for (;;) {}
//       return 0;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn loop_detection_cb(_idx: u64, _ctx: *mut num_context) -> i64 {
    loop {}
}

// HAND: loop_detection -- translate the C below (see the file comment)
//   SEC("?raw_tp")
//   __failure __msg("infinite loop detected")
//   int loop_detection(void *unused)
//   {
//       struct num_context loop_ctx = { .i = 0 };
//
//       bpf_loop(100, loop_detection_cb, &loop_ctx, 0);
//       return 0;
//   }
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn loop_detection(_unused: *mut c_void) -> i32 {
    let mut loop_ctx = num_context { i: 0, j: 0 };
    bpf_loop(100, loop_detection_cb, &mut loop_ctx, 0);
    0
}

// HAND: for_each_map_elem_cb -- translate the C below (see the file comment)
//   static __u64 for_each_map_elem_cb(struct bpf_map *map, __u32 *key, __u64 *val, void *data)
//   {
//       return oob_state_machine(data);
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn for_each_map_elem_cb(_map: *mut map, _key: *mut u32, _val: *mut u64, data: *mut num_context) -> i64 {
    oob_state_machine(data)
}

// HAND: unsafe_for_each_map_elem -- translate the C below (see the file comment)
//   SEC("?raw_tp")
//   __failure __msg("invalid access to map value, value_size=2 off=32 size=1")
//   int unsafe_for_each_map_elem(void *unused)
//   {
//       struct num_context loop_ctx = { .i = 0 };
//
//       bpf_for_each_map_elem(&map, for_each_map_elem_cb, &loop_ctx, 0);
//       return choice_arr[loop_ctx.i];
//   }
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn unsafe_for_each_map_elem(_unused: *mut c_void) -> i32 {
    let mut loop_ctx = num_context { i: 0, j: 0 };
    bpf_for_each_map_elem(&map, for_each_map_elem_cb, &mut loop_ctx, 0);
    unsafe { *core::ptr::addr_of!(choice_arr).cast::<u8>().add(loop_ctx.i as usize) as i32 }
}

// HAND: ringbuf_drain_cb -- translate the C below (see the file comment)
//   static __u64 ringbuf_drain_cb(struct bpf_dynptr *dynptr, void *data)
//   {
//       return oob_state_machine(data);
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn ringbuf_drain_cb(_dynptr: *mut c_void, data: *mut num_context) -> i64 {
    oob_state_machine(data)
}

// HAND: unsafe_ringbuf_drain -- translate the C below (see the file comment)
//   SEC("?raw_tp")
//   __failure __msg("invalid access to map value, value_size=2 off=32 size=1")
//   int unsafe_ringbuf_drain(void *unused)
//   {
//       struct num_context loop_ctx = { .i = 0 };
//
//       bpf_user_ringbuf_drain(&ringbuf, ringbuf_drain_cb, &loop_ctx, 0);
//       return choice_arr[loop_ctx.i];
//   }
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn unsafe_ringbuf_drain(_unused: *mut c_void) -> i32 {
    let mut loop_ctx = num_context { i: 0, j: 0 };
    bpf_user_ringbuf_drain(&ringbuf, ringbuf_drain_cb, &mut loop_ctx, 0);
    unsafe { *core::ptr::addr_of!(choice_arr).cast::<u8>().add(loop_ctx.i as usize) as i32 }
}

// HAND: find_vma_cb -- translate the C below (see the file comment)
//   static __u64 find_vma_cb(struct task_struct *task, struct vm_area_struct *vma, void *data)
//   {
//       return oob_state_machine(data);
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn find_vma_cb(_task: *mut c_void, _vma: *mut c_void, data: *mut num_context) -> i64 {
    oob_state_machine(data)
}

// HAND: unsafe_find_vma -- translate the C below (see the file comment)
//   SEC("?raw_tp")
//   __failure __msg("invalid access to map value, value_size=2 off=32 size=1")
//   int unsafe_find_vma(void *unused)
//   {
//       struct task_struct *task = bpf_get_current_task_btf();
//       struct num_context loop_ctx = { .i = 0 };
//
//       bpf_find_vma(task, 0, find_vma_cb, &loop_ctx, 0);
//       return choice_arr[loop_ctx.i];
//   }
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn unsafe_find_vma(_unused: *mut c_void) -> i32 {
    let task: *mut c_void = bpf_get_current_task_btf();
    let mut loop_ctx = num_context { i: 0, j: 0 };
    bpf_find_vma(task, 0, find_vma_cb, &mut loop_ctx, 0);
    unsafe { *core::ptr::addr_of!(choice_arr).cast::<u8>().add(loop_ctx.i as usize) as i32 }
}

// HAND: iter_limit_cb -- translate the C below (see the file comment)
//   static int iter_limit_cb(__u32 idx, struct num_context *ctx)
//   {
//       ctx->i++;
//       return 0;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn iter_limit_cb(_idx: u64, ctx: *mut num_context) -> i64 {
    unsafe { (*ctx).i = (*ctx).i.wrapping_add(1) };
    0
}

// HAND: bpf_loop_iter_limit_ok -- translate the C below (see the file comment)
//   SEC("?raw_tp")
//   __success
//   int bpf_loop_iter_limit_ok(void *unused)
//   {
//       struct num_context ctx = { .i = 0 };
//
//       bpf_loop(1, iter_limit_cb, &ctx, 0);
//       return choice_arr[ctx.i];
//   }
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn bpf_loop_iter_limit_ok(_unused: *mut c_void) -> i32 {
    let mut ctx = num_context { i: 0, j: 0 };
    bpf_loop(1, iter_limit_cb, &mut ctx, 0);
    unsafe { *core::ptr::addr_of!(choice_arr).cast::<u8>().add(ctx.i as usize) as i32 }
}

// HAND: bpf_loop_iter_limit_overflow -- translate the C below (see the file comment)
//   SEC("?raw_tp")
//   __failure __msg("invalid access to map value, value_size=2 off=2 size=1")
//   int bpf_loop_iter_limit_overflow(void *unused)
//   {
//       struct num_context ctx = { .i = 0 };
//
//       bpf_loop(2, iter_limit_cb, &ctx, 0);
//       return choice_arr[ctx.i];
//   }
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn bpf_loop_iter_limit_overflow(_unused: *mut c_void) -> i32 {
    let mut ctx = num_context { i: 0, j: 0 };
    bpf_loop(2, iter_limit_cb, &mut ctx, 0);
    unsafe { *core::ptr::addr_of!(choice_arr).cast::<u8>().add(ctx.i as usize) as i32 }
}

// HAND: iter_limit_level2a_cb -- translate the C below (see the file comment)
//   static int iter_limit_level2a_cb(__u32 idx, struct num_context *ctx)
//   {
//       ctx->i += 100;
//       return 0;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn iter_limit_level2a_cb(_idx: u64, ctx: *mut num_context) -> i64 {
    unsafe { (*ctx).i = (*ctx).i.wrapping_add(100) };
    0
}

// HAND: iter_limit_level2b_cb -- translate the C below (see the file comment)
//   static int iter_limit_level2b_cb(__u32 idx, struct num_context *ctx)
//   {
//       ctx->i += 10;
//       return 0;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn iter_limit_level2b_cb(_idx: u64, ctx: *mut num_context) -> i64 {
    unsafe { (*ctx).i = (*ctx).i.wrapping_add(10) };
    0
}

// HAND: iter_limit_level1_cb -- translate the C below (see the file comment)
//   static int iter_limit_level1_cb(__u32 idx, struct num_context *ctx)
//   {
//       ctx->i += 1;
//       bpf_loop(1, iter_limit_level2a_cb, ctx, 0);
//       bpf_loop(1, iter_limit_level2b_cb, ctx, 0);
//       return 0;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn iter_limit_level1_cb(_idx: u64, ctx: *mut num_context) -> i64 {
    unsafe { (*ctx).i = (*ctx).i.wrapping_add(1) };
    bpf_loop(1, iter_limit_level2a_cb, ctx, 0);
    bpf_loop(1, iter_limit_level2b_cb, ctx, 0);
    0
}

// HAND: bpf_loop_iter_limit_nested -- translate the C below (see the file comment)
//   /* Check that path visiting every callback function once had been
//    * reached by verifier. Variables 'ctx{1,2}i' below serve as flags,
//    * with each decimal digit corresponding to a callback visit marker.
//    */
//   SEC("socket")
//   __success __retval(111111)
//   int bpf_loop_iter_limit_nested(void *unused)
//   {
//       struct num_context ctx1 = { .i = 0 };
//       struct num_context ctx2 = { .i = 0 };
//       __u64 a, b, c;
//
//       bpf_loop(1, iter_limit_level1_cb, &ctx1, 0);
//       bpf_loop(1, iter_limit_level1_cb, &ctx2, 0);
//       a = ctx1.i;
//       b = ctx2.i;
//       /* Force 'ctx1.i' and 'ctx2.i' precise. */
//       c = choice_arr[(a + b) % 2];
//       /* This makes 'c' zero, but neither clang nor verifier know it. */
//       c /= 10;
//       /* Make sure that verifier does not visit 'impossible' states:
//        * enumerate all possible callback visit masks.
//        */
//       if (a != 0 && a != 1 && a != 11 && a != 101 && a != 111 &&
//           b != 0 && b != 1 && b != 11 && b != 101 && b != 111)
//           asm volatile ("r0 /= 0;" ::: "r0");
//       return 1000 * a + b + c;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn bpf_loop_iter_limit_nested(_unused: *mut c_void) -> i32 {
    let mut ctx1 = num_context { i: 0, j: 0 };
    let mut ctx2 = num_context { i: 0, j: 0 };

    bpf_loop(1, iter_limit_level1_cb, &mut ctx1, 0);
    bpf_loop(1, iter_limit_level1_cb, &mut ctx2, 0);
    let a: u64 = ctx1.i;
    let b: u64 = ctx2.i;
    // force ctx1.i and ctx2.i precise
    let mut c: u64 = unsafe { *core::ptr::addr_of!(choice_arr).cast::<u8>().add((a.wrapping_add(b) % 2) as usize) } as u64;
    // this makes c zero, but neither the compiler nor the verifier know it
    c /= 10;
    // make sure the verifier does not visit 'impossible' states:
    // enumerate all possible callback visit masks
    if a != 0 && a != 1 && a != 11 && a != 101 && a != 111
        && b != 0 && b != 1 && b != 11 && b != 101 && b != 111
    {
        unsafe { core::arch::asm!("r0 /= 0;", out("r0") _, options(nostack)) };
    }
    (1000u64.wrapping_mul(a).wrapping_add(b).wrapping_add(c)) as i32
}

// HAND: iter_limit_bug -- translate the C below (see the file comment)
//   SEC("tc")
//   __failure
//   __flag(BPF_F_TEST_STATE_FREQ)
//   int iter_limit_bug(struct __sk_buff *skb)
//   {
//       struct iter_limit_bug_ctx ctx = { 7, 7, 7 };
//
//       bpf_loop(2, iter_limit_bug_cb, &ctx, 0);
//
//       /* This is the same as C code below,
//        * written in assembly to guarantee checks order.
//        *
//        *   if (ctx.a == 42 && ctx.b == 42 && ctx.c == 7)
//        *     asm volatile("r1 /= 0;":::"r1");
//        */
//       asm volatile (
//       "r1 = *(u64 *)%[ctx_a];"
//       "if r1 != 42 goto 1f;"
//       "r1 = *(u64 *)%[ctx_b];"
//       "if r1 != 42 goto 1f;"
//       "r1 = *(u64 *)%[ctx_c];"
//       "if r1 != 7 goto 1f;"
//       "r1 /= 0;"
//       "1:"
//       :
//       : [ctx_a]"m"(ctx.a),
//         [ctx_b]"m"(ctx.b),
//         [ctx_c]"m"(ctx.c)
//       : "r1"
//       );
//       return 0;
//   }
#[link_section = "tc"]
#[no_mangle]
extern "C" fn iter_limit_bug(_skb: *mut __sk_buff) -> i32 {
    let mut ctx = iter_limit_bug_ctx { a: 7, b: 7, c: 7 };

    // bpf_loop with the naked callback
    let bpf_loop_raw: extern "C" fn(u32, usize, *mut c_void, u64) -> i64 =
        unsafe { core::mem::transmute(181usize) };
    bpf_loop_raw(2, iter_limit_bug_cb as usize, &mut ctx as *mut iter_limit_bug_ctx as *mut c_void, 0);

    // The C's asm, its "m" operands read through a pointer to ctx:
    //   if (ctx.a == 42 && ctx.b == 42 && ctx.c == 7)
    //       asm volatile("r1 /= 0;":::"r1");
    unsafe {
        core::arch::asm!(
            "r1 = *(u64 *)({ctx} + 0);",
            "if r1 != 42 goto 1f;",
            "r1 = *(u64 *)({ctx} + 8);",
            "if r1 != 42 goto 1f;",
            "r1 = *(u64 *)({ctx} + 16);",
            "if r1 != 7 goto 1f;",
            "r1 /= 0;",
            "1:",
            ctx = in(reg) &mut ctx as *mut iter_limit_bug_ctx,
            out("r1") _,
            options(nostack)
        );
    }
    0
}

// HAND: cond_break1 -- translate the C below (see the file comment)
//   SEC("socket")
//   __success __retval(0xd495cdc0)
//   int cond_break1(const void *ctx)
//   {
//       unsigned long i;
//       unsigned int sum = 0;
//
//       for (i = zero; i < ARR_SZ && can_loop; i++)
//           sum += i;
//       for (i = zero; i < ARR_SZ; i++) {
//           barrier_var(i);
//           sum += i + arr[i];
//           cond_break;
//       }
//
//       return sum;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn cond_break1(_ctx: *const c_void) -> i32 {
    let mut sum: u32 = 0;

    let mut i: u64 = unsafe { zero } as u64;
    while i < ARR_SZ && unsafe { can_loop() } {
        sum = sum.wrapping_add(i as u32);
        i += 1;
    }
    let mut i: u64 = unsafe { zero } as u64;
    while i < ARR_SZ {
        barrier_var(&mut i);
        sum = sum.wrapping_add(i.wrapping_add(unsafe { *core::ptr::addr_of!(arr).cast::<i8>().add(i as usize) } as i64 as u64) as u32);
        if !unsafe { can_loop() } {
            break; // cond_break
        }
        i += 1;
    }

    sum as i32
}

// HAND: cond_break2 -- translate the C below (see the file comment)
//   SEC("socket")
//   __success __retval(999000000)
//   int cond_break2(const void *ctx)
//   {
//       int i, j;
//       int sum = 0;
//
//       for (i = zero; i < 1000 && can_loop; i++)
//           for (j = zero; j < 1000; j++) {
//               sum += i + j;
//               cond_break;
//       }
//       return sum;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn cond_break2(_ctx: *const c_void) -> i32 {
    let mut sum: i32 = 0;

    let mut i: i32 = unsafe { zero };
    while i < 1000 && unsafe { can_loop() } {
        let mut j: i32 = unsafe { zero };
        while j < 1000 {
            sum = sum.wrapping_add(i.wrapping_add(j));
            if !unsafe { can_loop() } {
                break; // cond_break
            }
            j += 1;
        }
        i += 1;
    }
    sum
}

// HAND: loop -- translate the C below (see the file comment)
//   static __noinline int loop(void)
//   {
//       int i, sum = 0;
//
//       for (i = zero; i <= 1000000 && can_loop; i++)
//           sum += i;
//
//       return sum;
//   }
#[export_name = "loop"]
#[inline(never)]
extern "C" fn loop_() -> i32 {
    let mut sum: i32 = 0;
    let mut i: i32 = unsafe { zero };
    while i <= 1000000 && unsafe { can_loop() } {
        sum = sum.wrapping_add(i);
        i += 1;
    }
    sum
}

// HAND: cond_break3 -- translate the C below (see the file comment)
//   SEC("socket")
//   __success __retval(0x6a5a2920)
//   int cond_break3(const void *ctx)
//   {
//       return loop();
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn cond_break3(_ctx: *const c_void) -> i32 {
    loop_()
}

// HAND: cond_break4 -- translate the C below (see the file comment)
//   SEC("socket")
//   __success __retval(1)
//   int cond_break4(const void *ctx)
//   {
//       int cnt = zero;
//
//       for (;;) {
//           /* should eventually break out of the loop */
//           cond_break;
//           cnt++;
//       }
//       /* if we looped a bit, it's a success */
//       return cnt > 1 ? 1 : 0;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn cond_break4(_ctx: *const c_void) -> i32 {
    let mut cnt: i32 = unsafe { zero };
    loop {
        // should eventually break out of the loop
        if !unsafe { can_loop() } {
            break;
        }
        cnt += 1;
    }
    // if we looped a bit, it's a success
    if cnt > 1 { 1 } else { 0 }
}

// HAND: static_subprog -- translate the C below (see the file comment)
//   static __noinline int static_subprog(void)
//   {
//       int cnt = zero;
//
//       for (;;) {
//           cond_break;
//           cnt++;
//       }
//
//       return cnt;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn static_subprog() -> i32 {
    let mut cnt: i32 = unsafe { zero };
    loop {
        if !unsafe { can_loop() } {
            break;
        }
        cnt += 1;
    }
    cnt
}

// HAND: cond_break5 -- translate the C below (see the file comment)
//   SEC("socket")
//   __success __retval(1)
//   int cond_break5(const void *ctx)
//   {
//       int cnt1 = zero, cnt2;
//
//       for (;;) {
//           cond_break;
//           cnt1++;
//       }
//
//       cnt2 = static_subprog();
//
//       /* main and subprog have to loop a bit */
//       return cnt1 > 1 && cnt2 > 1 ? 1 : 0;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn cond_break5(_ctx: *const c_void) -> i32 {
    let mut cnt1: i32 = unsafe { zero };
    loop {
        if !unsafe { can_loop() } {
            break;
        }
        cnt1 += 1;
    }
    let cnt2 = static_subprog();
    // main and subprog have to loop a bit
    if cnt1 > 1 && cnt2 > 1 { 1 } else { 0 }
}

// HAND: loop_inside_iter -- translate the C below (see the file comment)
//   SEC("socket")
//   __success __flag(BPF_F_TEST_STATE_FREQ)
//   int loop_inside_iter(const void *ctx)
//   {
//       struct bpf_iter_num it;
//       int *v, sum = 0;
//       __u64 i = 0;
//
//       bpf_iter_num_new(&it, 0, ARR2_SZ);
//       while ((v = bpf_iter_num_next(&it))) {
//           if (i < ARR2_SZ)
//               sum += arr2[i++];
//       }
//       bpf_iter_num_destroy(&it);
//       return sum;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn loop_inside_iter(_ctx: *const c_void) -> i32 {
    let mut it = core::mem::MaybeUninit::<[u64; 1]>::uninit();
    let mut sum: i32 = 0;
    let mut i: u64 = 0;

    unsafe {
        bpf_iter_num_new(it.as_mut_ptr() as *mut c_void, 0, ARR2_SZ as i32);
        while !bpf_iter_num_next(it.as_mut_ptr() as *mut c_void).is_null() {
            if i < ARR2_SZ {
                sum = sum.wrapping_add(*core::ptr::addr_of!(arr2).cast::<i8>().add(i as usize) as i32);
                i += 1;
            }
        }
        bpf_iter_num_destroy(it.as_mut_ptr() as *mut c_void);
    }
    sum
}

// HAND: loop_inside_iter_signed -- translate the C below (see the file comment)
//   SEC("socket")
//   __success __flag(BPF_F_TEST_STATE_FREQ)
//   int loop_inside_iter_signed(const void *ctx)
//   {
//       struct bpf_iter_num it;
//       int *v, sum = 0;
//       long i = 0;
//
//       bpf_iter_num_new(&it, 0, ARR2_SZ);
//       while ((v = bpf_iter_num_next(&it))) {
//           if (i < ARR2_SZ && i >= 0)
//               sum += arr2[i++];
//       }
//       bpf_iter_num_destroy(&it);
//       return sum;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn loop_inside_iter_signed(_ctx: *const c_void) -> i32 {
    let mut it = core::mem::MaybeUninit::<[u64; 1]>::uninit();
    let mut sum: i32 = 0;
    let mut i: i64 = 0;

    unsafe {
        bpf_iter_num_new(it.as_mut_ptr() as *mut c_void, 0, ARR2_SZ as i32);
        while !bpf_iter_num_next(it.as_mut_ptr() as *mut c_void).is_null() {
            if i < ARR2_SZ as i64 && i >= 0 {
                sum = sum.wrapping_add(*core::ptr::addr_of!(arr2).cast::<i8>().add(i as usize) as i32);
                i += 1;
            }
        }
        bpf_iter_num_destroy(it.as_mut_ptr() as *mut c_void);
    }
    sum
}

// HAND: loop_inside_iter_volatile_limit -- translate the C below (see the file comment)
//   SEC("socket")
//   __success __flag(BPF_F_TEST_STATE_FREQ)
//   int loop_inside_iter_volatile_limit(const void *ctx)
//   {
//       struct bpf_iter_num it;
//       int *v, sum = 0;
//       __u64 i = 0;
//
//       bpf_iter_num_new(&it, 0, ARR2_SZ);
//       while ((v = bpf_iter_num_next(&it))) {
//           if (i < limit)
//               sum += arr2[i++];
//       }
//       bpf_iter_num_destroy(&it);
//       return sum;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn loop_inside_iter_volatile_limit(_ctx: *const c_void) -> i32 {
    let mut it = core::mem::MaybeUninit::<[u64; 1]>::uninit();
    let mut sum: i32 = 0;
    let mut i: u64 = 0;

    unsafe {
        bpf_iter_num_new(it.as_mut_ptr() as *mut c_void, 0, ARR2_SZ as i32);
        while !bpf_iter_num_next(it.as_mut_ptr() as *mut c_void).is_null() {
            // `const volatile int limit`: read each time
            if i < core::ptr::read_volatile(core::ptr::addr_of!(limit)) as i64 as u64 {
                sum = sum.wrapping_add(*core::ptr::addr_of!(arr2).cast::<i8>().add(i as usize) as i32);
                i += 1;
            }
        }
        bpf_iter_num_destroy(it.as_mut_ptr() as *mut c_void);
    }
    sum
}

// HAND: test1 -- translate the C below (see the file comment)
//   SEC("socket")
//   __success
//   int test1(const void *ctx)
//   {
//       long i;
//
//       for (i = 0; i < ARR_LONG_SZ && can_loop; i++)
//           arr_long[i] = i;
//       return 0;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn test1(_ctx: *const c_void) -> i32 {
    let mut i: i64 = 0;
    while i < ARR_LONG_SZ as i64 && unsafe { can_loop() } {
        unsafe { *core::ptr::addr_of_mut!(arr_long).cast::<i64>().add(i as usize) = i };
        i += 1;
    }
    0
}

// HAND: test2 -- translate the C below (see the file comment)
//   SEC("socket")
//   __success
//   int test2(const void *ctx)
//   {
//       __u64 i;
//
//       for (i = zero; i < ARR_LONG_SZ && can_loop; i++) {
//           barrier_var(i);
//           arr_long[i] = i;
//       }
//       return 0;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn test2(_ctx: *const c_void) -> i32 {
    let mut i: u64 = unsafe { zero } as u64;
    while i < ARR_LONG_SZ && unsafe { can_loop() } {
        barrier_var(&mut i);
        unsafe { *core::ptr::addr_of_mut!(arr_long).cast::<i64>().add(i as usize) = i as i64 };
        i += 1;
    }
    0
}

// HAND: test3 -- translate the C below (see the file comment)
//   SEC("socket")
//   __success
//   int test3(const void *ctx)
//   {
//       __u64 i;
//
//       for (i = zero; i < ARR_LONG_SZ && can_loop; i++) {
//           barrier_var(i);
//           arr_foo[i].a = i;
//           arr_foo[i].b = i;
//       }
//       return 0;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn test3(_ctx: *const c_void) -> i32 {
    let mut i: u64 = unsafe { zero } as u64;
    while i < ARR_LONG_SZ && unsafe { can_loop() } {
        barrier_var(&mut i);
        unsafe {
            let e = core::ptr::addr_of_mut!(arr_foo).cast::<__anon_type637>().add(i as usize);
            (*e).a = i as i32;
            (*e).b = i as i32;
        }
        i += 1;
    }
    0
}

// HAND: test4 -- translate the C below (see the file comment)
//   SEC("socket")
//   __success
//   int test4(const void *ctx)
//   {
//       long i;
//
//       for (i = zero + ARR_LONG_SZ - 1; i < ARR_LONG_SZ && i >= 0 && can_loop; i--) {
//           barrier_var(i);
//           arr_foo[i].a = i;
//           arr_foo[i].b = i;
//       }
//       return 0;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn test4(_ctx: *const c_void) -> i32 {
    let mut i: i64 = (unsafe { zero } as i64).wrapping_add(ARR_LONG_SZ as i64 - 1);
    while i < ARR_LONG_SZ as i64 && i >= 0 && unsafe { can_loop() } {
        let mut iu = i as u64;
        barrier_var(&mut iu);
        i = iu as i64;
        unsafe {
            let e = core::ptr::addr_of_mut!(arr_foo).cast::<__anon_type637>().add(i as usize);
            (*e).a = i as i32;
            (*e).b = i as i32;
        }
        i -= 1;
    }
    0
}
