// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_global_subprogs.c, translated
// by hand; include!d by the generated progs/verifier_global_subprogs.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

// The C object was built at -mcpu=v3 and carries the test's v3 instruction
// counts for chained_global_func_calls_success; this object is v4 (global_good
// is a sign-extending load: 3 instructions, 12 processed), the C's own
// `#if __BPF_CPU_VERSION__ >= 4` branch.
// GEN_TAGS: chained_global_func_calls_success:
//     __success,
//     __log_level("6"),
//     __msg("('global_calls_good_only') is global and assumed valid."),
//     __msg("Validating global_good() func"),
//     __msg("('global_good') is safe for any args that match its prototype"),
//     __msg("subprog 0 (chained_global_func_calls_success) main insns_self 7 insns_total 7 stack"),
//     __msg("subprog {{[0-9]+}} (global_calls_good_only) global insns_self 2 insns_total 2 stack"),
//     __msg("subprog {{[0-9]+}} (global_good) global insns_self 3 insns_total 3 stack"),
//     __msg("processed 12 insns");
// translint: allow(test-tags:chained_global_func_calls_success)

// The C's weak global subprograms keep `__weak` (#[linkage = "weak"]); the
// kernel checks an `__arg_ctx` parameter's type by its name and kind only,
// so the kernel structs are the generated stand-ins. The C's
// `bpf_user_pt_regs_t *ctx` parameters are `*mut pt_regs` here (a Rust type
// alias leaves no TYPEDEF in BTF; on x86 the typedef is struct pt_regs,
// which the kernel accepts for kprobe and perf_event too), and the C's
// `typedef struct { int x; } user_struct_t` is the named struct below (same
// size, and a global subprogram's struct pointer is memory of that size).

use bpf_rs_core::helpers::{bpf_dynptr_data, bpf_get_prandom_u32, bpf_get_stack, bpf_loop, bpf_tail_call, sink_val};

#[allow(non_camel_case_types)]
#[repr(C)]
struct user_struct_t {
    x: i32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_iter_num {
    __opaque: [u64; 1],
}

// HAND: global_bad -- translate the C below (see the file comment)
//   __noinline long global_bad(void)
//   {
//       return arr[unkn_idx]; /* BOOM */
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn global_bad() -> i64 {
    // arr[unkn_idx]: BOOM
    unsafe { *(core::ptr::addr_of!(arr) as *const i32).offset(unkn_idx as isize) as i64 }
}

// HAND: global_good -- translate the C below (see the file comment)
//   __noinline long global_good(void)
//   {
//       return arr[0];
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn global_good() -> i64 {
    unsafe { arr[0] as i64 }
}

// HAND: global_calls_bad -- translate the C below (see the file comment)
//   __noinline long global_calls_bad(void)
//   {
//       return global_good() + global_bad() /* does BOOM indirectly */;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn global_calls_bad() -> i64 {
    let good = global_good();
    let bad = global_bad(); // does BOOM indirectly
    good.wrapping_add(bad)
}

// HAND: global_calls_good_only -- translate the C below (see the file comment)
//   __noinline long global_calls_good_only(void)
//   {
//       return global_good();
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn global_calls_good_only() -> i64 {
    global_good()
}

// HAND: global_dead -- translate the C below (see the file comment)
//   __noinline long global_dead(void)
//   {
//       return arr[0] * 2;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn global_dead() -> i64 {
    unsafe { arr[0].wrapping_mul(2) as i64 }
}

// HAND: chained_global_func_calls_success -- translate the C below (see the file comment)
//   SEC("?raw_tp")
//   __success __log_level(6)
//   /* main prog is validated completely first */
//   __msg("('global_calls_good_only') is global and assumed valid.")
//   /* eventually global_good() is transitively validated as well */
//   __msg("Validating global_good() func")
//   __msg("('global_good') is safe for any args that match its prototype")
//   __msg("subprog 0 (chained_global_func_calls_success) main insns_self 7 insns_total 7 stack")
//   __msg("subprog {{[0-9]+}} (global_calls_good_only) global insns_self 2 insns_total 2 stack")
//   #if defined(__BPF_CPU_VERSION__) && __BPF_CPU_VERSION__ >= 4
//   __msg("subprog {{[0-9]+}} (global_good) global insns_self 3 insns_total 3 stack")
//   __msg("processed 12 insns")
//   #else
//   __msg("subprog {{[0-9]+}} (global_good) global insns_self 5 insns_total 5 stack")
//   __msg("processed 14 insns")
//   #endif
//   int chained_global_func_calls_success(void)
//   {
//       int sum = 0;
//
//       if (call_dead_subprog)
//           sum += global_dead();
//       return global_calls_good_only() + sum;
//   }
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn chained_global_func_calls_success() -> i32 {
    let mut sum: i32 = 0;

    // read as a byte: a Rust bool load adds a `w1 &= 1`, one more verified
    // instruction than the C's (the test counts them: insns_self 7)
    if unsafe { core::ptr::read_volatile(core::ptr::addr_of!(call_dead_subprog) as *const u8) } != 0 {
        sum = sum.wrapping_add(global_dead() as i32);
    }
    global_calls_good_only().wrapping_add(sum as i64) as i32
}

// HAND: chained_global_func_calls_bad -- translate the C below (see the file comment)
//   SEC("?raw_tp")
//   __failure __log_level(2)
//   /* main prog validated successfully first */
//   __msg("('global_calls_bad') is global and assumed valid.")
//   /* eventually we validate global_bad() and fail */
//   __msg("Validating global_bad() func")
//   __msg("math between map_value pointer and register") /* BOOM */
//   int chained_global_func_calls_bad(void)
//   {
//       return global_calls_bad();
//   }
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn chained_global_func_calls_bad() -> i32 {
    global_calls_bad() as i32
}

// HAND: global_unsupp -- translate the C below (see the file comment)
//   /* do out of bounds access forcing verifier to fail verification if this
//    * global func is called
//    */
//   __noinline int global_unsupp(const int *mem)
//   {
//       if (!mem)
//           return 0;
//       return mem[100]; /* BOOM */
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn global_unsupp(mem: *mut i32) -> i32 {
    if mem.is_null() {
        return 0;
    }
    unsafe { *mem.add(100) } // BOOM
}

// HAND: guarded_unsupp_global_called -- translate the C below (see the file comment)
//   SEC("?raw_tp")
//   __success
//   int guarded_unsupp_global_called(void)
//   {
//       if (!skip_unsupp_global)
//           return global_unsupp(NULL);
//       return 0;
//   }
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn guarded_unsupp_global_called() -> i32 {
    if !unsafe { core::ptr::read_volatile(&skip_unsupp_global) } {
        return global_unsupp(core::ptr::null_mut());
    }
    0
}

// HAND: unguarded_unsupp_global_called -- translate the C below (see the file comment)
//   SEC("?raw_tp")
//   __failure __log_level(2)
//   __msg("Func#1 ('global_unsupp') is global and assumed valid.")
//   __msg("Validating global_unsupp() func#1...")
//   __msg("value is outside of the allowed memory range")
//   int unguarded_unsupp_global_called(void)
//   {
//       int x = 0;
//
//       return global_unsupp(&x);
//   }
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn unguarded_unsupp_global_called() -> i32 {
    let mut x_: i32 = 0; // the C's `x`, a local beside the global x

    global_unsupp(&mut x_)
}

// HAND: subprog_nullable_ptr_bad -- translate the C below (see the file comment)
//   __weak int subprog_nullable_ptr_bad(int *p)
//   {
//       return (*p) * 2; /* bad, missing null check */
//   }
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn subprog_nullable_ptr_bad(p: *mut i32) -> i32 {
    unsafe { (*p).wrapping_mul(2) } // bad, missing null check
}

// HAND: arg_tag_nullable_ptr_fail -- translate the C below (see the file comment)
//   SEC("?raw_tp")
//   __failure __log_level(2)
//   __msg("invalid mem access 'mem_or_null'")
//   int arg_tag_nullable_ptr_fail(void *ctx)
//   {
//       int x = 42;
//
//       return subprog_nullable_ptr_bad(&x);
//   }
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn arg_tag_nullable_ptr_fail(_ctx: *mut c_void) -> i32 {
    let mut x_: i32 = 42; // the C's `x`, a local beside the global x

    subprog_nullable_ptr_bad(&mut x_)
}

// HAND: subprog_user_anon_mem -- translate the C below (see the file comment)
//   __noinline __weak int subprog_user_anon_mem(user_struct_t *t)
//   {
//       return t ? t->x : 0;
//   }
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn subprog_user_anon_mem(t: *mut user_struct_t) -> i32 {
    if t.is_null() {
        0
    } else {
        unsafe { (*t).x }
    }
}

// HAND: anon_user_mem_invalid -- translate the C below (see the file comment)
//   SEC("?tracepoint")
//   __failure __log_level(2)
//   __msg("Caller passes invalid args into func#1 ('subprog_user_anon_mem')")
//   int anon_user_mem_invalid(void *ctx)
//   {
//       /* can't pass PTR_TO_CTX as user memory */
//       return subprog_user_anon_mem(ctx);
//   }
#[link_section = "?tracepoint"]
#[no_mangle]
extern "C" fn anon_user_mem_invalid(ctx: *mut c_void) -> i32 {
    // can't pass PTR_TO_CTX as user memory
    subprog_user_anon_mem(ctx as *mut user_struct_t)
}

// HAND: anon_user_mem_valid -- translate the C below (see the file comment)
//   SEC("?tracepoint")
//   __success __log_level(2)
//   __msg("Func#1 ('subprog_user_anon_mem') is safe for any args that match its prototype")
//   int anon_user_mem_valid(void *ctx)
//   {
//       user_struct_t t = { .x = 42 };
//
//       return subprog_user_anon_mem(&t);
//   }
#[link_section = "?tracepoint"]
#[no_mangle]
extern "C" fn anon_user_mem_valid(_ctx: *mut c_void) -> i32 {
    let mut t = user_struct_t { x: 42 };

    subprog_user_anon_mem(&mut t)
}

// HAND: subprog_user_anon_mem_huge -- translate the C below (see the file comment)
//   (definition of subprog_user_anon_mem_huge not found in the source)
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn subprog_user_anon_mem_huge(p: *mut [i32; 1073741823]) -> i32 {
    if p.is_null() {
        0
    } else {
        unsafe { (*p)[1] }
    }
}

// HAND: anon_user_mem_huge_size_invalid -- translate the C below (see the file comment)
//   SEC("?tracepoint")
//   __failure __log_level(2)
//   __msg("R1 memory size 4294967292 is too large")
//   int anon_user_mem_huge_size_invalid(void *ctx)
//   {
//       int (*p)[0x3fffffff];
//       int tiny = 42;
//
//       p = (void *)&tiny;
//       return subprog_user_anon_mem_huge(p) + tiny;
//   }
#[link_section = "?tracepoint"]
#[no_mangle]
extern "C" fn anon_user_mem_huge_size_invalid(_ctx: *mut c_void) -> i32 {
    let mut tiny: i32 = 42;
    let p = &mut tiny as *mut i32 as *mut [i32; 0x3fffffff];

    let r = subprog_user_anon_mem_huge(p);
    r.wrapping_add(unsafe { core::ptr::read_volatile(&tiny) })
}

// HAND: subprog_nonnull_ptr_good -- translate the C below (see the file comment)
//   __noinline __weak int subprog_nonnull_ptr_good(int *p1 __arg_nonnull, int *p2 __arg_nonnull)
//   {
//       return (*p1) * (*p2); /* good, no need for NULL checks */
//   }
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn subprog_nonnull_ptr_good(p1: *mut i32, p2: *mut i32) -> i32 {
    unsafe { (*p1).wrapping_mul(*p2) } // good, no need for NULL checks
}

// HAND: arg_tag_nonnull_ptr_good -- translate the C below (see the file comment)
//   SEC("?raw_tp")
//   __success __log_level(2)
//   int arg_tag_nonnull_ptr_good(void *ctx)
//   {
//       int y = 74;
//
//       return subprog_nonnull_ptr_good(&x, &y);
//   }
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn arg_tag_nonnull_ptr_good(_ctx: *mut c_void) -> i32 {
    let mut y: i32 = 74;

    subprog_nonnull_ptr_good(core::ptr::addr_of_mut!(x), &mut y)
}

// HAND: arg_tag_nonnull_ptr_null_bad -- translate the C below (see the file comment)
//   SEC("?raw_tp")
//   __failure __log_level(2)
//   __msg("Possibly NULL pointer passed to trusted R1")
//   int arg_tag_nonnull_ptr_null_bad(void *ctx)
//   {
//       int y = 74;
//
//       return subprog_nonnull_ptr_good(NULL, &y);
//   }
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn arg_tag_nonnull_ptr_null_bad(_ctx: *mut c_void) -> i32 {
    let mut y: i32 = 74;

    subprog_nonnull_ptr_good(core::ptr::null_mut(), &mut y)
}

// HAND: subprog_ctx_tag -- translate the C below (see the file comment)
//   /* this global subprog can be now called from many types of entry progs, each
//    * with different context type
//    */
//   __weak int subprog_ctx_tag(void *ctx __arg_ctx)
//   {
//       return bpf_get_stack(ctx, stack, sizeof(stack), 0);
//   }
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn subprog_ctx_tag(ctx: *mut c_void) -> i32 {
    bpf_get_stack(ctx as *const c_void, core::ptr::addr_of_mut!(stack) as *mut c_void, 1024, 0) as i32
}

// HAND: raw_tp_canonical -- translate the C below (see the file comment)
//   __weak int raw_tp_canonical(struct bpf_raw_tracepoint_args *ctx __arg_ctx)
//   {
//       return 0;
//   }
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn raw_tp_canonical(_ctx: *mut bpf_raw_tracepoint_args) -> i32 {
    0
}

// HAND: raw_tp_u64_array -- translate the C below (see the file comment)
//   __weak int raw_tp_u64_array(u64 *ctx __arg_ctx)
//   {
//       return 0;
//   }
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn raw_tp_u64_array(_ctx: *mut u64) -> i32 {
    0
}

// HAND: arg_tag_ctx_raw_tp -- translate the C below (see the file comment)
//   SEC("?raw_tp")
//   __success __log_level(2)
//   int arg_tag_ctx_raw_tp(void *ctx)
//   {
//       return subprog_ctx_tag(ctx) + raw_tp_canonical(ctx) + raw_tp_u64_array(ctx);
//   }
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn arg_tag_ctx_raw_tp(ctx: *mut c_void) -> i32 {
    subprog_ctx_tag(ctx)
        .wrapping_add(raw_tp_canonical(ctx as *mut bpf_raw_tracepoint_args))
        .wrapping_add(raw_tp_u64_array(ctx as *mut u64))
}

// HAND: arg_tag_ctx_raw_tp_writable -- translate the C below (see the file comment)
//   SEC("?raw_tp.w")
//   __success __log_level(2)
//   int arg_tag_ctx_raw_tp_writable(void *ctx)
//   {
//       return subprog_ctx_tag(ctx) + raw_tp_canonical(ctx) + raw_tp_u64_array(ctx);
//   }
#[link_section = "?raw_tp.w"]
#[no_mangle]
extern "C" fn arg_tag_ctx_raw_tp_writable(ctx: *mut c_void) -> i32 {
    subprog_ctx_tag(ctx)
        .wrapping_add(raw_tp_canonical(ctx as *mut bpf_raw_tracepoint_args))
        .wrapping_add(raw_tp_u64_array(ctx as *mut u64))
}

// HAND: arg_tag_ctx_raw_tp_btf -- translate the C below (see the file comment)
//   SEC("?tp_btf/sys_enter")
//   __success __log_level(2)
//   int arg_tag_ctx_raw_tp_btf(void *ctx)
//   {
//       return subprog_ctx_tag(ctx) + raw_tp_canonical(ctx) + raw_tp_u64_array(ctx);
//   }
#[link_section = "?tp_btf/sys_enter"]
#[no_mangle]
extern "C" fn arg_tag_ctx_raw_tp_btf(ctx: *mut c_void) -> i32 {
    subprog_ctx_tag(ctx)
        .wrapping_add(raw_tp_canonical(ctx as *mut bpf_raw_tracepoint_args))
        .wrapping_add(raw_tp_u64_array(ctx as *mut u64))
}

// HAND: tp_whatever -- translate the C below (see the file comment)
//   __weak int tp_whatever(struct whatever *ctx __arg_ctx)
//   {
//       return 0;
//   }
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn tp_whatever(_ctx: *mut whatever) -> i32 {
    0
}

// HAND: arg_tag_ctx_tp -- translate the C below (see the file comment)
//   SEC("?tp")
//   __success __log_level(2)
//   int arg_tag_ctx_tp(void *ctx)
//   {
//       return subprog_ctx_tag(ctx) + tp_whatever(ctx);
//   }
#[link_section = "?tp"]
#[no_mangle]
extern "C" fn arg_tag_ctx_tp(ctx: *mut c_void) -> i32 {
    subprog_ctx_tag(ctx)
        .wrapping_add(tp_whatever(ctx as *mut whatever))
}

// HAND: kprobe_subprog_pt_regs -- translate the C below (see the file comment)
//   __weak int kprobe_subprog_pt_regs(struct pt_regs *ctx __arg_ctx)
//   {
//       return 0;
//   }
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn kprobe_subprog_pt_regs(_ctx: *mut pt_regs) -> i32 {
    0
}

// HAND: kprobe_subprog_typedef -- translate the C below (see the file comment)
//   __weak int kprobe_subprog_typedef(bpf_user_pt_regs_t *ctx __arg_ctx)
//   {
//       return 0;
//   }
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn kprobe_subprog_typedef(_ctx: *mut pt_regs) -> i32 {
    0
}

// HAND: arg_tag_ctx_kprobe -- translate the C below (see the file comment)
//   SEC("?kprobe")
//   __success __log_level(2)
//   int arg_tag_ctx_kprobe(void *ctx)
//   {
//       return subprog_ctx_tag(ctx) +
//              kprobe_subprog_pt_regs(ctx) +
//              kprobe_subprog_typedef(ctx);
//   }
#[link_section = "?kprobe"]
#[no_mangle]
extern "C" fn arg_tag_ctx_kprobe(ctx: *mut c_void) -> i32 {
    subprog_ctx_tag(ctx)
        .wrapping_add(kprobe_subprog_pt_regs(ctx as *mut pt_regs))
        .wrapping_add(kprobe_subprog_typedef(ctx as *mut pt_regs))
}

// HAND: perf_subprog_regs -- translate the C below (see the file comment)
//   (definition of perf_subprog_regs not found in the source)
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn perf_subprog_regs(_ctx: *mut pt_regs) -> i32 {
    0
}

// HAND: perf_subprog_typedef -- translate the C below (see the file comment)
//   __weak int perf_subprog_typedef(bpf_user_pt_regs_t *ctx __arg_ctx)
//   {
//       return 0;
//   }
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn perf_subprog_typedef(_ctx: *mut pt_regs) -> i32 {
    0
}

// HAND: perf_subprog_canonical -- translate the C below (see the file comment)
//   __weak int perf_subprog_canonical(struct bpf_perf_event_data *ctx __arg_ctx)
//   {
//       return 0;
//   }
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn perf_subprog_canonical(_ctx: *mut bpf_perf_event_data) -> i32 {
    0
}

// HAND: arg_tag_ctx_perf -- translate the C below (see the file comment)
//   SEC("?perf_event")
//   __success __log_level(2)
//   int arg_tag_ctx_perf(void *ctx)
//   {
//       return subprog_ctx_tag(ctx) +
//              perf_subprog_regs(ctx) +
//              perf_subprog_typedef(ctx) +
//              perf_subprog_canonical(ctx);
//   }
#[link_section = "?perf_event"]
#[no_mangle]
extern "C" fn arg_tag_ctx_perf(ctx: *mut c_void) -> i32 {
    subprog_ctx_tag(ctx)
        .wrapping_add(perf_subprog_regs(ctx as *mut pt_regs))
        .wrapping_add(perf_subprog_typedef(ctx as *mut pt_regs))
        .wrapping_add(perf_subprog_canonical(ctx as *mut bpf_perf_event_data))
}

// HAND: iter_subprog_void -- translate the C below (see the file comment)
//   __weak int iter_subprog_void(void *ctx __arg_ctx)
//   {
//       return 0;
//   }
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn iter_subprog_void(_ctx: *mut c_void) -> i32 {
    0
}

// HAND: iter_subprog_typed -- translate the C below (see the file comment)
//   __weak int iter_subprog_typed(struct bpf_iter__task *ctx __arg_ctx)
//   {
//       return 0;
//   }
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn iter_subprog_typed(_ctx: *mut bpf_iter__task) -> i32 {
    0
}

// HAND: arg_tag_ctx_iter_task -- translate the C below (see the file comment)
//   SEC("?iter/task")
//   __success __log_level(2)
//   int arg_tag_ctx_iter_task(struct bpf_iter__task *ctx)
//   {
//       return (iter_subprog_void(ctx) + iter_subprog_typed(ctx)) & 1;
//   }
#[link_section = "?iter/task"]
#[no_mangle]
extern "C" fn arg_tag_ctx_iter_task(ctx: *mut bpf_iter__task) -> i32 {
    (iter_subprog_void(ctx as *mut c_void).wrapping_add(iter_subprog_typed(ctx))) & 1
}

// HAND: tracing_subprog_void -- translate the C below (see the file comment)
//   __weak int tracing_subprog_void(void *ctx __arg_ctx)
//   {
//       return 0;
//   }
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn tracing_subprog_void(_ctx: *mut c_void) -> i32 {
    0
}

// HAND: tracing_subprog_u64 -- translate the C below (see the file comment)
//   __weak int tracing_subprog_u64(u64 *ctx __arg_ctx)
//   {
//       return 0;
//   }
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn tracing_subprog_u64(_ctx: *mut u64) -> i32 {
    0
}

// HAND: arg_tag_ctx_fentry -- translate the C below (see the file comment)
//   SEC("?fentry/" SYS_PREFIX "sys_nanosleep")
//   __success __log_level(2)
//   int BPF_PROG(arg_tag_ctx_fentry)
//   {
//       acc += tracing_subprog_void(ctx) + tracing_subprog_u64(ctx);
//       return 0;
//   }
#[link_section = "?fentry/__x64_sys_nanosleep"]
#[no_mangle]
extern "C" fn arg_tag_ctx_fentry(ctx: *mut u64) -> i32 {
    unsafe { acc = acc.wrapping_add(tracing_subprog_void(ctx as *mut c_void).wrapping_add(tracing_subprog_u64(ctx))) };
    0
}

// HAND: arg_tag_ctx_fexit -- translate the C below (see the file comment)
//   SEC("?fexit/" SYS_PREFIX "sys_nanosleep")
//   __success __log_level(2)
//   int BPF_PROG(arg_tag_ctx_fexit)
//   {
//       acc += tracing_subprog_void(ctx) + tracing_subprog_u64(ctx);
//       return 0;
//   }
#[link_section = "?fexit/__x64_sys_nanosleep"]
#[no_mangle]
extern "C" fn arg_tag_ctx_fexit(ctx: *mut u64) -> i32 {
    unsafe { acc = acc.wrapping_add(tracing_subprog_void(ctx as *mut c_void).wrapping_add(tracing_subprog_u64(ctx))) };
    0
}

// HAND: arg_tag_ctx_fmod_ret -- translate the C below (see the file comment)
//   SEC("?fmod_ret/" SYS_PREFIX "sys_nanosleep")
//   __success __log_level(2)
//   int BPF_PROG(arg_tag_ctx_fmod_ret)
//   {
//       return tracing_subprog_void(ctx) + tracing_subprog_u64(ctx);
//   }
#[link_section = "?fmod_ret/__x64_sys_nanosleep"]
#[no_mangle]
extern "C" fn arg_tag_ctx_fmod_ret(ctx: *mut u64) -> i32 {
    tracing_subprog_void(ctx as *mut c_void).wrapping_add(tracing_subprog_u64(ctx))
}

// HAND: arg_tag_ctx_lsm -- translate the C below (see the file comment)
//   SEC("?lsm/bpf")
//   __success __log_level(2)
//   int BPF_PROG(arg_tag_ctx_lsm)
//   {
//       int ret;
//
//       ret = tracing_subprog_void(ctx) + tracing_subprog_u64(ctx);
//       set_if_not_errno_or_zero(ret, -1);
//       return ret;
//   }
#[link_section = "?lsm/bpf"]
#[no_mangle]
extern "C" fn arg_tag_ctx_lsm(ctx: *mut u64) -> i32 {
    let mut ret: i32 = tracing_subprog_void(ctx as *mut c_void).wrapping_add(tracing_subprog_u64(ctx));
    // set_if_not_errno_or_zero(ret, -1)
    unsafe {
        core::arch::asm!(
            "if {0} s< -4095 goto +1",
            "if {0} s<= 0 goto +1",
            "{0} = -1",
            inout(reg) ret,
            options(nostack),
        );
    }
    ret
}

// HAND: arg_tag_ctx_struct_ops -- translate the C below (see the file comment)
//   SEC("?struct_ops/test_1")
//   __success __log_level(2)
//   int BPF_PROG(arg_tag_ctx_struct_ops)
//   {
//       return tracing_subprog_void(ctx) + tracing_subprog_u64(ctx);
//   }
#[link_section = "?struct_ops/test_1"]
#[no_mangle]
extern "C" fn arg_tag_ctx_struct_ops(ctx: *mut u64) -> i32 {
    tracing_subprog_void(ctx as *mut c_void).wrapping_add(tracing_subprog_u64(ctx))
}

// HAND: arg_tag_ctx_syscall -- translate the C below (see the file comment)
//   SEC("?syscall")
//   __success __log_level(2)
//   int arg_tag_ctx_syscall(void *ctx)
//   {
//       return tracing_subprog_void(ctx) + tracing_subprog_u64(ctx) + tp_whatever(ctx);
//   }
#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn arg_tag_ctx_syscall(ctx: *mut c_void) -> i32 {
    tracing_subprog_void(ctx)
        .wrapping_add(tracing_subprog_u64(ctx as *mut u64))
        .wrapping_add(tp_whatever(ctx as *mut whatever))
}

// HAND: syscall_array_bpf_for -- translate the C below (see the file comment)
//   __weak int syscall_array_bpf_for(void *ctx __arg_ctx)
//   {
//       int *arr = ctx;
//       int i;
//
//       bpf_for(i, 0, 100)
//           arr[i] *= i;
//
//       return 0;
//   }
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn syscall_array_bpf_for(ctx: *mut c_void) -> i32 {
    let a = ctx as *mut i32; // the C's `arr`, a local beside the global arr
    let mut it = core::mem::MaybeUninit::<bpf_iter_num>::uninit();

    // bpf_for(i, 0, 100) arr[i] *= i;
    unsafe {
        bpf_iter_num_new(it.as_mut_ptr() as *mut c_void, 0, 100);
        loop {
            let t = bpf_iter_num_next(it.as_mut_ptr() as *mut c_void) as *mut i32;
            if t.is_null() {
                break;
            }
            let i = *t;
            if i < 0 || i >= 100 {
                break;
            }
            *a.add(i as usize) = (*a.add(i as usize)).wrapping_mul(i);
        }
        bpf_iter_num_destroy(it.as_mut_ptr() as *mut c_void);
    }

    0
}

// HAND: arg_tag_ctx_syscall_bpf_for -- translate the C below (see the file comment)
//   SEC("?syscall")
//   __success __log_level(2)
//   int arg_tag_ctx_syscall_bpf_for(void *ctx)
//   {
//       return syscall_array_bpf_for(ctx);
//   }
#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn arg_tag_ctx_syscall_bpf_for(ctx: *mut c_void) -> i32 {
    syscall_array_bpf_for(ctx)
}

// HAND: syscall_tailcall_target -- translate the C below (see the file comment)
//   SEC("syscall")
//   __auxiliary
//   int syscall_tailcall_target(void *ctx)
//   {
//       return syscall_array_bpf_for(ctx);
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn syscall_tailcall_target(ctx: *mut c_void) -> i32 {
    syscall_array_bpf_for(ctx)
}

// HAND: arg_tag_ctx_syscall_tailcall -- translate the C below (see the file comment)
//   SEC("?syscall")
//   __success __log_level(2)
//   int arg_tag_ctx_syscall_tailcall(void *ctx)
//   {
//       bpf_tail_call(ctx, &syscall_prog_array, 0);
//       return 0;
//   }
#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn arg_tag_ctx_syscall_tailcall(ctx: *mut c_void) -> i32 {
    bpf_tail_call(ctx as *const c_void, core::ptr::addr_of!(syscall_prog_array), 0);
    0
}

// HAND: arg_tag_ctx_syscall_tailcall_fixed_off_bad -- translate the C below (see the file comment)
//   SEC("?syscall")
//   __failure __log_level(2)
//   __msg("dereference of modified ctx ptr R1 off=8 disallowed")
//   int arg_tag_ctx_syscall_tailcall_fixed_off_bad(void *ctx)
//   {
//       char *p = ctx;
//
//       p += 8;
//       bpf_tail_call(p, &syscall_prog_array, 0);
//       return 0;
//   }
#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn arg_tag_ctx_syscall_tailcall_fixed_off_bad(ctx: *mut c_void) -> i32 {
    let p = (ctx as *mut u8).wrapping_add(8);

    bpf_tail_call(p as *const c_void, core::ptr::addr_of!(syscall_prog_array), 0);
    0
}

// HAND: arg_tag_ctx_syscall_tailcall_var_off_bad -- translate the C below (see the file comment)
//   SEC("?syscall")
//   __failure __log_level(2)
//   __msg("variable ctx access var_off=(0x0; 0x4) disallowed")
//   int arg_tag_ctx_syscall_tailcall_var_off_bad(void *ctx)
//   {
//       __u64 off = bpf_get_prandom_u32();
//       char *p = ctx;
//
//       off &= 4;
//       p += off;
//       bpf_tail_call(p, &syscall_prog_array, 0);
//       return 0;
//   }
#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn arg_tag_ctx_syscall_tailcall_var_off_bad(ctx: *mut c_void) -> i32 {
    let mut off: u64 = bpf_get_prandom_u32() as u64;

    off &= 4;
    let p = (ctx as *mut u8).wrapping_add(off as usize);
    bpf_tail_call(p as *const c_void, core::ptr::addr_of!(syscall_prog_array), 0);
    0
}

// HAND: arg_tag_ctx_syscall_fixed_off_bad -- translate the C below (see the file comment)
//   SEC("?syscall")
//   __failure __log_level(2)
//   __msg("dereference of modified ctx ptr R1 off=8 disallowed")
//   int arg_tag_ctx_syscall_fixed_off_bad(void *ctx)
//   {
//       char *p = ctx;
//
//       p += 8;
//       return subprog_ctx_tag(p);
//   }
#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn arg_tag_ctx_syscall_fixed_off_bad(ctx: *mut c_void) -> i32 {
    let p = (ctx as *mut u8).wrapping_add(8);

    subprog_ctx_tag(p as *mut c_void)
}

// HAND: arg_tag_ctx_syscall_var_off_bad -- translate the C below (see the file comment)
//   SEC("?syscall")
//   __failure __log_level(2)
//   __msg("variable ctx access var_off=(0x0; 0x4) disallowed")
//   int arg_tag_ctx_syscall_var_off_bad(void *ctx)
//   {
//       __u64 off = bpf_get_prandom_u32();
//       char *p = ctx;
//
//       off &= 4;
//       p += off;
//       return subprog_ctx_tag(p);
//   }
#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn arg_tag_ctx_syscall_var_off_bad(ctx: *mut c_void) -> i32 {
    let mut off: u64 = bpf_get_prandom_u32() as u64;

    off &= 4;
    let p = (ctx as *mut u8).wrapping_add(off as usize);
    subprog_ctx_tag(p as *mut c_void)
}

// HAND: subprog_dynptr -- translate the C below (see the file comment)
//   __weak int subprog_dynptr(struct bpf_dynptr *dptr)
//   {
//       long *d, t, buf[1] = {};
//
//       d = bpf_dynptr_data(dptr, 0, sizeof(long));
//       if (!d)
//           return 0;
//
//       t = *d + 1;
//
//       d = bpf_dynptr_slice(dptr, 0, &buf, sizeof(long));
//       if (!d)
//           return t;
//
//       t = *d + 2;
//
//       return t;
//   }
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn subprog_dynptr(dptr: *mut bpf_dynptr) -> i32 {
    let mut buf: [i64; 1] = [0];

    let d = bpf_dynptr_data(dptr as *const c_void, 0, 8) as *mut i64;
    if d.is_null() {
        return 0;
    }

    let mut t: i64 = unsafe { *d }.wrapping_add(1);

    let d = unsafe { bpf_dynptr_slice(dptr as *mut c_void, 0, buf.as_mut_ptr() as *mut c_void, 8) } as *mut i64;
    if d.is_null() {
        return t as i32;
    }

    t = unsafe { *d }.wrapping_add(2);

    t as i32
}

// HAND: arg_tag_dynptr -- translate the C below (see the file comment)
//   SEC("?xdp")
//   __success __log_level(2)
//   int arg_tag_dynptr(struct xdp_md *ctx)
//   {
//       struct bpf_dynptr dptr;
//
//       bpf_dynptr_from_xdp(ctx, 0, &dptr);
//
//       return subprog_dynptr(&dptr);
//   }
#[link_section = "?xdp"]
#[no_mangle]
extern "C" fn arg_tag_dynptr(ctx: *mut xdp_md) -> i32 {
    let mut dptr = core::mem::MaybeUninit::<bpf_dynptr>::uninit();

    unsafe { bpf_dynptr_from_xdp(ctx as *mut c_void, 0, dptr.as_mut_ptr() as *mut c_void) };

    subprog_dynptr(dptr.as_mut_ptr())
}

// HAND: foo -- translate the C below (see the file comment)
//   __weak
//   void foo(void)
//   {
//   }
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn foo() {}

// HAND: return_from_void_global -- translate the C below (see the file comment)
//   SEC("?tc")
//   __failure __msg("R0 !read_ok")
//   int return_from_void_global(struct __sk_buff *skb)
//   {
//       foo();
//
//       asm volatile(
//           "r1 = r0;"
//           :::
//       );
//
//       return 0;
//   }
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn return_from_void_global(_skb: *mut __sk_buff) -> i32 {
    foo();

    unsafe {
        core::arch::asm!("r1 = r0", out("r1") _, options(nostack));
    }

    0
}

// HAND: static_calls_global -- translate the C below (see the file comment)
//   static __noinline int static_calls_global(int x)
//   {
//       return global_calls_loop(x);
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn static_calls_global(x_: i32) -> i32 {
    global_calls_loop(x_)
}

// HAND: loop_cb_calls_static -- translate the C below (see the file comment)
//   static __noinline int loop_cb_calls_static(u32 i, void *ctx)
//   {
//       return static_calls_global(i);
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn loop_cb_calls_static(i: u32, _ctx: *mut c_void) -> i32 {
    static_calls_global(i as i32)
}

// HAND: global_calls_loop -- translate the C below (see the file comment)
//   __noinline int global_calls_loop(int x)
//   {
//       bpf_loop(1, loop_cb_calls_static, NULL, 0);
//       return 0;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn global_calls_loop(x_: i32) -> i32 {
    // the C never reads x either, but LLVM would then pass poison for it up
    // the chain (recursion_via_global_func_and_callback's `w1 = 0` vanishes)
    // and the verifier would see a ctx pointer where the global subprogram
    // wants a scalar, before it ever reaches the recursion check
    sink_val(x_);
    let cb: extern "C" fn(u64, *mut c_void) -> i64 =
        unsafe { core::mem::transmute(loop_cb_calls_static as extern "C" fn(u32, *mut c_void) -> i32) };
    bpf_loop(1, cb, core::ptr::null_mut(), 0);
    0
}

// HAND: recursion_via_global_func_and_callback -- translate the C below (see the file comment)
//   /*
//    * loop_cb_calls_static() -> static_calls_global() -> global_calls_loop() ->
//    * bpf_loop() -> loop_cb_calls_static() is an unbounded recursion that the
//    * main verification pass can't see, because it doesn't follow calls of global
//    * functions. None of the functions use stack.
//    */
//   SEC("?raw_tp")
//   __failure __msg("recursive call from global_calls_loop() to loop_cb_calls_static()")
//   int recursion_via_global_func_and_callback(const void *ctx)
//   {
//       return loop_cb_calls_static(0, NULL);
//   }
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn recursion_via_global_func_and_callback(_ctx: *mut c_void) -> i32 {
    loop_cb_calls_static(0, core::ptr::null_mut())
}
