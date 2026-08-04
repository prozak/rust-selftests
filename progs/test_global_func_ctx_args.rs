#![no_std]
#![no_main]

// Translation of tools/testing/selftests/bpf/progs/test_global_func_ctx_args.c
// (bpf-rs-core idiom).
//
// The C source exercises several ways a global (__weak) subprog can declare
// a ctx-typed pointer argument: a typedef name (bpf_user_pt_regs_t), the
// resolved underlying struct (pt_regs on non-s390x), an old-kernel opaque
// struct-name workaround, and libbpf's `void *ctx __arg_ctx` decl-tag
// mechanism (one subprog reused, with a *different* concrete ctx type, by
// several entry programs of different program types).
//
// rustc cannot emit BTF_KIND_DECL_TAG, so `__arg_ctx` itself is
// untranslatable (see TRANSLATING.md). The verifier's global-subprog ctx
// check (btf_is_prog_ctx_type in kernel/bpf/btf.c) has a second path that
// doesn't need any tag at all: it accepts a PTR argument whose pointee is a
// *named* struct, purely by comparing that name against the program type's
// canonical ctx struct name (e.g. "pt_regs" / "bpf_user_pt_regs_t" for
// kprobe, "bpf_raw_tracepoint_args" for raw_tp, "bpf_perf_event_data" for
// perf_event) -- the struct doesn't need any members. That's exactly the
// mechanism the C source's own `struct bpf_user_pt_regs_t {};` workaround
// relies on, and it's reused here for every ctx arg, including the
// __arg_ctx ones: since one Rust function can't have a polymorphic ctx
// type, `subprog_ctx_tag`/`subprog_multi_ctx_tags` keep their exact C names
// and types but are specialized to the perf_event call site (the one
// userspace actually loads and inspects, in subtest_ctx_arg_rewrite), and
// the raw_tp/kprobe call sites get their own concretely-typed twins.

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_stack;
use btf_macros::btf;

const STACK_BYTES: u32 = 256 * 8;

static mut stack: [i64; 256] = [0; 256];

// Name-only markers: the verifier's ctx-type check for global subprog
// arguments matches purely on BTF struct name, so these never need fields.
#[btf]
struct pt_regs {}

#[btf]
struct bpf_user_pt_regs_t {}

#[btf]
struct bpf_raw_tracepoint_args {}

#[btf]
struct bpf_perf_event_data {}

#[repr(C)]
struct my_struct {
    x: i32,
}

/*
 * KPROBE contexts
 */

#[no_mangle]
#[inline(never)]
pub extern "C" fn kprobe_typedef_ctx_subprog(ctx: *const bpf_user_pt_regs_t) -> i32 {
    unsafe {
        bpf_get_stack(
            ctx as *const c_void,
            core::ptr::addr_of_mut!(stack) as *mut c_void,
            STACK_BYTES,
            0,
        ) as i32
    }
}

#[link_section = "?kprobe"]
#[no_mangle]
pub extern "C" fn kprobe_typedef_ctx(ctx: *const c_void) -> i32 {
    kprobe_typedef_ctx_subprog(ctx as *const bpf_user_pt_regs_t)
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn kprobe_struct_ctx_subprog(ctx: *const pt_regs) -> i32 {
    unsafe {
        bpf_get_stack(
            ctx as *const c_void,
            core::ptr::addr_of_mut!(stack) as *mut c_void,
            STACK_BYTES,
            0,
        ) as i32
    }
}

#[link_section = "?kprobe"]
#[no_mangle]
pub extern "C" fn kprobe_resolved_ctx(ctx: *const c_void) -> i32 {
    kprobe_struct_ctx_subprog(ctx as *const pt_regs)
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn kprobe_workaround_ctx_subprog(ctx: *const bpf_user_pt_regs_t) -> i32 {
    unsafe {
        bpf_get_stack(
            ctx as *const c_void,
            core::ptr::addr_of_mut!(stack) as *mut c_void,
            STACK_BYTES,
            0,
        ) as i32
    }
}

#[link_section = "?kprobe"]
#[no_mangle]
pub extern "C" fn kprobe_workaround_ctx(ctx: *const c_void) -> i32 {
    kprobe_workaround_ctx_subprog(ctx as *const bpf_user_pt_regs_t)
}

/*
 * RAW_TRACEPOINT contexts
 */

#[no_mangle]
#[inline(never)]
pub extern "C" fn raw_tp_ctx_subprog(ctx: *const bpf_raw_tracepoint_args) -> i32 {
    unsafe {
        bpf_get_stack(
            ctx as *const c_void,
            core::ptr::addr_of_mut!(stack) as *mut c_void,
            STACK_BYTES,
            0,
        ) as i32
    }
}

#[link_section = "?raw_tp"]
#[no_mangle]
pub extern "C" fn raw_tp_ctx(ctx: *const c_void) -> i32 {
    raw_tp_ctx_subprog(ctx as *const bpf_raw_tracepoint_args)
}

/*
 * RAW_TRACEPOINT_WRITABLE contexts
 */

#[no_mangle]
#[inline(never)]
pub extern "C" fn raw_tp_writable_ctx_subprog(ctx: *const bpf_raw_tracepoint_args) -> i32 {
    unsafe {
        bpf_get_stack(
            ctx as *const c_void,
            core::ptr::addr_of_mut!(stack) as *mut c_void,
            STACK_BYTES,
            0,
        ) as i32
    }
}

#[link_section = "?raw_tp"]
#[no_mangle]
pub extern "C" fn raw_tp_writable_ctx(ctx: *const c_void) -> i32 {
    raw_tp_writable_ctx_subprog(ctx as *const bpf_raw_tracepoint_args)
}

/*
 * PERF_EVENT contexts
 */

#[no_mangle]
#[inline(never)]
pub extern "C" fn perf_event_ctx_subprog(ctx: *const bpf_perf_event_data) -> i32 {
    unsafe {
        bpf_get_stack(
            ctx as *const c_void,
            core::ptr::addr_of_mut!(stack) as *mut c_void,
            STACK_BYTES,
            0,
        ) as i32
    }
}

#[link_section = "?perf_event"]
#[no_mangle]
pub extern "C" fn perf_event_ctx(ctx: *const c_void) -> i32 {
    perf_event_ctx_subprog(ctx as *const bpf_perf_event_data)
}

// `void *ctx __arg_ctx` subprogs: no decl tags available, so each call site
// gets a concretely-typed twin instead of one polymorphic function. The
// perf_event twin keeps the exact C names, since that's the one
// prog_tests/test_global_funcs.c's subtest_ctx_arg_rewrite loads and
// inspects via BTF func_info.

#[no_mangle]
#[inline(never)]
pub extern "C" fn subprog_ctx_tag(ctx: *const bpf_perf_event_data) -> i32 {
    unsafe {
        bpf_get_stack(
            ctx as *const c_void,
            core::ptr::addr_of_mut!(stack) as *mut c_void,
            STACK_BYTES,
            0,
        ) as i32
    }
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn subprog_multi_ctx_tags(
    ctx1: *const bpf_perf_event_data,
    mem: *const my_struct,
    ctx2: *const bpf_perf_event_data,
) -> i32 {
    if mem.is_null() {
        return 0;
    }

    let a = unsafe {
        bpf_get_stack(
            ctx1 as *const c_void,
            core::ptr::addr_of_mut!(stack) as *mut c_void,
            STACK_BYTES,
            0,
        ) as i32
    };
    let b = unsafe { (*mem).x };
    let c = unsafe {
        bpf_get_stack(
            ctx2 as *const c_void,
            core::ptr::addr_of_mut!(stack) as *mut c_void,
            STACK_BYTES,
            0,
        ) as i32
    };
    a.wrapping_add(b).wrapping_add(c)
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn subprog_ctx_tag_raw_tp(ctx: *const bpf_raw_tracepoint_args) -> i32 {
    unsafe {
        bpf_get_stack(
            ctx as *const c_void,
            core::ptr::addr_of_mut!(stack) as *mut c_void,
            STACK_BYTES,
            0,
        ) as i32
    }
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn subprog_multi_ctx_tags_raw_tp(
    ctx1: *const bpf_raw_tracepoint_args,
    mem: *const my_struct,
    ctx2: *const bpf_raw_tracepoint_args,
) -> i32 {
    if mem.is_null() {
        return 0;
    }

    let a = unsafe {
        bpf_get_stack(
            ctx1 as *const c_void,
            core::ptr::addr_of_mut!(stack) as *mut c_void,
            STACK_BYTES,
            0,
        ) as i32
    };
    let b = unsafe { (*mem).x };
    let c = unsafe {
        bpf_get_stack(
            ctx2 as *const c_void,
            core::ptr::addr_of_mut!(stack) as *mut c_void,
            STACK_BYTES,
            0,
        ) as i32
    };
    a.wrapping_add(b).wrapping_add(c)
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn subprog_ctx_tag_kprobe(ctx: *const bpf_user_pt_regs_t) -> i32 {
    unsafe {
        bpf_get_stack(
            ctx as *const c_void,
            core::ptr::addr_of_mut!(stack) as *mut c_void,
            STACK_BYTES,
            0,
        ) as i32
    }
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn subprog_multi_ctx_tags_kprobe(
    ctx1: *const bpf_user_pt_regs_t,
    mem: *const my_struct,
    ctx2: *const bpf_user_pt_regs_t,
) -> i32 {
    if mem.is_null() {
        return 0;
    }

    let a = unsafe {
        bpf_get_stack(
            ctx1 as *const c_void,
            core::ptr::addr_of_mut!(stack) as *mut c_void,
            STACK_BYTES,
            0,
        ) as i32
    };
    let b = unsafe { (*mem).x };
    let c = unsafe {
        bpf_get_stack(
            ctx2 as *const c_void,
            core::ptr::addr_of_mut!(stack) as *mut c_void,
            STACK_BYTES,
            0,
        ) as i32
    };
    a.wrapping_add(b).wrapping_add(c)
}

#[link_section = "?raw_tp"]
#[no_mangle]
pub extern "C" fn arg_tag_ctx_raw_tp(ctx: *const c_void) -> i32 {
    let x = my_struct { x: 123 };
    subprog_ctx_tag_raw_tp(ctx as *const bpf_raw_tracepoint_args).wrapping_add(
        subprog_multi_ctx_tags_raw_tp(
            ctx as *const bpf_raw_tracepoint_args,
            &x,
            ctx as *const bpf_raw_tracepoint_args,
        ),
    )
}

#[link_section = "?perf_event"]
#[no_mangle]
pub extern "C" fn arg_tag_ctx_perf(ctx: *const c_void) -> i32 {
    let x = my_struct { x: 123 };
    subprog_ctx_tag(ctx as *const bpf_perf_event_data).wrapping_add(subprog_multi_ctx_tags(
        ctx as *const bpf_perf_event_data,
        &x,
        ctx as *const bpf_perf_event_data,
    ))
}

#[link_section = "?kprobe"]
#[no_mangle]
pub extern "C" fn arg_tag_ctx_kprobe(ctx: *const c_void) -> i32 {
    let x = my_struct { x: 123 };
    subprog_ctx_tag_kprobe(ctx as *const bpf_user_pt_regs_t).wrapping_add(
        subprog_multi_ctx_tags_kprobe(
            ctx as *const bpf_user_pt_regs_t,
            &x,
            ctx as *const bpf_user_pt_regs_t,
        ),
    )
}

bpf_object!("GPL");
