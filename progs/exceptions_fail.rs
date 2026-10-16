// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(linkage)]

// Direct translation of tools/testing/selftests/bpf/progs/exceptions_fail.c
// (bpf-rs-core idiom).
//
// Verifier rejection tests for bpf_throw() (prog_tests/exceptions.c:
// RUN_TESTS(exceptions_fail)); test_tags! mirrors the C __failure/__msg
// tags. C's __exception_cb(cb) is the decl tag "exception_callback:cb" on
// the program, carried by rust-bpf's #[btf_tag] (two of them on
// reject_multiple_exception_cb). C's __noinline global functions are
// #[no_mangle] #[inline(never)] here, so they stay global subprograms in
// .text with their C signatures (the exception callbacks' bad return and
// argument types are what the tests reject); __noinline static ones are
// #[inline(never)] without #[no_mangle]. `__weak void foo(void)` is a weak
// global subprog. lock and rbtree (private(A)) are C `__hidden` statics in
// `.bss.A` in clang's first-use order (lock 0, rbtree 8).

// BTF_TYPE_ID: foo_id local struct foo

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_loop, bpf_map_lookup_elem, bpf_spin_lock, bpf_spin_unlock, bpf_timer_set_callback};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::{bpf_object, test_tags};
use btf_macros::btf_tag;
use core::ffi::c_void;
use core::ptr::{addr_of_mut, null_mut};

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_spin_lock {
    val: u32,
}

#[allow(non_camel_case_types)]
#[repr(C, align(8))]
struct bpf_rb_root {
    __opaque: [u64; 2],
}

#[allow(non_camel_case_types)]
#[repr(C, align(8))]
struct bpf_rb_node {
    __opaque: [u64; 4],
}

#[allow(non_camel_case_types)]
#[repr(C, align(8))]
struct bpf_timer {
    __opaque: [u64; 2],
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct foo {
    node: bpf_rb_node,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct hmap_elem {
    timer: bpf_timer,
}

#[link_section = ".maps"]
#[no_mangle]
static hmap: BpfMap<i32, hmap_elem, { maps::HASH }, 64> = BpfMap::new();

#[allow(non_upper_case_globals)]
#[link_section = ".bss.A"]
static mut lock: bpf_spin_lock = bpf_spin_lock { val: 0 };

#[allow(non_upper_case_globals)]
#[btf_tag(decl_tag = "contains:foo:node")]
#[link_section = ".bss.A"]
static mut rbtree: bpf_rb_root = bpf_rb_root { __opaque: [0; 2] };

extern "C" {
    fn foo_id() -> u64;
    fn bpf_obj_new(local_type_id: u64) -> *mut c_void;
    fn bpf_obj_drop(obj: *mut c_void);
    fn bpf_rbtree_add(
        root: *mut bpf_rb_root,
        node: *mut bpf_rb_node,
        less: extern "C" fn(*mut bpf_rb_node, *const bpf_rb_node) -> bool,
    ) -> i32;
    fn bpf_throw(cookie: u64);
    fn bpf_rcu_read_lock();
    fn bpf_rcu_read_unlock();
    fn bpf_preempt_disable();
    fn bpf_preempt_enable();
    fn bpf_local_irq_save(flags: *mut u64);
    fn bpf_local_irq_restore(flags: *mut u64);
}

#[no_mangle]
#[inline(never)]
extern "C" fn exception_cb_bad_ret_type1(_cookie: u64) -> *mut c_void {
    null_mut()
}

#[no_mangle]
#[inline(never)]
extern "C" fn exception_cb_bad_ret_type2(_cookie: u64) {}

#[no_mangle]
#[inline(never)]
extern "C" fn exception_cb_bad_arg_0() -> i32 {
    0
}

#[no_mangle]
#[inline(never)]
extern "C" fn exception_cb_bad_arg_2(_a: i32, _b: i32) -> i32 {
    0
}

#[no_mangle]
#[inline(never)]
extern "C" fn exception_cb_ok_arg_small(_a: i32) -> i32 {
    0
}

#[btf_tag(decl_tag = "exception_callback:exception_cb_bad_ret_type1")]
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn reject_exception_cb_type_1(_ctx: *const __sk_buff) -> i32 {
    unsafe { bpf_throw(0) };
    0
}

#[btf_tag(decl_tag = "exception_callback:exception_cb_bad_arg_0")]
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn reject_exception_cb_type_2(_ctx: *const __sk_buff) -> i32 {
    unsafe { bpf_throw(0) };
    0
}

#[btf_tag(decl_tag = "exception_callback:exception_cb_bad_arg_2")]
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn reject_exception_cb_type_3(_ctx: *const __sk_buff) -> i32 {
    unsafe { bpf_throw(0) };
    0
}

#[btf_tag(decl_tag = "exception_callback:exception_cb_ok_arg_small")]
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn reject_exception_cb_type_4(_ctx: *const __sk_buff) -> i32 {
    unsafe { bpf_throw(0) };
    0
}

#[btf_tag(decl_tag = "exception_callback:exception_cb_bad_ret_type2")]
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn reject_exception_cb_type_5(_ctx: *const __sk_buff) -> i32 {
    unsafe { bpf_throw(0) };
    0
}

#[inline(never)]
extern "C" fn timer_cb(_map: *mut c_void, _key: *mut i32, _timer: *mut bpf_timer) -> i64 {
    unsafe { bpf_throw(0) };
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn reject_async_callback_throw(_ctx: *const __sk_buff) -> i32 {
    unsafe {
        let zero: i32 = 0;
        let elem = bpf_map_lookup_elem(&hmap, &zero) as *mut hmap_elem;
        if elem.is_null() {
            return 0;
        }
        bpf_timer_set_callback(addr_of_mut!((*elem).timer), timer_cb) as i32
    }
}

#[inline(never)]
unsafe fn subprog_lock(ctx: *const __sk_buff) -> i32 {
    // volatile int ret = 0;
    let ret: i32 = 0;

    bpf_spin_lock(addr_of_mut!(lock));
    if (*ctx).len != 0 {
        bpf_throw(0);
    }
    core::ptr::read_volatile(&ret)
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn reject_with_lock(_ctx: *const c_void) -> i32 {
    unsafe {
        bpf_spin_lock(addr_of_mut!(lock));
        bpf_throw(0);
        0
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn reject_subprog_with_lock(ctx: *const c_void) -> i32 {
    unsafe { subprog_lock(ctx as *const __sk_buff) }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn reject_with_rcu_read_lock(_ctx: *const c_void) -> i32 {
    unsafe {
        bpf_rcu_read_lock();
        bpf_throw(0);
        0
    }
}

#[inline(never)]
unsafe fn throwing_subprog(ctx: *const __sk_buff) -> i32 {
    if (*ctx).len != 0 {
        bpf_throw(0);
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn reject_subprog_with_rcu_read_lock(ctx: *const c_void) -> i32 {
    unsafe {
        bpf_rcu_read_lock();
        throwing_subprog(ctx as *const __sk_buff);
        bpf_rcu_read_unlock();
        0
    }
}

extern "C" fn rbless(_n1: *mut bpf_rb_node, _n2: *const bpf_rb_node) -> bool {
    unsafe { bpf_throw(0) };
    true
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn reject_with_rbtree_add_throw(_ctx: *const c_void) -> i32 {
    unsafe {
        let f = bpf_obj_new(foo_id()) as *mut foo;
        if f.is_null() {
            return 0;
        }
        bpf_spin_lock(addr_of_mut!(lock));
        bpf_rbtree_add(addr_of_mut!(rbtree), addr_of_mut!((*f).node), rbless);
        bpf_spin_unlock(addr_of_mut!(lock));
        0
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn reject_with_reference(_ctx: *const c_void) -> i32 {
    unsafe {
        let f = bpf_obj_new(foo_id()) as *mut foo;
        if f.is_null() {
            return 0;
        }
        bpf_throw(0);
        0
    }
}

#[no_mangle]
#[inline(never)]
extern "C" fn global_subprog_may_throw(ctx: *const __sk_buff) -> i32 {
    unsafe {
        if (*ctx).len != 0 {
            bpf_throw(0);
        }
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn reject_global_subprog_throw_with_reference(ctx: *const __sk_buff) -> i32 {
    unsafe {
        let f = bpf_obj_new(foo_id()) as *mut foo;
        if f.is_null() {
            return 0;
        }
        if (*ctx).protocol != 0 {
            global_subprog_may_throw(ctx);
        }
        bpf_obj_drop(f.cast());
        0
    }
}

#[inline(never)]
unsafe fn subprog_ref(_ctx: *const __sk_buff) -> i32 {
    let f = bpf_obj_new(foo_id()) as *mut foo;
    if f.is_null() {
        return 0;
    }
    bpf_throw(0);
    0
}

#[inline(never)]
extern "C" fn subprog_cb_ref(_i: u64, _ctx: *mut c_void) -> i64 {
    unsafe { bpf_throw(0) };
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn reject_with_cb_reference(_ctx: *const c_void) -> i32 {
    unsafe {
        let f = bpf_obj_new(foo_id()) as *mut foo;
        if f.is_null() {
            return 0;
        }
        bpf_loop(5, subprog_cb_ref, null_mut::<c_void>(), 0);
        bpf_obj_drop(f.cast());
        0
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn reject_with_cb(_ctx: *const c_void) -> i32 {
    bpf_loop(5, subprog_cb_ref, null_mut::<c_void>(), 0);
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn reject_with_subprog_reference(ctx: *const c_void) -> i32 {
    unsafe { subprog_ref(ctx as *const __sk_buff) + 1 }
}

#[no_mangle]
#[inline(never)]
extern "C" fn throwing_exception_cb(c: u64) -> i32 {
    unsafe { bpf_throw(0) };
    c as i32
}

#[no_mangle]
#[inline(never)]
extern "C" fn exception_cb1(c: u64) -> i32 {
    c as i32
}

#[no_mangle]
#[inline(never)]
extern "C" fn exception_cb2(c: u64) -> i32 {
    c as i32
}

#[inline(never)]
unsafe fn static_func(ctx: *const __sk_buff) -> i32 {
    exception_cb1((*ctx).tstamp)
}

#[no_mangle]
#[inline(never)]
extern "C" fn global_func(ctx: *const __sk_buff) -> i32 {
    unsafe { exception_cb1((*ctx).tstamp) }
}

#[btf_tag(decl_tag = "exception_callback:throwing_exception_cb")]
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn reject_throwing_exception_cb(_ctx: *const __sk_buff) -> i32 {
    0
}

#[btf_tag(decl_tag = "exception_callback:exception_cb1")]
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn reject_exception_cb_call_global_func(ctx: *const __sk_buff) -> i32 {
    global_func(ctx)
}

#[btf_tag(decl_tag = "exception_callback:exception_cb1")]
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn reject_exception_cb_call_static_func(ctx: *const __sk_buff) -> i32 {
    unsafe { static_func(ctx) }
}

#[btf_tag(decl_tag = "exception_callback:exception_cb1")]
#[btf_tag(decl_tag = "exception_callback:exception_cb2")]
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn reject_multiple_exception_cb(_ctx: *const __sk_buff) -> i32 {
    unsafe { bpf_throw(0) };
    16
}

#[no_mangle]
#[inline(never)]
extern "C" fn exception_cb_bad_ret(c: u64) -> i32 {
    c as i32
}

#[btf_tag(decl_tag = "exception_callback:exception_cb_bad_ret")]
#[link_section = "?fentry/bpf_check"]
#[no_mangle]
extern "C" fn reject_set_exception_cb_bad_ret1(_ctx: *const c_void) -> i32 {
    0
}

#[link_section = "?fentry/bpf_check"]
#[no_mangle]
extern "C" fn reject_set_exception_cb_bad_ret2(_ctx: *const c_void) -> i32 {
    unsafe { bpf_throw(64) };
    0
}

#[inline(never)]
extern "C" fn loop_cb1(_index: u64, _ctx: *mut i32) -> i64 {
    unsafe { bpf_throw(0) };
    0
}

#[inline(never)]
extern "C" fn loop_cb2(_index: u64, _ctx: *mut i32) -> i64 {
    unsafe { bpf_throw(0) };
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn reject_exception_throw_cb(_ctx: *const __sk_buff) -> i32 {
    bpf_loop(5, loop_cb1, null_mut::<i32>(), 0);
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn reject_exception_throw_cb_diff(ctx: *const __sk_buff) -> i32 {
    unsafe {
        if (*ctx).protocol != 0 {
            bpf_loop(5, loop_cb1, null_mut::<i32>(), 0);
        } else {
            bpf_loop(5, loop_cb2, null_mut::<i32>(), 0);
        }
    }
    0
}

// __weak void foo(void)
#[no_mangle]
#[inline(never)]
#[linkage = "weak"]
extern "C" fn foo() {
    unsafe { bpf_throw(1) };
}

#[link_section = "?fentry/bpf_check"]
#[no_mangle]
extern "C" fn reject_out_of_range_global_throw(_skb: *const __sk_buff) -> i32 {
    foo();

    0
}

#[inline(never)]
unsafe fn always_throws() -> i32 {
    bpf_throw(0);
    0
}

#[inline(never)]
unsafe fn rcu_lock_then_throw() -> i32 {
    bpf_rcu_read_lock();
    bpf_throw(0);
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn reject_subprog_rcu_lock_throw(_ctx: *const c_void) -> i32 {
    unsafe {
        rcu_lock_then_throw();
        0
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn reject_subprog_throw_preempt_lock(_ctx: *const c_void) -> i32 {
    unsafe {
        bpf_preempt_disable();
        always_throws();
        bpf_preempt_enable();
        0
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn reject_subprog_throw_irq_lock(_ctx: *const c_void) -> i32 {
    unsafe {
        let mut flags: u64 = 0;

        bpf_local_irq_save(&mut flags);
        always_throws();
        bpf_local_irq_restore(&mut flags);
        0
    }
}

test_tags! {
    reject_exception_cb_type_1: __failure, __msg("Only void, scalar, arena pointer, or a struct/union of scalars and arena pointers up to 16 bytes is supported.");
    reject_exception_cb_type_2: __failure, __msg("exception cb only supports single integer argument");
    reject_exception_cb_type_3: __failure, __msg("exception cb only supports single integer argument");
    reject_exception_cb_type_4: __success;
    reject_exception_cb_type_5: __failure, __msg("exception cb cannot return void");
    reject_async_callback_throw: __failure, __msg("cannot be called from callback subprog");
    reject_with_lock: __failure, __msg("function calls are not allowed while holding a lock");
    reject_subprog_with_lock: __failure, __msg("function calls are not allowed while holding a lock");
    reject_with_rcu_read_lock: __failure, __msg("bpf_throw cannot be used inside bpf_rcu_read_lock-ed region");
    reject_subprog_with_rcu_read_lock: __failure, __msg("bpf_throw cannot be used inside bpf_rcu_read_lock-ed region");
    reject_with_rbtree_add_throw: __failure, __msg("function calls are not allowed while holding a lock");
    reject_with_reference: __failure, __msg("Unreleased reference");
    reject_global_subprog_throw_with_reference: __failure, __msg("Unreleased reference");
    reject_with_cb_reference: __failure, __msg("Unreleased reference");
    reject_with_cb: __failure, __msg("cannot be called from callback");
    reject_with_subprog_reference: __failure, __msg("Unreleased reference");
    reject_throwing_exception_cb: __failure, __msg("cannot be called from callback subprog");
    reject_exception_cb_call_global_func: __failure, __msg("cannot call exception cb directly");
    reject_exception_cb_call_static_func: __failure, __msg("cannot call exception cb directly");
    reject_multiple_exception_cb: __failure, __msg("multiple exception callback tags for main subprog");
    reject_set_exception_cb_bad_ret1: __failure, __msg("At program exit the register R0 has unknown scalar value should");
    reject_set_exception_cb_bad_ret2: __failure, __msg("At program exit the register R1 has smin=64 smax=64 should");
    reject_exception_throw_cb: __failure, __msg("cannot be called from callback");
    reject_exception_throw_cb_diff: __failure, __msg("cannot be called from callback");
    reject_out_of_range_global_throw: __failure, __msg("At program exit the register R1 has smin=1 smax=1 should");
    reject_subprog_rcu_lock_throw: __failure, __msg("bpf_throw cannot be used inside bpf_rcu_read_lock-ed region");
    reject_subprog_throw_preempt_lock: __failure, __msg("bpf_throw cannot be used inside bpf_preempt_disable-ed region");
    reject_subprog_throw_irq_lock: __failure, __msg("bpf_throw cannot be used inside bpf_local_irq_save-ed region");
}

bpf_object!("GPL");
