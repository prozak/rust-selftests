// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/tailcall_fail.c,
// bpf-rs-core idiom.
//
// Four NEGATIVE verifier tests (prog_tests/tailcalls.c RUN_TESTS this
// object): a tail call while holding a spin lock, inside an RCU read
// section, inside a bpf_preempt_disable region (C's bpf_guard_preempt(), a
// cleanup-attribute pair of the two kfuncs), and with an unreleased
// bpf_obj_new() allocation. C's bpf_obj_new(typeof(*p)) on the
// function-local `struct foo { int i; }` is bpf_obj_new_impl with the local
// type id imported by the BTF_TYPE_ID marker. The `__hidden` lock lives in
// its own `.bss.A` section as in the C.

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_spin_lock, bpf_tail_call};
use bpf_rs_core::maps;
use bpf_rs_core::{bpf_map, test_tags};
use core::ffi::c_void;
use core::ptr::addr_of_mut;

test_tags! {
    reject_tail_call_spin_lock: __failure, __msg("function calls are not allowed while holding a lock");
    reject_tail_call_rcu_lock: __failure, __msg("tail_call cannot be used inside bpf_rcu_read_lock-ed region");
    reject_tail_call_preempt_lock: __failure, __msg("tail_call cannot be used inside bpf_preempt_disable-ed region");
    reject_tail_call_ref: __failure, __msg("tail_call would lead to reference leak");
}

/// struct bpf_spin_lock { __u32 val; }; -- matched by BTF struct name.
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_spin_lock {
    val: u32,
}

// C: private(A) struct bpf_spin_lock lock; (= SEC(".bss.A") __hidden)
#[allow(non_upper_case_globals)]
#[link_section = ".bss.A"]
static mut lock: bpf_spin_lock = bpf_spin_lock { val: 0 };

bpf_map! {
    jmp_table {
        r#type: *const [i32; maps::PROG_ARRAY],
        max_entries: *const [i32; 3],
        key_size: *const [i32; 4],
        value_size: *const [i32; 4],
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct foo {
    i: i32,
}

// BTF_TYPE_ID: foo_id local struct foo
extern "C" {
    fn foo_id() -> u64;
    fn bpf_obj_new_impl(local_type_id: u64, meta: *mut c_void) -> *mut c_void;
    fn bpf_rcu_read_lock();
    fn bpf_rcu_read_unlock();
    fn bpf_preempt_disable();
    fn bpf_preempt_enable();
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn reject_tail_call_spin_lock(ctx: *mut __sk_buff) -> i32 {
    bpf_spin_lock(unsafe { addr_of_mut!(lock) });
    bpf_tail_call(ctx as *const c_void, &jmp_table, 0);
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn reject_tail_call_rcu_lock(ctx: *mut __sk_buff) -> i32 {
    unsafe { bpf_rcu_read_lock() };
    bpf_tail_call(ctx as *const c_void, &jmp_table, 0);
    unsafe { bpf_rcu_read_unlock() };
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn reject_tail_call_preempt_lock(ctx: *mut __sk_buff) -> i32 {
    unsafe { bpf_preempt_disable() };
    bpf_tail_call(ctx as *const c_void, &jmp_table, 0);
    unsafe { bpf_preempt_enable() };
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn reject_tail_call_ref(ctx: *mut __sk_buff) -> i32 {
    let _p = unsafe { bpf_obj_new_impl(foo_id(), core::ptr::null_mut()) } as *mut foo;
    bpf_tail_call(ctx as *const c_void, &jmp_table, 0);
    0
}

bpf_object!("GPL");
