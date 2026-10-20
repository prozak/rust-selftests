// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/wakeup_source_fail.c,
// bpf-rs-core idiom (test_wakeup_source.rs is the positive counterpart).
//
// Five NEGATIVE verifier tests on the wakeup-source kfuncs
// (prog_tests/wakeup_source.c RUN_TESTS this object): leaking the read
// lock, dereferencing the opaque lock, unlocking a scalar, unlocking NULL,
// and dereferencing the untyped list head bpf_wakeup_sources_get_head()
// returns (a `void *`, a scalar to the verifier).

use bpf_rs_core::bpf_object;
use bpf_rs_core::test_tags;
use btf_macros::btf;
use core::ffi::c_void;

test_tags! {
    wakeup_source_lock_no_unlock: __failure, __msg("BPF_EXIT instruction in main prog would lead to reference leak");
    wakeup_source_access_lock_fields: __failure, __msg("access beyond struct");
    wakeup_source_unlock_no_lock: __failure, __msg("R1 type=scalar expected=ptr_, trusted_ptr_, rcu_ptr_");
    wakeup_source_unlock_null: __failure, __msg("Possibly NULL pointer passed to trusted");
    wakeup_source_unsafe_dereference: __failure, __msg("R0 invalid mem access 'scalar'");
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_ws_lock {
    _priv: [u8; 0],
}

#[btf]
struct list_head {
    next: *mut list_head,
}

extern "C" {
    fn bpf_wakeup_sources_read_lock() -> *mut bpf_ws_lock;
    fn bpf_wakeup_sources_read_unlock(lock: *mut bpf_ws_lock);
    fn bpf_wakeup_sources_get_head() -> *mut c_void;
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn wakeup_source_lock_no_unlock(_ctx: *mut c_void) -> i32 {
    let lock = unsafe { bpf_wakeup_sources_read_lock() };
    if lock.is_null() {
        return 0;
    }

    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn wakeup_source_access_lock_fields(_ctx: *mut c_void) -> i32 {
    let lock = unsafe { bpf_wakeup_sources_read_lock() };
    if lock.is_null() {
        return 0;
    }

    let val = unsafe { core::ptr::read_volatile(lock as *const i32) };

    unsafe { bpf_wakeup_sources_read_unlock(lock) };
    val
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn wakeup_source_unlock_no_lock(_ctx: *mut c_void) -> i32 {
    let lock = 0x1 as *mut bpf_ws_lock;

    unsafe { bpf_wakeup_sources_read_unlock(lock) };

    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn wakeup_source_unlock_null(_ctx: *mut c_void) -> i32 {
    unsafe { bpf_wakeup_sources_read_unlock(core::ptr::null_mut()) };

    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn wakeup_source_unsafe_dereference(_ctx: *mut c_void) -> i32 {
    let head = unsafe { bpf_wakeup_sources_get_head() } as *mut list_head;

    if !(*unsafe { &*head }.next().get().unwrap()).is_null() {
        return 1;
    }

    0
}

bpf_object!("GPL");
