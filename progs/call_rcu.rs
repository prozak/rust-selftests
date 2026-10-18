// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/call_rcu.c
// (bpf-rs-core idiom). The programs arm bpf_call_rcu (or the tasks-trace
// variant) on the bpf_rcu_head of an array element, twice in a row so that
// the second arm reports -EBUSY; the callback records what it was handed in
// the bss globals, clears the value and, when the test asks for a chain,
// re-arms itself. prog_tests/call_rcu.c reads the globals and the element.
// `map->max_entries` is a CO-RE read of the kernel's struct bpf_map.

use core::ffi::c_void;
use core::sync::atomic::{AtomicI32, AtomicU64, Ordering};

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_map_lookup_elem;
use bpf_rs_core::maps::{self, BpfMap};
use btf_macros::btf;

/* rh is not at offset 0, so the callback's value recovery is exercised. */
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_rcu_head {
    __opaque: [u64; 6],
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct elem {
    #[allow(dead_code)]
    pad: u64,
    rh: bpf_rcu_head,
    val: u64,
}

#[link_section = ".maps"]
#[no_mangle]
static arr: BpfMap<u32, elem, { maps::ARRAY }, 2> = BpfMap::new();

#[no_mangle]
static mut cb_key: u32 = 0;
#[no_mangle]
static mut cb_keys: u64 = 0;
#[no_mangle]
static mut cb_val: u64 = 0;
#[no_mangle]
static mut cb_max_entries: u32 = 0;
#[no_mangle]
static mut callbacks: i32 = 0;
#[no_mangle]
static mut arm_err: i32 = 0;
#[no_mangle]
static mut busy_err: i32 = 0;
/* set by userspace: number of times to re-arm from the callback */
#[no_mangle]
static mut chain: i32 = 0;
#[no_mangle]
static mut chain_err: i32 = 0;

#[btf]
struct bpf_map {
    max_entries: u32,
}

type ReclaimFn = extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> i32;

extern "C" {
    fn bpf_call_rcu(rh: *mut c_void, map: *mut c_void, callback: ReclaimFn) -> i32;
    fn bpf_call_rcu_tasks_trace(rh: *mut c_void, map: *mut c_void, callback: ReclaimFn) -> i32;
    fn bpf_rcu_read_lock();
    fn bpf_rcu_read_unlock();
}

#[inline(always)]
fn arr_map() -> *mut c_void {
    &arr as *const _ as *mut c_void
}

extern "C" fn reclaim(map: *mut c_void, key: *mut c_void, value: *mut c_void) -> i32 {
    let e = value as *mut elem;

    unsafe {
        cb_key = *(key as *const u32);
        (*(core::ptr::addr_of_mut!(cb_keys) as *mut AtomicU64)).fetch_or(1u64 << cb_key, Ordering::SeqCst);
        cb_val = (*e).val;
        cb_max_entries = *(&*(map as *const bpf_map)).max_entries().get().unwrap();
        (*e).val = 0;

        if chain > 0 {
            chain -= 1;
            chain_err = bpf_call_rcu(core::ptr::addr_of_mut!((*e).rh) as *mut c_void, arr_map(), reclaim);
        }

        (*(core::ptr::addr_of_mut!(callbacks) as *mut AtomicI32)).fetch_add(1, Ordering::SeqCst);
    }
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn arm(_ctx: *mut c_void) -> i32 {
    let key: u32 = 1;

    let e = bpf_map_lookup_elem(&arr, &key) as *mut elem;
    if e.is_null() {
        return 1;
    }

    unsafe {
        (*e).val = 0xdeadbeef_u64;
        /* Keep a grace period from elapsing between the two arms. */
        bpf_rcu_read_lock();
        arm_err = bpf_call_rcu(core::ptr::addr_of_mut!((*e).rh) as *mut c_void, arr_map(), reclaim);
        busy_err = bpf_call_rcu(core::ptr::addr_of_mut!((*e).rh) as *mut c_void, arr_map(), reclaim);
        bpf_rcu_read_unlock();
    }
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn arm_both(_ctx: *mut c_void) -> i32 {
    let key0: u32 = 0;
    let key1: u32 = 1;

    let e0 = bpf_map_lookup_elem(&arr, &key0) as *mut elem;
    let e1 = bpf_map_lookup_elem(&arr, &key1) as *mut elem;
    if e0.is_null() || e1.is_null() {
        return 1;
    }

    unsafe {
        (*e0).val = 0xdeadbeef_u64;
        (*e1).val = 0xdeadbeef_u64;
        arm_err = bpf_call_rcu(core::ptr::addr_of_mut!((*e0).rh) as *mut c_void, arr_map(), reclaim);
        arm_err |= bpf_call_rcu(core::ptr::addr_of_mut!((*e1).rh) as *mut c_void, arr_map(), reclaim);
    }
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn arm_trace(_ctx: *mut c_void) -> i32 {
    let key: u32 = 1;

    let e = bpf_map_lookup_elem(&arr, &key) as *mut elem;
    if e.is_null() {
        return 1;
    }

    unsafe {
        (*e).val = 0xdeadbeef_u64;
        /* No lock needed: the enclosing rcu_read_lock_trace() already blocks the grace period. */
        arm_err = bpf_call_rcu_tasks_trace(core::ptr::addr_of_mut!((*e).rh) as *mut c_void, arr_map(), reclaim);
        busy_err = bpf_call_rcu_tasks_trace(core::ptr::addr_of_mut!((*e).rh) as *mut c_void, arr_map(), reclaim);
    }
    0
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_iter_meta {
    #[allow(dead_code)]
    seq: *mut c_void,
    #[allow(dead_code)]
    session_id: u64,
    #[allow(dead_code)]
    seq_num: u64,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_iter__bpf_map_elem {
    #[allow(dead_code)]
    meta: *mut bpf_iter_meta,
    #[allow(dead_code)]
    map: *mut c_void,
    #[allow(dead_code)]
    key: *mut c_void,
    #[allow(dead_code)]
    value: *mut c_void,
}

#[link_section = "iter/bpf_map_elem"]
#[no_mangle]
extern "C" fn dump(_ctx: *const bpf_iter__bpf_map_elem) -> i32 {
    0
}

bpf_object!("GPL");
