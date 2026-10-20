// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![allow(non_camel_case_types, non_upper_case_globals)]

// Direct translation of tools/testing/selftests/bpf/progs/cpumask_failure.c
// (+ cpumask_common.h), bpf-rs-core idiom.
//
// bpf_cpumask kfunc misuse rejections (prog_tests/cpumask.c:
// RUN_TESTS(cpumask_failure)). The common header's map, `private(MASK)`
// global kptr (a `static mut` in .bss.MASK), kfunc externs and
// create/insert/lookup helpers are those of cpumask_success.rs; the
// __kptr members and globals are tagged by btf_type_tags!. The nested
// array of CPUMASK_KPTR_FIELDS_MAX + 1 kptrs lives in .bss.MASK_NESTED
// so that map's btf_parse_fields() fails. `task->cpus_ptr` is a #[btf]
// CO-RE read; `__sink(x)` is helpers::sink.

use bpf_rs_core::helpers::{bpf_kptr_xchg, bpf_map_lookup_elem, bpf_map_update_elem, sink};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::progs::fentry_arg;
use bpf_rs_core::{bpf_object, btf_type_tags, test_tags};
use btf_macros::btf;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ptr::{addr_of_mut, null_mut};

const ENOENT: i32 = 2;
const EEXIST: i32 = 17;
const CPUMASK_KPTR_FIELDS_MAX: usize = 11;

struct bpf_cpumask;

// The pointee of a #[btf] field must be #[btf] itself (kernel struct
// cpumask; no field is read).
#[btf]
struct cpumask {
    bits: [u64; 1],
}

#[btf]
struct task_struct {
    cpus_ptr: *const cpumask,
}

extern "C" {
    fn bpf_cpumask_create() -> *mut bpf_cpumask;
    fn bpf_cpumask_release(cpumask: *mut bpf_cpumask);
    fn bpf_cpumask_acquire(cpumask: *mut bpf_cpumask) -> *mut bpf_cpumask;
    fn bpf_cpumask_set_cpu(cpu: u32, cpumask: *mut bpf_cpumask);
    fn bpf_cpumask_test_cpu(cpu: u32, cpumask: *const cpumask) -> bool;
    fn bpf_cpumask_empty(cpumask: *const cpumask) -> bool;
    fn bpf_cpumask_populate(cpumask: *mut bpf_cpumask, src: *mut c_void, src_sz: usize) -> i32;
    fn bpf_rcu_read_lock();
    fn bpf_rcu_read_unlock();
}

#[no_mangle]
static mut err: i32 = 0;

#[repr(C)]
struct __cpumask_map_value {
    cpumask: *mut bpf_cpumask,
}

#[link_section = ".maps"]
#[no_mangle]
static __cpumask_map: BpfMap<i32, __cpumask_map_value, { maps::ARRAY }, 1> = BpfMap::new();

// C: private(MASK) static struct bpf_cpumask __kptr * global_mask;
#[link_section = ".bss.MASK"]
static mut global_mask: *mut bpf_cpumask = null_mut();

#[repr(C)]
struct kptr_nested_array_2 {
    mask: *mut bpf_cpumask,
}

#[repr(C)]
struct kptr_nested_array_1 {
    // Make btf_parse_fields() in map_create() return -E2BIG
    d_2: [kptr_nested_array_2; CPUMASK_KPTR_FIELDS_MAX + 1],
}

#[repr(C)]
struct kptr_nested_array {
    d_1: kptr_nested_array_1,
}

#[link_section = ".bss.MASK_NESTED"]
static mut global_mask_nested_arr: kptr_nested_array = kptr_nested_array {
    d_1: kptr_nested_array_1 {
        d_2: [const { kptr_nested_array_2 { mask: null_mut() } }; CPUMASK_KPTR_FIELDS_MAX + 1],
    },
};

btf_type_tags! {
    __cpumask_map_value.cpumask: kptr;
    global_mask: kptr;
    kptr_nested_array_2.mask: kptr;
}

#[inline(always)]
fn cast(m: *mut bpf_cpumask) -> *const cpumask {
    m as *const cpumask
}

#[inline(always)]
fn xchg(p: *mut *mut bpf_cpumask, m: *mut bpf_cpumask) -> *mut bpf_cpumask {
    bpf_kptr_xchg(p.cast(), m.cast()).cast()
}

#[inline(always)]
fn task_cpus_ptr(task: *mut task_struct) -> *const cpumask {
    *unsafe { &*task }.cpus_ptr().get().unwrap()
}

fn create_cpumask() -> *mut bpf_cpumask {
    let mask = unsafe { bpf_cpumask_create() };
    if mask.is_null() {
        unsafe { err = 1 };
        return null_mut();
    }
    if !unsafe { bpf_cpumask_empty(cast(mask)) } {
        unsafe {
            err = 2;
            bpf_cpumask_release(mask);
        }
        return null_mut();
    }
    mask
}

fn cpumask_map_value_lookup() -> *mut __cpumask_map_value {
    let key: u32 = 0;
    bpf_map_lookup_elem(&__cpumask_map, &key).cast()
}

fn cpumask_map_insert(mask: *mut bpf_cpumask) -> i32 {
    let key: u32 = 0;
    let local = __cpumask_map_value { cpumask: null_mut() };
    let status = bpf_map_update_elem(&__cpumask_map, &key, &local, 0);
    if status != 0 {
        unsafe { bpf_cpumask_release(mask) };
        return status as i32;
    }
    let v = cpumask_map_value_lookup();
    if v.is_null() {
        unsafe { bpf_cpumask_release(mask) };
        return -ENOENT;
    }
    let old = xchg(unsafe { addr_of_mut!((*v).cpumask) }, mask);
    if !old.is_null() {
        unsafe { bpf_cpumask_release(old) };
        return -EEXIST;
    }
    0
}

// Prototype for all of the program trace events below:
//
// TRACE_EVENT(task_newtask,
//         TP_PROTO(struct task_struct *p, u64 clone_flags)

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_alloc_no_release(_ctx: *const u64) -> i32 {
    let mut mask = create_cpumask();
    sink(&mut mask);

    // cpumask is never released.
    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_alloc_double_release(_ctx: *const u64) -> i32 {
    let mask = create_cpumask();

    // cpumask is released twice.
    unsafe {
        bpf_cpumask_release(mask);
        bpf_cpumask_release(mask);
    }

    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_acquire_wrong_cpumask(ctx: *const u64) -> i32 {
    let task = fentry_arg(ctx, 0) as *mut task_struct;

    // Can't acquire a non-struct bpf_cpumask.
    let mut mask = unsafe { bpf_cpumask_acquire(task_cpus_ptr(task) as *mut bpf_cpumask) };
    sink(&mut mask);

    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_mutate_cpumask(ctx: *const u64) -> i32 {
    let task = fentry_arg(ctx, 0) as *mut task_struct;

    // Can't set the CPU of a non-struct bpf_cpumask.
    unsafe { bpf_cpumask_set_cpu(0, task_cpus_ptr(task) as *mut bpf_cpumask) };

    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_insert_remove_no_release(_ctx: *const u64) -> i32 {
    let mask = create_cpumask();
    if mask.is_null() {
        return 0;
    }

    if cpumask_map_insert(mask) != 0 {
        return 0;
    }

    let v = cpumask_map_value_lookup();
    if v.is_null() {
        return 0;
    }

    let _mask = xchg(unsafe { addr_of_mut!((*v).cpumask) }, null_mut());

    // cpumask is never released.
    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_cpumask_null(_ctx: *const u64) -> i32 {
    // NULL passed to kfunc.
    unsafe { bpf_cpumask_empty(core::ptr::null()) };

    0
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn test_global_mask_out_of_rcu(_ctx: *const c_void) -> i32 {
    let local = create_cpumask();
    if local.is_null() {
        return 0;
    }

    unsafe {
        let prev = xchg(addr_of_mut!(global_mask), local);
        if !prev.is_null() {
            bpf_cpumask_release(prev);
            err = 3;
            return 0;
        }

        // Use a sleepable program so explicit RCU is the only source of RCU
        // protection.
        bpf_rcu_read_lock();
        let local = global_mask;
        if local.is_null() {
            err = 4;
            bpf_rcu_read_unlock();
            return 0;
        }

        bpf_rcu_read_unlock();

        // RCU region is exited before calling KF_RCU kfunc.

        bpf_cpumask_test_cpu(0, cast(local));
    }

    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_global_mask_no_null_check(_ctx: *const u64) -> i32 {
    let local = create_cpumask();
    if local.is_null() {
        return 0;
    }

    unsafe {
        let prev = xchg(addr_of_mut!(global_mask), local);
        if !prev.is_null() {
            bpf_cpumask_release(prev);
            err = 3;
            return 0;
        }

        bpf_rcu_read_lock();
        let local = global_mask;

        // No NULL check is performed on global cpumask kptr.
        bpf_cpumask_test_cpu(0, cast(local));

        bpf_rcu_read_unlock();
    }

    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_global_mask_rcu_no_null_check(_ctx: *const u64) -> i32 {
    unsafe {
        let curr = bpf_cpumask_create();
        if curr.is_null() {
            return 0;
        }

        let prev = xchg(addr_of_mut!(global_mask), curr);
        if !prev.is_null() {
            bpf_cpumask_release(prev);
        }

        bpf_rcu_read_lock();
        let curr = global_mask;
        // PTR_TO_BTF_ID | PTR_MAYBE_NULL | MEM_RCU passed to bpf_kptr_xchg()
        let prev = xchg(addr_of_mut!(global_mask), curr);
        bpf_rcu_read_unlock();
        if !prev.is_null() {
            bpf_cpumask_release(prev);
        }
    }

    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_invalid_nested_array(_ctx: *const u64) -> i32 {
    let local = create_cpumask();
    if local.is_null() {
        return 0;
    }

    unsafe {
        let prev = xchg(
            addr_of_mut!(global_mask_nested_arr.d_1.d_2[CPUMASK_KPTR_FIELDS_MAX].mask),
            local,
        );
        if !prev.is_null() {
            bpf_cpumask_release(prev);
            err = 3;
            return 0;
        }
    }

    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_populate_invalid_destination(_ctx: *const u64) -> i32 {
    let invalid = 0x123456usize as *mut bpf_cpumask;
    let mut bits = MaybeUninit::<u64>::uninit();

    let ret = unsafe { bpf_cpumask_populate(invalid, bits.as_mut_ptr() as *mut c_void, 8) };
    if ret == 0 {
        unsafe { err = 2 };
    }

    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_populate_invalid_source(_ctx: *const u64) -> i32 {
    let garbage = 0x123456usize as *mut c_void;

    let local = create_cpumask();
    if local.is_null() {
        unsafe { err = 1 };
        return 0;
    }

    let ret = unsafe { bpf_cpumask_populate(local, garbage, 8) };
    if ret == 0 {
        unsafe { err = 2 };
    }

    unsafe { bpf_cpumask_release(local) };

    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_populate_borrowed_destination(ctx: *const u64) -> i32 {
    let task = fentry_arg(ctx, 0) as *mut task_struct;
    let mut bits = MaybeUninit::<u64>::uninit();

    // task->cpus_ptr is a borrowed, read-only struct cpumask *, not an
    // owned struct bpf_cpumask *. The verifier must reject it as a
    // writable destination for bpf_cpumask_populate().
    let ret = unsafe {
        bpf_cpumask_populate(
            task_cpus_ptr(task) as *mut bpf_cpumask,
            bits.as_mut_ptr() as *mut c_void,
            8,
        )
    };
    if ret == 0 {
        unsafe { err = 2 };
    }

    0
}

test_tags! {
    test_alloc_no_release: __failure, __msg("Unreleased reference");
    test_alloc_double_release: __failure, __msg("NULL pointer passed to trusted R1");
    test_acquire_wrong_cpumask: __failure, __msg("must be referenced");
    test_mutate_cpumask: __failure, __msg("bpf_cpumask_set_cpu R2 expected pointer to STRUCT bpf_cpumask");
    test_insert_remove_no_release: __failure, __msg("Unreleased reference");
    test_cpumask_null: __failure, __msg("NULL pointer passed to trusted R1");
    test_global_mask_out_of_rcu: __failure, __msg("R2 must be a rcu pointer");
    test_global_mask_no_null_check: __failure, __msg("NULL pointer passed to trusted R2");
    test_global_mask_rcu_no_null_check: __failure, __msg("release function bpf_kptr_xchg expects referenced PTR_TO_BTF_ID passed to R2");
    test_invalid_nested_array: __failure, __msg("has no valid kptr");
    test_populate_invalid_destination: __failure, __msg("type=scalar expected=fp");
    test_populate_invalid_source: __failure, __msg("R2 type=scalar expected=fp");
    test_populate_borrowed_destination: __failure, __msg("expected pointer to STRUCT bpf_cpumask but R1 has a pointer to STRUCT cpumask");
}

bpf_object!("GPL");
