// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/iters_testmod.c
// (bpf-rs-core idiom): what the verifier makes of the pointers that the
// task_vma / task / num open-coded iterators and the bpf_testmod
// KF_RCU_PROTECTED kfuncs return, checked by passing them to the
// bpf_testmod bpf_kfunc_trusted_*_test / bpf_kfunc_rcu_task_test kfuncs.
// The test_loader decl tags are declared with test_tags! and appended to
// the object's BTF by scripts/btf_test_tags.py.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_get_current_task_btf, bpf_this_cpu_ptr};
use bpf_rs_core::test_tags;
use btf_macros::btf;
use core::ffi::c_void;
use core::mem::MaybeUninit;

#[btf]
struct task_struct {
    pid: i32,
}

#[btf]
struct vm_area_struct {}

// struct bpf_iter_task_vma { __u64 __opaque[1]; } __attribute__((aligned(8)));
#[repr(C, align(8))]
struct bpf_iter_task_vma {
    __opaque: [u64; 1],
}

// struct bpf_iter_task { __u64 __opaque[3]; } __attribute__((aligned(8)));
#[repr(C, align(8))]
struct bpf_iter_task {
    __opaque: [u64; 3],
}

// struct bpf_iter_num { __u64 __opaque[1]; } __attribute__((aligned(8)));
#[repr(C, align(8))]
struct bpf_iter_num {
    __opaque: [u64; 1],
}

extern "C" {
    fn bpf_iter_task_vma_new(it: *mut bpf_iter_task_vma, task: *mut task_struct, addr: u64) -> i32;
    fn bpf_iter_task_vma_next(it: *mut bpf_iter_task_vma) -> *mut vm_area_struct;
    fn bpf_iter_task_vma_destroy(it: *mut bpf_iter_task_vma);
    fn bpf_iter_task_new(it: *mut bpf_iter_task, task: *mut task_struct, flags: u32) -> i32;
    fn bpf_iter_task_next(it: *mut bpf_iter_task) -> *mut task_struct;
    fn bpf_iter_task_destroy(it: *mut bpf_iter_task);
    fn bpf_iter_num_new(it: *mut bpf_iter_num, start: i32, end: i32) -> i32;
    fn bpf_iter_num_next(it: *mut bpf_iter_num) -> *mut i32;
    fn bpf_iter_num_destroy(it: *mut bpf_iter_num);
    fn bpf_rcu_read_lock();
    fn bpf_rcu_read_unlock();
    // bpf_testmod kfuncs (../test_kmods/bpf_testmod_kfunc.h)
    fn bpf_kfunc_trusted_vma_test(ptr: *mut vm_area_struct);
    fn bpf_kfunc_trusted_task_test(ptr: *mut task_struct);
    fn bpf_kfunc_trusted_num_test(ptr: *mut i32);
    fn bpf_kfunc_rcu_task_test(ptr: *mut task_struct);
    fn bpf_kfunc_ret_rcu_test() -> *mut task_struct;
    fn bpf_kfunc_ret_rcu_test_nostruct(rdonly_buf_size: i32) -> *mut i32;
}

test_tags! {
    iter_next_trusted: __success;
    iter_next_trusted_or_null: __failure, __msg("Possibly NULL pointer passed to trusted R1");
    iter_next_rcu: __success;
    iter_next_rcu_or_null: __failure, __msg("Possibly NULL pointer passed to trusted R1");
    iter_next_rcu_not_trusted: __failure, __msg("R1 must be referenced or trusted");
    iter_next_ptr_mem_not_trusted: __failure, __msg("R1 type=rdonly_mem expected=fp");
    iter_ret_rcu_test_protected: __failure, __msg("kernel func bpf_kfunc_ret_rcu_test requires RCU critical section protection");
    iter_ret_rcu_test_type: __failure, __msg("Possibly NULL pointer passed to trusted R1");
    iter_ret_rcu_test_protected_nostruct: __failure, __msg("kernel func bpf_kfunc_ret_rcu_test_nostruct requires RCU critical section protection");
    iter_ret_rcu_test_type_nostruct: __failure, __msg("Possibly NULL pointer passed to trusted R1");
}

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn iter_next_trusted(_ctx: *const c_void) -> i32 {
    let cur_task: *mut task_struct = bpf_get_current_task_btf();
    let mut vma_it = MaybeUninit::<bpf_iter_task_vma>::uninit();

    unsafe {
        bpf_iter_task_vma_new(vma_it.as_mut_ptr(), cur_task, 0);

        let vma_ptr = bpf_iter_task_vma_next(vma_it.as_mut_ptr());
        if !vma_ptr.is_null() {
            bpf_kfunc_trusted_vma_test(vma_ptr);
        }
        bpf_iter_task_vma_destroy(vma_it.as_mut_ptr());
    }
    0
}

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn iter_next_trusted_or_null(_ctx: *const c_void) -> i32 {
    let cur_task: *mut task_struct = bpf_get_current_task_btf();
    let mut vma_it = MaybeUninit::<bpf_iter_task_vma>::uninit();

    unsafe {
        bpf_iter_task_vma_new(vma_it.as_mut_ptr(), cur_task, 0);

        let vma_ptr = bpf_iter_task_vma_next(vma_it.as_mut_ptr());

        bpf_kfunc_trusted_vma_test(vma_ptr);

        bpf_iter_task_vma_destroy(vma_it.as_mut_ptr());
    }
    0
}

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn iter_next_rcu(_ctx: *const c_void) -> i32 {
    let cur_task: *mut task_struct = bpf_get_current_task_btf();
    let mut task_it = MaybeUninit::<bpf_iter_task>::uninit();

    unsafe {
        bpf_iter_task_new(task_it.as_mut_ptr(), cur_task, 0);

        let task_ptr = bpf_iter_task_next(task_it.as_mut_ptr());
        if !task_ptr.is_null() {
            bpf_kfunc_rcu_task_test(task_ptr);
        }
        bpf_iter_task_destroy(task_it.as_mut_ptr());
    }
    0
}

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn iter_next_rcu_or_null(_ctx: *const c_void) -> i32 {
    let cur_task: *mut task_struct = bpf_get_current_task_btf();
    let mut task_it = MaybeUninit::<bpf_iter_task>::uninit();

    unsafe {
        bpf_iter_task_new(task_it.as_mut_ptr(), cur_task, 0);

        let task_ptr = bpf_iter_task_next(task_it.as_mut_ptr());

        bpf_kfunc_rcu_task_test(task_ptr);

        bpf_iter_task_destroy(task_it.as_mut_ptr());
    }
    0
}

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn iter_next_rcu_not_trusted(_ctx: *const c_void) -> i32 {
    let cur_task: *mut task_struct = bpf_get_current_task_btf();
    let mut task_it = MaybeUninit::<bpf_iter_task>::uninit();

    unsafe {
        bpf_iter_task_new(task_it.as_mut_ptr(), cur_task, 0);

        let task_ptr = bpf_iter_task_next(task_it.as_mut_ptr());
        if !task_ptr.is_null() {
            bpf_kfunc_trusted_task_test(task_ptr);
        }
        bpf_iter_task_destroy(task_it.as_mut_ptr());
    }
    0
}

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn iter_next_ptr_mem_not_trusted(_ctx: *const c_void) -> i32 {
    let mut num_it = MaybeUninit::<bpf_iter_num>::uninit();

    unsafe {
        bpf_iter_num_new(num_it.as_mut_ptr(), 0, 10);

        let num_ptr = bpf_iter_num_next(num_it.as_mut_ptr());
        if !num_ptr.is_null() {
            bpf_kfunc_trusted_num_test(num_ptr);
        }
        bpf_iter_num_destroy(num_it.as_mut_ptr());
    }
    0
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn iter_ret_rcu_test_protected(_ctx: *const c_void) -> i32 {
    let p = unsafe { bpf_kfunc_ret_rcu_test() };
    *unsafe { &*p }.pid().get().unwrap()
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn iter_ret_rcu_test_type(_ctx: *const c_void) -> i32 {
    unsafe {
        bpf_rcu_read_lock();
        let p = bpf_kfunc_ret_rcu_test();
        bpf_this_cpu_ptr(p as *const c_void);
        bpf_rcu_read_unlock();
    }
    0
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn iter_ret_rcu_test_protected_nostruct(_ctx: *const c_void) -> i32 {
    let p = unsafe { bpf_kfunc_ret_rcu_test_nostruct(4) };
    unsafe { *p }
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn iter_ret_rcu_test_type_nostruct(_ctx: *const c_void) -> i32 {
    unsafe {
        bpf_rcu_read_lock();
        let p = bpf_kfunc_ret_rcu_test_nostruct(4);
        bpf_this_cpu_ptr(p as *const c_void);
        bpf_rcu_read_unlock();
    }
    0
}

bpf_object!("GPL");
