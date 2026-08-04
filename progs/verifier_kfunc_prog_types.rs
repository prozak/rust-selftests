#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/verifier_kfunc_prog_types.c
// (bpf-next-x86), bpf-rs-core idiom.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_current_task_btf;
use btf_macros::btf;

#[btf]
struct task_struct {
    pid: i32,
}

struct cgroup;
struct bpf_cpumask;
struct cpumask;

extern "C" {
    fn bpf_task_from_pid(pid: i32) -> *mut task_struct;
    fn bpf_task_acquire(p: *mut task_struct) -> *mut task_struct;
    fn bpf_task_release(p: *mut task_struct);

    fn bpf_cgroup_from_id(cgid: u64) -> *mut cgroup;
    fn bpf_cgroup_acquire(p: *mut cgroup) -> *mut cgroup;
    fn bpf_cgroup_release(p: *mut cgroup);

    fn bpf_cpumask_create() -> *mut bpf_cpumask;
    fn bpf_cpumask_acquire(cpumask: *mut bpf_cpumask) -> *mut bpf_cpumask;
    fn bpf_cpumask_release(cpumask: *mut bpf_cpumask);
    fn bpf_cpumask_set_cpu(cpu: u32, cpumask: *mut bpf_cpumask);
    fn bpf_cpumask_test_cpu(cpu: u32, cpumask: *const cpumask) -> bool;
}

#[inline(never)]
fn task_kfunc_load_test() {
    let current: *mut task_struct = bpf_get_current_task_btf();
    let pid = *unsafe { &*current }.pid().get().unwrap();

    let ref_1 = unsafe { bpf_task_from_pid(pid) };
    if ref_1.is_null() {
        return;
    }

    let ref_2 = unsafe { bpf_task_acquire(ref_1) };
    if !ref_2.is_null() {
        unsafe { bpf_task_release(ref_2) };
    }
    unsafe { bpf_task_release(ref_1) };
}

#[inline(never)]
fn cgrp_kfunc_load_test() {
    let cgrp = unsafe { bpf_cgroup_from_id(0) };
    if cgrp.is_null() {
        return;
    }

    let r#ref = unsafe { bpf_cgroup_acquire(cgrp) };
    if r#ref.is_null() {
        unsafe { bpf_cgroup_release(cgrp) };
        return;
    }

    unsafe { bpf_cgroup_release(r#ref) };
    unsafe { bpf_cgroup_release(cgrp) };
}

#[inline(never)]
fn cpumask_kfunc_load_test() {
    let alloc = unsafe { bpf_cpumask_create() };
    if alloc.is_null() {
        return;
    }

    let r#ref = unsafe { bpf_cpumask_acquire(alloc) };
    unsafe { bpf_cpumask_set_cpu(0, alloc) };
    unsafe { bpf_cpumask_test_cpu(0, r#ref as *const cpumask) };

    unsafe { bpf_cpumask_release(r#ref) };
    unsafe { bpf_cpumask_release(alloc) };
}

#[link_section = "raw_tp"]
#[no_mangle]
extern "C" fn task_kfunc_raw_tp(_ctx: *const u64) -> i32 {
    task_kfunc_load_test();
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn task_kfunc_syscall(_ctx: *const u64) -> i32 {
    task_kfunc_load_test();
    0
}

#[link_section = "tracepoint"]
#[no_mangle]
extern "C" fn task_kfunc_tracepoint(_ctx: *const u64) -> i32 {
    task_kfunc_load_test();
    0
}

#[link_section = "perf_event"]
#[no_mangle]
extern "C" fn task_kfunc_perf_event(_ctx: *const u64) -> i32 {
    task_kfunc_load_test();
    0
}

#[link_section = "raw_tp"]
#[no_mangle]
extern "C" fn cgrp_kfunc_raw_tp(_ctx: *const u64) -> i32 {
    cgrp_kfunc_load_test();
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn cgrp_kfunc_syscall(_ctx: *const u64) -> i32 {
    cgrp_kfunc_load_test();
    0
}

#[link_section = "tracepoint"]
#[no_mangle]
extern "C" fn cgrp_kfunc_tracepoint(_ctx: *const u64) -> i32 {
    cgrp_kfunc_load_test();
    0
}

#[link_section = "perf_event"]
#[no_mangle]
extern "C" fn cgrp_kfunc_perf_event(_ctx: *const u64) -> i32 {
    cgrp_kfunc_load_test();
    0
}

#[link_section = "raw_tp"]
#[no_mangle]
extern "C" fn cpumask_kfunc_raw_tp(_ctx: *const u64) -> i32 {
    cpumask_kfunc_load_test();
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn cpumask_kfunc_syscall(_ctx: *const u64) -> i32 {
    cpumask_kfunc_load_test();
    0
}

#[link_section = "tracepoint"]
#[no_mangle]
extern "C" fn cpumask_kfunc_tracepoint(_ctx: *const u64) -> i32 {
    cpumask_kfunc_load_test();
    0
}

#[link_section = "perf_event"]
#[no_mangle]
extern "C" fn cpumask_kfunc_perf_event(_ctx: *const u64) -> i32 {
    cpumask_kfunc_load_test();
    0
}

bpf_object!("GPL");
