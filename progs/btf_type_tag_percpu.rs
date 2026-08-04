#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/btf_type_tag_percpu.c
// (bpf-rs-core idiom).
//
// prog_tests/btf_tag.c expects test_percpu1/test_percpu2/test_percpu_load to
// FAIL verifier load (ASSERT_ERR) because they dereference a __percpu-tagged
// pointer directly, and test_percpu_helper to load OK (ASSERT_OK) because it
// converts the percpu pointer via bpf_per_cpu_ptr() first. The __percpu tag
// lives on the *target* function's argument BTF (bpf_testmod.ko for
// test_percpu1/2, vmlinux for cgrp->self.rstat_cpu) -- it is intrinsic to
// what we dereference, not something this translation needs to emit itself,
// so the same verifier rejection fires regardless of translation language.
//
// `cgrp->self` is the first (offset-0) member of `struct cgroup`, so a
// plain pointer cast (`cgrp as *mut cgroup_subsys_state`) is `&cgrp->self`
// without needing a CO-RE field access (same pattern as
// read_cgroupfs_xattr.rs / cgroup_iter_memcg.rs).

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_smp_processor_id;
use bpf_rs_core::helpers::bpf_per_cpu_ptr;
use bpf_rs_core::progs::fentry_arg as arg;
use btf_macros::btf;

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_testmod_btf_type_tag_1 {
    a: i32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_testmod_btf_type_tag_2 {
    p: *mut bpf_testmod_btf_type_tag_1,
}

#[btf]
struct css_rstat_cpu {
    updated_children: *mut cgroup_subsys_state,
}

#[btf]
struct cgroup_subsys_state {
    rstat_cpu: *mut css_rstat_cpu,
}

#[no_mangle]
static mut g: u64 = 0;

#[link_section = "fentry/bpf_testmod_test_btf_type_tag_percpu_1"]
#[no_mangle]
extern "C" fn test_percpu1(ctx: *const u64) -> i32 {
    let argp = arg(ctx, 0) as *const bpf_testmod_btf_type_tag_1;
    let a = unsafe { (*argp).a };
    unsafe { g = a as u64 };
    0
}

#[link_section = "fentry/bpf_testmod_test_btf_type_tag_percpu_2"]
#[no_mangle]
extern "C" fn test_percpu2(ctx: *const u64) -> i32 {
    let argp = arg(ctx, 0) as *const bpf_testmod_btf_type_tag_2;
    let p = unsafe { (*argp).p };
    let a = unsafe { (*p).a };
    unsafe { g = a as u64 };
    0
}

#[link_section = "tp_btf/cgroup_mkdir"]
#[no_mangle]
extern "C" fn test_percpu_load(ctx: *const u64) -> i32 {
    let cgrp = arg(ctx, 0) as *mut cgroup_subsys_state;
    let rstat_cpu = unsafe { *(&*cgrp).rstat_cpu().as_ptr() };
    let updated_children = unsafe { *(&*rstat_cpu).updated_children().as_ptr() };
    unsafe { g = updated_children as u64 };
    0
}

#[link_section = "tp_btf/cgroup_mkdir"]
#[no_mangle]
extern "C" fn test_percpu_helper(ctx: *const u64) -> i32 {
    let cgrp = arg(ctx, 0) as *mut cgroup_subsys_state;
    let cpu = bpf_get_smp_processor_id();
    let rstat_cpu_percpu = unsafe { *(&*cgrp).rstat_cpu().as_ptr() };
    let rstat = bpf_per_cpu_ptr(rstat_cpu_percpu as *const c_void, cpu) as *mut css_rstat_cpu;
    if !rstat.is_null() {
        unsafe { core::ptr::read_volatile(rstat as *const i64) };
    }
    0
}

bpf_object!("GPL");
