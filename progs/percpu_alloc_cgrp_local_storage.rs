// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/percpu_alloc_cgrp_local_storage.c
// (bpf-rs-core idiom). The cgroup-storage element of the current task's
// default cgroup holds a __percpu_kptr to a val_t allocated with
// bpf_percpu_obj_new(); prog_tests/percpu_alloc.c runs the first program
// (the fentry programs chain through bpf_fentry_test1..3) and reads
// cpu0_field_d and sum_field_c back. task->cgroups->dfl_cgrp is a trusted
// pointer chase through #[btf] views (cgrp_ls_recursion.rs).
// BTF_TYPE_ID: val_t_id local struct val_t

use core::ffi::c_void;
use core::ptr::{addr_of_mut, read_volatile};

use bpf_rs_core::helpers::{
    bpf_cgrp_storage_get, bpf_get_current_pid_tgid, bpf_get_current_task_btf, bpf_kptr_xchg,
    bpf_per_cpu_ptr,
};
use bpf_rs_core::{bpf_map, bpf_object, btf_type_tags};
use btf_macros::btf;

const BPF_LOCAL_STORAGE_GET_F_CREATE: u64 = 1;

#[allow(non_camel_case_types)]
#[repr(C)]
struct val_t {
    b: i64,
    c: i64,
    d: i64,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct elem {
    sum: i64,
    pc: *mut val_t,
}

btf_type_tags! {
    elem.pc: percpu_kptr;
}

bpf_map! {
    cgrp {
        r#type: *const [i32; 32],   // BPF_MAP_TYPE_CGRP_STORAGE
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        key: *const i32,
        value: *const elem,
    }
}

#[link_section = ".rodata"]
#[no_mangle]
static nr_cpus: i32 = 0;

#[btf]
struct task_struct {
    cgroups: *mut css_set,
}

#[btf]
struct css_set {
    dfl_cgrp: *mut cgroup,
}

#[btf]
struct cgroup {}

#[repr(C, align(8))]
struct bpf_iter_num {
    __opaque: [u64; 1],
}

extern "C" {
    fn val_t_id() -> u64;
    fn bpf_percpu_obj_new(local_type_id: u64) -> *mut c_void;
    fn bpf_percpu_obj_drop(p: *mut c_void);
    fn bpf_iter_num_new(it: *mut bpf_iter_num, start: i32, end: i32) -> i32;
    fn bpf_iter_num_next(it: *mut bpf_iter_num) -> *mut i32;
    fn bpf_iter_num_destroy(it: *mut bpf_iter_num);
}

/// `bpf_cgrp_storage_get(&cgrp, task->cgroups->dfl_cgrp, 0, flags)` for the
/// current task
#[inline(always)]
fn current_cgrp_storage(flags: u64) -> *mut elem {
    let task: *mut task_struct = bpf_get_current_task_btf();
    let cgroups_ptr = *unsafe { &*task }.cgroups().get().unwrap();
    let dfl_cgrp = *unsafe { &*cgroups_ptr }.dfl_cgrp().get().unwrap();
    bpf_cgrp_storage_get(&cgrp, dfl_cgrp, core::ptr::null_mut(), flags) as *mut elem
}

/* Initialize the percpu object */
#[link_section = "fentry/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test_cgrp_local_storage_1(_ctx: *const u64) -> i32 {
    let e = current_cgrp_storage(BPF_LOCAL_STORAGE_GET_F_CREATE);
    if e.is_null() {
        return 0;
    }

    unsafe {
        let p = bpf_percpu_obj_new(val_t_id());
        if p.is_null() {
            return 0;
        }

        let p = bpf_kptr_xchg(addr_of_mut!((*e).pc).cast(), p);
        if !p.is_null() {
            bpf_percpu_obj_drop(p);
        }
    }

    0
}

/* Percpu data collection */
#[link_section = "fentry/bpf_fentry_test2"]
#[no_mangle]
extern "C" fn test_cgrp_local_storage_2(_ctx: *const u64) -> i32 {
    let e = current_cgrp_storage(0);
    if e.is_null() {
        return 0;
    }

    unsafe {
        let p = (*e).pc;
        if p.is_null() {
            return 0;
        }

        let v = bpf_per_cpu_ptr(p.cast(), 0) as *mut val_t;
        if v.is_null() {
            return 0;
        }
        (*v).c = 1;
        (*v).d = 2;
    }
    0
}

#[no_mangle]
static mut cpu0_field_d: i32 = 0;
#[no_mangle]
static mut sum_field_c: i32 = 0;
#[no_mangle]
static mut my_pid: i32 = 0;

/* Summarize percpu data collection */
#[link_section = "fentry/bpf_fentry_test3"]
#[no_mangle]
extern "C" fn test_cgrp_local_storage_3(_ctx: *const u64) -> i32 {
    if (bpf_get_current_pid_tgid() >> 32) != unsafe { my_pid } as i64 as u64 {
        return 0;
    }

    let e = current_cgrp_storage(0);
    if e.is_null() {
        return 0;
    }

    unsafe {
        let p = (*e).pc;
        if p.is_null() {
            return 0;
        }

        let mut it = bpf_iter_num { __opaque: [0; 1] };
        bpf_iter_num_new(&mut it, 0, read_volatile(&nr_cpus));
        loop {
            let ip = bpf_iter_num_next(&mut it);
            if ip.is_null() {
                break;
            }
            let i = *ip;
            let v = bpf_per_cpu_ptr(p.cast(), i as u32) as *mut val_t;
            if !v.is_null() {
                if i == 0 {
                    cpu0_field_d = (*v).d as i32;
                }
                sum_field_c = sum_field_c.wrapping_add((*v).c as i32);
            }
        }
        bpf_iter_num_destroy(&mut it);
    }

    0
}

bpf_object!("GPL");
