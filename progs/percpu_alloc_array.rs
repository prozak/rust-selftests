// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/percpu_alloc_array.c
// (bpf-rs-core idiom). The array map's one element holds a __percpu_kptr to
// a val_t allocated with bpf_percpu_obj_new(); prog_tests/percpu_alloc.c
// enables test_array_map_1..4 (or _10 alone), runs the first one (the
// fentry programs chain through bpf_fentry_test1..4) and reads cpu0_field_d
// and sum_field_c back. bpf_for() is the bpf_iter_num kfunc triple.
// BTF_TYPE_ID: val_t_id local struct val_t

use core::ffi::c_void;
use core::ptr::{addr_of_mut, read_volatile};

use bpf_rs_core::helpers::{
    bpf_get_current_pid_tgid, bpf_get_local_storage, bpf_kptr_xchg, bpf_map_lookup_elem,
    bpf_map_update_elem, bpf_per_cpu_ptr, bpf_this_cpu_ptr,
};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::{bpf_map, bpf_object, btf_type_tags};

const BPF_ANY: u64 = 0;

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

#[link_section = ".maps"]
#[no_mangle]
static array: BpfMap<i32, elem, { maps::ARRAY }, 1> = BpfMap::new();

#[repr(C, align(8))]
struct bpf_iter_num {
    __opaque: [u64; 1],
}

extern "C" {
    fn bpf_rcu_read_lock();
    fn bpf_rcu_read_unlock();
    fn val_t_id() -> u64;
    fn bpf_percpu_obj_new(local_type_id: u64) -> *mut c_void;
    fn bpf_percpu_obj_drop(p: *mut c_void);
    fn bpf_iter_num_new(it: *mut bpf_iter_num, start: i32, end: i32) -> i32;
    fn bpf_iter_num_next(it: *mut bpf_iter_num) -> *mut i32;
    fn bpf_iter_num_destroy(it: *mut bpf_iter_num);
}

#[link_section = ".rodata"]
#[no_mangle]
static nr_cpus: i32 = 0;

/* Initialize the percpu object */
#[link_section = "?fentry/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test_array_map_1(_ctx: *const u64) -> i32 {
    let index: i32 = 0;

    let e = bpf_map_lookup_elem(&array, &index) as *mut elem;
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

/* Update percpu data */
#[link_section = "?fentry/bpf_fentry_test2"]
#[no_mangle]
extern "C" fn test_array_map_2(_ctx: *const u64) -> i32 {
    let index: i32 = 0;

    let e = bpf_map_lookup_elem(&array, &index) as *mut elem;
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

/// `bpf_for(i, 0, nr_cpus) { v = bpf_per_cpu_ptr(p, i); if (v) { ... } }`
#[inline(always)]
unsafe fn sum_cpus(p: *mut val_t) {
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

/* Summarize percpu data */
#[link_section = "?fentry/bpf_fentry_test3"]
#[no_mangle]
extern "C" fn test_array_map_3(_ctx: *const u64) -> i32 {
    let index: i32 = 0;

    if (bpf_get_current_pid_tgid() >> 32) != unsafe { my_pid } as i64 as u64 {
        return 0;
    }

    let e = bpf_map_lookup_elem(&array, &index) as *mut elem;
    if e.is_null() {
        return 0;
    }

    unsafe {
        let p = (*e).pc;
        if p.is_null() {
            return 0;
        }

        sum_cpus(p);
    }

    0
}

/* Explicitly free allocated percpu data */
#[link_section = "?fentry/bpf_fentry_test4"]
#[no_mangle]
extern "C" fn test_array_map_4(_ctx: *const u64) -> i32 {
    let index: i32 = 0;

    let e = bpf_map_lookup_elem(&array, &index) as *mut elem;
    if e.is_null() {
        return 0;
    }

    unsafe {
        /* delete */
        let p = bpf_kptr_xchg(addr_of_mut!((*e).pc).cast(), core::ptr::null_mut());
        if !p.is_null() {
            bpf_percpu_obj_drop(p);
        }
    }

    0
}

#[link_section = "?fentry.s/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test_array_map_10(_ctx: *const u64) -> i32 {
    let index: i32 = 0;

    if (bpf_get_current_pid_tgid() >> 32) != unsafe { my_pid } as i64 as u64 {
        return 0;
    }

    let e = bpf_map_lookup_elem(&array, &index) as *mut elem;
    if e.is_null() {
        return 0;
    }

    unsafe {
        bpf_rcu_read_lock();
        'out: {
            let mut p = (*e).pc;
            if p.is_null() {
                p = bpf_percpu_obj_new(val_t_id()) as *mut val_t;
                if p.is_null() {
                    break 'out;
                }

                let p1 = bpf_kptr_xchg(addr_of_mut!((*e).pc).cast(), p.cast());
                if !p1.is_null() {
                    /* race condition */
                    bpf_percpu_obj_drop(p1);
                }
            }

            let v = bpf_this_cpu_ptr(p.cast()) as *mut val_t;
            (*v).c = 3;
            let v = bpf_this_cpu_ptr(p.cast()) as *mut val_t;
            (*v).c = 0;

            let v = bpf_per_cpu_ptr(p.cast(), 0) as *mut val_t;
            if v.is_null() {
                break 'out;
            }
            (*v).c = 1;
            (*v).d = 2;

            /* delete */
            let p1 = bpf_kptr_xchg(addr_of_mut!((*e).pc).cast(), core::ptr::null_mut());
            if p1.is_null() {
                break 'out;
            }

            sum_cpus(p);

            /* finally release p */
            bpf_percpu_obj_drop(p1);
        }
        bpf_rcu_read_unlock();
    }
    0
}

#[link_section = ".maps"]
#[no_mangle]
static percpu: BpfMap<i32, u32, { maps::PERCPU_ARRAY }, 2> = BpfMap::new();

// BPF_PROG(test_percpu_array, int x)
#[link_section = "?fentry/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test_percpu_array(_ctx: *const u64) -> i32 {
    let value: u64 = 0xDEADC0DE;
    let key: i32 = 0;

    bpf_map_update_elem(&percpu, &key, &value, BPF_ANY);
    0
}

// the map's BTF key type only (UAPI struct bpf_cgroup_storage_key, 16 bytes
// with its tail padding); no value of it is ever built here
// translint: allow(padding)
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_cgroup_storage_key {
    cgroup_inode_id: u64,
    attach_type: u32,
}

bpf_map! {
    percpu_cgroup_storage {
        r#type: *const [i32; 21], // BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE
        key: *const bpf_cgroup_storage_key,
        value: *const u32,
    }
}

#[link_section = "cgroup_skb/egress"]
#[no_mangle]
extern "C" fn cgroup_egress(_skb: *const c_void) -> i32 {
    let val = bpf_get_local_storage(&percpu_cgroup_storage, 0) as *mut u32;

    unsafe { *val = 1 };
    1
}

bpf_object!("GPL");
