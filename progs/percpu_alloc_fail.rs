// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![allow(non_camel_case_types, non_upper_case_globals)]

// Direct translation of tools/testing/selftests/bpf/progs/percpu_alloc_fail.c
// (bpf-rs-core idiom).
//
// bpf_percpu_obj_new()/__percpu_kptr misuse rejections
// (prog_tests/percpu_alloc.c: RUN_TESTS(percpu_alloc_fail)). The percpu
// kptr map-value members are plain pointers tagged by btf_type_tags! as
// in percpu_alloc_array.rs; each bpf_percpu_obj_new(struct T) /
// bpf_obj_new(struct T) type argument is a BTF_TYPE_ID local id; the
// kernel task_struct behind the kernel-type percpu kptr is an opaque
// local struct of that name; each allocation is typed `as *mut T` so the
// type stays in the debug info type_id.py reads. bpf_spin_lock in
// val_with_rb_root_t is the special field by name the verifier refuses.
// BTF_C_CHAR: u8
// BTF_TYPE_ID: val_t_id local struct val_t
// BTF_TYPE_ID: val2_t_id local struct val2_t
// BTF_TYPE_ID: val_with_ptr_t_id local struct val_with_ptr_t
// BTF_TYPE_ID: val_with_rb_root_t_id local struct val_with_rb_root_t
// BTF_TYPE_ID: val_600b_t_id local struct val_600b_t

use bpf_rs_core::helpers::{bpf_kptr_xchg, bpf_map_lookup_elem, bpf_this_cpu_ptr};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::{bpf_object, btf_type_tags, test_tags};
use core::ffi::c_void;
use core::ptr::addr_of_mut;

#[repr(C)]
struct val_t {
    b: i64,
    c: i64,
    d: i64,
}

#[repr(C)]
struct val2_t {
    b: i64,
}

#[repr(C)]
struct val_with_ptr_t {
    p: *mut u8,
}

// struct bpf_spin_lock { __u32 val; };
#[repr(C)]
struct bpf_spin_lock {
    val: u32,
}

#[repr(C)]
struct val_with_rb_root_t {
    lock: bpf_spin_lock,
}

#[repr(C)]
struct val_600b_t {
    b: [u8; 600],
}

#[repr(C)]
struct elem {
    sum: i64,
    pc: *mut val_t,
    pc2: *mut val_t,
}

#[link_section = ".maps"]
#[no_mangle]
static array: BpfMap<i32, elem, { maps::ARRAY }, 1> = BpfMap::new();

#[repr(C)]
struct task_struct {
    _opaque: [u8; 0],
}

#[repr(C)]
struct kernel_percpu_elem {
    task: *mut task_struct,
}

#[link_section = ".maps"]
#[no_mangle]
static kernel_percpu_array: BpfMap<i32, kernel_percpu_elem, { maps::ARRAY }, 1> = BpfMap::new();

btf_type_tags! {
    elem.pc: percpu_kptr;
    elem.pc2: percpu_kptr;
    kernel_percpu_elem.task: percpu_kptr;
}

extern "C" {
    fn val_t_id() -> u64;
    fn val2_t_id() -> u64;
    fn val_with_ptr_t_id() -> u64;
    fn val_with_rb_root_t_id() -> u64;
    fn val_600b_t_id() -> u64;
    fn bpf_obj_new(local_type_id: u64) -> *mut c_void;
    fn bpf_obj_drop(p: *mut c_void);
    fn bpf_percpu_obj_new(local_type_id: u64) -> *mut c_void;
    fn bpf_percpu_obj_drop(p: *mut c_void);
    fn bpf_task_from_pid(pid: i32) -> *mut task_struct;
    fn bpf_task_release(p: *mut task_struct);
    fn bpf_rcu_read_lock();
    fn bpf_rcu_read_unlock();
}

#[no_mangle]
static mut ret: i64 = 0;

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

        (*e).pc = ret as *mut val_t;
    }
    0
}

#[link_section = "?fentry/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test_array_map_2(_ctx: *const u64) -> i32 {
    let index: i32 = 0;

    let e = bpf_map_lookup_elem(&array, &index) as *mut elem;
    if e.is_null() {
        return 0;
    }

    unsafe {
        let p2 = bpf_percpu_obj_new(val2_t_id()) as *mut val2_t;
        if p2.is_null() {
            return 0;
        }

        let p = bpf_kptr_xchg(addr_of_mut!((*e).pc).cast(), p2.cast());
        if !p.is_null() {
            bpf_percpu_obj_drop(p);
        }
    }
    0
}

#[link_section = "?fentry.s/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test_array_map_3(_ctx: *const u64) -> i32 {
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

        let p1 = bpf_kptr_xchg(addr_of_mut!((*e).pc).cast(), p);
        if !p1.is_null() {
            bpf_percpu_obj_drop(p1);
        }

        let v = bpf_this_cpu_ptr(p) as *mut val_t;
        ret = (*v).b;
    }
    0
}

#[link_section = "?fentry.s/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn reject_nullable_percpu_xchg_alias(_ctx: *const u64) -> i32 {
    let index: i32 = 0;

    let e = bpf_map_lookup_elem(&array, &index) as *mut elem;
    if e.is_null() {
        return 0;
    }

    unsafe {
        let p1 = bpf_percpu_obj_new(val_t_id());
        let p2 = bpf_percpu_obj_new(val_t_id());

        bpf_rcu_read_lock();
        let old = bpf_kptr_xchg(addr_of_mut!((*e).pc).cast(), p1);
        if !old.is_null() {
            bpf_percpu_obj_drop(old);
        }
        let old = bpf_kptr_xchg(addr_of_mut!((*e).pc2).cast(), p2);
        if !old.is_null() {
            bpf_percpu_obj_drop(old);
        }

        if !p1.is_null() {
            let v = bpf_this_cpu_ptr(p2) as *mut val_t;
            (*v).b = 1;
        }
        bpf_rcu_read_unlock();
    }
    0
}

#[link_section = "?fentry.s/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test_array_map_4(_ctx: *const u64) -> i32 {
    unsafe {
        let p = bpf_percpu_obj_new(val_t_id());
        if p.is_null() {
            return 0;
        }

        bpf_obj_drop(p);
    }
    0
}

#[link_section = "?fentry.s/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test_array_map_5(_ctx: *const u64) -> i32 {
    unsafe {
        let p = bpf_obj_new(val_t_id());
        if p.is_null() {
            return 0;
        }

        bpf_percpu_obj_drop(p);
    }
    0
}

#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn reject_kernel_ptr_into_percpu_kptr(_ctx: *mut c_void) -> i32 {
    let index: i32 = 0;

    let e = bpf_map_lookup_elem(&kernel_percpu_array, &index) as *mut kernel_percpu_elem;
    if e.is_null() {
        return 0;
    }

    unsafe {
        let p = bpf_task_from_pid(1);
        if p.is_null() {
            return 0;
        }

        let old = bpf_kptr_xchg(addr_of_mut!((*e).task).cast(), p.cast()) as *mut task_struct;
        if !old.is_null() {
            bpf_task_release(old);
        }
    }
    0
}

#[link_section = "?fentry.s/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn reject_plain_alloc_into_percpu_kptr(_ctx: *const u64) -> i32 {
    let index: i32 = 0;

    let e = bpf_map_lookup_elem(&array, &index) as *mut elem;
    if e.is_null() {
        return 0;
    }

    unsafe {
        let p = bpf_obj_new(val_t_id());
        if p.is_null() {
            return 0;
        }

        let old = bpf_kptr_xchg(addr_of_mut!((*e).pc).cast(), p);
        if !old.is_null() {
            bpf_percpu_obj_drop(old);
        }
    }
    0
}

#[link_section = "?fentry.s/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test_array_map_6(_ctx: *const u64) -> i32 {
    unsafe {
        let p = bpf_percpu_obj_new(val_with_ptr_t_id()) as *mut val_with_ptr_t;
        if p.is_null() {
            return 0;
        }

        bpf_percpu_obj_drop(p.cast());
    }
    0
}

#[link_section = "?fentry.s/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test_array_map_7(_ctx: *const u64) -> i32 {
    unsafe {
        let p = bpf_percpu_obj_new(val_with_rb_root_t_id()) as *mut val_with_rb_root_t;
        if p.is_null() {
            return 0;
        }

        bpf_percpu_obj_drop(p.cast());
    }
    0
}

#[link_section = "?fentry.s/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test_array_map_8(_ctx: *const u64) -> i32 {
    unsafe {
        let p = bpf_percpu_obj_new(val_600b_t_id()) as *mut val_600b_t;
        if p.is_null() {
            return 0;
        }

        bpf_percpu_obj_drop(p.cast());
    }
    0
}

test_tags! {
    test_array_map_1: __failure, __msg("store to referenced kptr disallowed");
    test_array_map_2: __failure, __msg("invalid kptr access, R2 type=percpu_ptr_val2_t expected=ptr_val_t");
    test_array_map_3: __failure, __msg("R1 type=scalar expected=percpu_ptr_, percpu_rcu_ptr_, percpu_trusted_ptr_");
    reject_nullable_percpu_xchg_alias: __failure, __msg("Possibly NULL pointer passed to trusted R1");
    test_array_map_4: __failure, __msg("R1 expected for bpf_percpu_obj_drop()");
    test_array_map_5: __failure, __msg("R1 expected for bpf_obj_drop()");
    reject_kernel_ptr_into_percpu_kptr: __failure, __msg("invalid kptr access, R2 type=trusted_ptr_ expected=ptr_task_struct");
    reject_plain_alloc_into_percpu_kptr: __failure, __msg("invalid kptr access, R2 type=ptr_ expected=ptr_val_t");
    test_array_map_6: __failure, __msg("bpf_percpu_obj_new type ID argument must be of a struct of scalars");
    test_array_map_7: __failure, __msg("bpf_percpu_obj_new type ID argument must not contain special fields");
    test_array_map_8: __failure, __msg("bpf_percpu_obj_new type size (600) is greater than 512");
}

bpf_object!("GPL");
