// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/uptr_update_failure.c
// (bpf-rs-core idiom).
//
// `not_used` is a load-only program (per the C comment) — the userspace test
// (task_local_storage.c: test_uptr_update_failure) never attaches/runs it.
// It open_and_load()s the skeleton, then drives `datamap` purely from
// userspace bpf_map_update_elem() calls and asserts specific errno values.
//
// struct value_lock_type { struct user_data __uptr *udata; struct
// bpf_spin_lock lock; } (uptr_test_common.h): the __uptr is the `uptr` BTF
// type tag that btf_type_tags! puts on `udata` (scripts/btf_type_tags.py), so
// the kernel classifies the field as BPF_UPTR, bpf_map_update_elem(BPF_F_LOCK)
// fails with EOPNOTSUPP as the test asserts, and the verifier lets the
// program dereference udata like the C does. The header's four dummy_*
// globals keep the pointee structs in BTF in full (see below).

use bpf_rs_core::bpf_map;
use bpf_rs_core::helpers::{
    bpf_get_current_task_btf, bpf_spin_lock, bpf_spin_unlock, bpf_task_storage_get,
};
use bpf_rs_core::{btf_type_tags, bpf_object, maps};

const TASK_STORAGE: usize = 29; // enum bpf_map_type
const NO_PREALLOC: usize = 1; // BPF_F_NO_PREALLOC

// struct bpf_spin_lock { __u32 val; };  -- matched by BTF struct name.
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_spin_lock {
    val: u32,
}

const MAGIC_VALUE: u32 = 0xabcd1234;

#[allow(non_camel_case_types)]
#[repr(C)]
struct user_data {
    a: i32,
    b: i32,
    result: i32,
    nested_result: i32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct value_lock_type {
    udata: *mut user_data,
    lock: bpf_spin_lock,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct task_struct {
    _unused: [u8; 0],
}

bpf_map! {
    datamap {
        r#type: *const [i32; TASK_STORAGE],
        map_flags: *const [i32; NO_PREALLOC],
        key: *const i32,
        value: *const value_lock_type,
    }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn not_used(_ctx: *const core::ffi::c_void) -> i32 {
    let task = bpf_get_current_task_btf::<task_struct>();

    let ptr = bpf_task_storage_get(&datamap, task, core::ptr::null(), 0) as *mut value_lock_type;
    if ptr.is_null() {
        return 0;
    }

    unsafe {
        bpf_spin_lock(core::ptr::addr_of_mut!((*ptr).lock));

        let udata = (*ptr).udata;
        if udata.is_null() {
            bpf_spin_unlock(core::ptr::addr_of_mut!((*ptr).lock));
            return 0;
        }
        (*udata).result = (MAGIC_VALUE as i32).wrapping_add((*udata).a).wrapping_add((*udata).b);

        bpf_spin_unlock(core::ptr::addr_of_mut!((*ptr).lock));
    }

    0
}

// uptr_test_common.h keeps these four globals so that the structs behind
// the __uptr/__kptr pointers reach BTF in full (a pointee that is only ever
// pointed at would be a FWD, and the kernel classifies struct kptrs only).
#[allow(non_camel_case_types)]
#[repr(C)]
struct large_data {
    one_page: [u8; 4096],
    a: i32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct empty_data {}

// struct cgroup: a kernel type this program never dereferences
#[allow(non_camel_case_types)]
#[repr(C)]
struct cgroup {}

#[no_mangle]
static mut dummy_large_data: *mut large_data = core::ptr::null_mut();
#[no_mangle]
static mut dummy_empty_data: *mut empty_data = core::ptr::null_mut();
#[no_mangle]
static mut dummy_data: *mut user_data = core::ptr::null_mut();
#[no_mangle]
static mut dummy_cgrp: *mut cgroup = core::ptr::null_mut();

btf_type_tags! {
    value_lock_type.udata: uptr;
}

bpf_object!("GPL");
