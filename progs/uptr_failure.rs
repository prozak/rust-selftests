// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/uptr_failure.c,
// bpf-rs-core idiom (task_ls_uptr.rs carries the same uptr_test_common.h
// value_type: the __uptr/__kptr markers are the BTF type tags declared with
// btf_type_tags!, and the header's four dummy_* globals keep the pointee
// structs in BTF in full).
//
// Five NEGATIVE verifier tests (prog_tests/task_local_storage.c RUN_TESTS
// this object; the `?` sections stay unloaded otherwise): a store to an
// uptr field, to a nested one, a dereference of an uptr without a NULL
// check, bpf_kptr_xchg on an uptr field, and an uptr read from a
// bpf_obj_new()ed local value_type (a scalar there). C's bpf_obj_new /
// bpf_obj_drop are the two-argument _impl kfuncs with the local type id
// imported by the BTF_TYPE_ID marker.

use bpf_rs_core::bpf_map;
use bpf_rs_core::helpers::{bpf_get_current_task_btf, bpf_kptr_xchg, bpf_task_storage_get};
use bpf_rs_core::{bpf_object, btf_type_tags, test_tags};
use core::ffi::c_void;
use core::ptr::addr_of_mut;

const TASK_STORAGE: usize = 29; // enum bpf_map_type
const NO_PREALLOC: usize = 1; // BPF_F_NO_PREALLOC
const BPF_LOCAL_STORAGE_GET_F_CREATE: u64 = 1;
const PAGE_SIZE: usize = 4096;

#[allow(non_camel_case_types)]
#[repr(C)]
struct task_struct {
    _unused: [u8; 0],
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct cgroup {
    _unused: [u8; 0],
}

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
struct nested_udata {
    udata: *mut user_data,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct value_type {
    udata: *mut user_data,
    cgrp: *mut cgroup,
    nested: nested_udata,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct large_data {
    one_page: [u8; PAGE_SIZE],
    a: i32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct empty_data {}

#[no_mangle]
static mut dummy_large_data: *mut large_data = core::ptr::null_mut();
#[no_mangle]
static mut dummy_empty_data: *mut empty_data = core::ptr::null_mut();
#[no_mangle]
static mut dummy_data: *mut user_data = core::ptr::null_mut();
#[no_mangle]
static mut dummy_cgrp: *mut cgroup = core::ptr::null_mut();

bpf_map! {
    datamap {
        r#type: *const [i32; TASK_STORAGE],
        map_flags: *const [i32; NO_PREALLOC],
        key: *const i32,
        value: *const value_type,
    }
}

// BTF_TYPE_ID: value_type_id local struct value_type
extern "C" {
    fn value_type_id() -> u64;
    fn bpf_obj_new_impl(local_type_id: u64, meta: *mut c_void) -> *mut c_void;
    fn bpf_obj_drop_impl(obj: *mut c_void, meta: *mut c_void);
}

test_tags! {
    uptr_write: __failure, __msg("store to uptr disallowed");
    uptr_write_nested: __failure, __msg("store to uptr disallowed");
    uptr_no_null_check: __failure, __msg("R1 invalid mem access 'mem_or_null'");
    uptr_kptr_xchg: __failure, __msg("doesn't point to kptr");
    uptr_obj_new: __failure, __msg("invalid mem access 'scalar'");
}

#[inline(always)]
fn storage() -> *mut value_type {
    let task = bpf_get_current_task_btf::<task_struct>();
    bpf_task_storage_get(&datamap, task, core::ptr::null(), BPF_LOCAL_STORAGE_GET_F_CREATE) as *mut value_type
}

#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn uptr_write(_ctx: *const c_void) -> i32 {
    let v = storage();
    if v.is_null() {
        return 0;
    }

    unsafe { (*v).udata = core::ptr::null_mut() };
    0
}

#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn uptr_write_nested(_ctx: *const c_void) -> i32 {
    let v = storage();
    if v.is_null() {
        return 0;
    }

    unsafe { (*v).nested.udata = core::ptr::null_mut() };
    0
}

#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn uptr_no_null_check(_ctx: *const c_void) -> i32 {
    let v = storage();
    if v.is_null() {
        return 0;
    }

    unsafe { (*(*v).udata).result = 0 };

    0
}

#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn uptr_kptr_xchg(_ctx: *const c_void) -> i32 {
    let v = storage();
    if v.is_null() {
        return 0;
    }

    unsafe { bpf_kptr_xchg(addr_of_mut!((*v).udata).cast(), core::ptr::null_mut()) };

    0
}

#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn uptr_obj_new(_ctx: *const c_void) -> i32 {
    let v = unsafe { bpf_obj_new_impl(value_type_id(), core::ptr::null_mut()) } as *mut value_type;
    if v.is_null() {
        return 0;
    }

    unsafe {
        if !(*v).udata.is_null() {
            (*(*v).udata).result = 0;
        }

        bpf_obj_drop_impl(v.cast(), core::ptr::null_mut());
    }

    0
}

btf_type_tags! {
    value_type.udata: uptr;
    value_type.cgrp: kptr;
    nested_udata.udata: uptr;
}

bpf_object!("GPL");
