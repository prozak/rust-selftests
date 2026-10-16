// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/task_ls_uptr.c
// (bpf-rs-core idiom). datamap's value_type mirrors uptr_test_common.h's
// `struct value_type { struct user_data __uptr *udata; struct cgroup
// __kptr *cgrp; struct nested_udata nested; }` byte-for-byte (offsets 0/8/16,
// size 24); the __uptr/__kptr markers are the BTF type tags btf_type_tags!
// declares (scripts/btf_type_tags.py), which the kernel's btf_find_kptr()
// classifies as BPF_UPTR / BPF_KPTR_REF. The header's four dummy_* globals
// keep the pointee structs in BTF in full.

use core::ffi::c_void;

use bpf_rs_core::bpf_map;
use bpf_rs_core::{bpf_object, btf_type_tags};
use bpf_rs_core::helpers::{bpf_get_current_task_btf, bpf_kptr_xchg, bpf_task_storage_get};
use btf_macros::btf;

#[btf]
struct task_struct {
    pid: i32,
}

#[btf]
struct cgroup {
    level: i32,
}

#[repr(C)]
struct user_data {
    a: i32,
    b: i32,
    result: i32,
    nested_result: i32,
}

#[repr(C)]
struct nested_udata {
    udata: *mut user_data,
}

#[repr(C)]
struct value_type {
    udata: *mut user_data,
    cgrp: *mut cgroup,
    nested: nested_udata,
}

bpf_map! {
    datamap {
        r#type: *const [i32; 29],   // BPF_MAP_TYPE_TASK_STORAGE
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        key: *const i32,
        value: *const value_type,
    }
}

#[no_mangle]
static mut target_pid: i32 = 0;
#[no_mangle]
static mut parent_pid: i32 = 0;

extern "C" {
    fn bpf_task_from_pid(pid: i32) -> *mut task_struct;
    fn bpf_task_release(p: *mut task_struct);
    fn bpf_cgroup_release(cgrp: *mut cgroup);
}

const MAGIC_VALUE: u32 = 0xabcd1234;

#[link_section = "tp_btf/sys_enter"]
#[no_mangle]
extern "C" fn on_enter(_ctx: *const u64) -> i32 {
    let task: *mut task_struct = bpf_get_current_task_btf();
    let task_pid = *unsafe { &*task }.pid().get().unwrap();
    if task_pid != unsafe { target_pid } {
        return 0;
    }

    let data_task = unsafe { bpf_task_from_pid(unsafe { parent_pid }) };
    if data_task.is_null() {
        return 0;
    }

    let ptr = bpf_task_storage_get(&datamap, data_task, core::ptr::null_mut(), 0)
        as *mut value_type;
    unsafe { bpf_task_release(data_task) };
    if ptr.is_null() {
        return 0;
    }

    let cgrp = bpf_kptr_xchg(
        unsafe { core::ptr::addr_of_mut!((*ptr).cgrp) as *mut c_void },
        core::ptr::null_mut(),
    ) as *mut cgroup;
    if !cgrp.is_null() {
        let lvl = *unsafe { &*cgrp }.level().get().unwrap();
        unsafe { bpf_cgroup_release(cgrp) };
        return lvl;
    }

    let udata = unsafe { (*ptr).udata };
    if udata.is_null() || unsafe { (*udata).result } != 0 {
        return 0;
    }
    let a = unsafe { (*udata).a };
    let b = unsafe { (*udata).b };
    let result = MAGIC_VALUE.wrapping_add(a as u32).wrapping_add(b as u32) as i32;
    unsafe { (*udata).result = result };

    let udata = unsafe { (*ptr).nested.udata };
    if !udata.is_null() && unsafe { (*udata).nested_result } == 0 {
        unsafe { (*udata).nested_result = (*udata).result };
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

#[no_mangle]
static mut dummy_large_data: *mut large_data = core::ptr::null_mut();
#[no_mangle]
static mut dummy_empty_data: *mut empty_data = core::ptr::null_mut();
#[no_mangle]
static mut dummy_data: *mut user_data = core::ptr::null_mut();
#[no_mangle]
static mut dummy_cgrp: *mut cgroup = core::ptr::null_mut();

btf_type_tags! {
    value_type.udata: uptr;
    value_type.cgrp: kptr;
    nested_udata.udata: uptr;
}

bpf_object!("GPL");
