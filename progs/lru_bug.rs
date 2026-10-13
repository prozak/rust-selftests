// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/lru_bug.c,
// bpf-rs-core idiom.
//
// map_value.ptr is __kptr_untrusted in the C; the tag comes from the
// btf_type_tags! declaration below. The test depends on it: with the tag,
// a map update that reuses the just-deleted LRU node leaves the kptr bytes
// alone.

use core::ffi::c_void;

use bpf_rs_core::helpers::{
    bpf_get_current_task_btf, bpf_ktime_get_ns, bpf_map_delete_elem, bpf_map_lookup_elem,
    bpf_map_update_elem,
};
use bpf_rs_core::{bpf_object, btf_type_tags};
use bpf_rs_core::maps::{self, BpfMap};
use btf_macros::btf;

#[btf]
struct task_struct {
    pid: i32,
}

#[repr(C)]
struct map_value {
    ptr: *mut task_struct,
}

#[link_section = ".maps"]
#[no_mangle]
static lru_map: BpfMap<i32, map_value, { maps::LRU_HASH }, 1> = BpfMap::new();

#[no_mangle]
static mut pid: i32 = 0;
#[no_mangle]
static mut result: i32 = 1;

#[link_section = "fentry/bpf_ktime_get_ns"]
#[no_mangle]
extern "C" fn printk(_ctx: *const c_void) -> i32 {
    let v = map_value {
        ptr: core::ptr::null_mut(),
    };

    let cur: *mut task_struct = bpf_get_current_task_btf();
    let cur_pid = *unsafe { &*cur }.pid().get().unwrap();
    if unsafe { pid } == cur_pid {
        let key: i32 = 0;
        bpf_map_update_elem(&lru_map, &key, &v, 0);
    }
    0
}

#[link_section = "fentry/do_nanosleep"]
#[no_mangle]
extern "C" fn nanosleep(_ctx: *const c_void) -> i32 {
    let val = map_value {
        ptr: core::ptr::null_mut(),
    };
    let key: i32 = 0;

    bpf_map_update_elem(&lru_map, &key, &val, 0);
    let v = bpf_map_lookup_elem(&lru_map, &key) as *mut map_value;
    if v.is_null() {
        return 0;
    }
    bpf_map_delete_elem(&lru_map, &key);
    let current: *mut task_struct = bpf_get_current_task_btf();
    unsafe { (*v).ptr = current };
    let current_pid = *unsafe { &*current }.pid().get().unwrap();
    unsafe { pid = current_pid };
    bpf_ktime_get_ns();
    unsafe { result = (*v).ptr.is_null() as i32 };
    0
}

btf_type_tags! {
    map_value.ptr: kptr_untrusted;
}

bpf_object!("GPL");
