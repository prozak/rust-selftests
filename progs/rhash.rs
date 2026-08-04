#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/rhash.c
// (bpf-rs-core idiom).

use bpf_rs_core::helpers::{bpf_map_delete_elem, bpf_map_lookup_elem, bpf_map_update_elem};
use bpf_rs_core::{bpf_map, bpf_object};
use core::ffi::c_void;

const BPF_ANY: u64 = 0;
const BPF_NOEXIST: u64 = 1;
const BPF_EXIST: u64 = 2;

const ENOENT: i64 = 2;
const EEXIST: i64 = 17;

#[repr(C)]
struct Elem {
    arr: [u8; 128],
    val: i32,
}

bpf_map! {
    rhmap {
        r#type: *const [i32; 35],       // BPF_MAP_TYPE_RHASH
        map_flags: *const [i32; 1],     // BPF_F_NO_PREALLOC
        max_entries: *const [i32; 128],
        key: *const i32,
        value: *const Elem,
    }
}

#[no_mangle]
static mut err: i32 = 0;

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_rhash_lookup_update(_ctx: *const c_void) -> i32 {
    let key: i32 = 5;
    let empty = Elem { arr: [0; 128], val: 3 };

    unsafe { err = 1 };
    let mut e = bpf_map_lookup_elem(&rhmap, &key);
    if !e.is_null() {
        return 1;
    }

    let ret = bpf_map_update_elem(&rhmap, &key, &empty, BPF_NOEXIST);
    unsafe { err = ret as i32 };
    if ret != 0 {
        return 1;
    }

    e = bpf_map_lookup_elem(&rhmap, &key);
    if e.is_null() || unsafe { (*(e as *const Elem)).val != empty.val } {
        unsafe { err = 2 };
        return 2;
    }

    unsafe { err = 0 };
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_rhash_update_delete(_ctx: *const c_void) -> i32 {
    let key: i32 = 6;
    let empty = Elem { arr: [0; 128], val: 4 };

    unsafe { err = 1 };
    let mut e = bpf_map_lookup_elem(&rhmap, &key);
    if !e.is_null() {
        return 1;
    }

    let mut ret = bpf_map_update_elem(&rhmap, &key, &empty, BPF_NOEXIST);
    unsafe { err = ret as i32 };
    if ret != 0 {
        return 2;
    }

    ret = bpf_map_delete_elem(&rhmap, &key);
    unsafe { err = ret as i32 };
    if ret != 0 {
        return 3;
    }

    e = bpf_map_lookup_elem(&rhmap, &key);
    if !e.is_null() {
        unsafe { err = 4 };
        return 4;
    }

    unsafe { err = 0 };
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_rhash_update_elements(_ctx: *const c_void) -> i32 {
    let mut empty = Elem { arr: [0; 128], val: 4 };

    unsafe { err = 1 };

    for i in 0..128i32 {
        let key = i;
        let e = bpf_map_lookup_elem(&rhmap, &key);
        if !e.is_null() {
            return 1;
        }

        empty.val = key;
        let ret = bpf_map_update_elem(&rhmap, &key, &empty, BPF_NOEXIST);
        unsafe { err = ret as i32 };
        if ret != 0 {
            return 2;
        }

        let e = bpf_map_lookup_elem(&rhmap, &key);
        if e.is_null() || unsafe { (*(e as *const Elem)).val != key } {
            unsafe { err = 4 };
            return 4;
        }
    }

    for i in 0..128i32 {
        let key = i;
        let ret = bpf_map_delete_elem(&rhmap, &key);
        unsafe { err = ret as i32 };
        if ret != 0 {
            return 3;
        }

        let e = bpf_map_lookup_elem(&rhmap, &key);
        if !e.is_null() {
            unsafe { err = 5 };
            return 5;
        }
    }

    unsafe { err = 0 };
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_rhash_update_exist(_ctx: *const c_void) -> i32 {
    let key: i32 = 10;
    let val1 = Elem { arr: [0; 128], val: 100 };
    let val2 = Elem { arr: [0; 128], val: 200 };

    unsafe { err = 1 };

    // BPF_EXIST on non-existent key should fail with -ENOENT
    let mut ret = bpf_map_update_elem(&rhmap, &key, &val1, BPF_EXIST);
    if ret != -ENOENT {
        return 1;
    }

    // Insert element first
    ret = bpf_map_update_elem(&rhmap, &key, &val1, BPF_NOEXIST);
    if ret != 0 {
        return 2;
    }

    // Verify initial value
    let mut e = bpf_map_lookup_elem(&rhmap, &key);
    if e.is_null() || unsafe { (*(e as *const Elem)).val != 100 } {
        return 3;
    }

    // BPF_EXIST on existing key should succeed and update value
    ret = bpf_map_update_elem(&rhmap, &key, &val2, BPF_EXIST);
    if ret != 0 {
        return 4;
    }

    // Verify value was updated
    e = bpf_map_lookup_elem(&rhmap, &key);
    if e.is_null() || unsafe { (*(e as *const Elem)).val != 200 } {
        return 5;
    }

    // Cleanup
    bpf_map_delete_elem(&rhmap, &key);
    unsafe { err = 0 };
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_rhash_update_any(_ctx: *const c_void) -> i32 {
    let key: i32 = 11;
    let val1 = Elem { arr: [0; 128], val: 111 };
    let val2 = Elem { arr: [0; 128], val: 222 };

    unsafe { err = 1 };

    // BPF_ANY on non-existent key should insert
    let mut ret = bpf_map_update_elem(&rhmap, &key, &val1, BPF_ANY);
    if ret != 0 {
        return 1;
    }

    let mut e = bpf_map_lookup_elem(&rhmap, &key);
    if e.is_null() || unsafe { (*(e as *const Elem)).val != 111 } {
        return 2;
    }

    // BPF_ANY on existing key should update
    ret = bpf_map_update_elem(&rhmap, &key, &val2, BPF_ANY);
    if ret != 0 {
        return 3;
    }

    e = bpf_map_lookup_elem(&rhmap, &key);
    if e.is_null() || unsafe { (*(e as *const Elem)).val != 222 } {
        return 4;
    }

    // Cleanup
    bpf_map_delete_elem(&rhmap, &key);
    unsafe { err = 0 };
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_rhash_noexist_duplicate(_ctx: *const c_void) -> i32 {
    let key: i32 = 12;
    let val = Elem { arr: [0; 128], val: 600 };

    unsafe { err = 1 };

    // Insert element
    let mut ret = bpf_map_update_elem(&rhmap, &key, &val, BPF_NOEXIST);
    if ret != 0 {
        return 1;
    }

    // Try to insert again with BPF_NOEXIST - should fail with -EEXIST
    ret = bpf_map_update_elem(&rhmap, &key, &val, BPF_NOEXIST);
    if ret != -EEXIST {
        return 2;
    }

    // Cleanup
    bpf_map_delete_elem(&rhmap, &key);
    unsafe { err = 0 };
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_rhash_delete_nonexistent(_ctx: *const c_void) -> i32 {
    let key: i32 = 99999;

    unsafe { err = 1 };

    // Delete non-existent key should return -ENOENT
    let ret = bpf_map_delete_elem(&rhmap, &key);
    if ret != -ENOENT {
        return 1;
    }

    unsafe { err = 0 };
    0
}

bpf_object!("GPL");
