// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/map_kptr.c
// (bpf-rs-core idiom). Map values with an untrusted and a referenced kptr to
// bpf_testmod's prog_test_ref_kfunc, in every map kind that can hold them
// (arrays, hashes, LRU, per-CPU, the four local storages, twelve maps of
// maps with their one inner map preset). prog_tests/map_kptr.c runs the
// ref1/ref2/ref3 programs and checks the object's refcount through the
// `ref` global and count_ref; test_map_uninit.c loads the object and
// checks the per-CPU array's tail bytes. test_kptr is the C object's local
// subprogram. The kptr pointee is a #[btf] view of the module struct, also
// used for the a/b/next/cnt reads.

use core::ffi::c_void;
use core::ptr::{addr_of_mut, write_volatile};

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{
    bpf_cgrp_storage_get, bpf_get_current_task_btf, bpf_inode_storage_get, bpf_kptr_xchg,
    bpf_map_lookup_elem, bpf_map_lookup_percpu_elem, bpf_map_update_elem, bpf_sk_storage_get,
    bpf_task_storage_delete, bpf_task_storage_get,
};
use bpf_rs_core::maps;
use bpf_rs_core::progs::fentry_arg as arg;
use bpf_rs_core::{bpf_map, bpf_object, btf_type_tags};
use btf_macros::btf;

const BPF_NOEXIST: u64 = 1;
const BPF_EXIST: u64 = 2;
const BPF_LOCAL_STORAGE_GET_F_CREATE: u64 = 1;

#[btf]
struct prog_test_ref_kfunc {
    a: i32,
    b: i32,
    next: *mut prog_test_ref_kfunc,
    cnt: refcount_struct,
}

#[btf]
struct refcount_struct {
    refs: atomic_t,
}

#[btf]
struct atomic_t {
    counter: i32,
}

#[allow(non_camel_case_types)]
#[repr(C, packed)]
struct map_uninit_value {
    unref_ptr: *mut prog_test_ref_kfunc,
    data: u32,
}

bpf_map! {
    pcpu_array {
        r#type: *const [i32; maps::PERCPU_ARRAY],
        key: *const i32,
        value: *const map_uninit_value,
        max_entries: *const [i32; 1],
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct map_value {
    unref_ptr: *mut prog_test_ref_kfunc,
    ref_ptr: *mut prog_test_ref_kfunc,
}

btf_type_tags! {
    map_uninit_value.unref_ptr: kptr_untrusted;
    map_value.unref_ptr: kptr_untrusted;
    map_value.ref_ptr: kptr;
}

macro_rules! value_map {
    ($name:ident, $kind:expr) => {
        bpf_map! {
            $name {
                r#type: *const [i32; $kind],
                key: *const i32,
                value: *const map_value,
                max_entries: *const [i32; 1],
            }
        }
    };
    ($name:ident, $kind:expr, no_prealloc) => {
        bpf_map! {
            $name {
                r#type: *const [i32; $kind],
                key: *const i32,
                value: *const map_value,
                max_entries: *const [i32; 1],
                map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
            }
        }
    };
}

macro_rules! storage_map {
    ($name:ident, $kind:expr) => {
        bpf_map! {
            $name {
                r#type: *const [i32; $kind],
                map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
                key: *const i32,
                value: *const map_value,
            }
        }
    };
}

value_map!(array_map, maps::ARRAY);
value_map!(pcpu_array_map, maps::PERCPU_ARRAY);
value_map!(hash_map, maps::HASH);
value_map!(pcpu_hash_map, maps::PERCPU_HASH);
value_map!(hash_malloc_map, maps::HASH, no_prealloc);
value_map!(pcpu_hash_malloc_map, maps::PERCPU_HASH, no_prealloc);
value_map!(lru_hash_map, maps::LRU_HASH);
value_map!(lru_pcpu_hash_map, maps::LRU_PERCPU_HASH);
storage_map!(cgrp_ls_map, 32); // BPF_MAP_TYPE_CGRP_STORAGE
storage_map!(task_ls_map, 29); // BPF_MAP_TYPE_TASK_STORAGE
storage_map!(inode_ls_map, 28); // BPF_MAP_TYPE_INODE_STORAGE
storage_map!(sk_ls_map, 24); // BPF_MAP_TYPE_SK_STORAGE

const ARRAY_OF_MAPS: usize = 12;
const HASH_OF_MAPS: usize = 13;

// DEFINE_MAP_OF_MAP(map_type, inner_map_type, name): key_size/value_size
// sizeof(int), one slot preset to the inner map (scripts/btf_map_slots.py)
macro_rules! map_of_map {
    ($name:ident, $def:ident, $kind:expr, $inner:ident) => {
        #[allow(non_camel_case_types)]
        #[repr(C)]
        struct $def {
            r#type: *const [i32; $kind],
            max_entries: *const [i32; 1],
            key_size: *const [i32; 4],
            value_size: *const [i32; 4],
            values: [*const $inner; 1],
        }

        unsafe impl Sync for $def {}

        #[link_section = ".maps"]
        #[no_mangle]
        static $name: $def = $def {
            r#type: core::ptr::null(),
            max_entries: core::ptr::null(),
            key_size: core::ptr::null(),
            value_size: core::ptr::null(),
            values: [&$inner],
        };
    };
}

map_of_map!(array_of_array_maps, array_of_array_maps_def, ARRAY_OF_MAPS, array_map);
map_of_map!(array_of_hash_maps, array_of_hash_maps_def, ARRAY_OF_MAPS, hash_map);
map_of_map!(array_of_hash_malloc_maps, array_of_hash_malloc_maps_def, ARRAY_OF_MAPS, hash_malloc_map);
map_of_map!(array_of_lru_hash_maps, array_of_lru_hash_maps_def, ARRAY_OF_MAPS, lru_hash_map);
map_of_map!(array_of_pcpu_array_maps, array_of_pcpu_array_maps_def, ARRAY_OF_MAPS, pcpu_array_map);
map_of_map!(array_of_pcpu_hash_maps, array_of_pcpu_hash_maps_def, ARRAY_OF_MAPS, pcpu_hash_map);
map_of_map!(hash_of_array_maps, hash_of_array_maps_def, HASH_OF_MAPS, array_map);
map_of_map!(hash_of_hash_maps, hash_of_hash_maps_def, HASH_OF_MAPS, hash_map);
map_of_map!(hash_of_hash_malloc_maps, hash_of_hash_malloc_maps_def, HASH_OF_MAPS, hash_malloc_map);
map_of_map!(hash_of_lru_hash_maps, hash_of_lru_hash_maps_def, HASH_OF_MAPS, lru_hash_map);
map_of_map!(hash_of_pcpu_array_maps, hash_of_pcpu_array_maps_def, HASH_OF_MAPS, pcpu_array_map);
map_of_map!(hash_of_pcpu_hash_maps, hash_of_pcpu_hash_maps_def, HASH_OF_MAPS, pcpu_hash_map);

extern "C" {
    fn bpf_kfunc_call_test_acquire(scalar_ptr: *mut u64) -> *mut prog_test_ref_kfunc;
    fn bpf_kfunc_call_test_release(p: *mut prog_test_ref_kfunc);
    fn bpf_kfunc_call_test_ref(p: *mut prog_test_ref_kfunc);
}

/// `p->a + p->b > 100`
#[inline(always)]
unsafe fn a_plus_b_over_100(p: *mut prog_test_ref_kfunc) -> bool {
    let a = *(&*p).a().as_ptr();
    let b = *(&*p).b().as_ptr();
    a.wrapping_add(b) > 100
}

#[inline(always)]
unsafe fn test_kptr_unref(v: *mut map_value) {
    let p = (*v).unref_ptr;
    /* store untrusted_ptr_or_null_ */
    write_volatile(addr_of_mut!((*v).unref_ptr), p);
    if p.is_null() {
        return;
    }
    if a_plus_b_over_100(p) {
        return;
    }
    /* store untrusted_ptr_ */
    write_volatile(addr_of_mut!((*v).unref_ptr), p);
    /* store NULL */
    write_volatile(addr_of_mut!((*v).unref_ptr), core::ptr::null_mut());
}

#[inline(always)]
unsafe fn test_kptr_ref(v: *mut map_value) {
    let p = (*v).ref_ptr;
    /* store ptr_or_null_ */
    write_volatile(addr_of_mut!((*v).unref_ptr), p);
    if p.is_null() {
        return;
    }
    /*
     * p is rcu_ptr_prog_test_ref_kfunc,
     * because bpf prog is non-sleepable and runs in RCU CS.
     * p can be passed to kfunc that requires KF_RCU.
     */
    bpf_kfunc_call_test_ref(p);
    if a_plus_b_over_100(p) {
        return;
    }
    /* store NULL */
    let p = bpf_kptr_xchg(addr_of_mut!((*v).ref_ptr).cast(), core::ptr::null_mut()) as *mut prog_test_ref_kfunc;
    if p.is_null() {
        return;
    }
    /*
     * p is trusted_ptr_prog_test_ref_kfunc.
     * p can be passed to kfunc that requires KF_RCU.
     */
    bpf_kfunc_call_test_ref(p);
    if a_plus_b_over_100(p) {
        bpf_kfunc_call_test_release(p);
        return;
    }
    /* store ptr_ */
    write_volatile(addr_of_mut!((*v).unref_ptr), p);
    bpf_kfunc_call_test_release(p);

    let mut zero: u64 = 0;
    let p = bpf_kfunc_call_test_acquire(&mut zero);
    if p.is_null() {
        return;
    }
    /* store ptr_ */
    let p = bpf_kptr_xchg(addr_of_mut!((*v).ref_ptr).cast(), p.cast()) as *mut prog_test_ref_kfunc;
    if p.is_null() {
        return;
    }
    if a_plus_b_over_100(p) {
        bpf_kfunc_call_test_release(p);
        return;
    }
    bpf_kfunc_call_test_release(p);
}

// the C object keeps test_kptr as a local subprogram
#[inline(never)]
#[export_name = "test_kptr"]
extern "C" fn test_kptr(v: *mut map_value) {
    unsafe {
        test_kptr_unref(v);
        test_kptr_ref(v);
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_map_kptr(_ctx: *mut __sk_buff) -> i32 {
    let key: i32 = 0;

    macro_rules! test {
        ($map:ident) => {
            let v = bpf_map_lookup_elem(&$map, &key) as *mut map_value;
            if v.is_null() {
                return 0;
            }
            test_kptr(v);
        };
    }

    test!(array_map);
    test!(hash_map);
    test!(hash_malloc_map);
    test!(lru_hash_map);
    test!(pcpu_array_map);
    test!(pcpu_hash_map);

    0
}

// BPF_PROG(test_cgrp_map_kptr, struct cgroup *cgrp, const char *path)
#[link_section = "tp_btf/cgroup_mkdir"]
#[no_mangle]
extern "C" fn test_cgrp_map_kptr(ctx: *const u64) -> i32 {
    let cgrp = arg(ctx, 0) as *mut c_void;

    let v = bpf_cgrp_storage_get(&cgrp_ls_map, cgrp, core::ptr::null_mut(), BPF_LOCAL_STORAGE_GET_F_CREATE)
        as *mut map_value;
    if !v.is_null() {
        test_kptr(v);
    }
    0
}

// BPF_PROG(test_task_map_kptr, struct inode *inode, struct dentry *victim)
#[link_section = "lsm/inode_unlink"]
#[no_mangle]
extern "C" fn test_task_map_kptr(_ctx: *const u64) -> i32 {
    let task: *mut c_void = bpf_get_current_task_btf();
    if task.is_null() {
        return 0;
    }
    let v = bpf_task_storage_get(&task_ls_map, task, core::ptr::null(), BPF_LOCAL_STORAGE_GET_F_CREATE)
        as *mut map_value;
    if !v.is_null() {
        test_kptr(v);
    }
    0
}

// BPF_PROG(test_inode_map_kptr, struct inode *inode, struct dentry *victim)
#[link_section = "lsm/inode_unlink"]
#[no_mangle]
extern "C" fn test_inode_map_kptr(ctx: *const u64) -> i32 {
    let inode = arg(ctx, 0) as *mut c_void;

    let v = bpf_inode_storage_get(&inode_ls_map, inode, core::ptr::null(), BPF_LOCAL_STORAGE_GET_F_CREATE)
        as *mut map_value;
    if !v.is_null() {
        test_kptr(v);
    }
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_sk_map_kptr(ctx: *mut __sk_buff) -> i32 {
    let sk = unsafe { (*ctx).sk } as *const c_void;
    if sk.is_null() {
        return 0;
    }
    let v = bpf_sk_storage_get(&sk_ls_map, sk, core::ptr::null(), BPF_LOCAL_STORAGE_GET_F_CREATE)
        as *mut map_value;
    if !v.is_null() {
        test_kptr(v);
    }
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_map_in_map_kptr(_ctx: *mut __sk_buff) -> i32 {
    let key: i32 = 0;

    macro_rules! test {
        ($map_in_map:ident) => {
            let map = bpf_map_lookup_elem(&$map_in_map, &key);
            if map.is_null() {
                return 0;
            }
            let v = bpf_map_lookup_elem(map as *const c_void, &key) as *mut map_value;
            if v.is_null() {
                return 0;
            }
            test_kptr(v);
        };
    }

    test!(array_of_array_maps);
    test!(array_of_hash_maps);
    test!(array_of_hash_malloc_maps);
    test!(array_of_lru_hash_maps);
    test!(array_of_pcpu_array_maps);
    test!(array_of_pcpu_hash_maps);
    test!(hash_of_array_maps);
    test!(hash_of_hash_maps);
    test!(hash_of_hash_malloc_maps);
    test!(hash_of_lru_hash_maps);
    test!(hash_of_pcpu_array_maps);
    test!(hash_of_pcpu_hash_maps);

    0
}

#[no_mangle]
static mut r#ref: i32 = 1;

/// `p->cnt.refs.counter`
#[inline(always)]
unsafe fn refs_counter(p: *mut prog_test_ref_kfunc) -> i32 {
    *(&*p).cnt().refs().counter().as_ptr()
}

#[inline(always)]
unsafe fn test_map_kptr_ref_pre(v: *mut map_value) -> i32 {
    let mut arg_: u64 = 0;

    let mut p = bpf_kfunc_call_test_acquire(&mut arg_);
    if p.is_null() {
        return 1;
    }
    r#ref += 1;

    let p_st = *(&*p).next().as_ptr();
    let ret: i32 = 'end: {
        if refs_counter(p_st) != r#ref {
            break 'end 2;
        }

        p = bpf_kptr_xchg(addr_of_mut!((*v).ref_ptr).cast(), p.cast()) as *mut prog_test_ref_kfunc;
        if !p.is_null() {
            break 'end 3;
        }
        if refs_counter(p_st) != r#ref {
            return 4;
        }

        p = bpf_kptr_xchg(addr_of_mut!((*v).ref_ptr).cast(), core::ptr::null_mut()) as *mut prog_test_ref_kfunc;
        if p.is_null() {
            return 5;
        }
        bpf_kfunc_call_test_release(p);
        r#ref -= 1;
        if refs_counter(p_st) != r#ref {
            return 6;
        }

        p = bpf_kfunc_call_test_acquire(&mut arg_);
        if p.is_null() {
            return 7;
        }
        r#ref += 1;
        p = bpf_kptr_xchg(addr_of_mut!((*v).ref_ptr).cast(), p.cast()) as *mut prog_test_ref_kfunc;
        if !p.is_null() {
            break 'end 8;
        }
        if refs_counter(p_st) != r#ref {
            return 9;
        }
        /* Leave in map */

        return 0;
    };
    // end:
    r#ref -= 1;
    bpf_kfunc_call_test_release(p);
    ret
}

#[inline(always)]
unsafe fn test_map_kptr_ref_post(v: *mut map_value) -> i32 {
    let p_st = (*v).ref_ptr;
    if p_st.is_null() || refs_counter(p_st) != r#ref {
        return 1;
    }

    let p = bpf_kptr_xchg(addr_of_mut!((*v).ref_ptr).cast(), core::ptr::null_mut()) as *mut prog_test_ref_kfunc;
    if p.is_null() {
        return 2;
    }
    if refs_counter(p_st) != r#ref {
        bpf_kfunc_call_test_release(p);
        return 3;
    }

    let p = bpf_kptr_xchg(addr_of_mut!((*v).ref_ptr).cast(), p.cast()) as *mut prog_test_ref_kfunc;
    if !p.is_null() {
        bpf_kfunc_call_test_release(p);
        return 4;
    }
    if refs_counter(p_st) != r#ref {
        return 5;
    }

    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_map_kptr_ref1(_ctx: *mut __sk_buff) -> i32 {
    let val = map_value { unref_ptr: core::ptr::null_mut(), ref_ptr: core::ptr::null_mut() };
    let key: i32 = 0;

    bpf_map_update_elem(&hash_map, &key, &val, 0);
    bpf_map_update_elem(&hash_malloc_map, &key, &val, 0);
    bpf_map_update_elem(&lru_hash_map, &key, &val, 0);

    bpf_map_update_elem(&pcpu_hash_map, &key, &val, 0);
    bpf_map_update_elem(&pcpu_hash_malloc_map, &key, &val, 0);
    bpf_map_update_elem(&lru_pcpu_hash_map, &key, &val, 0);

    macro_rules! test {
        ($map:ident) => {
            let v = bpf_map_lookup_elem(&$map, &key) as *mut map_value;
            if v.is_null() {
                return -1;
            }
            let ret = unsafe { test_map_kptr_ref_pre(v) };
            if ret != 0 {
                return ret;
            }
        };
    }
    macro_rules! test_pcpu {
        ($map:ident) => {
            let v = bpf_map_lookup_percpu_elem(&$map, &key, 0) as *mut map_value;
            if v.is_null() {
                return -1;
            }
            let ret = unsafe { test_map_kptr_ref_pre(v) };
            if ret != 0 {
                return ret;
            }
        };
    }

    test!(array_map);
    test!(hash_map);
    test!(hash_malloc_map);
    test!(lru_hash_map);

    test_pcpu!(pcpu_array_map);
    test_pcpu!(pcpu_hash_map);
    test_pcpu!(pcpu_hash_malloc_map);
    test_pcpu!(lru_pcpu_hash_map);

    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_map_kptr_ref2(_ctx: *mut __sk_buff) -> i32 {
    let key: i32 = 0;

    macro_rules! test {
        ($map:ident) => {
            let v = bpf_map_lookup_elem(&$map, &key) as *mut map_value;
            if v.is_null() {
                return -1;
            }
            let ret = unsafe { test_map_kptr_ref_post(v) };
            if ret != 0 {
                return ret;
            }
        };
    }
    macro_rules! test_pcpu {
        ($map:ident) => {
            let v = bpf_map_lookup_percpu_elem(&$map, &key, 0) as *mut map_value;
            if v.is_null() {
                return -1;
            }
            let ret = unsafe { test_map_kptr_ref_post(v) };
            if ret != 0 {
                return ret;
            }
        };
    }

    test!(array_map);
    test!(hash_map);
    test!(hash_malloc_map);
    test!(lru_hash_map);

    test_pcpu!(pcpu_array_map);
    test_pcpu!(pcpu_hash_map);
    test_pcpu!(pcpu_hash_malloc_map);
    test_pcpu!(lru_pcpu_hash_map);

    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_map_kptr_ref3(_ctx: *mut __sk_buff) -> i32 {
    let mut sp: u64 = 0;

    unsafe {
        let p = bpf_kfunc_call_test_acquire(&mut sp);
        if p.is_null() {
            return 1;
        }
        r#ref += 1;
        if refs_counter(p) != r#ref {
            bpf_kfunc_call_test_release(p);
            return 2;
        }
        bpf_kfunc_call_test_release(p);
        r#ref -= 1;
    }
    0
}

#[no_mangle]
static mut num_of_refs: i32 = 0;

#[inline(always)]
unsafe fn read_ref_count() -> i32 {
    let mut arg_: u64 = 0;

    let p = bpf_kfunc_call_test_acquire(&mut arg_);
    if p.is_null() {
        return 1;
    }

    num_of_refs = refs_counter(p);
    bpf_kfunc_call_test_release(p);
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn count_ref(_ctx: *mut c_void) -> i32 {
    unsafe { read_ref_count() }
}

#[inline(always)]
unsafe fn stash_ref_ptr(v: *mut map_value) -> i32 {
    let mut arg_: u64 = 0;

    let p = bpf_kfunc_call_test_acquire(&mut arg_);
    if p.is_null() {
        return 1;
    }

    let old = bpf_kptr_xchg(addr_of_mut!((*v).ref_ptr).cast(), p.cast()) as *mut prog_test_ref_kfunc;
    if !old.is_null() {
        bpf_kfunc_call_test_release(old);
        let old = bpf_kptr_xchg(addr_of_mut!((*v).ref_ptr).cast(), core::ptr::null_mut()) as *mut prog_test_ref_kfunc;
        if !old.is_null() {
            bpf_kfunc_call_test_release(old);
        }
        return 2;
    }
    0
}

#[inline(always)]
unsafe fn check_refs(expected: i32) -> i32 {
    let ret = read_ref_count();
    if ret != 0 {
        return ret;
    }
    if num_of_refs == expected {
        0
    } else {
        3
    }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_array_map_update_kptr(_ctx: *mut c_void) -> i32 {
    let init = map_value { unref_ptr: core::ptr::null_mut(), ref_ptr: core::ptr::null_mut() };
    let key: i32 = 0;

    let v = bpf_map_lookup_elem(&array_map, &key) as *mut map_value;
    if v.is_null() {
        return 1;
    }
    unsafe {
        let ret = stash_ref_ptr(v);
        if ret != 0 {
            return ret;
        }
        let ret = check_refs(3);
        if ret != 0 {
            return ret;
        }
        let ret = bpf_map_update_elem(&array_map, &key, &init, BPF_EXIST);
        if ret != 0 {
            return 4;
        }
        check_refs(3)
    }
}

// DEFINE_HASH_UPDATE_KPTR_TEST(name, map)
macro_rules! define_hash_update_kptr_test {
    ($name:ident, $map:ident) => {
        #[link_section = "syscall"]
        #[no_mangle]
        extern "C" fn $name(_ctx: *mut c_void) -> i32 {
            let init = map_value { unref_ptr: core::ptr::null_mut(), ref_ptr: core::ptr::null_mut() };
            let key: i32 = 0;

            let ret = bpf_map_update_elem(&$map, &key, &init, BPF_NOEXIST);
            if ret != 0 {
                return 1;
            }
            let v = bpf_map_lookup_elem(&$map, &key) as *mut map_value;
            if v.is_null() {
                return 2;
            }
            unsafe {
                let ret = stash_ref_ptr(v);
                if ret != 0 {
                    return ret;
                }
                let ret = check_refs(3);
                if ret != 0 {
                    return ret;
                }
                let ret = bpf_map_update_elem(&$map, &key, &init, BPF_EXIST);
                if ret != 0 {
                    return 4;
                }
                check_refs(3)
            }
        }
    };
}

define_hash_update_kptr_test!(test_hash_map_update_kptr, hash_map);
define_hash_update_kptr_test!(test_hash_malloc_map_update_kptr, hash_malloc_map);

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_ls_map_kptr_ref1(_ctx: *mut c_void) -> i32 {
    let current: *mut c_void = bpf_get_current_task_btf();
    if current.is_null() {
        return 100;
    }
    let v = bpf_task_storage_get(&task_ls_map, current, core::ptr::null(), 0) as *mut map_value;
    if !v.is_null() {
        return 150;
    }
    let v = bpf_task_storage_get(&task_ls_map, current, core::ptr::null(), BPF_LOCAL_STORAGE_GET_F_CREATE)
        as *mut map_value;
    if v.is_null() {
        return 200;
    }
    unsafe { test_map_kptr_ref_pre(v) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_ls_map_kptr_ref2(_ctx: *mut c_void) -> i32 {
    let current: *mut c_void = bpf_get_current_task_btf();
    if current.is_null() {
        return 100;
    }
    let v = bpf_task_storage_get(&task_ls_map, current, core::ptr::null(), 0) as *mut map_value;
    if v.is_null() {
        return 200;
    }
    unsafe { test_map_kptr_ref_post(v) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_ls_map_kptr_ref_del(_ctx: *mut c_void) -> i32 {
    let current: *mut c_void = bpf_get_current_task_btf();
    if current.is_null() {
        return 100;
    }
    let v = bpf_task_storage_get(&task_ls_map, current, core::ptr::null(), 0) as *mut map_value;
    if v.is_null() {
        return 200;
    }
    if unsafe { (*v).ref_ptr }.is_null() {
        return 300;
    }
    bpf_task_storage_delete(&task_ls_map, current) as i32
}

bpf_object!("GPL");
