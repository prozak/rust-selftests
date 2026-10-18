// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/map_kptr_race.c
// (bpf-rs-core idiom). Each leak program stores a referenced
// prog_test_ref_kfunc (bpf_testmod) kptr into a map element, deletes the
// element while still holding the element pointer, and stores another one
// into the freed element; prog_tests/map_kptr_race.c then watches the map's
// release through the map_put/..._map_free programs of a second instance
// and reads the object's refcount with count_ref. The kptr pointee is a
// #[btf] view of the module struct, also used for the refcount read.

use core::ffi::c_void;
use core::ptr::{addr_of_mut, read_volatile};

use bpf_rs_core::helpers::{
    bpf_kptr_xchg, bpf_map_delete_elem, bpf_map_lookup_elem, bpf_map_lookup_percpu_elem,
    bpf_map_update_elem, bpf_sk_storage_delete, bpf_sk_storage_get,
};
use bpf_rs_core::progs::fentry_arg as arg;
use bpf_rs_core::{bpf_map, bpf_object, btf_type_tags, maps};
use btf_macros::btf;

const BPF_ANY: u64 = 0;
const BPF_TCP_SYN_SENT: i32 = 2;
const BPF_SK_STORAGE_GET_F_CREATE: u64 = 1;

#[btf]
struct prog_test_ref_kfunc {
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
#[repr(C)]
struct map_value {
    ref_ptr: *mut prog_test_ref_kfunc,
}

btf_type_tags! {
    map_value.ref_ptr: kptr;
}

bpf_map! {
    race_hash_map {
        r#type: *const [i32; maps::HASH],
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        key: *const i32,
        value: *const map_value,
        max_entries: *const [i32; 1],
    }
}

bpf_map! {
    race_percpu_hash_map {
        r#type: *const [i32; maps::PERCPU_HASH],
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        key: *const i32,
        value: *const map_value,
        max_entries: *const [i32; 1],
    }
}

bpf_map! {
    race_sk_ls_map {
        r#type: *const [i32; 24],   // BPF_MAP_TYPE_SK_STORAGE
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        key: *const i32,
        value: *const map_value,
    }
}

#[no_mangle]
static mut num_of_refs: i32 = 0;
#[no_mangle]
static mut sk_ls_leak_done: i32 = 0;
#[no_mangle]
static mut target_map_id: i32 = 0;
#[no_mangle]
static mut map_freed: i32 = 0;
#[link_section = ".rodata"]
#[no_mangle]
static nr_cpus: i32 = 0;

extern "C" {
    fn bpf_kfunc_call_test_acquire(scalar_ptr: *mut u64) -> *mut prog_test_ref_kfunc;
    fn bpf_kfunc_call_test_release(p: *mut prog_test_ref_kfunc);
}

/// `p = bpf_kfunc_call_test_acquire(&(unsigned long){0}); old = bpf_kptr_xchg(&v->ref_ptr, p);
/// if (old) bpf_kfunc_call_test_release(old);` — false when the acquire failed
#[inline(always)]
unsafe fn acquire_into(v: *mut map_value) -> bool {
    let mut zero: u64 = 0;
    let p = bpf_kfunc_call_test_acquire(&mut zero);
    if p.is_null() {
        return false;
    }
    let old = bpf_kptr_xchg(addr_of_mut!((*v).ref_ptr).cast(), p.cast()) as *mut prog_test_ref_kfunc;
    if !old.is_null() {
        bpf_kfunc_call_test_release(old);
    }
    true
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_htab_leak(_skb: *const c_void) -> i32 {
    let val = map_value { ref_ptr: core::ptr::null_mut() };
    let key: i32 = 0;

    if bpf_map_update_elem(&race_hash_map, &key, &val, BPF_ANY) != 0 {
        return 1;
    }

    let v = bpf_map_lookup_elem(&race_hash_map, &key) as *mut map_value;
    if v.is_null() {
        return 2;
    }

    unsafe {
        if !acquire_into(v) {
            return 3;
        }

        bpf_map_delete_elem(&race_hash_map, &key);

        if !acquire_into(v) {
            return 4;
        }
    }

    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_percpu_htab_leak(_skb: *const c_void) -> i32 {
    let mut arr: [*mut map_value; 16] = [core::ptr::null_mut(); 16];
    let val = map_value { ref_ptr: core::ptr::null_mut() };
    let key: i32 = 0;

    if bpf_map_update_elem(&race_percpu_hash_map, &key, &val, BPF_ANY) != 0 {
        return 1;
    }

    unsafe {
        let mut i: i32 = 0;
        while i < read_volatile(&nr_cpus) {
            let v = bpf_map_lookup_percpu_elem(&race_percpu_hash_map, &key, i as u32) as *mut map_value;
            if v.is_null() {
                return 2;
            }
            *arr.as_mut_ptr().add(i as usize) = v;
            i += 1;
        }

        bpf_map_delete_elem(&race_percpu_hash_map, &key);

        let mut i: i32 = 0;
        while i < read_volatile(&nr_cpus) {
            let v = *arr.as_ptr().add(i as usize);
            // fill_percpu_kptr(v)
            if !acquire_into(v) {
                return 3;
            }
            i += 1;
        }
    }

    0
}

// BPF_PROG(test_sk_ls_leak, struct sock *sk, int oldstate, int newstate)
#[link_section = "tp_btf/inet_sock_set_state"]
#[no_mangle]
extern "C" fn test_sk_ls_leak(ctx: *const u64) -> i32 {
    let sk = arg(ctx, 0) as *mut c_void;
    let newstate = arg(ctx, 2) as i32;

    if newstate != BPF_TCP_SYN_SENT {
        return 0;
    }

    if unsafe { sk_ls_leak_done } != 0 {
        return 0;
    }

    let v = bpf_sk_storage_get(
        &race_sk_ls_map,
        sk,
        core::ptr::null(),
        BPF_SK_STORAGE_GET_F_CREATE,
    ) as *mut map_value;
    if v.is_null() {
        return 0;
    }

    unsafe {
        if !acquire_into(v) {
            return 0;
        }

        bpf_sk_storage_delete(&race_sk_ls_map, sk);

        if !acquire_into(v) {
            return 0;
        }

        sk_ls_leak_done = 1;
    }
    0
}

#[no_mangle]
static mut target_map_ptr: i64 = 0;

#[btf]
struct bpf_map {
    id: u32,
}

// BPF_PROG(map_put, struct bpf_map *map)
#[link_section = "fentry/bpf_map_put"]
#[no_mangle]
extern "C" fn map_put(ctx: *const u64) -> i32 {
    let map = arg(ctx, 0) as *const bpf_map;

    unsafe {
        if target_map_id != 0 && *(&*map).id().as_ptr() == target_map_id as u32 {
            target_map_ptr = map as i64;
        }
    }
    0
}

// BPF_PROG(htab_map_free, struct bpf_map *map)
#[link_section = "fexit/htab_map_free"]
#[no_mangle]
extern "C" fn htab_map_free(ctx: *const u64) -> i32 {
    let map = arg(ctx, 0) as i64;

    unsafe {
        if target_map_ptr != 0 && map == target_map_ptr {
            map_freed = 1;
        }
    }
    0
}

// BPF_PROG(sk_map_free, struct bpf_map *map)
#[link_section = "fexit/bpf_sk_storage_map_free"]
#[no_mangle]
extern "C" fn sk_map_free(ctx: *const u64) -> i32 {
    let map = arg(ctx, 0) as i64;

    unsafe {
        if target_map_ptr != 0 && map == target_map_ptr {
            map_freed = 1;
        }
    }
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn count_ref(_ctx: *mut c_void) -> i32 {
    let mut arg_: u64 = 0;

    unsafe {
        let p = bpf_kfunc_call_test_acquire(&mut arg_);
        if p.is_null() {
            return 1;
        }

        num_of_refs = *(&*p).cnt().refs().counter().as_ptr();

        bpf_kfunc_call_test_release(p);
    }
    0
}

bpf_object!("GPL");
