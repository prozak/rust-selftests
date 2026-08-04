#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/wq.c
// (bpf-rs-core idiom).
//
// bpf_wq_init/_start/_set_callback are kfuncs (bpf_wq_set_callback is
// KF_IMPLICIT_ARGS, same shape as bpf_timer_set_callback but resolved via
// the kfunc/ksym path instead of a helper ID -- add_ksyms.py mirrors the
// real kernel prototypes onto these externs, so the trailing implicit
// `struct bpf_prog_aux *aux` arg is omitted here just like the C original
// omits it (see ../test_kmods/... hid_bpf_helpers.h's own declaration).

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_map_lookup_elem, bpf_map_update_elem};
use bpf_rs_core::maps::{self, BpfMap};
use core::ffi::c_void;

// struct bpf_timer { __u64 __opaque[2]; } __attribute__((aligned(8)));
#[allow(non_camel_case_types)]
#[repr(C, align(8))]
struct bpf_timer {
    __opaque: [u64; 2],
}

// struct bpf_spin_lock { __u32 val; };
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_spin_lock {
    val: u32,
}

// struct bpf_wq { __u64 __opaque[2]; } __attribute__((aligned(8)));
#[allow(non_camel_case_types)]
#[repr(C, align(8))]
struct bpf_wq {
    __opaque: [u64; 2],
}

#[repr(C)]
struct hmap_elem {
    counter: i32,
    timer: bpf_timer,
    lock: bpf_spin_lock,
    work: bpf_wq,
}

#[repr(C)]
struct elem {
    ok_offset: i32,
    w: bpf_wq,
}

#[link_section = ".maps"]
#[no_mangle]
static hmap: BpfMap<i32, hmap_elem, { maps::HASH }, 1000> = BpfMap::new();

bpf_map! {
    hmap_malloc {
        r#type: *const [i32; maps::HASH],
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        max_entries: *const [i32; 1000],
        key: *const i32,
        value: *const hmap_elem,
    }
}

#[link_section = ".maps"]
#[no_mangle]
static array: BpfMap<i32, elem, { maps::ARRAY }, 2> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static lru: BpfMap<i32, elem, { maps::LRU_HASH }, 4> = BpfMap::new();

#[no_mangle]
static mut ok: u32 = 0;

#[no_mangle]
static mut ok_sleepable: u32 = 0;

extern "C" {
    fn bpf_wq_init(wq: *mut bpf_wq, map: *mut c_void, flags: u32) -> i32;
    fn bpf_wq_start(wq: *mut bpf_wq, flags: u32) -> i32;
    fn bpf_wq_set_callback(
        wq: *mut bpf_wq,
        callback_fn: extern "C" fn(*mut c_void, *mut i32, *mut c_void) -> i32,
        flags: u32,
    ) -> i32;
    fn bpf_kfunc_common_test();
    fn bpf_kfunc_call_test_sleepable();
}

fn test_elem_callback<M>(
    map: &'static M,
    key: i32,
    is_lru: bool,
    callback_fn: extern "C" fn(*mut c_void, *mut i32, *mut c_void) -> i32,
) -> i32 {
    let cur_ok = unsafe { ok };
    let cur_ok_sleepable = unsafe { ok_sleepable };
    if (cur_ok & (1u32 << key)) != 0 || (cur_ok_sleepable & (1u32 << key)) != 0 {
        return -22;
    }

    if is_lru {
        let init = elem {
            ok_offset: 0,
            w: bpf_wq { __opaque: [0; 2] },
        };
        if bpf_map_update_elem(map, &key, &init, 0) != 0 {
            return -1;
        }
    }

    let val = bpf_map_lookup_elem(map, &key) as *mut elem;
    if val.is_null() {
        return -2;
    }

    unsafe {
        (*val).ok_offset = key;
    }

    let wq = unsafe { core::ptr::addr_of_mut!((*val).w) };

    if unsafe { bpf_wq_init(wq, map as *const M as *mut c_void, 0) } != 0 {
        return -3;
    }

    if unsafe { bpf_wq_set_callback(wq, callback_fn, 0) } != 0 {
        return -4;
    }

    if unsafe { bpf_wq_start(wq, 0) } != 0 {
        return -5;
    }

    0
}

fn test_hmap_elem_callback<M>(
    map: &'static M,
    key: i32,
    callback_fn: extern "C" fn(*mut c_void, *mut i32, *mut c_void) -> i32,
) -> i32 {
    let cur_ok = unsafe { ok };
    let cur_ok_sleepable = unsafe { ok_sleepable };
    if (cur_ok & (1u32 << key)) != 0 || (cur_ok_sleepable & (1u32 << key)) != 0 {
        return -22;
    }

    let init = hmap_elem {
        counter: 0,
        timer: bpf_timer { __opaque: [0; 2] },
        lock: bpf_spin_lock { val: 0 },
        work: bpf_wq { __opaque: [0; 2] },
    };
    if bpf_map_update_elem(map, &key, &init, 0) != 0 {
        return -1;
    }

    let val = bpf_map_lookup_elem(map, &key) as *mut hmap_elem;
    if val.is_null() {
        return -2;
    }

    let wq = unsafe { core::ptr::addr_of_mut!((*val).work) };

    if unsafe { bpf_wq_init(wq, map as *const M as *mut c_void, 0) } != 0 {
        return -3;
    }

    if unsafe { bpf_wq_set_callback(wq, callback_fn, 0) } != 0 {
        return -4;
    }

    if unsafe { bpf_wq_start(wq, 0) } != 0 {
        return -5;
    }

    0
}

// callback for non sleepable workqueue
extern "C" fn wq_callback(_map: *mut c_void, key: *mut i32, _value: *mut c_void) -> i32 {
    let k = unsafe { *key };
    unsafe {
        bpf_kfunc_common_test();
        ok |= 1u32 << k;
    }
    0
}

// callback for sleepable workqueue
extern "C" fn wq_cb_sleepable(_map: *mut c_void, key: *mut i32, value: *mut c_void) -> i32 {
    let data = value as *mut elem;
    let offset = unsafe { (*data).ok_offset };
    let k = unsafe { *key };

    if k != offset {
        return 0;
    }

    unsafe {
        bpf_kfunc_call_test_sleepable();
        ok_sleepable |= 1u32 << offset;
    }

    0
}

#[link_section = "tc"]
#[no_mangle]
// test that workqueues can be used from an array
extern "C" fn test_call_array_sleepable(_ctx: *const __sk_buff) -> i32 {
    let key = 0;

    test_elem_callback(&array, key, false, wq_cb_sleepable)
}

#[link_section = "syscall"]
#[no_mangle]
// Same test than above but from a sleepable context.
extern "C" fn test_syscall_array_sleepable(_ctx: *const c_void) -> i32 {
    let key = 1;

    test_elem_callback(&array, key, false, wq_cb_sleepable)
}

#[link_section = "tc"]
#[no_mangle]
// test that workqueues can be used from a hashmap
extern "C" fn test_call_hash_sleepable(_ctx: *const __sk_buff) -> i32 {
    let key = 2;

    test_hmap_elem_callback(&hmap, key, wq_callback)
}

#[link_section = "tc"]
#[no_mangle]
// test that workqueues can be used from a hashmap with NO_PREALLOC.
extern "C" fn test_call_hash_malloc_sleepable(_ctx: *const __sk_buff) -> i32 {
    let key = 3;

    test_hmap_elem_callback(&hmap_malloc, key, wq_callback)
}

#[link_section = "tc"]
#[no_mangle]
// test that workqueues can be used from a LRU map
extern "C" fn test_call_lru_sleepable(_ctx: *const __sk_buff) -> i32 {
    let key = 4;

    test_elem_callback(&lru, key, true, wq_callback)
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_map_no_btf(_ctx: *const __sk_buff) -> i32 {
    let key: i32 = 42;

    let val = bpf_map_lookup_elem(&array, &key) as *mut elem;
    if val.is_null() {
        return -2;
    }

    let wq = unsafe { core::ptr::addr_of_mut!((*val).w) };

    if unsafe { bpf_wq_init(wq, &array as *const _ as *mut c_void, 0) } != 0 {
        return -3;
    }

    0
}

bpf_object!("GPL");
