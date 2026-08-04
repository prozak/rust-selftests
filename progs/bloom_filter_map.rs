#![no_std]
#![no_main]

use core::ffi::c_void;

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_for_each_map_elem, bpf_map_lookup_elem, bpf_map_peek_elem};
use bpf_rs_core::maps::{self, BpfMap};

// enum bpf_map_type values not yet in bpf_rs_core::maps.
const BLOOM_FILTER: usize = 30;
const ARRAY_OF_MAPS: usize = 12;

type RandomDataMap = BpfMap<u32, u32, { maps::ARRAY }, 1000>;

#[link_section = ".maps"]
#[no_mangle]
static map_random_data: RandomDataMap = BpfMap::new();

// BPF_MAP_TYPE_BLOOM_FILTER has no key member; reused below as the inner-map
// template for outer_map's `values` array, same as the C source reusing
// `struct map_bloom_type` for both.
bpf_map! {
    map_bloom {
        r#type: *const [i32; BLOOM_FILTER],
        value: *const u32,
        max_entries: *const [i32; 10000],
        map_extra: *const [i32; 5],
    }
}

#[repr(C)]
struct OuterMapDef {
    r#type: *const [i32; ARRAY_OF_MAPS],
    key: *const i32,
    value: *const i32,
    max_entries: *const [i32; 1],
    values: [*const map_bloom; 0],
}
unsafe impl Sync for OuterMapDef {}

#[link_section = ".maps"]
#[no_mangle]
static outer_map: OuterMapDef = OuterMapDef {
    r#type: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
    max_entries: core::ptr::null(),
    values: [],
};

#[repr(C)]
struct CallbackCtx {
    map: *mut c_void,
}

#[no_mangle]
static mut error: i32 = 0;

extern "C" fn check_elem(
    _map: *mut RandomDataMap,
    _key: *mut u32,
    val: *mut u32,
    data: *mut CallbackCtx,
) -> i64 {
    let data = unsafe { &*data };
    let val = unsafe { &mut *val };
    if bpf_map_peek_elem(data.map as *const c_void, val) != 0 {
        unsafe { error |= 1 };
        return 1; // stop the iteration
    }
    0
}

#[link_section = "fentry/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn inner_map(_ctx: *const c_void) -> i32 {
    let key: i32 = 0;

    let inner = bpf_map_lookup_elem(&outer_map, &key);
    if inner.is_null() {
        unsafe { error |= 2 };
        return 0;
    }

    let mut data = CallbackCtx { map: inner };
    bpf_for_each_map_elem(&map_random_data, check_elem, &mut data, 0);

    0
}

#[link_section = "fentry/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn check_bloom(_ctx: *const c_void) -> i32 {
    let mut data = CallbackCtx {
        map: core::ptr::addr_of!(map_bloom) as *mut c_void,
    };
    bpf_for_each_map_elem(&map_random_data, check_elem, &mut data, 0);

    0
}

bpf_object!("GPL");
