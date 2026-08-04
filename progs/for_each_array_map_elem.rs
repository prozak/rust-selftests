#![no_std]
#![no_main]

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_for_each_map_elem, bpf_get_smp_processor_id};
use bpf_rs_core::maps::{self, BpfMap};

type ArrayMap = BpfMap<u32, u64, { maps::ARRAY }, 3>;
type PercpuMap = BpfMap<u32, u64, { maps::PERCPU_ARRAY }, 1>;

#[link_section = ".maps"]
#[no_mangle]
static arraymap: ArrayMap = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static percpu_map: PercpuMap = BpfMap::new();

struct CallbackCtx {
    output: i32,
}

#[link_section = ".rodata"]
#[no_mangle]
static bypass_unused: i32 = 1;

extern "C" fn unused_subprog(
    _map: *mut ArrayMap,
    _key: *mut u32,
    _val: *mut u64,
    data: *mut CallbackCtx,
) -> i64 {
    unsafe { (*data).output = 0 };
    1
}

extern "C" fn check_array_elem(
    _map: *mut ArrayMap,
    key: *mut u32,
    val: *mut u64,
    data: *mut CallbackCtx,
) -> i64 {
    let k = unsafe { *key };
    let v = unsafe { *val };
    unsafe { (*data).output += v as i32 };
    if k == 1 {
        return 1;
    }
    0
}

#[no_mangle]
static mut cpu: u32 = 0;
#[no_mangle]
static mut percpu_val: u64 = 0;

extern "C" fn check_percpu_elem(
    _map: *mut PercpuMap,
    _key: *mut u32,
    val: *mut u64,
    _data: *mut c_void,
) -> i64 {
    unsafe { cpu = bpf_get_smp_processor_id() };
    unsafe { percpu_val = *val };
    0
}

#[no_mangle]
static mut arraymap_output: u32 = 0;

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_pkt_access(_skb: *const __sk_buff) -> i32 {
    let mut data = CallbackCtx { output: 0 };

    bpf_for_each_map_elem(&arraymap, check_array_elem, &mut data, 0);

    let bypass = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(bypass_unused)) };
    if bypass == 0 {
        bpf_for_each_map_elem(&arraymap, unused_subprog, &mut data, 0);
    }

    unsafe { arraymap_output = data.output as u32 };

    bpf_for_each_map_elem(
        &percpu_map,
        check_percpu_elem,
        core::ptr::null_mut::<c_void>(),
        0,
    );

    0
}

bpf_object!("GPL");
