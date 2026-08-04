#![no_std]
#![no_main]

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_for_each_map_elem, bpf_get_smp_processor_id, bpf_map_delete_elem};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::vload;

type HashMap = BpfMap<u32, u64, { maps::HASH }, 3>;
type PercpuMap = BpfMap<u32, u64, { maps::PERCPU_HASH }, 1>;

#[link_section = ".maps"]
#[no_mangle]
static hashmap: HashMap = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static percpu_map: PercpuMap = BpfMap::new();

#[repr(C)]
struct CallbackCtx {
    ctx: *const __sk_buff,
    input: i32,
    output: i32,
}

extern "C" fn check_hash_elem(
    map: *mut HashMap,
    key: *mut u32,
    val: *mut u64,
    data: *mut CallbackCtx,
) -> i64 {
    let data_ref = unsafe { &mut *data };

    if !data_ref.ctx.is_null() {
        let skb = data_ref.ctx;
        let k = unsafe { *key };
        let v = unsafe { *val };
        let len = vload!((*skb).len);
        if len == 10000 && k == 10 && v == 10 {
            data_ref.output = 3;
        } else {
            data_ref.output = 4;
        }
    } else {
        data_ref.output = data_ref.input;
        bpf_map_delete_elem(map as *const HashMap, unsafe { &*key });
    }

    0
}

#[no_mangle]
static mut cpu: u32 = 0;
#[no_mangle]
static mut percpu_called: u32 = 0;
#[no_mangle]
static mut percpu_key: u32 = 0;
#[no_mangle]
static mut percpu_val: u64 = 0;
#[no_mangle]
static mut percpu_output: i32 = 0;

extern "C" fn check_percpu_elem(
    _map: *mut PercpuMap,
    key: *mut u32,
    val: *mut u64,
    _unused: *mut CallbackCtx,
) -> i64 {
    let mut data = CallbackCtx {
        ctx: core::ptr::null(),
        input: 100,
        output: 0,
    };

    unsafe {
        percpu_called += 1;
        cpu = bpf_get_smp_processor_id();
        percpu_key = *key;
        percpu_val = *val;
    }

    bpf_for_each_map_elem(&hashmap, check_hash_elem, &mut data as *mut CallbackCtx, 0);

    unsafe {
        percpu_output = data.output;
    }

    0
}

#[no_mangle]
static mut hashmap_output: i32 = 0;
#[no_mangle]
static mut hashmap_elems: i32 = 0;
#[no_mangle]
static mut percpu_map_elems: i32 = 0;

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_pkt_access(skb: *const __sk_buff) -> i32 {
    let mut data = CallbackCtx {
        ctx: skb,
        input: 10,
        output: 0,
    };

    let elems = bpf_for_each_map_elem(&hashmap, check_hash_elem, &mut data as *mut CallbackCtx, 0);
    unsafe {
        hashmap_elems = elems as i32;
        hashmap_output = data.output;
    }

    let percpu_elems = bpf_for_each_map_elem(
        &percpu_map,
        check_percpu_elem,
        core::ptr::null_mut::<CallbackCtx>(),
        0,
    );
    unsafe {
        percpu_map_elems = percpu_elems as i32;
    }

    0
}

bpf_object!("GPL");
