#![no_std]
#![no_main]

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::bpf_for_each_map_elem;
use bpf_rs_core::maps::{self, BpfMap};

type ArrayMap = BpfMap<u32, u64, { maps::ARRAY }, 3>;
type HashMap = BpfMap<u32, u64, { maps::HASH }, 5>;

#[link_section = ".maps"]
#[no_mangle]
static arraymap: ArrayMap = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static hashmap: HashMap = BpfMap::new();

#[repr(C)]
struct callback_ctx {
    output: i32,
}

#[no_mangle]
static mut data_output: u32 = 0;
#[no_mangle]
static mut use_array: i32 = 0;

extern "C" fn check_map_elem_array(
    _map: *mut ArrayMap,
    _key: *mut u32,
    val: *mut u64,
    data: *mut callback_ctx,
) -> i64 {
    unsafe {
        (*data).output += *val as i32;
    }
    0
}

extern "C" fn check_map_elem_hash(
    _map: *mut HashMap,
    _key: *mut u32,
    val: *mut u64,
    data: *mut callback_ctx,
) -> i64 {
    unsafe {
        (*data).output += *val as i32;
    }
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_pkt_access(_skb: *const __sk_buff) -> i32 {
    let mut data = callback_ctx { output: 0 };

    if unsafe { use_array } != 0 {
        bpf_for_each_map_elem(&arraymap, check_map_elem_array, &mut data, 0);
    } else {
        bpf_for_each_map_elem(&hashmap, check_map_elem_hash, &mut data, 0);
    }
    unsafe {
        data_output = data.output as u32;
    }

    0
}

bpf_object!("GPL");
