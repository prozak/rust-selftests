#![no_std]
#![no_main]

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_for_each_map_elem, bpf_map_delete_elem, bpf_map_update_elem};
use bpf_rs_core::maps::{self, BpfMap};

type HashMap = BpfMap<u64, u64, { maps::HASH }, 128>;

#[link_section = ".maps"]
#[no_mangle]
static hashmap: HashMap = BpfMap::new();

extern "C" fn cb(map: *mut HashMap, key: *mut u64, val: *mut u64, _arg: *mut c_void) -> i64 {
    let key_ref = unsafe { &*key };
    let val_ref = unsafe { &*val };
    bpf_map_delete_elem(map as *const HashMap, key_ref);
    bpf_map_update_elem(map as *const HashMap, key_ref, val_ref, 0);
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_pkt_access(_skb: *const __sk_buff) -> i32 {
    bpf_for_each_map_elem(&hashmap, cb, core::ptr::null_mut::<c_void>(), 0);
    0
}

bpf_object!("GPL");
