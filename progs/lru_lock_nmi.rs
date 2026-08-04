#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/lru_lock_nmi.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_get_prandom_u32, bpf_map_delete_elem, bpf_map_update_elem, sync_fetch_and_add_u32,
};
use bpf_rs_core::maps::{self, BpfMap};

const BPF_ANY: u64 = 0;

#[link_section = ".maps"]
#[no_mangle]
static lru_map: BpfMap<u32, u64, { maps::LRU_HASH }, 64> = BpfMap::new();

#[no_mangle]
static mut hits: i32 = 0;

#[link_section = "perf_event"]
#[no_mangle]
extern "C" fn oncpu(_ctx: *mut core::ffi::c_void) -> i32 {
    // Key range deliberately wider than max_entries to force LRU
    // eviction on every other update.
    let key: u32 = bpf_get_prandom_u32() % 128;
    let do_update = bpf_get_prandom_u32() & 1 != 0;
    let val: u64 = 1;

    if do_update {
        bpf_map_update_elem(&lru_map, &key, &val, BPF_ANY);
    } else {
        bpf_map_delete_elem(&lru_map, &key);
    }
    sync_fetch_and_add_u32(core::ptr::addr_of_mut!(hits) as *mut u32, 1);

    0
}

bpf_object!("GPL");
