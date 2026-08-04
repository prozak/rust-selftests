#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/cgroup_storage.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_get_local_storage, bpf_map_update_elem, sync_fetch_and_add};
use bpf_rs_core::maps::{self, BpfMap};
use core::ffi::c_void;

const BPF_ANY: u64 = 0;

// struct bpf_cgroup_storage_key (UAPI linux/bpf.h).
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_cgroup_storage_key {
    cgroup_inode_id: u64,
    attach_type: u32,
}

// No __uint(max_entries, ...) in the C source: BPF_MAP_TYPE_CGROUP_STORAGE
// is sized implicitly, so this needs the bpf_map! escape hatch rather than
// the BpfMap<K, V, TYPE, MAX> generic.
bpf_map! {
    cgroup_storage {
        r#type: *const [i32; 19], // BPF_MAP_TYPE_CGROUP_STORAGE
        key: *const bpf_cgroup_storage_key,
        value: *const u64,
    }
}

#[link_section = "cgroup_skb/egress"]
#[no_mangle]
extern "C" fn bpf_prog(_skb: *const __sk_buff) -> i32 {
    let counter = bpf_get_local_storage(&cgroup_storage, 0) as *mut isize;
    sync_fetch_and_add(counter, 1);

    // Drop one out of every two packets
    (unsafe { *counter } & 1) as i32
}

/* Maps for OOB test */

// value is a 4-byte __u32, not 8-byte aligned -- same escape hatch as above.
bpf_map! {
    cgroup_storage_oob {
        r#type: *const [i32; 19], // BPF_MAP_TYPE_CGROUP_STORAGE
        key: *const bpf_cgroup_storage_key,
        value: *const u32,
    }
}

#[link_section = ".maps"]
#[no_mangle]
static lru_map: BpfMap<u32, u32, { maps::LRU_PERCPU_HASH }, 1> = BpfMap::new();

#[link_section = "cgroup/sock_create"]
#[no_mangle]
extern "C" fn trigger_oob(_sk: *const c_void) -> i32 {
    let key: u32 = 0;
    let value: u32 = 0x1234_5678;

    // Get cgroup storage value
    let cgroup_val = bpf_get_local_storage(&cgroup_storage_oob, 0) as *mut u32;
    if cgroup_val.is_null() {
        return 0;
    }

    // Initialize cgroup storage
    unsafe { *cgroup_val = value };

    /* This triggers the OOB read:
     * bpf_map_update_elem() -> htab_map_update_elem() ->
     * pcpu_init_value() -> copy_map_value_long() ->
     * bpf_obj_memcpy(..., long_memcpy=true) ->
     * bpf_long_memcpy(dst, src, round_up(4, 8))
     *
     * The copy size is rounded up to 8 bytes, but cgroup_val
     * points to a 4-byte buffer, causing a 4-byte OOB read.
     */
    bpf_map_update_elem(&lru_map, &key, unsafe { &*cgroup_val }, BPF_ANY);

    1
}

bpf_object!("GPL");
