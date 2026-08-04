#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/tailcall_cgrp_storage_owner.c,
// bpf-rs-core idiom.

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_get_local_storage, bpf_tail_call};
use bpf_rs_core::{bpf_map, bpf_object, maps};

// struct bpf_cgroup_storage_key (UAPI linux/bpf.h).
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_cgroup_storage_key {
    cgroup_inode_id: u64,
    attach_type: u32,
}

// No __uint(max_entries, ...) in the C source: BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE
// is sized implicitly, so this needs the bpf_map! escape hatch rather than
// the BpfMap<K, V, TYPE, MAX> generic.
bpf_map! {
    storage_map {
        r#type: *const [i32; 21], // BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE
        key: *const bpf_cgroup_storage_key,
        value: *const u64,
    }
}

bpf_map! {
    prog_array {
        r#type: *const [i32; maps::PROG_ARRAY],
        max_entries: *const [i32; 1],
        key_size: *const [i32; 4],
        value_size: *const [i32; 4],
    }
}

#[link_section = "cgroup_skb/egress"]
#[no_mangle]
extern "C" fn prog_array_owner(skb: *const __sk_buff) -> i32 {
    let storage = bpf_get_local_storage(&storage_map, 0) as *mut u64;
    if !storage.is_null() {
        unsafe { *storage = 1 };
    }

    bpf_tail_call(skb as *const core::ffi::c_void, &prog_array, 0);
    1
}

bpf_object!("GPL");
