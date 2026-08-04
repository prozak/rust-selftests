#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/cg_storage_multi_isolated.c
// (bpf-rs-core idiom). Consumed by prog_tests/cg_storage_multi.c's
// test_isolated(): each of the three programs below gets its own per-cgroup
// storage slot (BPF_CGROUP_STORAGE_SHARED is keyed by attach_type here since
// this .c has no BPF_MAP_TYPE_CGRP_STORAGE map shared across attach types).

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_get_local_storage, sync_fetch_and_add_u32};

// struct bpf_cgroup_storage_key (UAPI linux/bpf.h).
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_cgroup_storage_key {
    cgroup_inode_id: u64,
    attach_type: u32,
}

// struct cgroup_value from progs/cg_storage_multi.h.
#[allow(non_camel_case_types)]
#[repr(C)]
struct cgroup_value {
    egress_pkts: u32,
    ingress_pkts: u32,
}

// No __uint(max_entries, ...) in the C source: BPF_MAP_TYPE_CGROUP_STORAGE
// is sized implicitly, so this needs the bpf_map! escape hatch rather than
// the BpfMap<K, V, TYPE, MAX> generic.
bpf_map! {
    cgroup_storage {
        r#type: *const [i32; 19], // BPF_MAP_TYPE_CGROUP_STORAGE
        key: *const bpf_cgroup_storage_key,
        value: *const cgroup_value,
    }
}

#[no_mangle]
static mut invocations: u32 = 0;

#[link_section = "cgroup_skb/egress"]
#[no_mangle]
extern "C" fn egress1(_skb: *const __sk_buff) -> i32 {
    let ptr_cg_storage = bpf_get_local_storage(&cgroup_storage, 0) as *mut cgroup_value;

    unsafe {
        sync_fetch_and_add_u32(core::ptr::addr_of_mut!((*ptr_cg_storage).egress_pkts), 1);
        sync_fetch_and_add_u32(core::ptr::addr_of_mut!(invocations), 1);
    }

    1
}

#[link_section = "cgroup_skb/egress"]
#[no_mangle]
extern "C" fn egress2(_skb: *const __sk_buff) -> i32 {
    let ptr_cg_storage = bpf_get_local_storage(&cgroup_storage, 0) as *mut cgroup_value;

    unsafe {
        sync_fetch_and_add_u32(core::ptr::addr_of_mut!((*ptr_cg_storage).egress_pkts), 1);
        sync_fetch_and_add_u32(core::ptr::addr_of_mut!(invocations), 1);
    }

    1
}

#[link_section = "cgroup_skb/ingress"]
#[no_mangle]
extern "C" fn ingress(_skb: *const __sk_buff) -> i32 {
    let ptr_cg_storage = bpf_get_local_storage(&cgroup_storage, 0) as *mut cgroup_value;

    unsafe {
        sync_fetch_and_add_u32(core::ptr::addr_of_mut!((*ptr_cg_storage).ingress_pkts), 1);
        sync_fetch_and_add_u32(core::ptr::addr_of_mut!(invocations), 1);
    }

    1
}

bpf_object!("GPL");
