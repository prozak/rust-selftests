#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/cg_storage_multi_egress_only.c,
// bpf-rs-core idiom.
//
// BPF_MAP_TYPE_CGROUP_STORAGE (value 19, aka the "_DEPRECATED" enumerator
// that BPF_MAP_TYPE_CGROUP_STORAGE aliases to) isn't in maps::, so the
// bpf_map! escape hatch is used, matching struct bpf_cgroup_storage_key /
// struct cgroup_value from progs/cg_storage_multi.h byte-for-byte.

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_get_local_storage, sync_fetch_and_add_u32};
use bpf_rs_core::{bpf_map, bpf_object};

#[repr(C)]
struct bpf_cgroup_storage_key {
    cgroup_inode_id: u64,
    attach_type: u32,
}

#[repr(C)]
struct cgroup_value {
    egress_pkts: u32,
    ingress_pkts: u32,
}

bpf_map! {
    cgroup_storage {
        r#type: *const [i32; 19],
        key: *const bpf_cgroup_storage_key,
        value: *const cgroup_value,
    }
}

#[no_mangle]
static mut invocations: u32 = 0;

#[link_section = "cgroup_skb/egress"]
#[no_mangle]
extern "C" fn egress(_skb: *const __sk_buff) -> i32 {
    let ptr_cg_storage = bpf_get_local_storage(&cgroup_storage, 0) as *mut cgroup_value;

    unsafe {
        sync_fetch_and_add_u32(core::ptr::addr_of_mut!((*ptr_cg_storage).egress_pkts), 1);
    }
    sync_fetch_and_add_u32(core::ptr::addr_of_mut!(invocations), 1);

    1
}

bpf_object!("GPL");
