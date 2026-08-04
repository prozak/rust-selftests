#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/cg_storage_multi_shared.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_get_local_storage, sync_fetch_and_add_u32};

#[repr(C)]
struct cgroup_value {
    egress_pkts: u32,
    ingress_pkts: u32,
}

// BPF_MAP_TYPE_CGROUP_STORAGE has no max_entries member; key is __u64.
bpf_map! {
    cgroup_storage {
        r#type: *const [i32; 19],
        key: *const u64,
        value: *const cgroup_value,
    }
}

#[no_mangle]
static mut invocations: u32 = 0;

#[link_section = "cgroup_skb/egress"]
#[no_mangle]
extern "C" fn egress1(_skb: *const __sk_buff) -> i32 {
    let ptr_cg_storage = bpf_get_local_storage(&cgroup_storage, 0) as *mut cgroup_value;
    sync_fetch_and_add_u32(unsafe { core::ptr::addr_of_mut!((*ptr_cg_storage).egress_pkts) }, 1);
    sync_fetch_and_add_u32(unsafe { core::ptr::addr_of_mut!(invocations) }, 1);
    1
}

#[link_section = "cgroup_skb/egress"]
#[no_mangle]
extern "C" fn egress2(_skb: *const __sk_buff) -> i32 {
    let ptr_cg_storage = bpf_get_local_storage(&cgroup_storage, 0) as *mut cgroup_value;
    sync_fetch_and_add_u32(unsafe { core::ptr::addr_of_mut!((*ptr_cg_storage).egress_pkts) }, 1);
    sync_fetch_and_add_u32(unsafe { core::ptr::addr_of_mut!(invocations) }, 1);
    1
}

#[link_section = "cgroup_skb/ingress"]
#[no_mangle]
extern "C" fn ingress(_skb: *const __sk_buff) -> i32 {
    let ptr_cg_storage = bpf_get_local_storage(&cgroup_storage, 0) as *mut cgroup_value;
    sync_fetch_and_add_u32(unsafe { core::ptr::addr_of_mut!((*ptr_cg_storage).ingress_pkts) }, 1);
    sync_fetch_and_add_u32(unsafe { core::ptr::addr_of_mut!(invocations) }, 1);
    1
}

bpf_object!("GPL");
