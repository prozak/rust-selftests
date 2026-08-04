#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/netcnt_prog.c
// (bpf-rs-core idiom). Value-type sizes mirror netcnt_common.h exactly
// (PCPU_MIN_UNIT_SIZE / BPF_LOCAL_STORAGE_MAX_VALUE_SIZE) since libbpf
// derives each cgroup-storage map's value_size from the BTF type's sizeof,
// and the userspace test computes its lookup buffer stride the same way.

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_get_local_storage, bpf_ktime_get_ns, sync_fetch_and_add};
use bpf_rs_core::vload;

const MAX_PERCPU_PACKETS: u64 = 32;

const SIZEOF_BPF_LOCAL_STORAGE_ELEM: usize = 768;
const BPF_LOCAL_STORAGE_MAX_VALUE_SIZE: usize = 0xFFFF - SIZEOF_BPF_LOCAL_STORAGE_ELEM;
const PCPU_MIN_UNIT_SIZE: usize = 32768;

const MAX_BPS: u64 = 3 * 1024 * 1024;
const REFRESH_TIME_NS: u64 = 100_000_000;
const NS_PER_SEC: u64 = 1_000_000_000;

// struct bpf_cgroup_storage_key (UAPI linux/bpf.h).
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_cgroup_storage_key {
    cgroup_inode_id: u64,
    attach_type: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PercpuNetCntFields {
    packets: u64,
    bytes: u64,
    prev_ts: u64,
    prev_packets: u64,
    prev_bytes: u64,
}

// union percpu_net_cnt (netcnt_common.h).
#[allow(non_camel_case_types)]
#[repr(C)]
union percpu_net_cnt {
    fields: PercpuNetCntFields,
    data: [u8; PCPU_MIN_UNIT_SIZE],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NetCntFields {
    packets: u64,
    bytes: u64,
}

// union net_cnt (netcnt_common.h).
#[allow(non_camel_case_types)]
#[repr(C)]
union net_cnt {
    fields: NetCntFields,
    data: [u8; BPF_LOCAL_STORAGE_MAX_VALUE_SIZE],
}

// No __uint(max_entries, ...) in the C source: both cgroup-storage map
// types are sized implicitly, so this needs the bpf_map! escape hatch
// rather than the BpfMap<K, V, TYPE, MAX> generic.
bpf_map! {
    percpu_netcnt {
        r#type: *const [i32; 21], // BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE
        key: *const bpf_cgroup_storage_key,
        value: *const percpu_net_cnt,
    }
}

bpf_map! {
    netcnt {
        r#type: *const [i32; 19], // BPF_MAP_TYPE_CGROUP_STORAGE
        key: *const bpf_cgroup_storage_key,
        value: *const net_cnt,
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
extern "C" fn bpf_nextcnt(skb: *const __sk_buff) -> i32 {
    let cnt = bpf_get_local_storage(&netcnt, 0) as *mut net_cnt;
    let percpu_cnt = bpf_get_local_storage(&percpu_netcnt, 0) as *mut percpu_net_cnt;

    unsafe {
        (*percpu_cnt).fields.packets += 1;
        (*percpu_cnt).fields.bytes = (*percpu_cnt)
            .fields
            .bytes
            .wrapping_add(vload!((*skb).len) as u64);

        if (*percpu_cnt).fields.packets > MAX_PERCPU_PACKETS {
            sync_fetch_and_add(
                core::ptr::addr_of_mut!((*cnt).fields.packets) as *mut isize,
                (*percpu_cnt).fields.packets as isize,
            );
            (*percpu_cnt).fields.packets = 0;

            sync_fetch_and_add(
                core::ptr::addr_of_mut!((*cnt).fields.bytes) as *mut isize,
                (*percpu_cnt).fields.bytes as isize,
            );
            (*percpu_cnt).fields.bytes = 0;
        }

        let ts = bpf_ktime_get_ns();
        let mut dt = ts.wrapping_sub((*percpu_cnt).fields.prev_ts);

        dt = dt.wrapping_mul(MAX_BPS);
        dt /= NS_PER_SEC;

        let ret: i32 = if (*cnt)
            .fields
            .bytes
            .wrapping_add((*percpu_cnt).fields.bytes)
            .wrapping_sub((*percpu_cnt).fields.prev_bytes)
            < dt
        {
            1
        } else {
            0
        };

        if dt > REFRESH_TIME_NS {
            (*percpu_cnt).fields.prev_ts = ts;
            (*percpu_cnt).fields.prev_packets = (*cnt).fields.packets;
            (*percpu_cnt).fields.prev_bytes = (*cnt).fields.bytes;
        }

        ret
    }
}

bpf_object!("GPL");
