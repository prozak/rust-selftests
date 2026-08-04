#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/load_bytes_relative.c, bpf-rs-core idiom.

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_map_update_elem, bpf_skb_load_bytes_relative};
use bpf_rs_core::{bpf_object, maps};
use bpf_rs_core::maps::BpfMap;

const BPF_HDR_START_MAC: u32 = 0;
const BPF_HDR_START_NET: u32 = 1;
const BPF_ANY: u64 = 0;
const EFAULT: i64 = 14;

#[link_section = ".maps"]
#[no_mangle]
static test_result: BpfMap<u32, u32, { maps::ARRAY }, 1> = BpfMap::new();

#[repr(C)]
struct EthHdr {
    _h_dest: [u8; 6],
    _h_source: [u8; 6],
    _h_proto: u16,
}

#[repr(C)]
struct IpHdr {
    _bytes: [u8; 20],
}

#[link_section = "cgroup_skb/egress"]
#[no_mangle]
extern "C" fn load_bytes_relative(skb: *const __sk_buff) -> i32 {
    let mut eth = EthHdr {
        _h_dest: [0; 6],
        _h_source: [0; 6],
        _h_proto: 0,
    };
    let mut iph = IpHdr { _bytes: [0; 20] };

    let map_key: u32 = 0;
    let mut test_passed: u32 = 0;

    let skb_void = skb as *const core::ffi::c_void;

    'fail: {
        if bpf_skb_load_bytes_relative(
            skb_void,
            0,
            &mut eth as *mut EthHdr as *mut core::ffi::c_void,
            core::mem::size_of::<EthHdr>() as u32,
            BPF_HDR_START_MAC,
        ) != -EFAULT
        {
            break 'fail;
        }

        if bpf_skb_load_bytes_relative(
            skb_void,
            0,
            &mut iph as *mut IpHdr as *mut core::ffi::c_void,
            core::mem::size_of::<IpHdr>() as u32,
            BPF_HDR_START_NET,
        ) != 0
        {
            break 'fail;
        }

        if bpf_skb_load_bytes_relative(
            skb_void,
            0xffff,
            &mut iph as *mut IpHdr as *mut core::ffi::c_void,
            core::mem::size_of::<IpHdr>() as u32,
            BPF_HDR_START_NET,
        ) != -EFAULT
        {
            break 'fail;
        }

        test_passed = 1;
    }

    bpf_map_update_elem(&test_result, &map_key, &test_passed, BPF_ANY);

    1
}

bpf_object!("GPL");
