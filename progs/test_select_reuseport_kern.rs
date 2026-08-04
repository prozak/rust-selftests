#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_select_reuseport_kern.c
// (bpf-rs-core idiom). Common types/enum come from
// test_select_reuseport_common.h.

use core::ffi::c_void;
use core::mem::size_of;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_map_lookup_elem, bpf_map_update_elem, bpf_sk_select_reuseport, bpf_skb_load_bytes,
    bpf_skb_load_bytes_relative,
};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::vload;

const ETH_P_IP: u16 = 0x0800;
const IPPROTO_TCP: u32 = 6;
const IPPROTO_UDP: u32 = 17;

const BPF_HDR_START_NET: u32 = 1;
const BPF_ANY: u64 = 0;

const SK_DROP: i32 = 0;
const SK_PASS: i32 = 1;

// enum result (test_select_reuseport_common.h).
const DROP_ERR_INNER_MAP: u32 = 0;
const DROP_ERR_SKB_DATA: u32 = 1;
const DROP_ERR_SK_SELECT_REUSEPORT: u32 = 2;
const DROP_MISC: u32 = 3;
const RESULT_PASS: u32 = 4;
const PASS_ERR_SK_SELECT_REUSEPORT: u32 = 5;
const NR_RESULTS: usize = 6;

const ARRAY_OF_MAPS: usize = 12; // BPF_MAP_TYPE_ARRAY_OF_MAPS

#[inline(always)]
fn htons(x: u16) -> u16 {
    x.to_be()
}

// struct cmd (test_select_reuseport_common.h).
#[repr(C)]
#[derive(Clone, Copy)]
struct Cmd {
    reuseport_index: u32,
    pass_on_failure: u32,
}

// struct data_check (test_select_reuseport_common.h). Only the userspace
// harness's memcmp() cares about the offset of `equal_check_end`; the BPF
// side never reads it, but the map value's overall size must match the C
// struct so the harness's raw read lines up field-for-field.
#[repr(C)]
#[derive(Clone, Copy)]
struct DataCheck {
    ip_protocol: u32,
    skb_addrs: [u32; 8],
    skb_ports: [u16; 2],
    eth_protocol: u16,
    bind_inany: u8,
    #[allow(dead_code)]
    equal_check_end: [u8; 0],
    len: u32,
    hash: u32,
}

// struct tcphdr (linux/tcp.h) — packed: it directly overlays ctx->data,
// which the kernel gives no alignment guarantee for. `flags` packs the
// little-endian bitfield res1:4, doff:4, fin:1, syn:1, rst:1, psh:1,
// ack:1, urg:1, ece:1, cwr:1 (doff is bits 4-7, fin is bit 8).
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct TcpHdr {
    source: u16,
    dest: u16,
    #[allow(dead_code)]
    seq: u32,
    #[allow(dead_code)]
    ack_seq: u32,
    flags: u16,
    #[allow(dead_code)]
    window: u16,
    #[allow(dead_code)]
    check: u16,
    #[allow(dead_code)]
    urg_ptr: u16,
}

const _: () = assert!(size_of::<TcpHdr>() == 20);

// struct udphdr (linux/udp.h) — packed, same alignment reasoning as TcpHdr.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct UdpHdr {
    source: u16,
    dest: u16,
    #[allow(dead_code)]
    len: u16,
    #[allow(dead_code)]
    check: u16,
}

const _: () = assert!(size_of::<UdpHdr>() == 8);

/// UAPI struct sk_reuseport_md (linux/bpf.h). data/data_end are
/// __bpf_md_ptr unions (pointer overlaid with u64), represented as u64.
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct sk_reuseport_md {
    pub data: u64,
    pub data_end: u64,
    pub len: u32,
    pub eth_protocol: u32,
    pub ip_protocol: u32,
    pub bind_inany: u32,
    pub hash: u32,
    #[allow(dead_code)]
    pub sk: u64,
    #[allow(dead_code)]
    pub migrating_sk: u64,
}

#[link_section = ".maps"]
#[no_mangle]
static outer_map: BpfMap<u32, u32, { ARRAY_OF_MAPS }, 1> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static result_map: BpfMap<u32, u32, { maps::ARRAY }, { NR_RESULTS }> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static tmp_index_ovr_map: BpfMap<u32, i32, { maps::ARRAY }, 1> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static linum_map: BpfMap<u32, u32, { maps::ARRAY }, 1> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static data_check_map: BpfMap<u32, DataCheck, { maps::ARRAY }, 1> = BpfMap::new();

#[link_section = "sk_reuseport"]
#[no_mangle]
extern "C" fn _select_by_skb_data(reuse_md: *const sk_reuseport_md) -> i32 {
    let mut linum: u32 = 0;
    let index_zero: u32 = 0;
    let mut index: u32 = 0;
    let mut data_check = DataCheck {
        ip_protocol: 0,
        skb_addrs: [0; 8],
        skb_ports: [0; 2],
        eth_protocol: 0,
        bind_inany: 0,
        equal_check_end: [],
        len: 0,
        hash: 0,
    };

    let reuse_void = reuse_md as *const c_void;
    let data = vload!((*reuse_md).data) as usize;
    let data_end = vload!((*reuse_md).data_end) as usize;
    data_check.len = vload!((*reuse_md).len);
    data_check.eth_protocol = vload!((*reuse_md).eth_protocol) as u16;
    data_check.ip_protocol = vload!((*reuse_md).ip_protocol);
    data_check.hash = vload!((*reuse_md).hash);
    data_check.bind_inany = vload!((*reuse_md).bind_inany) as u8;

    let result: u32;

    'done: {
        if data_check.eth_protocol == htons(ETH_P_IP) {
            // offsetof(struct iphdr, saddr) == 12
            if bpf_skb_load_bytes_relative(
                reuse_void,
                12,
                data_check.skb_addrs.as_mut_ptr() as *mut c_void,
                8,
                BPF_HDR_START_NET,
            ) != 0
            {
                result = DROP_MISC;
                linum = line!();
                break 'done;
            }
        } else {
            // offsetof(struct ipv6hdr, saddr) == 8
            if bpf_skb_load_bytes_relative(
                reuse_void,
                8,
                data_check.skb_addrs.as_mut_ptr() as *mut c_void,
                32,
                BPF_HDR_START_NET,
            ) != 0
            {
                result = DROP_MISC;
                linum = line!();
                break 'done;
            }
        }

        let mut cmd_copy = Cmd {
            reuseport_index: 0,
            pass_on_failure: 0,
        };
        let cmd_ptr: *const Cmd;

        if data_check.ip_protocol == IPPROTO_TCP {
            let th = data as *const TcpHdr;
            if (th as usize) + size_of::<TcpHdr>() > data_end {
                result = DROP_MISC;
                linum = line!();
                break 'done;
            }

            let source = unsafe { (*th).source };
            let dest = unsafe { (*th).dest };
            data_check.skb_ports[0] = source;
            data_check.skb_ports[1] = dest;

            let tcp_flags = unsafe { (*th).flags };
            let fin = (tcp_flags >> 8) & 1;
            if fin != 0 {
                // The connection is being torn down at the end of a test.
                // It can't contain a cmd, so return early.
                return SK_PASS;
            }

            let doff = ((tcp_flags >> 4) & 0xF) as u32;
            if (doff << 2) + size_of::<Cmd>() as u32 > data_check.len {
                result = DROP_ERR_SKB_DATA;
                linum = line!();
                break 'done;
            }
            if bpf_skb_load_bytes(
                reuse_void,
                doff << 2,
                &mut cmd_copy as *mut Cmd as *mut c_void,
                size_of::<Cmd>() as u32,
            ) != 0
            {
                result = DROP_MISC;
                linum = line!();
                break 'done;
            }
            cmd_ptr = &cmd_copy;
        } else if data_check.ip_protocol == IPPROTO_UDP {
            let uh = data as *const UdpHdr;
            if (uh as usize) + size_of::<UdpHdr>() > data_end {
                result = DROP_MISC;
                linum = line!();
                break 'done;
            }

            data_check.skb_ports[0] = unsafe { (*uh).source };
            data_check.skb_ports[1] = unsafe { (*uh).dest };

            if (size_of::<UdpHdr>() as u32) + (size_of::<Cmd>() as u32) > data_check.len {
                result = DROP_ERR_SKB_DATA;
                linum = line!();
                break 'done;
            }
            if data + size_of::<UdpHdr>() + size_of::<Cmd>() > data_end {
                if bpf_skb_load_bytes(
                    reuse_void,
                    size_of::<UdpHdr>() as u32,
                    &mut cmd_copy as *mut Cmd as *mut c_void,
                    size_of::<Cmd>() as u32,
                ) != 0
                {
                    result = DROP_MISC;
                    linum = line!();
                    break 'done;
                }
                cmd_ptr = &cmd_copy;
            } else {
                cmd_ptr = (data + size_of::<UdpHdr>()) as *const Cmd;
            }
        } else {
            result = DROP_MISC;
            linum = line!();
            break 'done;
        }

        let reuseport_array = bpf_map_lookup_elem(&outer_map, &index_zero);
        if reuseport_array.is_null() {
            result = DROP_ERR_INNER_MAP;
            linum = line!();
            break 'done;
        }

        index = unsafe { (*cmd_ptr).reuseport_index };
        let index_ovr = bpf_map_lookup_elem(&tmp_index_ovr_map, &index_zero) as *mut i32;
        if index_ovr.is_null() {
            result = DROP_MISC;
            linum = line!();
            break 'done;
        }

        let ovr = unsafe { *index_ovr };
        if ovr != -1 {
            index = ovr as u32;
            unsafe { *index_ovr = -1 };
        }

        let err = bpf_sk_select_reuseport(reuse_md, reuseport_array, &index, 0u64);
        if err == 0 {
            result = RESULT_PASS;
            linum = line!();
            break 'done;
        }

        let pass_on_failure = unsafe { (*cmd_ptr).pass_on_failure };
        if pass_on_failure != 0 {
            result = PASS_ERR_SK_SELECT_REUSEPORT;
            linum = line!();
            break 'done;
        } else {
            result = DROP_ERR_SK_SELECT_REUSEPORT;
            linum = line!();
            break 'done;
        }
    }

    let result_cnt = bpf_map_lookup_elem(&result_map, &result) as *mut u32;
    if result_cnt.is_null() {
        return SK_DROP;
    }

    bpf_map_update_elem(&linum_map, &index_zero, &linum, BPF_ANY);
    bpf_map_update_elem(&data_check_map, &index_zero, &data_check, BPF_ANY);

    unsafe {
        *result_cnt += 1;
    }

    if result < RESULT_PASS {
        SK_DROP
    } else {
        SK_PASS
    }
}

bpf_object!("GPL");
