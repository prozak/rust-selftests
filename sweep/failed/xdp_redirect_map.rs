#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/xdp_redirect_map.c
// (bpf-rs-core idiom).
//
// tx_port uses key_size/value_size (not __type) in the C source, so its BTF
// map struct is the bpf_map! escape hatch (type/max_entries/key_size/
// value_size members, same __uint(...) pointer-array encoding throughout).

use bpf_rs_core::bpf_map;
use bpf_rs_core::helpers::{bpf_map_lookup_elem, bpf_map_update_elem, bpf_redirect_map};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::{bpf_object, vload};

const XDP_PASS: i32 = 2;
const XDP_DROP: i32 = 1;

const ETH_P_IP: u16 = 0x0800;

#[inline(always)]
fn htons(x: u16) -> u16 {
    x.to_be()
}

/// UAPI struct xdp_md (linux/bpf.h).
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct xdp_md {
    pub data: u32,
    pub data_end: u32,
    pub data_meta: u32,
    pub ingress_ifindex: u32,
    pub rx_queue_index: u32,
    pub egress_ifindex: u32,
}

// struct ethhdr (linux/if_ether.h). Read only through raw-pointer unaligned
// loads below: the XDP data pointer carries no alignment guarantee for the
// 2-byte h_proto field.
#[repr(C, packed)]
struct ethhdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

bpf_map! {
    tx_port {
        r#type: *const [i32; 14], // BPF_MAP_TYPE_DEVMAP
        max_entries: *const [i32; 8],
        key_size: *const [i32; 4],   // sizeof(int)
        value_size: *const [i32; 4], // sizeof(int)
    }
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_redirect_map_0(_xdp: *const xdp_md) -> i32 {
    bpf_redirect_map(&tx_port, 0, 0) as i32
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_redirect_map_1(_xdp: *const xdp_md) -> i32 {
    bpf_redirect_map(&tx_port, 1, 0) as i32
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_redirect_map_2(_xdp: *const xdp_md) -> i32 {
    bpf_redirect_map(&tx_port, 2, 0) as i32
}

#[link_section = ".maps"]
#[no_mangle]
static rxcnt: BpfMap<u32, u64, { maps::ARRAY }, 3> = BpfMap::new();

#[inline(always)]
fn xdp_count(xdp: *const xdp_md, key: u32) -> i32 {
    let data_end = vload!((*xdp).data_end) as usize;
    let data = vload!((*xdp).data) as usize;

    if data + core::mem::size_of::<ethhdr>() > data_end {
        return XDP_DROP;
    }

    let eth = data as *const ethhdr;
    let h_proto = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*eth).h_proto)) };

    if htons(h_proto) == ETH_P_IP {
        // We only count IPv4 packets
        let count = bpf_map_lookup_elem(&rxcnt, &key) as *mut u64;
        if !count.is_null() {
            unsafe { *count += 1 };
        }
    }

    XDP_PASS
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_count_0(xdp: *const xdp_md) -> i32 {
    xdp_count(xdp, 0)
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_count_1(xdp: *const xdp_md) -> i32 {
    xdp_count(xdp, 1)
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_count_2(xdp: *const xdp_md) -> i32 {
    xdp_count(xdp, 2)
}

#[link_section = ".maps"]
#[no_mangle]
static rx_mac: BpfMap<u32, u64, { maps::ARRAY }, 2> = BpfMap::new();

#[inline(always)]
fn store_mac(xdp: *const xdp_md, id: u32) -> i32 {
    let data_end = vload!((*xdp).data_end) as usize;
    let data = vload!((*xdp).data) as usize;
    let key: u32 = id;
    let mut mac: u64 = 0;

    if data + core::mem::size_of::<ethhdr>() > data_end {
        return XDP_DROP;
    }

    let eth = data as *const ethhdr;
    let h_proto = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*eth).h_proto)) };

    // Only store IPv4 MAC to avoid being polluted by IPv6 packets
    if h_proto == htons(ETH_P_IP) {
        let h_source = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*eth).h_source)) };
        // Byte-at-a-time, not copy_nonoverlapping: an unlowered memcpy call
        // gets rewritten by add_ksyms.py into an extern bpf_arena_memcpy
        // kfunc call, which isn't in this kernel's BTF outside arena progs.
        let mut i = 0usize;
        while i < 6 {
            mac |= (h_source[i] as u64) << (i * 8);
            i += 1;
        }
        bpf_map_update_elem(&rx_mac, &key, &mac, 0);
    }

    XDP_PASS
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn store_mac_1(xdp: *const xdp_md) -> i32 {
    store_mac(xdp, 0)
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn store_mac_2(xdp: *const xdp_md) -> i32 {
    store_mac(xdp, 1)
}

bpf_object!("GPL");
