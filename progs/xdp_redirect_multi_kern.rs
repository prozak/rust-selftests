#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/xdp_redirect_multi_kern.c,
// bpf-rs-core idiom.
//
// map_all and map_egress use key_size/value_size (not __type) in the C
// source, so their BTF map structs are the bpf_map! escape hatch, same
// __uint(...) pointer-array encoding as xdp_redirect_map.rs /
// test_xdp_with_devmap_helpers.rs. value_size for map_egress =
// sizeof(struct bpf_devmap_val) = 8 (u32 ifindex + union{int fd; __u32 id}).
// mac_map and redirect_flags use __type(key, ...)/__type(value, ...), so
// they take the generic BpfMap<K, V, TYPE, N> form.

use bpf_rs_core::bpf_map;
use bpf_rs_core::helpers::{bpf_map_lookup_elem, bpf_redirect_map};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::{bpf_object, vload};

const XDP_PASS: i32 = 2;
const XDP_DROP: i32 = 1;

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;

const BPF_F_BROADCAST: u64 = 1 << 3;
const BPF_F_EXCLUDE_INGRESS: u64 = 1 << 4;

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

// One map use devmap, another one use devmap_hash for testing.
bpf_map! {
    map_all {
        r#type: *const [i32; 14], // BPF_MAP_TYPE_DEVMAP
        key_size: *const [i32; 4],   // sizeof(int)
        value_size: *const [i32; 4], // sizeof(int)
        max_entries: *const [i32; 1024],
    }
}

bpf_map! {
    map_egress {
        r#type: *const [i32; 25], // BPF_MAP_TYPE_DEVMAP_HASH
        key_size: *const [i32; 4],  // sizeof(int)
        value_size: *const [i32; 8], // sizeof(struct bpf_devmap_val)
        max_entries: *const [i32; 128],
    }
}

// map to store egress interfaces mac addresses
#[link_section = ".maps"]
#[no_mangle]
static mac_map: BpfMap<u32, u64, { maps::HASH }, 128> = BpfMap::new();

// map to store redirect flags for each protocol
#[link_section = ".maps"]
#[no_mangle]
static redirect_flags: BpfMap<u16, u64, { maps::HASH }, 16> = BpfMap::new();

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_redirect_map_multi_prog(ctx: *const xdp_md) -> i32 {
    let data_end = vload!((*ctx).data_end) as usize;
    let data = vload!((*ctx).data) as usize;
    let if_index = vload!((*ctx).ingress_ifindex);

    let nh_off = core::mem::size_of::<ethhdr>();
    if data + nh_off > data_end {
        return XDP_DROP;
    }

    let eth = data as *const ethhdr;
    let h_proto_raw = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*eth).h_proto)) };
    let h_proto = htons(h_proto_raw);

    let flags_from_map = bpf_map_lookup_elem(&redirect_flags, &h_proto) as *const u64;

    let flags: u64;
    // Default flags for IPv4 : (BPF_F_BROADCAST | BPF_F_EXCLUDE_INGRESS)
    if h_proto == ETH_P_IP {
        flags = if !flags_from_map.is_null() {
            unsafe { *flags_from_map }
        } else {
            BPF_F_BROADCAST | BPF_F_EXCLUDE_INGRESS
        };
        return bpf_redirect_map(&map_all, 0, flags) as i32;
    }
    // Default flags for IPv6 : 0
    if h_proto == ETH_P_IPV6 {
        flags = if !flags_from_map.is_null() {
            unsafe { *flags_from_map }
        } else {
            0
        };
        // C: `int if_index` sign-extends into the helper's u64 key param.
        return bpf_redirect_map(&map_all, if_index as i32 as i64 as u64, flags) as i32;
    }
    // Default flags for others BPF_F_BROADCAST : 0
    flags = if !flags_from_map.is_null() {
        unsafe { *flags_from_map }
    } else {
        BPF_F_BROADCAST
    };
    bpf_redirect_map(&map_all, 0, flags) as i32
}

// The following 2 progs are for 2nd devmap prog testing.
#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_redirect_map_all_prog(_ctx: *const xdp_md) -> i32 {
    bpf_redirect_map(&map_egress, 0, BPF_F_BROADCAST | BPF_F_EXCLUDE_INGRESS) as i32
}

#[link_section = "xdp/devmap"]
#[no_mangle]
extern "C" fn xdp_devmap_prog(ctx: *const xdp_md) -> i32 {
    let data_end = vload!((*ctx).data_end) as usize;
    let data = vload!((*ctx).data) as usize;
    let key = vload!((*ctx).egress_ifindex);

    let nh_off = core::mem::size_of::<ethhdr>();
    if data + nh_off > data_end {
        return XDP_DROP;
    }

    let mac = bpf_map_lookup_elem(&mac_map, &key) as *const u8;
    if !mac.is_null() {
        let eth = data as *mut ethhdr;
        let dest = unsafe { core::ptr::addr_of_mut!((*eth).h_source) } as *mut u8;
        // Byte-at-a-time, not copy_nonoverlapping: an unlowered memcpy call
        // gets rewritten by add_ksyms.py into an extern bpf_arena_memcpy
        // kfunc call, which isn't in this kernel's BTF outside arena progs.
        let mut i = 0usize;
        while i < 6 {
            let b = unsafe { core::ptr::read_unaligned(mac.add(i)) };
            unsafe { core::ptr::write_unaligned(dest.add(i), b) };
            i += 1;
        }
    }

    XDP_PASS
}

bpf_object!("GPL");
