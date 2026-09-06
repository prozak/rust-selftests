#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/fib_lookup.c
// (bpf-rs-core idiom).

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::{__sk_buff, TC_ACT_SHOT};
use bpf_rs_core::helpers::{bpf_fib_lookup, bpf_redirect};
use bpf_rs_core::vload;

const XDP_DROP: i32 = 1;
const XDP_PASS: i32 = 2;
const BPF_FIB_LKUP_RET_SUCCESS: i64 = 0;
const ETH_P_IP: u16 = 0x0800;
const IPPROTO_TCP: u8 = 6;

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

// struct ethhdr (linux/if_ether.h); h_proto is read unaligned, the XDP
// data pointer carries no alignment guarantee for it.
#[repr(C, packed)]
struct ethhdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

// struct iphdr (linux/ip.h), little-endian bitfield order: ihl:4, version:4.
#[repr(C, packed)]
struct iphdr {
    ihl_version: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    check: u16,
    saddr: u32,
    daddr: u32,
}

// struct bpf_fib_lookup (linux/bpf.h): 64-byte layout, unions represented
// with matching Rust unions. `fib_params` is a real global here (the
// userspace test reads/writes it through skel->bss->fib_params using the
// kernel uapi struct directly), but since the test never goes through a
// bpftool-generated typed field accessor for it (it just casts the mmap'd
// bss region to `struct bpf_fib_lookup *`), only the raw byte layout needs
// to match the uapi struct — field/union type names here are not
// load-bearing. Same layout as progs/test_tc_neigh_fib.rs's local copy.
#[repr(C)]
union TotLenOrMtu {
    tot_len: u16,
    #[allow(dead_code)]
    mtu_result: u16,
}

#[repr(C)]
union TosOrFlowinfo {
    #[allow(dead_code)]
    tos: u8,
    #[allow(dead_code)]
    flowinfo: u32,
    #[allow(dead_code)]
    rt_metric: u32,
}

#[repr(C)]
union AddrSrc {
    #[allow(dead_code)]
    ipv4_src: u32,
    #[allow(dead_code)]
    ipv6_src: [u32; 4],
}

#[repr(C)]
union AddrDst {
    #[allow(dead_code)]
    ipv4_dst: u32,
    #[allow(dead_code)]
    ipv6_dst: [u32; 4],
}

#[repr(C)]
union VlanOrTbid {
    #[allow(dead_code)]
    h_vlan: [u16; 2],
    #[allow(dead_code)]
    tbid: u32,
}

#[repr(C)]
union MarkOrMac {
    #[allow(dead_code)]
    mark: u32,
    #[allow(dead_code)]
    mac: MacPair,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct MacPair {
    #[allow(dead_code)]
    smac: [u8; 6],
    #[allow(dead_code)]
    dmac: [u8; 6],
}

#[repr(C)]
struct bpf_fib_lookup {
    family: u8,
    l4_protocol: u8,
    sport: u16,
    dport: u16,
    tot_len: TotLenOrMtu,
    ifindex: u32,
    tos_flowinfo: TosOrFlowinfo,
    addr_src: AddrSrc,
    addr_dst: AddrDst,
    vlan_tbid: VlanOrTbid,
    mark_mac: MarkOrMac,
}

const _: () = assert!(core::mem::size_of::<bpf_fib_lookup>() == 64);

#[no_mangle]
static mut fib_params: bpf_fib_lookup = bpf_fib_lookup {
    family: 0,
    l4_protocol: 0,
    sport: 0,
    dport: 0,
    tot_len: TotLenOrMtu { tot_len: 0 },
    ifindex: 0,
    tos_flowinfo: TosOrFlowinfo { tos: 0 },
    addr_src: AddrSrc { ipv4_src: 0 },
    addr_dst: AddrDst { ipv4_dst: 0 },
    vlan_tbid: VlanOrTbid { tbid: 0 },
    mark_mac: MarkOrMac { mark: 0 },
};

#[no_mangle]
static mut fib_lookup_ret: i32 = 0;

#[no_mangle]
static mut lookup_flags: i32 = 0;

#[link_section = "tc"]
#[no_mangle]
extern "C" fn fib_lookup(skb: *const __sk_buff) -> i32 {
    let flags = unsafe { lookup_flags } as u32;
    let ret = bpf_fib_lookup(
        skb as *const c_void,
        core::ptr::addr_of_mut!(fib_params),
        core::mem::size_of::<bpf_fib_lookup>() as i32,
        flags,
    );
    unsafe {
        fib_lookup_ret = ret as i32;
    }

    TC_ACT_SHOT
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn fib_lookup_xdp(ctx: *const xdp_md) -> i32 {
    let flags = unsafe { lookup_flags } as u32;
    let ret = bpf_fib_lookup(
        ctx as *const c_void,
        core::ptr::addr_of_mut!(fib_params),
        core::mem::size_of::<bpf_fib_lookup>() as i32,
        flags,
    );
    unsafe {
        fib_lookup_ret = ret as i32;
    }

    XDP_DROP
}

#[no_mangle]
static mut redirected: i32 = 0;
#[no_mangle]
static mut passed: i32 = 0;
#[no_mangle]
static mut delivered: i32 = 0;

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn fib_lookup_redirect(ctx: *const xdp_md) -> i32 {
    // C: `struct bpf_fib_lookup params = fib_params;` -- a by-value copy of
    // the global onto the stack, so the lookup's writes stay local. A plain
    // struct read is memcpy-shaped and add_ksyms.py would turn the
    // llvm.memcpy into a bpf_arena_memcpy kfunc call (see
    // test_xdp_meta.rs), so copy it as 16 volatile u32 words, which is
    // also how clang loads the 4-aligned struct.
    let mut params = core::mem::MaybeUninit::<bpf_fib_lookup>::uninit();
    unsafe {
        let src = core::ptr::addr_of!(fib_params) as *const u32;
        let dst = params.as_mut_ptr() as *mut u32;
        let mut i = 0;
        while i < core::mem::size_of::<bpf_fib_lookup>() / 4 {
            dst.add(i).write(src.add(i).read_volatile());
            i += 1;
        }
    }
    let mut params = unsafe { params.assume_init() };
    let flags = unsafe { lookup_flags } as u32;

    let ret = bpf_fib_lookup(
        ctx as *const c_void,
        &mut params,
        core::mem::size_of::<bpf_fib_lookup>() as i32,
        flags,
    );
    if ret == BPF_FIB_LKUP_RET_SUCCESS {
        unsafe {
            redirected += 1;
        }
        return bpf_redirect(params.ifindex, 0) as i32;
    }

    unsafe {
        passed += 1;
    }
    XDP_PASS
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_count(ctx: *const xdp_md) -> i32 {
    let data = vload!((*ctx).data) as usize;
    let data_end = vload!((*ctx).data_end) as usize;

    // count only the test's TCP frames: the netns has live link-local
    // traffic (DAD, MLD) that would satisfy a bare counter
    if data + core::mem::size_of::<ethhdr>() > data_end {
        return XDP_DROP;
    }
    let eth = data as *const ethhdr;
    let h_proto = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*eth).h_proto)) };
    if h_proto != htons(ETH_P_IP) {
        return XDP_DROP;
    }
    let iph_off = data + core::mem::size_of::<ethhdr>();
    if iph_off + core::mem::size_of::<iphdr>() > data_end {
        return XDP_DROP;
    }
    let iph = iph_off as *const iphdr;
    let protocol = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*iph).protocol)) };
    if protocol != IPPROTO_TCP {
        return XDP_DROP;
    }

    unsafe {
        delivered += 1;
    }
    XDP_DROP
}

bpf_object!("GPL");
