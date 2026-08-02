#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_tc_neigh_fib.c
// (bpf-rs-core idiom).

use core::ffi::c_void;

use bpf_rs_core::ctx::{__sk_buff, TC_ACT_OK, TC_ACT_SHOT};
use bpf_rs_core::helpers::{bpf_fib_lookup, bpf_redirect, bpf_redirect_neigh, bpf_skb_store_bytes};
use bpf_rs_core::{bpf_object, vload};

const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;

const ETH_ALEN: usize = 6;

const BPF_FIB_LKUP_RET_SUCCESS: i64 = 0;
const BPF_FIB_LKUP_RET_NOT_FWDED: i64 = 4;
const BPF_FIB_LKUP_RET_NO_NEIGH: i64 = 7;

#[inline(always)]
fn htons(x: u16) -> u16 {
    x.to_be()
}

// struct ethhdr (linux/if_ether.h) — packed.
#[repr(C, packed)]
struct ethhdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

// struct iphdr (linux/ip.h) — packed (follows a 14-byte ethhdr, so never
// 4-byte aligned); only through daddr, no options.
#[repr(C, packed)]
struct iphdr {
    version_ihl: u8,
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

// struct ipv6hdr (linux/ipv6.h) — packed.
#[repr(C, packed)]
struct ipv6hdr {
    version_priority: u8,
    flow_lbl: [u8; 3],
    payload_len: u16,
    nexthdr: u8,
    hop_limit: u8,
    saddr: [u32; 4],
    daddr: [u32; 4],
}

// struct bpf_fib_lookup (linux/bpf.h): 64-byte layout, unions represented
// with matching Rust unions. This is a stack scratch buffer passed by
// pointer to bpf_fib_lookup()/read back after the call — not BTF-matched
// like a map value or global, so only the raw offsets need to agree with
// the kernel's struct.
#[repr(C)]
union TotLenOrMtu {
    tot_len: u16,
    #[allow(dead_code)]
    mtu_result: u16,
}

#[repr(C)]
union TosOrFlowinfo {
    tos: u8,
    flowinfo: u32,
    #[allow(dead_code)]
    rt_metric: u32,
}

#[repr(C)]
union AddrSrc {
    ipv4_src: u32,
    #[allow(dead_code)]
    ipv6_src: [u32; 4],
}

#[repr(C)]
union AddrDst {
    ipv4_dst: u32,
    ipv6_dst: [u32; 4],
}

#[repr(C)]
union VlanOrTbid {
    #[allow(dead_code)]
    h_vlan: [u16; 2],
    tbid: u32,
}

#[repr(C)]
union MarkOrMac {
    mark: u32,
    mac: MacPair,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct MacPair {
    smac: [u8; 6],
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

// struct bpf_redir_neigh (linux/bpf.h): 20-byte layout.
#[repr(C)]
union NhAddr {
    #[allow(dead_code)]
    ipv4_nh: u32,
    ipv6_nh: [u32; 4],
}

#[repr(C)]
struct bpf_redir_neigh {
    nh_family: u32,
    nh_addr: NhAddr,
}

const _: () = assert!(core::mem::size_of::<bpf_redir_neigh>() == 20);

// Word-at-a-time, not an aggregate assignment: a 16-byte in6_addr copy
// lowers to an llvm.memcpy that add_ksyms.py rewrites into an extern
// bpf_arena_memcpy kfunc call, which isn't in this kernel's BTF outside
// arena progs.
#[inline(always)]
unsafe fn copy_in6_addr(dst: *mut [u32; 4], src: *const [u32; 4]) {
    let dst = dst as *mut u32;
    let src = src as *const u32;
    let mut i = 0usize;
    while i < 4 {
        core::ptr::write_unaligned(dst.add(i), core::ptr::read_unaligned(src.add(i)));
        i += 1;
    }
}

#[inline(always)]
fn fill_fib_params_v4(skb: *const __sk_buff, fib_params: &mut bpf_fib_lookup) -> i32 {
    let data_end = vload!((*skb).data_end) as usize;
    let data = vload!((*skb).data) as usize;

    if data + core::mem::size_of::<ethhdr>() > data_end {
        return -1;
    }

    let ip4h = (data + core::mem::size_of::<ethhdr>()) as *const iphdr;
    if ip4h as usize + core::mem::size_of::<iphdr>() > data_end {
        return -1;
    }

    unsafe {
        fib_params.family = AF_INET;
        fib_params.tos_flowinfo.tos = (*ip4h).tos;
        fib_params.l4_protocol = (*ip4h).protocol;
        fib_params.sport = 0;
        fib_params.dport = 0;
        fib_params.tot_len.tot_len = u16::from_be((*ip4h).tot_len);
        fib_params.addr_src.ipv4_src = (*ip4h).saddr;
        fib_params.addr_dst.ipv4_dst = (*ip4h).daddr;
    }

    0
}

#[inline(always)]
fn fill_fib_params_v6(skb: *const __sk_buff, fib_params: &mut bpf_fib_lookup) -> i32 {
    let data_end = vload!((*skb).data_end) as usize;
    let data = vload!((*skb).data) as usize;

    if data + core::mem::size_of::<ethhdr>() > data_end {
        return -1;
    }

    let ip6h = (data + core::mem::size_of::<ethhdr>()) as *const ipv6hdr;
    if ip6h as usize + core::mem::size_of::<ipv6hdr>() > data_end {
        return -1;
    }

    unsafe {
        fib_params.family = AF_INET6;
        fib_params.tos_flowinfo.flowinfo = 0;
        fib_params.l4_protocol = (*ip6h).nexthdr;
        fib_params.sport = 0;
        fib_params.dport = 0;
        fib_params.tot_len.tot_len = u16::from_be((*ip6h).payload_len);
        copy_in6_addr(
            core::ptr::addr_of_mut!(fib_params.addr_src.ipv6_src),
            core::ptr::addr_of!((*ip6h).saddr),
        );
        copy_in6_addr(
            core::ptr::addr_of_mut!(fib_params.addr_dst.ipv6_dst),
            core::ptr::addr_of!((*ip6h).daddr),
        );
    }

    0
}

#[inline(always)]
fn tc_redir(skb: *const __sk_buff) -> i32 {
    let mut fib_params: bpf_fib_lookup = unsafe { core::mem::zeroed() };
    fib_params.ifindex = vload!((*skb).ingress_ifindex);

    let protocol = vload!((*skb).protocol);
    let ret = if protocol == htons(ETH_P_IP) as u32 {
        fill_fib_params_v4(skb, &mut fib_params)
    } else if protocol == htons(ETH_P_IPV6) as u32 {
        fill_fib_params_v6(skb, &mut fib_params)
    } else {
        -1
    };

    if ret != 0 {
        return TC_ACT_OK;
    }

    let fib_ret = bpf_fib_lookup(
        skb as *const c_void,
        &mut fib_params as *mut bpf_fib_lookup,
        core::mem::size_of::<bpf_fib_lookup>() as i32,
        0,
    );

    if fib_ret == BPF_FIB_LKUP_RET_NOT_FWDED || fib_ret < 0 {
        return TC_ACT_OK;
    }

    let zero = [0u8; ETH_ALEN * 2];
    if bpf_skb_store_bytes(
        skb as *const c_void,
        0,
        zero.as_ptr() as *const c_void,
        (ETH_ALEN * 2) as u32,
        0,
    ) < 0
    {
        return TC_ACT_SHOT;
    }

    if fib_ret == BPF_FIB_LKUP_RET_NO_NEIGH {
        let mut nh_params: bpf_redir_neigh = unsafe { core::mem::zeroed() };
        unsafe {
            nh_params.nh_family = fib_params.family as u32;
            copy_in6_addr(
                core::ptr::addr_of_mut!(nh_params.nh_addr.ipv6_nh),
                core::ptr::addr_of!(fib_params.addr_dst.ipv6_dst),
            );
        }

        bpf_redirect_neigh(
            fib_params.ifindex,
            &mut nh_params as *mut bpf_redir_neigh,
            core::mem::size_of::<bpf_redir_neigh>() as i32,
            0,
        ) as i32
    } else if fib_ret == BPF_FIB_LKUP_RET_SUCCESS {
        let data_end = vload!((*skb).data_end) as usize;
        let data = vload!((*skb).data) as usize;

        if data + core::mem::size_of::<ethhdr>() > data_end {
            return TC_ACT_SHOT;
        }

        let eth = data as *mut ethhdr;
        unsafe {
            let mac = fib_params.mark_mac.mac;
            // Byte-at-a-time, not a whole-array write_unaligned: an
            // unlowered memcpy-shaped store gets rewritten by add_ksyms.py
            // into an extern bpf_arena_memcpy kfunc call, which isn't in
            // this kernel's BTF outside arena progs.
            let dest_ptr = core::ptr::addr_of_mut!((*eth).h_dest) as *mut u8;
            let src_ptr = core::ptr::addr_of_mut!((*eth).h_source) as *mut u8;
            let mut i = 0usize;
            while i < ETH_ALEN {
                core::ptr::write_unaligned(dest_ptr.add(i), mac.dmac[i]);
                core::ptr::write_unaligned(src_ptr.add(i), mac.smac[i]);
                i += 1;
            }
        }

        bpf_redirect(fib_params.ifindex, 0) as i32
    } else {
        TC_ACT_SHOT
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn tc_chk(skb: *const __sk_buff) -> i32 {
    let data_end = vload!((*skb).data_end) as usize;
    let data = vload!((*skb).data) as usize;

    if data + core::mem::size_of::<ethhdr>() > data_end {
        return TC_ACT_SHOT;
    }

    let raw = data as *const u32;
    let r0 = unsafe { core::ptr::read_unaligned(raw) };
    let r1 = unsafe { core::ptr::read_unaligned(raw.add(1)) };
    let r2 = unsafe { core::ptr::read_unaligned(raw.add(2)) };

    if r0 == 0 && r1 == 0 && r2 == 0 {
        TC_ACT_SHOT
    } else {
        TC_ACT_OK
    }
}

// these are identical, but kept separate for compatibility with the section
// names expected by test_tc_redirect.sh
#[link_section = "tc"]
#[no_mangle]
extern "C" fn tc_dst(skb: *const __sk_buff) -> i32 {
    tc_redir(skb)
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn tc_src(skb: *const __sk_buff) -> i32 {
    tc_redir(skb)
}

// The C source names its license global `__license` (not the crate macro's
// default `_license`); the internalize keep-list is derived from the C
// object's global symbol names, so without a matching symbol here the
// license section is silently DCE'd away and every GPL-only helper call
// (bpf_fib_lookup, bpf_redirect_neigh) is rejected as non-GPL.
#[link_section = "license"]
#[no_mangle]
static __license: [u8; 4] = bpf_rs_core::__lic_bytes::<4>("GPL");

bpf_object!("GPL");
