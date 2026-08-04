#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_xdp_dynptr.c
// (bpf-rs-core idiom).
//
// Only consumer in the userspace test tree: prog_tests/xdp_attach.c's
// serial_test_xdp_attach() calls test_xdp_attach("./test_xdp_dynptr.bpf.o"),
// which loads the object, attaches/replaces/detaches `_xdp_tx_iptunnel` on
// lo via bpf_xdp_attach()/bpf_xdp_detach(), and never runs a packet through
// it (no bpf_prog_test_run_opts call, no skeleton). The oracle is therefore
// "verifier-loads and is attachable as XDP", not packet-rewrite behavior —
// still, the translation follows the C source's dynptr/pointer arithmetic
// faithfully (including its pre-existing quirks, e.g. handle_ipv6's size
// check reusing the v4 tcphdr/iphdr constants) so the object's map/global
// BTF shape matches the clang-built one.
//
// All the C source's `static __always_inline` helpers become
// `#[inline(always)]` Rust fns so they collapse into the single
// SEC("xdp") `_xdp_tx_iptunnel` function, matching the clang object's
// single-global-FUNC-symbol shape (see the "Extra/missing global symbols"
// rule in TRANSLATING.md).
//
// Packed packet-header structs are only ever touched through raw pointers
// via the `pget!`/`pset!` macros (`read_unaligned`/`write_unaligned` over
// `addr_of!`/`addr_of_mut!`), matching test_cls_redirect.rs's convention.
// The two multi-byte copies (6-byte MAC, 16-byte IPv6 address) go through a
// byte-at-a-time `vcopy` instead, since a read_unaligned/write_unaligned
// *array* copy is memcpy-shaped and LLVM's MemCpyOpt pass can still turn it
// into an `llvm.memcpy` call that add_ksyms.py rewrites into an extern
// `bpf_arena_memcpy` kfunc call (not in this kernel's BTF outside arena
// progs) — see [[copy-nonoverlapping-becomes-arena-memcpy-kfunc]].

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_dynptr_write, bpf_map_lookup_elem, bpf_xdp_adjust_head};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::vload;

const XDP_DROP: i32 = 1;
const XDP_PASS: i32 = 2;
const XDP_TX: i32 = 3;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_IPIP: u8 = 4;
const IPPROTO_IPV6: u8 = 41;

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;

#[inline(always)]
fn htons(x: u16) -> u16 {
    x.to_be()
}

#[inline(always)]
fn ntohs(x: u16) -> u16 {
    u16::from_be(x)
}

// ---- Unaligned packed-field access -----------------------------------

macro_rules! pget {
    ($place:expr) => {
        unsafe { core::ptr::read_unaligned(core::ptr::addr_of!($place)) }
    };
}

macro_rules! pset {
    ($place:expr, $val:expr) => {
        unsafe { core::ptr::write_unaligned(core::ptr::addr_of_mut!($place), $val) }
    };
}

#[inline(always)]
unsafe fn vcopy(dst: *mut u8, src: *const u8, len: usize) {
    let mut i = 0usize;
    while i < len {
        core::ptr::write_volatile(dst.add(i), core::ptr::read_volatile(src.add(i)));
        i += 1;
    }
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

// UAPI struct bpf_dynptr (linux/bpf.h): opaque, two anonymous __u64
// bitfields, aligned(8).
#[repr(C, align(8))]
struct bpf_dynptr {
    __opaque: [u64; 2],
}

extern "C" {
    fn bpf_dynptr_from_xdp(xdp: *mut xdp_md, flags: u64, ptr: *mut bpf_dynptr) -> i32;
    fn bpf_dynptr_slice(
        ptr: *const bpf_dynptr,
        offset: u64,
        buffer: *mut c_void,
        buffer_sz: u64,
    ) -> *mut c_void;
    fn bpf_dynptr_slice_rdwr(
        ptr: *const bpf_dynptr,
        offset: u64,
        buffer: *mut c_void,
        buffer_sz: u64,
    ) -> *mut c_void;
}

// linux/if_ether.h.
#[repr(C, packed)]
struct ethhdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

// linux/ip.h: ihl/version bitfield byte folded into one field (low nibble =
// ihl, high nibble = version on LE, matching test_lwt_ip_encap.rs).
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

// linux/ipv6.h: version/priority bitfield byte folded (high nibble =
// version).
#[repr(C, packed)]
struct ipv6hdr {
    version_priority: u8,
    flow_lbl: [u8; 3],
    payload_len: u16,
    nexthdr: u8,
    hop_limit: u8,
    saddr: [u8; 16],
    daddr: [u8; 16],
}

// linux/tcp.h: only the leading fixed fields up to `dest` matter here; doff
// etc. are never read, folded into one raw u16.
#[repr(C, packed)]
struct tcphdr {
    source: u16,
    dest: u16,
    seq: u32,
    ack_seq: u32,
    doff_flags: u16,
    window: u16,
    check: u16,
    urg_ptr: u16,
}

// linux/udp.h.
#[repr(C, packed)]
struct udphdr {
    source: u16,
    dest: u16,
    len: u16,
    check: u16,
}

const ETHHDR_SZ: usize = core::mem::size_of::<ethhdr>();
const IPHDR_SZ: usize = core::mem::size_of::<iphdr>();
const IPV6HDR_SZ: usize = core::mem::size_of::<ipv6hdr>();
const TCPHDR_SZ: usize = core::mem::size_of::<tcphdr>();
const UDPHDR_SZ: usize = core::mem::size_of::<udphdr>();

// test_iptunnel_common.h: `union { __u32 v6[4]; __u32 v4; }`.
#[repr(C)]
#[derive(Clone, Copy)]
union Addr {
    v6: [u32; 4],
    v4: u32,
}

// test_iptunnel_common.h `struct vip` (map key): the union+u16+u16+u8 tail
// leaves 3 trailing pad bytes to bring the struct up to 4-byte alignment —
// named explicitly and zeroed via core::mem::zeroed() below rather than
// left to per-field init, matching
// [[map-key-struct-padding-zeroed-not-reliable]].
#[repr(C)]
struct vip {
    daddr: Addr,
    dport: u16,
    family: u16,
    protocol: u8,
    _pad: [u8; 3],
}

// test_iptunnel_common.h `struct iptnl_info` (map value).
#[repr(C)]
struct iptnl_info {
    saddr: Addr,
    daddr: Addr,
    family: u16,
    dmac: [u8; 6],
}

#[link_section = ".maps"]
#[no_mangle]
static rxcnt: BpfMap<u32, u64, { maps::PERCPU_ARRAY }, 256> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static vip2tnl: BpfMap<vip, iptnl_info, { maps::HASH }, 256> = BpfMap::new();

#[inline(always)]
fn count_tx(protocol: u32) {
    let rxcnt_count = bpf_map_lookup_elem(&rxcnt, &protocol) as *mut u64;
    if !rxcnt_count.is_null() {
        unsafe {
            *rxcnt_count += 1;
        }
    }
}

#[inline(always)]
fn get_dport(trans_data: *const u8, protocol: u8) -> i32 {
    if protocol == IPPROTO_TCP {
        let th = trans_data as *const tcphdr;
        pget!((*th).dest) as i32
    } else if protocol == IPPROTO_UDP {
        let uh = trans_data as *const udphdr;
        pget!((*uh).dest) as i32
    } else {
        0
    }
}

#[inline(always)]
unsafe fn set_ethhdr(
    new_eth: *mut ethhdr,
    old_eth: *const ethhdr,
    tnl: *const iptnl_info,
    h_proto: u16,
) {
    vcopy(
        core::ptr::addr_of_mut!((*new_eth).h_source) as *mut u8,
        core::ptr::addr_of!((*old_eth).h_dest) as *const u8,
        6,
    );
    vcopy(
        core::ptr::addr_of_mut!((*new_eth).h_dest) as *mut u8,
        core::ptr::addr_of!((*tnl).dmac) as *const u8,
        6,
    );
    pset!((*new_eth).h_proto, h_proto);
}

#[inline(always)]
fn handle_ipv4(xdp: *const xdp_md, xdp_ptr: *mut bpf_dynptr) -> i32 {
    let mut eth_buffer = [0u8; ETHHDR_SZ + IPHDR_SZ + ETHHDR_SZ];
    let mut iph_buffer_tcp = [0u8; IPHDR_SZ + TCPHDR_SZ];
    let mut iph_buffer_udp = [0u8; IPHDR_SZ + UDPHDR_SZ];
    let mut new_xdp_ptr = bpf_dynptr { __opaque: [0, 0] };
    let mut vip: vip = unsafe { core::mem::zeroed() };

    let data_end = vload!((*xdp).data_end);
    let data = vload!((*xdp).data);

    let iph = if (ETHHDR_SZ + IPHDR_SZ + TCPHDR_SZ) as u32 > data_end - data {
        unsafe {
            bpf_dynptr_slice(
                xdp_ptr as *const bpf_dynptr,
                ETHHDR_SZ as u64,
                iph_buffer_udp.as_mut_ptr() as *mut c_void,
                iph_buffer_udp.len() as u64,
            ) as *const iphdr
        }
    } else {
        unsafe {
            bpf_dynptr_slice(
                xdp_ptr as *const bpf_dynptr,
                ETHHDR_SZ as u64,
                iph_buffer_tcp.as_mut_ptr() as *mut c_void,
                iph_buffer_tcp.len() as u64,
            ) as *const iphdr
        }
    };

    if iph.is_null() {
        return XDP_DROP;
    }

    let trans_data = (iph as *const u8).wrapping_add(IPHDR_SZ);
    let protocol = pget!((*iph).protocol);
    let dport = get_dport(trans_data, protocol);
    if dport == -1 {
        return XDP_DROP;
    }

    vip.protocol = protocol;
    vip.family = AF_INET;
    vip.daddr.v4 = pget!((*iph).daddr);
    vip.dport = dport as u16;
    let payload_len = ntohs(pget!((*iph).tot_len));

    let tnl = bpf_map_lookup_elem(&vip2tnl, &vip) as *mut iptnl_info;
    // It only does v4-in-v4.
    if tnl.is_null() || unsafe { (*tnl).family } != AF_INET {
        return XDP_PASS;
    }

    if bpf_xdp_adjust_head(xdp as *mut xdp_md, -(IPHDR_SZ as i32)) != 0 {
        return XDP_DROP;
    }

    unsafe {
        bpf_dynptr_from_xdp(xdp as *mut xdp_md, 0, &mut new_xdp_ptr as *mut bpf_dynptr);
    }
    let new_eth = unsafe {
        bpf_dynptr_slice_rdwr(
            &new_xdp_ptr as *const bpf_dynptr,
            0,
            eth_buffer.as_mut_ptr() as *mut c_void,
            eth_buffer.len() as u64,
        ) as *mut ethhdr
    };
    if new_eth.is_null() {
        return XDP_DROP;
    }

    let iph2 = (new_eth as *mut u8).wrapping_add(ETHHDR_SZ) as *mut iphdr;
    let old_eth = (iph2 as *const u8).wrapping_add(IPHDR_SZ) as *const ethhdr;

    unsafe {
        set_ethhdr(new_eth, old_eth, tnl, htons(ETH_P_IP));
    }

    if (new_eth as *mut u8) == eth_buffer.as_mut_ptr() {
        bpf_dynptr_write(
            &new_xdp_ptr as *const bpf_dynptr,
            0,
            eth_buffer.as_mut_ptr() as *mut c_void,
            eth_buffer.len() as u64,
            0,
        );
    }

    pset!((*iph2).ihl_version, (4u8 << 4) | 5u8);
    pset!((*iph2).frag_off, 0u16);
    pset!((*iph2).protocol, IPPROTO_IPIP);
    pset!((*iph2).check, 0u16);
    pset!((*iph2).tos, 0u8);
    pset!(
        (*iph2).tot_len,
        htons(payload_len.wrapping_add(IPHDR_SZ as u16))
    );
    pset!((*iph2).daddr, (*tnl).daddr.v4);
    pset!((*iph2).saddr, (*tnl).saddr.v4);
    pset!((*iph2).ttl, 8u8);

    let mut csum: u32 = 0;
    let mut next_iph = iph2 as *const u16;
    let mut i = 0usize;
    while i < (IPHDR_SZ >> 1) {
        csum = csum.wrapping_add(unsafe { core::ptr::read_unaligned(next_iph) } as u32);
        next_iph = unsafe { next_iph.add(1) };
        i += 1;
    }
    let s = (csum & 0xffff) + (csum >> 16);
    pset!((*iph2).check, !(s as u16));

    count_tx(vip.protocol as u32);

    XDP_TX
}

#[inline(always)]
fn handle_ipv6(xdp: *const xdp_md, xdp_ptr: *mut bpf_dynptr) -> i32 {
    let mut eth_buffer = [0u8; ETHHDR_SZ + IPV6HDR_SZ + ETHHDR_SZ];
    let mut ip6h_buffer_tcp = [0u8; IPV6HDR_SZ + TCPHDR_SZ];
    let mut ip6h_buffer_udp = [0u8; IPV6HDR_SZ + UDPHDR_SZ];
    let mut new_xdp_ptr = bpf_dynptr { __opaque: [0, 0] };
    let mut vip: vip = unsafe { core::mem::zeroed() };

    let data_end = vload!((*xdp).data_end);
    let data = vload!((*xdp).data);

    // Matches the C source's condition verbatim: it reuses the v4
    // ethhdr_sz + iphdr_sz + tcphdr_sz threshold here too, not the v6
    // sizes — a pre-existing upstream quirk, not something to "fix".
    let ip6h = if (ETHHDR_SZ + IPHDR_SZ + TCPHDR_SZ) as u32 > data_end - data {
        unsafe {
            bpf_dynptr_slice(
                xdp_ptr as *const bpf_dynptr,
                ETHHDR_SZ as u64,
                ip6h_buffer_udp.as_mut_ptr() as *mut c_void,
                ip6h_buffer_udp.len() as u64,
            ) as *const ipv6hdr
        }
    } else {
        unsafe {
            bpf_dynptr_slice(
                xdp_ptr as *const bpf_dynptr,
                ETHHDR_SZ as u64,
                ip6h_buffer_tcp.as_mut_ptr() as *mut c_void,
                ip6h_buffer_tcp.len() as u64,
            ) as *const ipv6hdr
        }
    };

    if ip6h.is_null() {
        return XDP_DROP;
    }

    let trans_data = (ip6h as *const u8).wrapping_add(IPV6HDR_SZ);
    let nexthdr = pget!((*ip6h).nexthdr);
    let dport = get_dport(trans_data, nexthdr);
    if dport == -1 {
        return XDP_DROP;
    }

    vip.protocol = nexthdr;
    vip.family = AF_INET6;
    unsafe {
        vcopy(
            vip.daddr.v6.as_mut_ptr() as *mut u8,
            core::ptr::addr_of!((*ip6h).daddr) as *const u8,
            16,
        );
    }
    vip.dport = dport as u16;
    let payload_len = pget!((*ip6h).payload_len);

    let tnl = bpf_map_lookup_elem(&vip2tnl, &vip) as *mut iptnl_info;
    // It only does v6-in-v6.
    if tnl.is_null() || unsafe { (*tnl).family } != AF_INET6 {
        return XDP_PASS;
    }

    if bpf_xdp_adjust_head(xdp as *mut xdp_md, -(IPV6HDR_SZ as i32)) != 0 {
        return XDP_DROP;
    }

    unsafe {
        bpf_dynptr_from_xdp(xdp as *mut xdp_md, 0, &mut new_xdp_ptr as *mut bpf_dynptr);
    }
    let new_eth = unsafe {
        bpf_dynptr_slice_rdwr(
            &new_xdp_ptr as *const bpf_dynptr,
            0,
            eth_buffer.as_mut_ptr() as *mut c_void,
            eth_buffer.len() as u64,
        ) as *mut ethhdr
    };
    if new_eth.is_null() {
        return XDP_DROP;
    }

    let ip6h2 = (new_eth as *mut u8).wrapping_add(ETHHDR_SZ) as *mut ipv6hdr;
    let old_eth = (ip6h2 as *const u8).wrapping_add(IPV6HDR_SZ) as *const ethhdr;

    unsafe {
        set_ethhdr(new_eth, old_eth, tnl, htons(ETH_P_IPV6));
    }

    if (new_eth as *mut u8) == eth_buffer.as_mut_ptr() {
        bpf_dynptr_write(
            &new_xdp_ptr as *const bpf_dynptr,
            0,
            eth_buffer.as_mut_ptr() as *mut c_void,
            eth_buffer.len() as u64,
            0,
        );
    }

    pset!((*ip6h2).version_priority, 6u8 << 4);
    unsafe {
        let flow_lbl = core::ptr::addr_of_mut!((*ip6h2).flow_lbl) as *mut u8;
        core::ptr::write_volatile(flow_lbl, 0u8);
        core::ptr::write_volatile(flow_lbl.add(1), 0u8);
        core::ptr::write_volatile(flow_lbl.add(2), 0u8);
    }
    pset!(
        (*ip6h2).payload_len,
        htons(ntohs(payload_len).wrapping_add(IPV6HDR_SZ as u16))
    );
    pset!((*ip6h2).nexthdr, IPPROTO_IPV6);
    pset!((*ip6h2).hop_limit, 8u8);
    unsafe {
        vcopy(
            core::ptr::addr_of_mut!((*ip6h2).saddr) as *mut u8,
            (*tnl).saddr.v6.as_ptr() as *const u8,
            16,
        );
        vcopy(
            core::ptr::addr_of_mut!((*ip6h2).daddr) as *mut u8,
            (*tnl).daddr.v6.as_ptr() as *const u8,
            16,
        );
    }

    count_tx(vip.protocol as u32);

    XDP_TX
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn _xdp_tx_iptunnel(xdp: *const xdp_md) -> i32 {
    let mut buffer = [0u8; ETHHDR_SZ];
    let mut ptr = bpf_dynptr { __opaque: [0, 0] };

    unsafe {
        bpf_dynptr_from_xdp(xdp as *mut xdp_md, 0, &mut ptr as *mut bpf_dynptr);
    }

    let eth = unsafe {
        bpf_dynptr_slice(
            &ptr as *const bpf_dynptr,
            0,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len() as u64,
        ) as *const ethhdr
    };
    if eth.is_null() {
        return XDP_DROP;
    }

    let h_proto = pget!((*eth).h_proto);

    if h_proto == htons(ETH_P_IP) {
        handle_ipv4(xdp, &mut ptr as *mut bpf_dynptr)
    } else if h_proto == htons(ETH_P_IPV6) {
        handle_ipv6(xdp, &mut ptr as *mut bpf_dynptr)
    } else {
        XDP_DROP
    }
}

bpf_object!("GPL");
