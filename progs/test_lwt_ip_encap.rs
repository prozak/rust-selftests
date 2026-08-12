#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_lwt_ip_encap.c
// (bpf-rs-core idiom).
//
// The fexit hook reads the just-pushed packet's IP header directly out of
// `skb->head + skb->network_header` (kernel-selftest packet-parsing idiom).
// `head`/`network_header`/`transport_header` are plain (non-bitfield)
// `sk_buff` fields, read through the `#[btf]` CO-RE path like any other
// trusted-pointer field. The header bytes at that computed address are
// packet content, not a further BTF-typed object, and `iphdr.version`/
// `ihl` are C bitfields (no bitfield CO-RE support here) — read them with
// `bpf_probe_read_kernel`, which accepts an arbitrary computed address
// (ARG_ANYTHING) and is exactly what fault-tolerant BTF field loads do
// under the hood.

use core::ffi::c_void;

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_lwt_push_encap, bpf_probe_read_kernel};
use bpf_rs_core::progs::fentry_arg as arg;
use bpf_rs_core::{bpf_object, vload};
use btf_macros::btf;

const BPF_LWT_ENCAP_IP: u32 = 2;
const BPF_DROP: i32 = 2;
const BPF_LWT_REROUTE: i32 = 128;

#[inline(always)]
fn htons(x: u16) -> u16 {
    x.to_be()
}

#[inline(always)]
fn htonl(x: u32) -> u32 {
    x.to_be()
}

#[repr(C, packed)]
struct grehdr {
    flags: u16,
    protocol: u16,
}

#[repr(C, packed)]
struct iphdr {
    ihl_version: u8, // low nibble = ihl, high nibble = version
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

#[repr(C, packed)]
struct ipv6hdr {
    version_priority: u8, // low nibble = priority, high nibble = version
    flow_lbl: [u8; 3],
    payload_len: u16,
    nexthdr: u8,
    hop_limit: u8,
    saddr: [u8; 16],
    daddr: [u8; 16],
}

#[repr(C, packed)]
struct udphdr {
    source: u16,
    dest: u16,
    len: u16,
    check: u16,
}

#[repr(C, packed)]
struct vxlanhdr {
    vx_flags: u32,
    vx_vni: u32,
}

#[repr(C, packed)]
struct ethhdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

#[repr(C, packed)]
struct EncapHdrGre {
    iph: iphdr,
    greh: grehdr,
}

#[repr(C, packed)]
struct EncapHdrGre6 {
    ip6hdr: ipv6hdr,
    greh: grehdr,
}

#[repr(C, packed)]
struct EncapHdrVxlan {
    iph: iphdr,
    udph: udphdr,
    vxh: vxlanhdr,
    eth: ethhdr,
}

#[repr(C, packed)]
struct EncapHdrVxlan6 {
    ip6hdr: ipv6hdr,
    udph: udphdr,
    vxh: vxlanhdr,
    eth: ethhdr,
}

const VXLAN_PORT: u16 = 4789;
const VXLAN_FLAGS: u32 = 0x08000000;
const VXLAN_VNI: u32 = 1;

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;

const BCAST: [u8; 6] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
const SRCMAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

#[inline(always)]
fn copy_mac(dst: &mut [u8; 6], src: &[u8; 6]) {
    let mut i = 0usize;
    while i < 6 {
        dst[i] = src[i];
        i += 1;
    }
}

#[link_section = "encap_gre"]
#[no_mangle]
extern "C" fn bpf_lwt_encap_gre(skb: *const __sk_buff) -> i32 {
    let mut hdr: EncapHdrGre = unsafe { core::mem::zeroed() };

    hdr.iph.ihl_version = (4u8 << 4) | 5u8;
    hdr.iph.ttl = 0x40;
    hdr.iph.protocol = 47; // IPPROTO_GRE
    hdr.iph.saddr = 0x640110ac; // 172.16.1.100
    hdr.iph.daddr = 0x641010ac; // 172.16.16.100
    hdr.iph.tot_len = htons((vload!((*skb).len) + core::mem::size_of::<EncapHdrGre>() as u32) as u16);

    hdr.greh.protocol = vload!((*skb).protocol) as u16;

    let err = bpf_lwt_push_encap(
        skb as *const c_void,
        BPF_LWT_ENCAP_IP,
        &hdr as *const EncapHdrGre as *const c_void,
        core::mem::size_of::<EncapHdrGre>() as u32,
    );
    if err != 0 {
        return BPF_DROP;
    }

    BPF_LWT_REROUTE
}

#[link_section = "encap_gre6"]
#[no_mangle]
extern "C" fn bpf_lwt_encap_gre6(skb: *const __sk_buff) -> i32 {
    let mut hdr: EncapHdrGre6 = unsafe { core::mem::zeroed() };

    hdr.ip6hdr.version_priority = 6u8 << 4;
    hdr.ip6hdr.payload_len =
        htons((vload!((*skb).len) + core::mem::size_of::<grehdr>() as u32) as u16);
    hdr.ip6hdr.nexthdr = 47; // IPPROTO_GRE
    hdr.ip6hdr.hop_limit = 0x40;
    // fb01::1
    hdr.ip6hdr.saddr[0] = 0xfb;
    hdr.ip6hdr.saddr[1] = 1;
    hdr.ip6hdr.saddr[15] = 1;
    // fb10::1
    hdr.ip6hdr.daddr[0] = 0xfb;
    hdr.ip6hdr.daddr[1] = 0x10;
    hdr.ip6hdr.daddr[15] = 1;

    hdr.greh.protocol = vload!((*skb).protocol) as u16;

    let err = bpf_lwt_push_encap(
        skb as *const c_void,
        BPF_LWT_ENCAP_IP,
        &hdr as *const EncapHdrGre6 as *const c_void,
        core::mem::size_of::<EncapHdrGre6>() as u32,
    );
    if err != 0 {
        return BPF_DROP;
    }

    BPF_LWT_REROUTE
}

#[link_section = "encap_vxlan"]
#[no_mangle]
extern "C" fn bpf_lwt_encap_vxlan(skb: *const __sk_buff) -> i32 {
    let mut hdr: EncapHdrVxlan = unsafe { core::mem::zeroed() };

    hdr.iph.ihl_version = (4u8 << 4) | 5u8;
    hdr.iph.ttl = 0x40;
    hdr.iph.protocol = 17; // IPPROTO_UDP
    hdr.iph.tot_len = htons((vload!((*skb).len) + core::mem::size_of::<EncapHdrVxlan>() as u32) as u16);
    hdr.iph.saddr = 0x640510ac; // 172.16.5.100
    hdr.iph.daddr = 0x641110ac; // 172.16.17.100

    hdr.udph.source = htons(VXLAN_PORT);
    hdr.udph.dest = htons(VXLAN_PORT);
    hdr.udph.len = htons(
        (vload!((*skb).len)
            + core::mem::size_of::<udphdr>() as u32
            + core::mem::size_of::<vxlanhdr>() as u32
            + core::mem::size_of::<ethhdr>() as u32) as u16,
    );

    hdr.vxh.vx_flags = htonl(VXLAN_FLAGS);
    hdr.vxh.vx_vni = htonl(VXLAN_VNI << 8);

    copy_mac(&mut hdr.eth.h_dest, &BCAST);
    copy_mac(&mut hdr.eth.h_source, &SRCMAC);
    hdr.eth.h_proto = htons(ETH_P_IP);

    let err = bpf_lwt_push_encap(
        skb as *const c_void,
        BPF_LWT_ENCAP_IP,
        &hdr as *const EncapHdrVxlan as *const c_void,
        core::mem::size_of::<EncapHdrVxlan>() as u32,
    );
    if err != 0 {
        return BPF_DROP;
    }

    BPF_LWT_REROUTE
}

#[link_section = "encap_vxlan6"]
#[no_mangle]
extern "C" fn bpf_lwt_encap_vxlan6(skb: *const __sk_buff) -> i32 {
    let mut hdr: EncapHdrVxlan6 = unsafe { core::mem::zeroed() };

    hdr.ip6hdr.version_priority = 6u8 << 4;
    hdr.ip6hdr.nexthdr = 17; // IPPROTO_UDP
    hdr.ip6hdr.hop_limit = 0x40;
    hdr.ip6hdr.payload_len = htons(
        (vload!((*skb).len)
            + core::mem::size_of::<udphdr>() as u32
            + core::mem::size_of::<vxlanhdr>() as u32
            + core::mem::size_of::<ethhdr>() as u32) as u16,
    );
    // fb05::1
    hdr.ip6hdr.saddr[0] = 0xfb;
    hdr.ip6hdr.saddr[1] = 0x05;
    hdr.ip6hdr.saddr[15] = 1;
    // fb11::1
    hdr.ip6hdr.daddr[0] = 0xfb;
    hdr.ip6hdr.daddr[1] = 0x11;
    hdr.ip6hdr.daddr[15] = 1;

    hdr.udph.source = htons(VXLAN_PORT);
    hdr.udph.dest = htons(VXLAN_PORT);
    hdr.udph.len = htons(
        (vload!((*skb).len)
            + core::mem::size_of::<udphdr>() as u32
            + core::mem::size_of::<vxlanhdr>() as u32
            + core::mem::size_of::<ethhdr>() as u32) as u16,
    );

    hdr.vxh.vx_flags = htonl(VXLAN_FLAGS);
    hdr.vxh.vx_vni = htonl(VXLAN_VNI << 8);

    copy_mac(&mut hdr.eth.h_dest, &BCAST);
    copy_mac(&mut hdr.eth.h_source, &SRCMAC);
    hdr.eth.h_proto = htons(ETH_P_IPV6);

    let err = bpf_lwt_push_encap(
        skb as *const c_void,
        BPF_LWT_ENCAP_IP,
        &hdr as *const EncapHdrVxlan6 as *const c_void,
        core::mem::size_of::<EncapHdrVxlan6>() as u32,
    );
    if err != 0 {
        return BPF_DROP;
    }

    BPF_LWT_REROUTE
}

// Minimal local BTF view of the kernel's `struct sk_buff`: only the plain
// (non-bitfield) fields this program reads. CO-RE field-byte-offset
// relocation matches these by name against the target kernel's sk_buff
// (which nests them inside anonymous unions/structs) — no need to mirror
// that nesting locally.
#[btf]
struct sk_buff {
    head: *const u8,
    network_header: u16,
    transport_header: u16,
}

#[link_section = ".rodata"]
#[no_mangle]
static tgt_ip_version: i32 = 0;

#[no_mangle]
static mut transport_hdr: u16 = 0;
#[no_mangle]
static mut network_hdr: u16 = 0;
#[no_mangle]
// translint: allow(bool-global) — equivalence prover confirms EQUIV: the C
// object compiles `if (fexit_triggered)` as `jne 0`, matching Rust.
static mut fexit_triggered: bool = false;

#[link_section = "?fexit/bpf_lwt_push_ip_encap"]
#[no_mangle]
extern "C" fn fexit_lwt_push_ip_encap(ctx: *const u64) -> i32 {
    let skb = arg(ctx, 0) as *const sk_buff;
    let retval = arg(ctx, 4) as i32;

    if retval != 0 || unsafe { fexit_triggered } {
        return 0;
    }

    let head = *unsafe { &*skb }.head().get().unwrap();
    let network_header = *unsafe { &*skb }.network_header().get().unwrap();

    let iph_addr = (head as usize).wrapping_add(network_header as usize);

    let mut byte0: u8 = 0;
    bpf_probe_read_kernel(&mut byte0, 1, iph_addr as *const c_void);
    let version = byte0 >> 4;

    let tgt = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(tgt_ip_version)) };
    if version as i32 != tgt {
        return 0;
    }

    let matched = if version == 4 {
        let mut protocol: u8 = 0;
        bpf_probe_read_kernel(&mut protocol, 1, (iph_addr + 9) as *const c_void);
        protocol == 17 // IPPROTO_UDP
    } else if version == 6 {
        let mut nexthdr: u8 = 0;
        bpf_probe_read_kernel(&mut nexthdr, 1, (iph_addr + 6) as *const c_void);
        nexthdr == 17 // IPPROTO_UDP
    } else {
        false
    };

    if matched {
        let transport_header = *unsafe { &*skb }.transport_header().get().unwrap();
        unsafe {
            fexit_triggered = true;
            transport_hdr = transport_header;
            network_hdr = network_header;
        }
    }

    0
}

bpf_object!("GPL");
