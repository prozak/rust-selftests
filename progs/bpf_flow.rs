#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_flow.c
// (bpf-rs-core idiom).
//
// PROG(F) in the C source macro-expands to flow_dissector_<N> (N = the
// tail-call slot index: IP=0, IPV6=1, IPV6OP=2, IPV6FR=3, MPLS=4, VLAN=5) —
// verified via the ## non-expansion rule and matched against
// prog_tests/flow_dissector.c's "flow_dissector_%d" lookup.
//
// struct bpf_flow_keys is the pointee of skb->flow_keys (a kernel-owned,
// fixed-size PTR_TO_FLOW_KEYS buffer, not a BTF/CO-RE-tracked kernel
// struct) — plain #[repr(C)] with the exact UAPI field order/sizes is
// enough, no #[btf] needed. The ipv4/ipv6 addr union is a real Rust union
// since we own the whole layout end to end (unlike CO-RE reads of a
// kernel-owned union, which need the #[btf] intermediate-struct trick).
//
// All whole-struct copies (bpf_flow_keys into the map value, the 2*saddr
// ipv6 addr copy) go through a manual word-at-a-time
// read_unaligned/write_unaligned loop: a plain struct-copy/memcpy here gets
// rewritten by add_ksyms.py into a bpf_arena_memcpy kfunc call that doesn't
// exist outside arena programs.

use core::ffi::c_void;

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_map_update_elem, bpf_skb_load_bytes, bpf_tail_call};
use bpf_rs_core::{bpf_map, bpf_object, maps, vload};

const BPF_ANY: u64 = 0;

const BPF_OK: i32 = 0;
const BPF_DROP: i32 = 2;
const BPF_FLOW_DISSECTOR_CONTINUE: i32 = 129;

const BPF_FLOW_DISSECTOR_F_PARSE_1ST_FRAG: u32 = 1 << 0;
const BPF_FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL: u32 = 1 << 1;
const BPF_FLOW_DISSECTOR_F_STOP_AT_ENCAP: u32 = 1 << 2;

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const ETH_P_MPLS_UC: u16 = 0x8847;
const ETH_P_MPLS_MC: u16 = 0x8848;
const ETH_P_8021Q: u16 = 0x8100;
const ETH_P_8021AD: u16 = 0x88A8;
const ETH_P_TEB: u16 = 0x6558;

const IPPROTO_ICMP: u8 = 1;
const IPPROTO_IPIP: u8 = 4;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_IPV6: u8 = 41;
const IPPROTO_GRE: u8 = 47;
const IPPROTO_UDPLITE: u8 = 136;
const IPPROTO_HOPOPTS: u8 = 0;
const IPPROTO_FRAGMENT: u8 = 44;
const IPPROTO_DSTOPTS: u8 = 60;

const IP_MF: u16 = 0x2000;
const IP_OFFSET: u16 = 0x1FFF;
const IP6_OFFSET: u16 = 0xFFF8;

// GRE_* from linux/if_tunnel.h are already __cpu_to_be16() compile-time
// constants (compared directly against the raw wire bytes of gre->flags,
// no additional swap at the compare site); .to_be() reproduces that same
// byte-swapped-constant idiom.
const GRE_CSUM: u16 = 0x8000u16.to_be();
const GRE_KEY: u16 = 0x2000u16.to_be();
const GRE_SEQ: u16 = 0x1000u16.to_be();
const GRE_VERSION: u16 = 0x0007u16.to_be();

const IPV6_FLOWLABEL_MASK: u32 = 0x000FFFFFu32.to_be();

const FLOW_CONTINUE_SADDR: u32 = 0x7f00007f;

const IP: u32 = 0;
const IPV6: u32 = 1;
const IPV6OP: u32 = 2;
const IPV6FR: u32 = 3;
const MPLS: u32 = 4;
const VLAN: u32 = 5;
const MAX_PROG: usize = 6;

#[inline(always)]
fn htons(x: u16) -> u16 {
    x.to_be()
}

#[inline(always)]
fn htonl(x: u32) -> u32 {
    x.to_be()
}

#[inline(always)]
unsafe fn copy_words(dst: *mut u32, src: *const u32, n: usize) {
    let mut i = 0usize;
    while i < n {
        core::ptr::write_unaligned(dst.add(i), core::ptr::read_unaligned(src.add(i)));
        i += 1;
    }
}

// struct vlan_hdr (defined locally in the C source).
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct VlanHdr {
    #[allow(dead_code)]
    h_vlan_tci: u16,
    h_vlan_encapsulated_proto: u16,
}

// struct gre_hdr (defined locally in the C source).
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct GreHdr {
    flags: u16,
    proto: u16,
}

// struct frag_hdr (defined locally in the C source).
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct FragHdr {
    nexthdr: u8,
    #[allow(dead_code)]
    reserved: u8,
    frag_off: u16,
    #[allow(dead_code)]
    identification: u32,
}

// struct ethhdr (linux/if_ether.h).
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct EthHdr {
    #[allow(dead_code)]
    h_dest: [u8; 6],
    #[allow(dead_code)]
    h_source: [u8; 6],
    h_proto: u16,
}

// struct iphdr (linux/ip.h), fixed part only (no options), packed since it
// may sit at an arbitrary offset in the packet buffer.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct IpHdr {
    ihl_version: u8,
    #[allow(dead_code)]
    tos: u8,
    #[allow(dead_code)]
    tot_len: u16,
    #[allow(dead_code)]
    id: u16,
    frag_off: u16,
    #[allow(dead_code)]
    ttl: u8,
    protocol: u8,
    #[allow(dead_code)]
    check: u16,
    saddr: u32,
    daddr: u32,
}

// struct ipv6hdr (linux/ipv6.h).
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Ipv6Hdr {
    #[allow(dead_code)]
    version_priority: u8,
    #[allow(dead_code)]
    flow_lbl: [u8; 3],
    #[allow(dead_code)]
    payload_len: u16,
    nexthdr: u8,
    #[allow(dead_code)]
    hop_limit: u8,
    saddr: [u32; 4],
    #[allow(dead_code)]
    daddr: [u32; 4],
}

// struct ipv6_opt_hdr (linux/ipv6.h), fixed part only.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Ipv6OptHdr {
    nexthdr: u8,
    hdrlen: u8,
}

// struct tcphdr (linux/tcp.h): res1/doff/flags are a 16-bit LE bitfield;
// the first byte (offset 12) carries res1 in its low nibble and doff in
// its high nibble.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct TcpHdr {
    source: u16,
    dest: u16,
    #[allow(dead_code)]
    seq: u32,
    #[allow(dead_code)]
    ack_seq: u32,
    res1_doff: u8,
    #[allow(dead_code)]
    flags: u8,
    #[allow(dead_code)]
    window: u16,
    #[allow(dead_code)]
    check: u16,
    #[allow(dead_code)]
    urg_ptr: u16,
}

// struct udphdr (linux/udp.h).
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

// struct bpf_flow_keys (linux/bpf.h) — pointee of skb->flow_keys, a plain
// UAPI struct (not CO-RE-tracked). Layout: 16 bytes of scalars, a 32-byte
// ipv4/ipv6 addr union, then flags + flow_label. No implicit padding.
#[repr(C)]
#[derive(Clone, Copy)]
struct Addr4 {
    ipv4_src: u32,
    ipv4_dst: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Addr6 {
    ipv6_src: [u32; 4],
    #[allow(dead_code)]
    ipv6_dst: [u32; 4],
}

#[repr(C)]
#[derive(Clone, Copy)]
union AddrUnion {
    v4: Addr4,
    v6: Addr6,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct BpfFlowKeys {
    nhoff: u16,
    thoff: u16,
    addr_proto: u16,
    is_frag: u8,
    is_first_frag: u8,
    is_encap: u8,
    ip_proto: u8,
    n_proto: u16,
    sport: u16,
    dport: u16,
    addr: AddrUnion,
    flags: u32,
    flow_label: u32,
}

const _: () = assert!(core::mem::size_of::<BpfFlowKeys>() == 56);

bpf_map! {
    jmp_table {
        r#type: *const [i32; maps::PROG_ARRAY],
        max_entries: *const [i32; MAX_PROG],
        key_size: *const [i32; 4],
        value_size: *const [i32; 4],
    }
}

#[link_section = ".maps"]
#[no_mangle]
static last_dissection: maps::BpfMap<u32, BpfFlowKeys, { maps::HASH }, 1024> = maps::BpfMap::new();

#[inline(always)]
fn export_flow_keys(keys: *mut BpfFlowKeys, ret: i32) -> i32 {
    let sport = unsafe { (*keys).sport };
    let dport = unsafe { (*keys).dport };
    let key: u32 = ((sport as u32) << 16) | (dport as u32);

    let mut val: BpfFlowKeys = unsafe { core::mem::zeroed() };
    unsafe {
        copy_words(
            &mut val as *mut BpfFlowKeys as *mut u32,
            keys as *const u32,
            core::mem::size_of::<BpfFlowKeys>() / 4,
        );
    }

    bpf_map_update_elem(&last_dissection, &key, &val, BPF_ANY);
    ret
}

#[inline(always)]
fn ip6_flowlabel(hdr: *const Ipv6Hdr) -> u32 {
    let raw = unsafe { core::ptr::read_unaligned(hdr as *const u32) };
    raw & IPV6_FLOWLABEL_MASK
}

#[inline(always)]
fn get_header(skb: *const __sk_buff, hdr_size: u16, buffer: *mut c_void) -> *mut c_void {
    let data_end = vload!((*skb).data_end) as usize;
    let data = vload!((*skb).data) as usize;
    let keys = vload!((*skb).flow_keys) as usize as *mut BpfFlowKeys;
    let thoff = unsafe { (*keys).thoff };

    if thoff > u16::MAX - hdr_size {
        return core::ptr::null_mut();
    }

    let hdr = data + thoff as usize;
    if hdr + hdr_size as usize <= data_end {
        return hdr as *mut c_void;
    }

    if bpf_skb_load_bytes(skb as *const c_void, thoff as u32, buffer, hdr_size as u32) != 0 {
        return core::ptr::null_mut();
    }

    buffer
}

#[inline(always)]
fn parse_eth_proto(skb: *const __sk_buff, proto: u16) -> i32 {
    let keys = vload!((*skb).flow_keys) as usize as *mut BpfFlowKeys;

    if proto == htons(ETH_P_IP) {
        bpf_tail_call(skb as *const c_void, &jmp_table, IP);
    } else if proto == htons(ETH_P_IPV6) {
        bpf_tail_call(skb as *const c_void, &jmp_table, IPV6);
    } else if proto == htons(ETH_P_MPLS_MC) || proto == htons(ETH_P_MPLS_UC) {
        bpf_tail_call(skb as *const c_void, &jmp_table, MPLS);
    } else if proto == htons(ETH_P_8021Q) || proto == htons(ETH_P_8021AD) {
        bpf_tail_call(skb as *const c_void, &jmp_table, VLAN);
    } else {
        return export_flow_keys(keys, BPF_DROP);
    }

    export_flow_keys(keys, BPF_DROP)
}

#[link_section = "flow_dissector"]
#[no_mangle]
extern "C" fn _dissect(skb: *const __sk_buff) -> i32 {
    let keys = vload!((*skb).flow_keys) as usize as *mut BpfFlowKeys;
    let n_proto = unsafe { (*keys).n_proto };

    if n_proto == htons(ETH_P_IP) {
        let mut buf: IpHdr = unsafe { core::mem::zeroed() };
        let iph = get_header(
            skb,
            core::mem::size_of::<IpHdr>() as u16,
            &mut buf as *mut IpHdr as *mut c_void,
        ) as *const IpHdr;

        if !iph.is_null() {
            let ihl = unsafe { (*iph).ihl_version } & 0x0F;
            let saddr = unsafe { (*iph).saddr };
            if ihl == 5 && saddr == htonl(FLOW_CONTINUE_SADDR) {
                return BPF_FLOW_DISSECTOR_CONTINUE;
            }
        }
    }

    parse_eth_proto(skb, n_proto)
}

#[inline(always)]
fn parse_ip_proto(skb: *const __sk_buff, proto: u8) -> i32 {
    let keys = vload!((*skb).flow_keys) as usize as *mut BpfFlowKeys;
    let data_end = vload!((*skb).data_end) as usize;

    match proto {
        IPPROTO_ICMP => {
            let mut buf = [0u8; 8];
            let icmp = get_header(skb, 8, buf.as_mut_ptr() as *mut c_void);
            if icmp.is_null() {
                return export_flow_keys(keys, BPF_DROP);
            }
            export_flow_keys(keys, BPF_OK)
        }
        IPPROTO_IPIP => {
            unsafe { (*keys).is_encap = 1 };
            let flags = unsafe { (*keys).flags };
            if flags & BPF_FLOW_DISSECTOR_F_STOP_AT_ENCAP != 0 {
                return export_flow_keys(keys, BPF_OK);
            }
            parse_eth_proto(skb, htons(ETH_P_IP))
        }
        IPPROTO_IPV6 => {
            unsafe { (*keys).is_encap = 1 };
            let flags = unsafe { (*keys).flags };
            if flags & BPF_FLOW_DISSECTOR_F_STOP_AT_ENCAP != 0 {
                return export_flow_keys(keys, BPF_OK);
            }
            parse_eth_proto(skb, htons(ETH_P_IPV6))
        }
        IPPROTO_GRE => {
            let mut buf: GreHdr = unsafe { core::mem::zeroed() };
            let gre = get_header(
                skb,
                core::mem::size_of::<GreHdr>() as u16,
                &mut buf as *mut GreHdr as *mut c_void,
            ) as *const GreHdr;
            if gre.is_null() {
                return export_flow_keys(keys, BPF_DROP);
            }

            let gre_flags = unsafe { (*gre).flags };
            if gre_flags & GRE_VERSION != 0 {
                return export_flow_keys(keys, BPF_OK);
            }

            unsafe {
                (*keys).thoff += core::mem::size_of::<GreHdr>() as u16;
            }
            if gre_flags & GRE_CSUM != 0 {
                unsafe { (*keys).thoff += 4 };
            }
            if gre_flags & GRE_KEY != 0 {
                unsafe { (*keys).thoff += 4 };
            }
            if gre_flags & GRE_SEQ != 0 {
                unsafe { (*keys).thoff += 4 };
            }

            unsafe { (*keys).is_encap = 1 };
            let flags = unsafe { (*keys).flags };
            if flags & BPF_FLOW_DISSECTOR_F_STOP_AT_ENCAP != 0 {
                return export_flow_keys(keys, BPF_OK);
            }

            let gre_proto = unsafe { (*gre).proto };
            if gre_proto == htons(ETH_P_TEB) {
                let mut ebuf: EthHdr = unsafe { core::mem::zeroed() };
                let eth = get_header(
                    skb,
                    core::mem::size_of::<EthHdr>() as u16,
                    &mut ebuf as *mut EthHdr as *mut c_void,
                ) as *const EthHdr;
                if eth.is_null() {
                    return export_flow_keys(keys, BPF_DROP);
                }

                unsafe {
                    (*keys).thoff += core::mem::size_of::<EthHdr>() as u16;
                }

                let h_proto = unsafe { (*eth).h_proto };
                parse_eth_proto(skb, h_proto)
            } else {
                parse_eth_proto(skb, gre_proto)
            }
        }
        IPPROTO_TCP => {
            let mut buf: TcpHdr = unsafe { core::mem::zeroed() };
            let tcp = get_header(
                skb,
                core::mem::size_of::<TcpHdr>() as u16,
                &mut buf as *mut TcpHdr as *mut c_void,
            ) as *const TcpHdr;
            if tcp.is_null() {
                return export_flow_keys(keys, BPF_DROP);
            }

            let doff = (unsafe { (*tcp).res1_doff } >> 4) & 0x0F;
            if doff < 5 {
                return export_flow_keys(keys, BPF_DROP);
            }

            if (tcp as usize) + ((doff as usize) << 2) > data_end {
                return export_flow_keys(keys, BPF_DROP);
            }

            let source = unsafe { (*tcp).source };
            let dest = unsafe { (*tcp).dest };
            unsafe {
                (*keys).sport = source;
                (*keys).dport = dest;
            }
            export_flow_keys(keys, BPF_OK)
        }
        IPPROTO_UDP | IPPROTO_UDPLITE => {
            let mut buf: UdpHdr = unsafe { core::mem::zeroed() };
            let udp = get_header(
                skb,
                core::mem::size_of::<UdpHdr>() as u16,
                &mut buf as *mut UdpHdr as *mut c_void,
            ) as *const UdpHdr;
            if udp.is_null() {
                return export_flow_keys(keys, BPF_DROP);
            }

            let source = unsafe { (*udp).source };
            let dest = unsafe { (*udp).dest };
            unsafe {
                (*keys).sport = source;
                (*keys).dport = dest;
            }
            export_flow_keys(keys, BPF_OK)
        }
        _ => export_flow_keys(keys, BPF_DROP),
    }
}

#[inline(always)]
fn parse_ipv6_proto(skb: *const __sk_buff, nexthdr: u8) -> i32 {
    let keys = vload!((*skb).flow_keys) as usize as *mut BpfFlowKeys;

    match nexthdr {
        IPPROTO_HOPOPTS | IPPROTO_DSTOPTS => {
            bpf_tail_call(skb as *const c_void, &jmp_table, IPV6OP);
        }
        IPPROTO_FRAGMENT => {
            bpf_tail_call(skb as *const c_void, &jmp_table, IPV6FR);
        }
        _ => {
            return parse_ip_proto(skb, nexthdr);
        }
    }

    export_flow_keys(keys, BPF_DROP)
}

#[link_section = "flow_dissector"]
#[no_mangle]
extern "C" fn flow_dissector_0(skb: *const __sk_buff) -> i32 {
    let data_end = vload!((*skb).data_end) as usize;
    let data = vload!((*skb).data) as usize;
    let keys = vload!((*skb).flow_keys) as usize as *mut BpfFlowKeys;

    let mut buf: IpHdr = unsafe { core::mem::zeroed() };
    let iph = get_header(
        skb,
        core::mem::size_of::<IpHdr>() as u16,
        &mut buf as *mut IpHdr as *mut c_void,
    ) as *const IpHdr;
    if iph.is_null() {
        return export_flow_keys(keys, BPF_DROP);
    }

    let ihl = unsafe { (*iph).ihl_version } & 0x0F;
    if ihl < 5 {
        return export_flow_keys(keys, BPF_DROP);
    }

    let saddr = unsafe { (*iph).saddr };
    let daddr = unsafe { (*iph).daddr };
    let protocol = unsafe { (*iph).protocol };
    unsafe {
        (*keys).addr_proto = ETH_P_IP;
        (*keys).addr.v4.ipv4_src = saddr;
        (*keys).addr.v4.ipv4_dst = daddr;
        (*keys).ip_proto = protocol;
        (*keys).thoff += (ihl as u16) << 2;
    }

    let thoff = unsafe { (*keys).thoff };
    if data + thoff as usize > data_end {
        return export_flow_keys(keys, BPF_DROP);
    }

    let frag_off = unsafe { (*iph).frag_off };
    let mut done = false;
    if frag_off & htons(IP_MF | IP_OFFSET) != 0 {
        unsafe { (*keys).is_frag = 1 };
        if frag_off & htons(IP_OFFSET) != 0 {
            done = true;
        } else {
            unsafe { (*keys).is_first_frag = 1 };
            let flags = unsafe { (*keys).flags };
            if flags & BPF_FLOW_DISSECTOR_F_PARSE_1ST_FRAG == 0 {
                done = true;
            }
        }
    }

    if done {
        return export_flow_keys(keys, BPF_OK);
    }

    parse_ip_proto(skb, protocol)
}

#[link_section = "flow_dissector"]
#[no_mangle]
extern "C" fn flow_dissector_1(skb: *const __sk_buff) -> i32 {
    let keys = vload!((*skb).flow_keys) as usize as *mut BpfFlowKeys;

    let mut buf: Ipv6Hdr = unsafe { core::mem::zeroed() };
    let ip6h = get_header(
        skb,
        core::mem::size_of::<Ipv6Hdr>() as u16,
        &mut buf as *mut Ipv6Hdr as *mut c_void,
    ) as *const Ipv6Hdr;
    if ip6h.is_null() {
        return export_flow_keys(keys, BPF_DROP);
    }

    let nexthdr = unsafe { (*ip6h).nexthdr };
    let flow_label = ip6_flowlabel(ip6h);

    unsafe {
        (*keys).addr_proto = ETH_P_IPV6;
        copy_words(
            core::ptr::addr_of_mut!((*keys).addr.v6.ipv6_src) as *mut u32,
            core::ptr::addr_of!((*ip6h).saddr) as *const u32,
            8,
        );
        (*keys).thoff += core::mem::size_of::<Ipv6Hdr>() as u16;
        (*keys).ip_proto = nexthdr;
        (*keys).flow_label = flow_label;
    }

    let flags = unsafe { (*keys).flags };
    if flow_label != 0 && flags & BPF_FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL != 0 {
        return export_flow_keys(keys, BPF_OK);
    }

    parse_ipv6_proto(skb, nexthdr)
}

#[link_section = "flow_dissector"]
#[no_mangle]
extern "C" fn flow_dissector_2(skb: *const __sk_buff) -> i32 {
    let keys = vload!((*skb).flow_keys) as usize as *mut BpfFlowKeys;

    let mut buf: Ipv6OptHdr = unsafe { core::mem::zeroed() };
    let ip6h = get_header(
        skb,
        core::mem::size_of::<Ipv6OptHdr>() as u16,
        &mut buf as *mut Ipv6OptHdr as *mut c_void,
    ) as *const Ipv6OptHdr;
    if ip6h.is_null() {
        return export_flow_keys(keys, BPF_DROP);
    }

    let hdrlen = unsafe { (*ip6h).hdrlen };
    let nexthdr = unsafe { (*ip6h).nexthdr };
    unsafe {
        (*keys).thoff += (1u16 + hdrlen as u16) << 3;
        (*keys).ip_proto = nexthdr;
    }

    parse_ipv6_proto(skb, nexthdr)
}

#[link_section = "flow_dissector"]
#[no_mangle]
extern "C" fn flow_dissector_3(skb: *const __sk_buff) -> i32 {
    let keys = vload!((*skb).flow_keys) as usize as *mut BpfFlowKeys;

    let mut buf: FragHdr = unsafe { core::mem::zeroed() };
    let fragh = get_header(
        skb,
        core::mem::size_of::<FragHdr>() as u16,
        &mut buf as *mut FragHdr as *mut c_void,
    ) as *const FragHdr;
    if fragh.is_null() {
        return export_flow_keys(keys, BPF_DROP);
    }

    let nexthdr = unsafe { (*fragh).nexthdr };
    let frag_off = unsafe { (*fragh).frag_off };
    unsafe {
        (*keys).thoff += core::mem::size_of::<FragHdr>() as u16;
        (*keys).is_frag = 1;
        (*keys).ip_proto = nexthdr;
    }

    if frag_off & htons(IP6_OFFSET) == 0 {
        unsafe { (*keys).is_first_frag = 1 };
        let flags = unsafe { (*keys).flags };
        if flags & BPF_FLOW_DISSECTOR_F_PARSE_1ST_FRAG == 0 {
            return export_flow_keys(keys, BPF_OK);
        }
    } else {
        return export_flow_keys(keys, BPF_OK);
    }

    parse_ipv6_proto(skb, nexthdr)
}

#[link_section = "flow_dissector"]
#[no_mangle]
extern "C" fn flow_dissector_4(skb: *const __sk_buff) -> i32 {
    let keys = vload!((*skb).flow_keys) as usize as *mut BpfFlowKeys;

    let mut buf = [0u8; 4];
    let mpls = get_header(skb, 4, buf.as_mut_ptr() as *mut c_void);
    if mpls.is_null() {
        return export_flow_keys(keys, BPF_DROP);
    }

    export_flow_keys(keys, BPF_OK)
}

#[link_section = "flow_dissector"]
#[no_mangle]
extern "C" fn flow_dissector_5(skb: *const __sk_buff) -> i32 {
    let keys = vload!((*skb).flow_keys) as usize as *mut BpfFlowKeys;
    let n_proto = unsafe { (*keys).n_proto };

    let mut buf: VlanHdr = unsafe { core::mem::zeroed() };

    if n_proto == htons(ETH_P_8021AD) {
        let vlan = get_header(
            skb,
            core::mem::size_of::<VlanHdr>() as u16,
            &mut buf as *mut VlanHdr as *mut c_void,
        ) as *const VlanHdr;
        if vlan.is_null() {
            return export_flow_keys(keys, BPF_DROP);
        }

        let encap_proto = unsafe { (*vlan).h_vlan_encapsulated_proto };
        if encap_proto != htons(ETH_P_8021Q) {
            return export_flow_keys(keys, BPF_DROP);
        }

        unsafe {
            (*keys).nhoff += core::mem::size_of::<VlanHdr>() as u16;
            (*keys).thoff += core::mem::size_of::<VlanHdr>() as u16;
        }
    }

    let vlan = get_header(
        skb,
        core::mem::size_of::<VlanHdr>() as u16,
        &mut buf as *mut VlanHdr as *mut c_void,
    ) as *const VlanHdr;
    if vlan.is_null() {
        return export_flow_keys(keys, BPF_DROP);
    }

    unsafe {
        (*keys).nhoff += core::mem::size_of::<VlanHdr>() as u16;
        (*keys).thoff += core::mem::size_of::<VlanHdr>() as u16;
    }

    let encap_proto = unsafe { (*vlan).h_vlan_encapsulated_proto };
    if encap_proto == htons(ETH_P_8021AD) || encap_proto == htons(ETH_P_8021Q) {
        return export_flow_keys(keys, BPF_DROP);
    }

    unsafe { (*keys).n_proto = encap_proto };
    parse_eth_proto(skb, encap_proto)
}

// The C source names its license global `__license` (not the crate macro's
// default `_license`); the internalize keep-list is derived from the C
// object's global symbol names, so without a matching symbol here the
// license section is silently DCE'd away and every GPL-only helper call is
// rejected as non-GPL.
#[link_section = "license"]
#[no_mangle]
static __license: [u8; 4] = bpf_rs_core::__lic_bytes::<4>("GPL");

bpf_object!("GPL");
