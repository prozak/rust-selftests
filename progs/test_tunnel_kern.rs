#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_tunnel_kern.c
// (bpf-rs-core idiom). ERSPAN_V1 is never defined for this object (checked
// against the kernel Makefile), so only the version-2 (BPF_CORE_WRITE_BITFIELD)
// branch of erspan_set_tunnel/ip4ip6erspan_set_tunnel is translated; the
// `#ifdef ERSPAN_V1` branches are dead in the C original too.

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::{__sk_buff, TC_ACT_OK, TC_ACT_SHOT};
use bpf_rs_core::helpers::{
    bpf_csum_diff, bpf_l3_csum_replace, bpf_map_lookup_elem, bpf_skb_change_type,
    bpf_skb_get_tunnel_key, bpf_skb_get_tunnel_opt, bpf_skb_get_xfrm_state,
    bpf_skb_set_tunnel_key, bpf_skb_set_tunnel_opt, bpf_skb_store_bytes,
};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::vload;
use btf_macros::btf;

const XDP_PASS: i32 = 2;

const VXLAN_UDP_PORT: u16 = 4789;
const ETH_P_IP: u16 = 0x0800;
const PACKET_HOST: u32 = 0;
const TUNNEL_CSUM: u16 = 0x0100; // bpf_htons(0x01)
const TUNNEL_KEY: u16 = 0x0400; // bpf_htons(0x04)

/* Only IPv4 address assigned to veth1: 172.16.1.200 */
const ASSIGNED_ADDR_VETH1: u32 = 0xac1001c8;

const BPF_F_TUNINFO_IPV6: u64 = 1 << 0;
const BPF_F_ZERO_CSUM_TX: u64 = 1 << 1;
const BPF_F_SEQ_NUMBER: u64 = 1 << 3;
const BPF_F_NO_TUNNEL_KEY: u64 = 1 << 4;
const BPF_F_TUNINFO_FLAGS: u64 = 1 << 4;
const BPF_F_CURRENT_NETNS: i32 = -1;

const IPPROTO_ICMP: u8 = 1;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ESP: u8 = 50;
const AF_INET: u16 = 2;

const ETH_HLEN: u32 = 14;

const FOU_BPF_ENCAP_FOU: i32 = 0;
const FOU_BPF_ENCAP_GUE: i32 = 1;

// struct bpf_tunnel_key (linux/bpf.h), full 44-byte layout: a stack scratch
// buffer passed by pointer to bpf_skb_{set,get}_tunnel_key(), not
// BTF-matched like a map value or global — only the raw offsets need to
// agree with the kernel's struct.
#[repr(C)]
union RemoteAddr {
    remote_ipv4: u32,
    remote_ipv6: [u32; 4],
}

#[repr(C)]
union TunnelExtOrFlags {
    #[allow(dead_code)]
    tunnel_ext: u16,
    tunnel_flags: u16,
}

#[repr(C)]
union LocalAddr {
    local_ipv4: u32,
    local_ipv6: [u32; 4],
}

#[repr(C)]
struct BpfTunnelKey {
    tunnel_id: u32,
    remote: RemoteAddr,
    tunnel_tos: u8,
    tunnel_ttl: u8,
    ext_flags: TunnelExtOrFlags,
    tunnel_label: u32,
    local: LocalAddr,
}

const _: () = assert!(core::mem::size_of::<BpfTunnelKey>() == 44);

// struct erspan_md2 (linux/erspan.h) LE bitfield layout: byte6 =
// hwid_upper(bits0-1)|ft(bits2-6)|p(bit7); byte7 =
// o(bit0)|gra(bits1-2)|dir(bit3)|hwid(bits4-7). ft/p/o/gra are always 0 in
// this translation (matches the C source, which never sets them).
#[derive(Clone, Copy)]
#[repr(C)]
struct ErspanMd2 {
    #[allow(dead_code)]
    timestamp: u32,
    #[allow(dead_code)]
    sgt: u16,
    byte6: u8,
    byte7: u8,
}

#[repr(C)]
union ErspanUnion {
    #[allow(dead_code)]
    index: u32,
    md2: ErspanMd2,
}

#[repr(C)]
struct ErspanMetadata {
    version: i32,
    u: ErspanUnion,
}

const _: () = assert!(core::mem::size_of::<ErspanMetadata>() == 12);

fn set_erspan_md2(md: &mut ErspanMetadata, direction: u8, hwid: u8) {
    let hwid_lo = hwid & 0xf;
    let hwid_upper = (hwid >> 4) & 0x3;
    unsafe {
        md.u.md2.byte6 = hwid_upper;
        md.u.md2.byte7 = (direction << 3) | (hwid_lo << 4);
    }
}

// struct vxlan_metadata (net/vxlan.h).
#[repr(C)]
struct VxlanMetadata {
    gbp: u32,
}

// struct geneve_opt (net/geneve.h): the LE bitfield byte is
// length(bits0-4)|r3(bit5)|r2(bit6)|r1(bit7); this translation only ever
// needs length=2, r1=r2=r3=0 (matches the C source), so the byte is a
// plain constant.
#[repr(C)]
struct GeneveOpt {
    #[allow(dead_code)]
    opt_class: u16,
    #[allow(dead_code)]
    type_: u8,
    #[allow(dead_code)]
    flags: u8,
}

const GENEVE_OPT_FLAGS: u8 = 2; // length=2, r1=r2=r3=0

#[repr(C)]
struct LocalGeneveOpt {
    gopt: GeneveOpt,
    data: u32,
}

const _: () = assert!(core::mem::size_of::<LocalGeneveOpt>() == 8);

// struct bpf_fou_encap (net/ipv4/fou_bpf.c).
#[repr(C)]
struct BpfFouEncap {
    sport: u16,
    dport: u16,
}

// struct bpf_xfrm_state (linux/bpf.h), full layout matching what
// bpf_skb_get_xfrm_state() writes.
#[repr(C)]
union XfrmRemote {
    remote_ipv4: u32,
    #[allow(dead_code)]
    remote_ipv6: [u32; 4],
}

#[repr(C)]
struct BpfXfrmState {
    reqid: u32,
    spi: u32,
    #[allow(dead_code)]
    family: u16,
    #[allow(dead_code)]
    ext: u16,
    remote: XfrmRemote,
}

// struct bpf_xfrm_state_opts (net/xfrm/xfrm_state_bpf.c).
#[repr(C)]
union XfrmAddr {
    a4: u32,
    #[allow(dead_code)]
    a6: [u32; 4],
}

#[repr(C)]
struct BpfXfrmStateOpts {
    #[allow(dead_code)]
    error: i32,
    netns_id: i32,
    #[allow(dead_code)]
    mark: u32,
    daddr: XfrmAddr,
    spi: u32,
    proto: u8,
    family: u16,
}

const _: () = assert!(core::mem::size_of::<BpfXfrmStateOpts>() == 36);

#[btf]
struct xfrm_replay_state_esn {
    replay_window: u32,
}

#[btf]
struct xfrm_state {
    replay_esn: *mut xfrm_replay_state_esn,
}

#[allow(non_camel_case_types)]
#[repr(C, align(8))]
struct bpf_dynptr {
    opaque: [u64; 2],
}

// struct ethhdr (linux/if_ether.h).
#[repr(C)]
struct EthHdr {
    #[allow(dead_code)]
    dest: [u8; 6],
    #[allow(dead_code)]
    source: [u8; 6],
    h_proto: u16,
}

// struct iphdr (linux/ip.h).
#[repr(C)]
struct IpHdr {
    #[allow(dead_code)]
    ihl_version: u8,
    #[allow(dead_code)]
    tos: u8,
    #[allow(dead_code)]
    tot_len: u16,
    #[allow(dead_code)]
    id: u16,
    #[allow(dead_code)]
    frag_off: u16,
    #[allow(dead_code)]
    ttl: u8,
    protocol: u8,
    #[allow(dead_code)]
    check: u16,
    #[allow(dead_code)]
    saddr: u32,
    daddr: u32,
}

const _: () = assert!(core::mem::size_of::<IpHdr>() == 20);

// struct ipv6hdr (linux/ipv6.h): only `nexthdr` is read.
#[repr(C)]
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
    #[allow(dead_code)]
    saddr: [u32; 4],
    #[allow(dead_code)]
    daddr: [u32; 4],
}

// struct udphdr (linux/udp.h): only `dest` is read.
#[repr(C)]
struct UdpHdr {
    #[allow(dead_code)]
    source: u16,
    dest: u16,
    #[allow(dead_code)]
    len: u16,
    #[allow(dead_code)]
    check: u16,
}

// struct ip_esp_hdr (linux/ip.h): only `spi` is read.
#[repr(C)]
struct IpEspHdr {
    spi: u32,
    #[allow(dead_code)]
    seq_no: u32,
}

/// UAPI struct xdp_md (linux/bpf.h).
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct xdp_md {
    pub data: u32,
    pub data_end: u32,
    #[allow(dead_code)]
    pub data_meta: u32,
    #[allow(dead_code)]
    pub ingress_ifindex: u32,
    #[allow(dead_code)]
    pub rx_queue_index: u32,
    #[allow(dead_code)]
    pub egress_ifindex: u32,
}

extern "C" {
    fn bpf_skb_set_fou_encap(skb_ctx: *mut __sk_buff, encap: *const BpfFouEncap, type_: i32) -> i32;
    fn bpf_skb_get_fou_encap(skb_ctx: *mut __sk_buff, encap: *mut BpfFouEncap) -> i32;
    fn bpf_xdp_get_xfrm_state(
        ctx: *mut xdp_md,
        opts: *mut BpfXfrmStateOpts,
        opts_sz: u32,
    ) -> *mut xfrm_state;
    fn bpf_xdp_xfrm_state_release(x: *mut xfrm_state);
    fn bpf_dynptr_from_xdp(xdp: *mut xdp_md, flags: u64, ptr: *mut bpf_dynptr) -> i32;
    fn bpf_dynptr_slice(
        ptr: *const bpf_dynptr,
        offset: u64,
        buffer: *mut c_void,
        buffer_sz: u64,
    ) -> *mut c_void;
}

#[link_section = ".maps"]
#[no_mangle]
static local_ip_map: BpfMap<u32, u32, { maps::ARRAY }, 1> = BpfMap::new();

#[link_section = "tc"]
#[no_mangle]
extern "C" fn gre_set_tunnel(skb: *const __sk_buff) -> i32 {
    let mut key: BpfTunnelKey = unsafe { core::mem::zeroed() };
    unsafe {
        key.remote.remote_ipv4 = 0xac100164; /* 172.16.1.100 */
        key.tunnel_id = 2;
        key.tunnel_tos = 0;
        key.tunnel_ttl = 64;
    }

    let ret = bpf_skb_set_tunnel_key(
        skb as *const c_void,
        &key as *const BpfTunnelKey,
        core::mem::size_of::<BpfTunnelKey>() as u32,
        BPF_F_ZERO_CSUM_TX | BPF_F_SEQ_NUMBER,
    );
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    TC_ACT_OK
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn gre_set_tunnel_no_key(skb: *const __sk_buff) -> i32 {
    let mut key: BpfTunnelKey = unsafe { core::mem::zeroed() };
    unsafe {
        key.remote.remote_ipv4 = 0xac100164; /* 172.16.1.100 */
        key.tunnel_ttl = 64;
    }

    let ret = bpf_skb_set_tunnel_key(
        skb as *const c_void,
        &key as *const BpfTunnelKey,
        core::mem::size_of::<BpfTunnelKey>() as u32,
        BPF_F_ZERO_CSUM_TX | BPF_F_SEQ_NUMBER | BPF_F_NO_TUNNEL_KEY,
    );
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    TC_ACT_OK
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn gre_get_tunnel(skb: *const __sk_buff) -> i32 {
    let mut key: BpfTunnelKey = unsafe { core::mem::zeroed() };
    let ret = bpf_skb_get_tunnel_key(
        skb as *const c_void,
        &mut key as *mut BpfTunnelKey,
        core::mem::size_of::<BpfTunnelKey>() as u32,
        0,
    );
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    TC_ACT_OK
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn ip6gretap_set_tunnel(skb: *const __sk_buff) -> i32 {
    let mut key: BpfTunnelKey = unsafe { core::mem::zeroed() };
    unsafe {
        key.remote.remote_ipv6[3] = 0x11u32.to_be(); /* ::11 */
        key.tunnel_id = 2;
        key.tunnel_tos = 0;
        key.tunnel_ttl = 64;
        key.tunnel_label = 0xabcde;
    }

    let ret = bpf_skb_set_tunnel_key(
        skb as *const c_void,
        &key as *const BpfTunnelKey,
        core::mem::size_of::<BpfTunnelKey>() as u32,
        BPF_F_TUNINFO_IPV6 | BPF_F_ZERO_CSUM_TX | BPF_F_SEQ_NUMBER,
    );
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    TC_ACT_OK
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn ip6gretap_get_tunnel(skb: *const __sk_buff) -> i32 {
    let mut key: BpfTunnelKey = unsafe { core::mem::zeroed() };
    let ret = bpf_skb_get_tunnel_key(
        skb as *const c_void,
        &mut key as *mut BpfTunnelKey,
        core::mem::size_of::<BpfTunnelKey>() as u32,
        BPF_F_TUNINFO_IPV6,
    );
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    TC_ACT_OK
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn erspan_set_tunnel(skb: *const __sk_buff) -> i32 {
    let mut key: BpfTunnelKey = unsafe { core::mem::zeroed() };
    unsafe {
        key.remote.remote_ipv4 = 0xac100164; /* 172.16.1.100 */
        key.tunnel_id = 2;
        key.tunnel_tos = 0;
        key.tunnel_ttl = 64;
    }

    let ret = bpf_skb_set_tunnel_key(
        skb as *const c_void,
        &key as *const BpfTunnelKey,
        core::mem::size_of::<BpfTunnelKey>() as u32,
        BPF_F_ZERO_CSUM_TX,
    );
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    let mut md: ErspanMetadata = unsafe { core::mem::zeroed() };
    md.version = 2;
    set_erspan_md2(&mut md, 1, 7);

    let ret = bpf_skb_set_tunnel_opt(
        skb as *const c_void,
        &md as *const ErspanMetadata,
        core::mem::size_of::<ErspanMetadata>() as u32,
    );
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    TC_ACT_OK
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn erspan_get_tunnel(skb: *const __sk_buff) -> i32 {
    let mut key: BpfTunnelKey = unsafe { core::mem::zeroed() };
    let ret = bpf_skb_get_tunnel_key(
        skb as *const c_void,
        &mut key as *mut BpfTunnelKey,
        core::mem::size_of::<BpfTunnelKey>() as u32,
        0,
    );
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    let mut md: ErspanMetadata = unsafe { core::mem::zeroed() };
    let ret = bpf_skb_get_tunnel_opt(
        skb as *const c_void,
        &mut md as *mut ErspanMetadata,
        core::mem::size_of::<ErspanMetadata>() as u32,
    );
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    TC_ACT_OK
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn ip4ip6erspan_set_tunnel(skb: *const __sk_buff) -> i32 {
    let mut key: BpfTunnelKey = unsafe { core::mem::zeroed() };
    unsafe {
        key.remote.remote_ipv6[3] = 0x11u32.to_be();
        key.tunnel_id = 2;
        key.tunnel_tos = 0;
        key.tunnel_ttl = 64;
    }

    let ret = bpf_skb_set_tunnel_key(
        skb as *const c_void,
        &key as *const BpfTunnelKey,
        core::mem::size_of::<BpfTunnelKey>() as u32,
        BPF_F_TUNINFO_IPV6,
    );
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    let mut md: ErspanMetadata = unsafe { core::mem::zeroed() };
    md.version = 2;
    set_erspan_md2(&mut md, 0, 17);

    let ret = bpf_skb_set_tunnel_opt(
        skb as *const c_void,
        &md as *const ErspanMetadata,
        core::mem::size_of::<ErspanMetadata>() as u32,
    );
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    TC_ACT_OK
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn ip4ip6erspan_get_tunnel(skb: *const __sk_buff) -> i32 {
    let mut key: BpfTunnelKey = unsafe { core::mem::zeroed() };
    let ret = bpf_skb_get_tunnel_key(
        skb as *const c_void,
        &mut key as *mut BpfTunnelKey,
        core::mem::size_of::<BpfTunnelKey>() as u32,
        BPF_F_TUNINFO_IPV6,
    );
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    let mut md: ErspanMetadata = unsafe { core::mem::zeroed() };
    let ret = bpf_skb_get_tunnel_opt(
        skb as *const c_void,
        &mut md as *mut ErspanMetadata,
        core::mem::size_of::<ErspanMetadata>() as u32,
    );
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    TC_ACT_OK
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn vxlan_set_tunnel_dst(skb: *const __sk_buff) -> i32 {
    let index: u32 = 0;
    let local_ip_ptr = bpf_map_lookup_elem(&local_ip_map, &index) as *const u32;
    if local_ip_ptr.is_null() {
        return TC_ACT_SHOT;
    }
    let local_ip = unsafe { *local_ip_ptr };

    let mut key: BpfTunnelKey = unsafe { core::mem::zeroed() };
    unsafe {
        key.local.local_ipv4 = 0xac100164; /* 172.16.1.100 */
        key.remote.remote_ipv4 = local_ip;
        key.tunnel_id = 2;
        key.tunnel_tos = 0;
        key.tunnel_ttl = 64;
    }

    let ret = bpf_skb_set_tunnel_key(
        skb as *const c_void,
        &key as *const BpfTunnelKey,
        core::mem::size_of::<BpfTunnelKey>() as u32,
        BPF_F_ZERO_CSUM_TX,
    );
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    let md = VxlanMetadata { gbp: 0x800FF };
    let ret = bpf_skb_set_tunnel_opt(
        skb as *const c_void,
        &md as *const VxlanMetadata,
        core::mem::size_of::<VxlanMetadata>() as u32,
    );
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    TC_ACT_OK
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn vxlan_set_tunnel_src(skb: *const __sk_buff) -> i32 {
    let index: u32 = 0;
    let local_ip_ptr = bpf_map_lookup_elem(&local_ip_map, &index) as *const u32;
    if local_ip_ptr.is_null() {
        return TC_ACT_SHOT;
    }
    let local_ip = unsafe { *local_ip_ptr };

    let mut key: BpfTunnelKey = unsafe { core::mem::zeroed() };
    unsafe {
        key.local.local_ipv4 = local_ip;
        key.remote.remote_ipv4 = 0xac100164; /* 172.16.1.100 */
        key.tunnel_id = 2;
        key.tunnel_tos = 0;
        key.tunnel_ttl = 64;
    }

    let ret = bpf_skb_set_tunnel_key(
        skb as *const c_void,
        &key as *const BpfTunnelKey,
        core::mem::size_of::<BpfTunnelKey>() as u32,
        BPF_F_ZERO_CSUM_TX,
    );
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    let md = VxlanMetadata { gbp: 0x800FF };
    let ret = bpf_skb_set_tunnel_opt(
        skb as *const c_void,
        &md as *const VxlanMetadata,
        core::mem::size_of::<VxlanMetadata>() as u32,
    );
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    TC_ACT_OK
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn vxlan_get_tunnel_src(skb: *const __sk_buff) -> i32 {
    let mut key: BpfTunnelKey = unsafe { core::mem::zeroed() };
    let ret = bpf_skb_get_tunnel_key(
        skb as *const c_void,
        &mut key as *mut BpfTunnelKey,
        core::mem::size_of::<BpfTunnelKey>() as u32,
        BPF_F_TUNINFO_FLAGS,
    );
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    let mut md: VxlanMetadata = unsafe { core::mem::zeroed() };
    let ret = bpf_skb_get_tunnel_opt(
        skb as *const c_void,
        &mut md as *mut VxlanMetadata,
        core::mem::size_of::<VxlanMetadata>() as u32,
    );
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    let local_ipv4 = unsafe { key.local.local_ipv4 };
    let tunnel_flags = unsafe { key.ext_flags.tunnel_flags };
    if local_ipv4 != ASSIGNED_ADDR_VETH1
        || md.gbp != 0x800FF
        || (tunnel_flags & TUNNEL_KEY) == 0
        || (tunnel_flags & TUNNEL_CSUM) != 0
    {
        return TC_ACT_SHOT;
    }

    TC_ACT_OK
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn veth_set_outer_dst(skb: *const __sk_buff) -> i32 {
    let data = vload!((*skb).data) as usize as *const u8;
    let data_end = vload!((*skb).data_end) as usize as *const u8;
    let assigned_ip: u32 = ASSIGNED_ADDR_VETH1.to_be();

    if unsafe { data.add(core::mem::size_of::<EthHdr>()) } > data_end {
        return TC_ACT_SHOT;
    }
    let eth = data as *const EthHdr;
    if unsafe { (*eth).h_proto } != ETH_P_IP.to_be() {
        return TC_ACT_OK;
    }

    let iph_addr = unsafe { data.add(core::mem::size_of::<EthHdr>()) };
    if unsafe { iph_addr.add(core::mem::size_of::<IpHdr>()) } > data_end {
        return TC_ACT_SHOT;
    }
    let iph = iph_addr as *const IpHdr;
    if unsafe { (*iph).protocol } != IPPROTO_UDP {
        return TC_ACT_OK;
    }

    let udph_addr = unsafe { iph_addr.add(core::mem::size_of::<IpHdr>()) };
    if unsafe { udph_addr.add(core::mem::size_of::<UdpHdr>()) } > data_end {
        return TC_ACT_SHOT;
    }
    let udph = udph_addr as *const UdpHdr;
    if unsafe { (*udph).dest } != VXLAN_UDP_PORT.to_be() {
        return TC_ACT_OK;
    }

    if unsafe { (*iph).daddr } != assigned_ip {
        let daddr_ptr = unsafe { core::ptr::addr_of!((*iph).daddr) };
        let csum = bpf_csum_diff(
            daddr_ptr as *const c_void,
            4,
            &assigned_ip as *const u32 as *const c_void,
            4,
            0,
        );
        if bpf_skb_store_bytes(
            skb as *const c_void,
            ETH_HLEN + 16, /* offsetof(struct iphdr, daddr) */
            &assigned_ip as *const u32 as *const c_void,
            4,
            0,
        ) < 0
        {
            return TC_ACT_SHOT;
        }
        if bpf_l3_csum_replace(
            skb as *const c_void,
            ETH_HLEN + 10, /* offsetof(struct iphdr, check) */
            0,
            csum as u64,
            0,
        ) < 0
        {
            return TC_ACT_SHOT;
        }
        bpf_skb_change_type(skb as *const c_void, PACKET_HOST);
    }

    TC_ACT_OK
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn ip6vxlan_set_tunnel_dst(skb: *const __sk_buff) -> i32 {
    let index: u32 = 0;
    let local_ip_ptr = bpf_map_lookup_elem(&local_ip_map, &index) as *const u32;
    if local_ip_ptr.is_null() {
        return TC_ACT_SHOT;
    }
    let local_ip = unsafe { *local_ip_ptr };

    let mut key: BpfTunnelKey = unsafe { core::mem::zeroed() };
    unsafe {
        key.local.local_ipv6[3] = 0x11u32.to_be(); /* ::11 */
        key.remote.remote_ipv6[3] = local_ip.to_be();
        key.tunnel_id = 22;
        key.tunnel_tos = 0;
        key.tunnel_ttl = 64;
    }

    let ret = bpf_skb_set_tunnel_key(
        skb as *const c_void,
        &key as *const BpfTunnelKey,
        core::mem::size_of::<BpfTunnelKey>() as u32,
        BPF_F_TUNINFO_IPV6,
    );
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    TC_ACT_OK
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn ip6vxlan_set_tunnel_src(skb: *const __sk_buff) -> i32 {
    let index: u32 = 0;
    let local_ip_ptr = bpf_map_lookup_elem(&local_ip_map, &index) as *const u32;
    if local_ip_ptr.is_null() {
        return TC_ACT_SHOT;
    }
    let local_ip = unsafe { *local_ip_ptr };

    let mut key: BpfTunnelKey = unsafe { core::mem::zeroed() };
    unsafe {
        key.local.local_ipv6[3] = local_ip.to_be();
        key.remote.remote_ipv6[3] = 0x11u32.to_be(); /* ::11 */
        key.tunnel_id = 22;
        key.tunnel_tos = 0;
        key.tunnel_ttl = 64;
    }

    let ret = bpf_skb_set_tunnel_key(
        skb as *const c_void,
        &key as *const BpfTunnelKey,
        core::mem::size_of::<BpfTunnelKey>() as u32,
        BPF_F_TUNINFO_IPV6,
    );
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    TC_ACT_OK
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn ip6vxlan_get_tunnel_src(skb: *const __sk_buff) -> i32 {
    let index: u32 = 0;
    let local_ip_ptr = bpf_map_lookup_elem(&local_ip_map, &index) as *const u32;
    if local_ip_ptr.is_null() {
        return TC_ACT_SHOT;
    }
    let local_ip = unsafe { *local_ip_ptr };

    let mut key: BpfTunnelKey = unsafe { core::mem::zeroed() };
    let ret = bpf_skb_get_tunnel_key(
        skb as *const c_void,
        &mut key as *mut BpfTunnelKey,
        core::mem::size_of::<BpfTunnelKey>() as u32,
        BPF_F_TUNINFO_IPV6 | BPF_F_TUNINFO_FLAGS,
    );
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    let local_ipv6_3 = unsafe { key.local.local_ipv6[3] };
    let tunnel_flags = unsafe { key.ext_flags.tunnel_flags };
    if u32::from_be(local_ipv6_3) != local_ip
        || (tunnel_flags & TUNNEL_KEY) == 0
        || (tunnel_flags & TUNNEL_CSUM) == 0
    {
        return TC_ACT_SHOT;
    }

    TC_ACT_OK
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn geneve_set_tunnel(skb: *const __sk_buff) -> i32 {
    let mut key: BpfTunnelKey = unsafe { core::mem::zeroed() };
    unsafe {
        key.remote.remote_ipv4 = 0xac100164; /* 172.16.1.100 */
        key.tunnel_id = 2;
        key.tunnel_tos = 0;
        key.tunnel_ttl = 64;
    }

    let local_gopt = LocalGeneveOpt {
        gopt: GeneveOpt {
            opt_class: 0x102u16.to_be(), /* Open Virtual Networking (OVN) */
            type_: 0x08,
            flags: GENEVE_OPT_FLAGS,
        },
        data: 0xdeadbeefu32.to_be(),
    };

    let ret = bpf_skb_set_tunnel_key(
        skb as *const c_void,
        &key as *const BpfTunnelKey,
        core::mem::size_of::<BpfTunnelKey>() as u32,
        BPF_F_ZERO_CSUM_TX,
    );
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    let ret = bpf_skb_set_tunnel_opt(
        skb as *const c_void,
        &local_gopt as *const LocalGeneveOpt,
        core::mem::size_of::<LocalGeneveOpt>() as u32,
    );
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    TC_ACT_OK
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn geneve_get_tunnel(skb: *const __sk_buff) -> i32 {
    let mut key: BpfTunnelKey = unsafe { core::mem::zeroed() };
    let ret = bpf_skb_get_tunnel_key(
        skb as *const c_void,
        &mut key as *mut BpfTunnelKey,
        core::mem::size_of::<BpfTunnelKey>() as u32,
        0,
    );
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    let mut gopt: GeneveOpt = unsafe { core::mem::zeroed() };
    let ret = bpf_skb_get_tunnel_opt(
        skb as *const c_void,
        &mut gopt as *mut GeneveOpt,
        core::mem::size_of::<GeneveOpt>() as u32,
    );
    if ret < 0 {
        gopt.opt_class = 0;
    }

    TC_ACT_OK
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn ip6geneve_set_tunnel(skb: *const __sk_buff) -> i32 {
    let mut key: BpfTunnelKey = unsafe { core::mem::zeroed() };
    unsafe {
        key.remote.remote_ipv6[3] = 0x11u32.to_be(); /* ::11 */
        key.tunnel_id = 22;
        key.tunnel_tos = 0;
        key.tunnel_ttl = 64;
    }

    let ret = bpf_skb_set_tunnel_key(
        skb as *const c_void,
        &key as *const BpfTunnelKey,
        core::mem::size_of::<BpfTunnelKey>() as u32,
        BPF_F_TUNINFO_IPV6,
    );
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    let local_gopt = LocalGeneveOpt {
        gopt: GeneveOpt {
            opt_class: 0x102u16.to_be(), /* Open Virtual Networking (OVN) */
            type_: 0x08,
            flags: GENEVE_OPT_FLAGS,
        },
        data: 0xfeedbeefu32.to_be(),
    };

    let ret = bpf_skb_set_tunnel_opt(
        skb as *const c_void,
        &local_gopt as *const LocalGeneveOpt,
        core::mem::size_of::<LocalGeneveOpt>() as u32,
    );
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    TC_ACT_OK
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn ip6geneve_get_tunnel(skb: *const __sk_buff) -> i32 {
    let mut key: BpfTunnelKey = unsafe { core::mem::zeroed() };
    let ret = bpf_skb_get_tunnel_key(
        skb as *const c_void,
        &mut key as *mut BpfTunnelKey,
        core::mem::size_of::<BpfTunnelKey>() as u32,
        BPF_F_TUNINFO_IPV6,
    );
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    let mut gopt: GeneveOpt = unsafe { core::mem::zeroed() };
    let ret = bpf_skb_get_tunnel_opt(
        skb as *const c_void,
        &mut gopt as *mut GeneveOpt,
        core::mem::size_of::<GeneveOpt>() as u32,
    );
    if ret < 0 {
        gopt.opt_class = 0;
    }

    TC_ACT_OK
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn ipip_set_tunnel(skb: *const __sk_buff) -> i32 {
    let mut key: BpfTunnelKey = unsafe { core::mem::zeroed() };

    let data = vload!((*skb).data) as usize as *const u8;
    let data_end = vload!((*skb).data_end) as usize as *const u8;

    if unsafe { data.add(core::mem::size_of::<IpHdr>()) } > data_end {
        return TC_ACT_SHOT;
    }
    let iph = data as *const IpHdr;

    key.tunnel_ttl = 64;
    if unsafe { (*iph).protocol } == IPPROTO_ICMP {
        unsafe { key.remote.remote_ipv4 = 0xac100164 }; /* 172.16.1.100 */
    }

    let ret = bpf_skb_set_tunnel_key(
        skb as *const c_void,
        &key as *const BpfTunnelKey,
        core::mem::size_of::<BpfTunnelKey>() as u32,
        0,
    );
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    TC_ACT_OK
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn ipip_get_tunnel(skb: *const __sk_buff) -> i32 {
    let mut key: BpfTunnelKey = unsafe { core::mem::zeroed() };
    let ret = bpf_skb_get_tunnel_key(
        skb as *const c_void,
        &mut key as *mut BpfTunnelKey,
        core::mem::size_of::<BpfTunnelKey>() as u32,
        0,
    );
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    TC_ACT_OK
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn ipip_gue_set_tunnel(skb: *const __sk_buff) -> i32 {
    let mut key: BpfTunnelKey = unsafe { core::mem::zeroed() };

    let data = vload!((*skb).data) as usize as *const u8;
    let data_end = vload!((*skb).data_end) as usize as *const u8;

    if unsafe { data.add(core::mem::size_of::<IpHdr>()) } > data_end {
        return TC_ACT_SHOT;
    }
    let iph = data as *const IpHdr;

    key.tunnel_ttl = 64;
    if unsafe { (*iph).protocol } == IPPROTO_ICMP {
        unsafe { key.remote.remote_ipv4 = 0xac100164 }; /* 172.16.1.100 */
    }

    let ret = bpf_skb_set_tunnel_key(
        skb as *const c_void,
        &key as *const BpfTunnelKey,
        core::mem::size_of::<BpfTunnelKey>() as u32,
        0,
    );
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    let encap = BpfFouEncap {
        sport: 0,
        dport: 5555u16.to_be(),
    };

    let ret = unsafe {
        bpf_skb_set_fou_encap(
            skb as *mut __sk_buff,
            &encap as *const BpfFouEncap,
            FOU_BPF_ENCAP_GUE,
        )
    };
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    TC_ACT_OK
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn ipip_fou_set_tunnel(skb: *const __sk_buff) -> i32 {
    let mut key: BpfTunnelKey = unsafe { core::mem::zeroed() };

    let data = vload!((*skb).data) as usize as *const u8;
    let data_end = vload!((*skb).data_end) as usize as *const u8;

    if unsafe { data.add(core::mem::size_of::<IpHdr>()) } > data_end {
        return TC_ACT_SHOT;
    }
    let iph = data as *const IpHdr;

    key.tunnel_ttl = 64;
    if unsafe { (*iph).protocol } == IPPROTO_ICMP {
        unsafe { key.remote.remote_ipv4 = 0xac100164 }; /* 172.16.1.100 */
    }

    let ret = bpf_skb_set_tunnel_key(
        skb as *const c_void,
        &key as *const BpfTunnelKey,
        core::mem::size_of::<BpfTunnelKey>() as u32,
        0,
    );
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    let encap = BpfFouEncap {
        sport: 0,
        dport: 5555u16.to_be(),
    };

    let ret = unsafe {
        bpf_skb_set_fou_encap(
            skb as *mut __sk_buff,
            &encap as *const BpfFouEncap,
            FOU_BPF_ENCAP_FOU,
        )
    };
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    TC_ACT_OK
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn ipip_encap_get_tunnel(skb: *const __sk_buff) -> i32 {
    let mut key: BpfTunnelKey = unsafe { core::mem::zeroed() };
    let ret = bpf_skb_get_tunnel_key(
        skb as *const c_void,
        &mut key as *mut BpfTunnelKey,
        core::mem::size_of::<BpfTunnelKey>() as u32,
        0,
    );
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    let mut encap: BpfFouEncap = unsafe { core::mem::zeroed() };
    let ret = unsafe { bpf_skb_get_fou_encap(skb as *mut __sk_buff, &mut encap as *mut BpfFouEncap) };
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    if u16::from_be(encap.dport) != 5555 {
        return TC_ACT_SHOT;
    }

    TC_ACT_OK
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn ipip6_set_tunnel(skb: *const __sk_buff) -> i32 {
    let mut key: BpfTunnelKey = unsafe { core::mem::zeroed() };

    let data = vload!((*skb).data) as usize as *const u8;
    let data_end = vload!((*skb).data_end) as usize as *const u8;

    if unsafe { data.add(core::mem::size_of::<IpHdr>()) } > data_end {
        return TC_ACT_SHOT;
    }
    let iph = data as *const IpHdr;

    key.tunnel_ttl = 64;
    if unsafe { (*iph).protocol } == IPPROTO_ICMP {
        unsafe { key.remote.remote_ipv6[3] = 0x11u32.to_be() }; /* ::11 */
    }

    let ret = bpf_skb_set_tunnel_key(
        skb as *const c_void,
        &key as *const BpfTunnelKey,
        core::mem::size_of::<BpfTunnelKey>() as u32,
        BPF_F_TUNINFO_IPV6,
    );
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    TC_ACT_OK
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn ipip6_get_tunnel(skb: *const __sk_buff) -> i32 {
    let mut key: BpfTunnelKey = unsafe { core::mem::zeroed() };
    let ret = bpf_skb_get_tunnel_key(
        skb as *const c_void,
        &mut key as *mut BpfTunnelKey,
        core::mem::size_of::<BpfTunnelKey>() as u32,
        BPF_F_TUNINFO_IPV6,
    );
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    TC_ACT_OK
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn ip6ip6_set_tunnel(skb: *const __sk_buff) -> i32 {
    let mut key: BpfTunnelKey = unsafe { core::mem::zeroed() };

    let data = vload!((*skb).data) as usize as *const u8;
    let data_end = vload!((*skb).data_end) as usize as *const u8;

    if unsafe { data.add(core::mem::size_of::<Ipv6Hdr>()) } > data_end {
        return TC_ACT_SHOT;
    }
    let iph = data as *const Ipv6Hdr;

    key.tunnel_ttl = 64;
    if unsafe { (*iph).nexthdr } == 58
    /* NEXTHDR_ICMP */
    {
        unsafe { key.remote.remote_ipv6[3] = 0x11u32.to_be() }; /* ::11 */
    }

    let ret = bpf_skb_set_tunnel_key(
        skb as *const c_void,
        &key as *const BpfTunnelKey,
        core::mem::size_of::<BpfTunnelKey>() as u32,
        BPF_F_TUNINFO_IPV6,
    );
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    TC_ACT_OK
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn ip6ip6_get_tunnel(skb: *const __sk_buff) -> i32 {
    let mut key: BpfTunnelKey = unsafe { core::mem::zeroed() };
    let ret = bpf_skb_get_tunnel_key(
        skb as *const c_void,
        &mut key as *mut BpfTunnelKey,
        core::mem::size_of::<BpfTunnelKey>() as u32,
        BPF_F_TUNINFO_IPV6,
    );
    if ret < 0 {
        return TC_ACT_SHOT;
    }

    TC_ACT_OK
}

#[no_mangle]
static mut xfrm_reqid: i32 = 0;
#[no_mangle]
static mut xfrm_spi: i32 = 0;
#[no_mangle]
static mut xfrm_remote_ip: i32 = 0;

#[link_section = "tc"]
#[no_mangle]
extern "C" fn xfrm_get_state(skb: *const __sk_buff) -> i32 {
    let mut x: BpfXfrmState = unsafe { core::mem::zeroed() };
    let ret = bpf_skb_get_xfrm_state(
        skb as *const c_void,
        0,
        &mut x as *mut BpfXfrmState,
        core::mem::size_of::<BpfXfrmState>() as u32,
        0,
    );
    if ret < 0 {
        return TC_ACT_OK;
    }

    unsafe {
        xfrm_reqid = x.reqid as i32;
        xfrm_spi = u32::from_be(x.spi) as i32;
        xfrm_remote_ip = u32::from_be(x.remote.remote_ipv4) as i32;
    }

    TC_ACT_OK
}

#[no_mangle]
static mut xfrm_replay_window: i32 = 0;

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xfrm_get_state_xdp(xdp: *mut xdp_md) -> i32 {
    let mut ptr = bpf_dynptr { opaque: [0u64; 2] };
    let mut iph_buf = [0u8; 20];
    let mut esph_buf = [0u8; 8];
    let mut opts: BpfXfrmStateOpts = unsafe { core::mem::zeroed() };
    let mut x: *mut xfrm_state = core::ptr::null_mut();

    if unsafe { bpf_dynptr_from_xdp(xdp, 0, &mut ptr as *mut bpf_dynptr) } == 0 {
        let off = core::mem::size_of::<EthHdr>() as u64;
        let iph = unsafe {
            bpf_dynptr_slice(
                &ptr as *const bpf_dynptr,
                off,
                iph_buf.as_mut_ptr() as *mut c_void,
                iph_buf.len() as u64,
            )
        } as *const IpHdr;

        if !iph.is_null() && unsafe { (*iph).protocol } == IPPROTO_ESP {
            let off = off + core::mem::size_of::<IpHdr>() as u64;
            let esph = unsafe {
                bpf_dynptr_slice(
                    &ptr as *const bpf_dynptr,
                    off,
                    esph_buf.as_mut_ptr() as *mut c_void,
                    esph_buf.len() as u64,
                )
            } as *const IpEspHdr;

            if !esph.is_null() {
                opts.netns_id = BPF_F_CURRENT_NETNS;
                unsafe {
                    opts.daddr.a4 = (*iph).daddr;
                }
                opts.spi = unsafe { (*esph).spi };
                opts.proto = IPPROTO_ESP;
                opts.family = AF_INET;

                x = unsafe {
                    bpf_xdp_get_xfrm_state(
                        xdp,
                        &mut opts as *mut BpfXfrmStateOpts,
                        core::mem::size_of::<BpfXfrmStateOpts>() as u32,
                    )
                };

                if !x.is_null() {
                    let replay_esn = unsafe { *(&*x).replay_esn().as_ptr() };
                    if !replay_esn.is_null() {
                        let replay_window = unsafe { *(&*replay_esn).replay_window().as_ptr() };
                        unsafe { xfrm_replay_window = replay_window as i32 };
                    }
                }
            }
        }
    }

    if !x.is_null() {
        unsafe { bpf_xdp_xfrm_state_release(x) };
    }

    XDP_PASS
}

bpf_object!("GPL");
