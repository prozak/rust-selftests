#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_sk_assign.c
// (bpf-rs-core idiom).
//
// server_map: the C source's `#if defined(IPROUTE2_HAVE_LIBBPF)` branch is
// NOT taken by this kernel tree's build (confirmed via the clang-built
// object's "maps" section: a 28-byte legacy `struct bpf_elf_map` blob, not
// a BTF ".maps" DATASEC) — the map is loaded by the `tc` userspace tool via
// the old iproute2 elf-map format and pinned under
// /sys/fs/bpf/tc/globals/server_map. Reproduced as a plain #[repr(C)]
// struct in a section literally named "maps" (no dot), byte-identical to
// the clang object.

use core::ffi::c_void;

use bpf_rs_core::ctx::{__sk_buff, TC_ACT_OK, TC_ACT_SHOT};
use bpf_rs_core::helpers::{
    bpf_map_lookup_elem, bpf_sk_assign, bpf_sk_lookup_udp, bpf_sk_release, bpf_skc_lookup_tcp,
};
use bpf_rs_core::{bpf_object, vload};

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const BPF_TCP_LISTEN: u32 = 10;
const BPF_F_CURRENT_NETNS: u64 = -1i64 as u64;

#[inline(always)]
fn htons(x: u16) -> u16 {
    x.to_be()
}

// struct ethhdr (linux/if_ether.h) — packed.
#[repr(C, packed)]
struct EthHdr {
    #[allow(dead_code)]
    h_dest: [u8; 6],
    #[allow(dead_code)]
    h_source: [u8; 6],
    h_proto: u16,
}

// struct iphdr (linux/ip.h) — packed, no options.
#[repr(C, packed)]
struct IpHdr {
    version_ihl: u8,
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
    saddr: u32,
    #[allow(dead_code)]
    daddr: u32,
}

// struct ipv6hdr (linux/ipv6.h) — packed.
#[repr(C, packed)]
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

// struct bpf_sock_tuple's `.ipv4`/`.ipv6` members (UAPI linux/bpf.h),
// overlaid on the packet bytes starting at &iph->saddr / &ip6h->saddr —
// same in-place reinterpret the C source uses (no copy).
#[repr(C, packed)]
struct TupleIpv4 {
    #[allow(dead_code)]
    saddr: u32,
    #[allow(dead_code)]
    daddr: u32,
    #[allow(dead_code)]
    sport: u16,
    dport: u16,
}

#[repr(C, packed)]
struct TupleIpv6 {
    #[allow(dead_code)]
    saddr: [u32; 4],
    #[allow(dead_code)]
    daddr: [u32; 4],
    #[allow(dead_code)]
    sport: u16,
    dport: u16,
}

// Only the fields up to and including `state` are used; the rest exist so
// this matches the real struct bpf_sock byte layout (the verifier checks
// sock-typed field access by offset).
#[repr(C)]
#[allow(dead_code)]
struct BpfSock {
    bound_dev_if: u32,
    family: u32,
    type_: u32,
    protocol: u32,
    mark: u32,
    priority: u32,
    src_ip4: u32,
    src_ip6: [u32; 4],
    src_port: u32,
    dst_port: u16,
    _pad: u16,
    dst_ip4: u32,
    dst_ip6: [u32; 4],
    state: u32,
    rx_queue_mapping: i32,
}

// Legacy iproute2 `struct bpf_elf_map` (7 x u32): type, size_key,
// size_value, max_elem, flags, id, pinning. Section "maps" (not ".maps").
#[repr(C)]
struct BpfElfMap {
    r#type: u32,
    size_key: u32,
    size_value: u32,
    max_elem: u32,
    flags: u32,
    id: u32,
    pinning: u32,
}

unsafe impl Sync for BpfElfMap {}

const BPF_MAP_TYPE_SOCKMAP: u32 = 15;
const PIN_GLOBAL_NS: u32 = 2;

#[link_section = "maps"]
#[no_mangle]
static server_map: BpfElfMap = BpfElfMap {
    r#type: BPF_MAP_TYPE_SOCKMAP,
    size_key: core::mem::size_of::<i32>() as u32,
    size_value: core::mem::size_of::<u64>() as u32,
    max_elem: 1,
    flags: 0,
    id: 0,
    pinning: PIN_GLOBAL_NS,
};

/// Fill 'tuple' with L3 info, and attempt to find L4. On fail, return null.
#[inline(always)]
fn get_tuple(skb: *const __sk_buff, ipv4: &mut bool, tcp: &mut bool) -> *mut u8 {
    let data_end = vload!((*skb).data_end) as usize;
    let data = vload!((*skb).data) as usize;

    let eth = data as *const EthHdr;
    if data + core::mem::size_of::<EthHdr>() > data_end {
        return core::ptr::null_mut();
    }

    let h_proto = unsafe { (*eth).h_proto };

    if h_proto == htons(ETH_P_IP) {
        let iph = (data + core::mem::size_of::<EthHdr>()) as *const IpHdr;
        if iph as usize + core::mem::size_of::<IpHdr>() > data_end {
            return core::ptr::null_mut();
        }
        if (unsafe { (*iph).version_ihl } & 0x0F) != 5 {
            // Options are not supported
            return core::ptr::null_mut();
        }
        let proto = unsafe { (*iph).protocol };
        if proto != IPPROTO_TCP && proto != IPPROTO_UDP {
            return core::ptr::null_mut();
        }
        *ipv4 = true;
        *tcp = proto == IPPROTO_TCP;
        unsafe { core::ptr::addr_of!((*iph).saddr) as *mut u8 }
    } else if h_proto == htons(ETH_P_IPV6) {
        let ip6h = (data + core::mem::size_of::<EthHdr>()) as *const Ipv6Hdr;
        if ip6h as usize + core::mem::size_of::<Ipv6Hdr>() > data_end {
            return core::ptr::null_mut();
        }
        let proto = unsafe { (*ip6h).nexthdr };
        if proto != IPPROTO_TCP && proto != IPPROTO_UDP {
            return core::ptr::null_mut();
        }
        *ipv4 = false;
        *tcp = proto == IPPROTO_TCP;
        unsafe { core::ptr::addr_of!((*ip6h).saddr) as *mut u8 }
    } else {
        data as *mut u8
    }
}

#[inline(always)]
fn tuple_dport(tuple: *const u8, ipv4: bool) -> u16 {
    if ipv4 {
        unsafe { (*(tuple as *const TupleIpv4)).dport }
    } else {
        unsafe { (*(tuple as *const TupleIpv6)).dport }
    }
}

#[inline(always)]
fn tuple_len(ipv4: bool) -> u32 {
    if ipv4 {
        core::mem::size_of::<TupleIpv4>() as u32
    } else {
        core::mem::size_of::<TupleIpv6>() as u32
    }
}

#[inline(always)]
fn handle_udp(skb: *const __sk_buff, tuple: *mut u8, ipv4: bool) -> i32 {
    let len = tuple_len(ipv4);
    let data_end = vload!((*skb).data_end) as usize;
    if tuple as usize + len as usize > data_end {
        return TC_ACT_SHOT;
    }

    let mut sk = bpf_sk_lookup_udp(
        skb as *const c_void,
        tuple as *const c_void,
        len,
        BPF_F_CURRENT_NETNS,
        0,
    );

    if sk.is_null() {
        let dport = tuple_dport(tuple, ipv4);
        if dport != htons(4321) {
            return TC_ACT_OK;
        }

        let zero: i32 = 0;
        sk = bpf_map_lookup_elem(&server_map, &zero);
        if sk.is_null() {
            return TC_ACT_SHOT;
        }
    }

    let ret = bpf_sk_assign(skb as *const c_void, sk, 0) as i32;
    bpf_sk_release(sk);
    ret
}

#[inline(always)]
fn handle_tcp(skb: *const __sk_buff, tuple: *mut u8, ipv4: bool) -> i32 {
    let len = tuple_len(ipv4);
    let data_end = vload!((*skb).data_end) as usize;
    if tuple as usize + len as usize > data_end {
        return TC_ACT_SHOT;
    }

    let mut sk = bpf_skc_lookup_tcp(
        skb as *const c_void,
        tuple as *const c_void,
        len,
        BPF_F_CURRENT_NETNS,
        0,
    );

    let assign = if !sk.is_null() {
        let state = unsafe { (*(sk as *const BpfSock)).state };
        if state != BPF_TCP_LISTEN {
            true
        } else {
            bpf_sk_release(sk);
            sk = core::ptr::null_mut();
            false
        }
    } else {
        false
    };

    if !assign {
        let dport = tuple_dport(tuple, ipv4);
        if dport != htons(4321) {
            return TC_ACT_OK;
        }

        let zero: i32 = 0;
        sk = bpf_map_lookup_elem(&server_map, &zero);
        if sk.is_null() {
            return TC_ACT_SHOT;
        }

        let state = unsafe { (*(sk as *const BpfSock)).state };
        if state != BPF_TCP_LISTEN {
            bpf_sk_release(sk);
            return TC_ACT_SHOT;
        }
    }

    let ret = bpf_sk_assign(skb as *const c_void, sk, 0) as i32;
    bpf_sk_release(sk);
    ret
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn bpf_sk_assign_test(skb: *const __sk_buff) -> i32 {
    let mut ipv4 = false;
    let mut tcp = false;

    let tuple = get_tuple(skb, &mut ipv4, &mut tcp);
    if tuple.is_null() {
        return TC_ACT_SHOT;
    }

    // Note that the verifier socket return type for bpf_skc_lookup_tcp()
    // differs from bpf_sk_lookup_udp(), so even though the C-level type is
    // the same here, if we try to share the implementations they will
    // fail to verify because we're crossing pointer types.
    let ret = if tcp {
        handle_tcp(skb, tuple, ipv4)
    } else {
        handle_udp(skb, tuple, ipv4)
    };

    if ret == 0 {
        TC_ACT_OK
    } else {
        TC_ACT_SHOT
    }
}

bpf_object!("GPL");
