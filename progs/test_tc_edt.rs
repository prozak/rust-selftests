#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_tc_edt.c
// (bpf-rs-core idiom).

use bpf_rs_core::ctx::{__sk_buff, TC_ACT_OK, TC_ACT_SHOT};
use bpf_rs_core::helpers::{
    bpf_ktime_get_ns, bpf_map_lookup_elem, bpf_map_update_elem, bpf_skb_ecn_set_ce,
};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::{bpf_object, vload, vstore};

const ETH_P_IP: u16 = 0x0800;
const IPPROTO_TCP: u8 = 6;

const TIME_HORIZON_NS: u64 = 2000 * 1000 * 1000;
const NS_PER_SEC: u64 = 1000000000;
const ECN_HORIZON_NS: u64 = 5000000;

const BPF_ANY: u64 = 0;
const BPF_EXIST: u64 = 2;

#[inline(always)]
fn htons(x: u16) -> u16 {
    x.to_be()
}

// struct ethhdr (linux/if_ether.h) — packed.
#[repr(C, packed)]
struct ethhdr {
    #[allow(dead_code)]
    h_dest: [u8; 6],
    #[allow(dead_code)]
    h_source: [u8; 6],
    #[allow(dead_code)]
    h_proto: u16,
}

// struct iphdr (linux/ip.h) — packed (follows a 14-byte ethhdr, so never
// 4-byte aligned); the bitfield version/ihl byte is split manually since
// Rust has no bitfields.
#[repr(C, packed)]
struct iphdr {
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
    #[allow(dead_code)]
    saddr: u32,
    #[allow(dead_code)]
    daddr: u32,
}

// struct tcphdr (linux/tcp.h): only `source` is read; the rest is kept as
// raw fields for the correct struct size.
#[repr(C, packed)]
struct tcphdr {
    source: u16,
    #[allow(dead_code)]
    dest: u16,
    #[allow(dead_code)]
    seq: u32,
    #[allow(dead_code)]
    ack_seq: u32,
    #[allow(dead_code)]
    flags: u16,
    #[allow(dead_code)]
    window: u16,
    #[allow(dead_code)]
    check: u16,
    #[allow(dead_code)]
    urg_ptr: u16,
}

/// flow_key => last_tstamp timestamp used
#[link_section = ".maps"]
#[no_mangle]
static flow_map: BpfMap<u32, u64, { maps::HASH }, 1> = BpfMap::new();

#[no_mangle]
static mut target_rate: u64 = 0;

#[inline(always)]
fn throttle_flow(skb: *mut __sk_buff) -> i32 {
    let key: u32 = 0;
    let last_tstamp = bpf_map_lookup_elem(&flow_map, &key) as *const u64;
    let len = vload!((*skb).len) as u64;
    let rate = unsafe { target_rate };
    // BPF's div-by-zero is defined (yields 0), unlike Rust's checked `/`;
    // guard explicitly so rustc doesn't insert a panicking div-by-zero
    // check (a reachable panic the verifier would reject).
    let delay_ns = if rate != 0 { len * NS_PER_SEC / rate } else { 0 };
    let now = bpf_ktime_get_ns();

    let mut next_tstamp: u64 = 0;
    if !last_tstamp.is_null() {
        next_tstamp = unsafe { core::ptr::read_unaligned(last_tstamp) } + delay_ns;
    }

    let mut tstamp = vload!((*skb).tstamp);
    if tstamp < now {
        tstamp = now;
    }

    // should we throttle?
    if next_tstamp <= tstamp {
        if bpf_map_update_elem(&flow_map, &key, &tstamp, BPF_ANY) != 0 {
            return TC_ACT_SHOT;
        }
        return TC_ACT_OK;
    }

    // do not queue past the time horizon
    if next_tstamp - now >= TIME_HORIZON_NS {
        return TC_ACT_SHOT;
    }

    // set ecn bit, if needed
    if next_tstamp - now >= ECN_HORIZON_NS {
        bpf_skb_ecn_set_ce(skb as *mut core::ffi::c_void);
    }

    if bpf_map_update_elem(&flow_map, &key, &next_tstamp, BPF_EXIST) != 0 {
        return TC_ACT_SHOT;
    }
    vstore!((*skb).tstamp, next_tstamp);

    TC_ACT_OK
}

#[inline(always)]
fn handle_tcp(skb: *mut __sk_buff, tcp: *const tcphdr) -> i32 {
    let data_end = vload!((*skb).data_end) as usize;

    // drop malformed packets
    if tcp as usize + core::mem::size_of::<tcphdr>() > data_end {
        return TC_ACT_SHOT;
    }

    let source = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*tcp).source)) };
    if source == htons(9000) {
        return throttle_flow(skb);
    }

    TC_ACT_OK
}

#[inline(always)]
fn handle_ipv4(skb: *mut __sk_buff) -> i32 {
    let data_end = vload!((*skb).data_end) as usize;
    let data = vload!((*skb).data) as usize;

    // drop malformed packets
    if data + core::mem::size_of::<ethhdr>() > data_end {
        return TC_ACT_SHOT;
    }
    let iph = (data + core::mem::size_of::<ethhdr>()) as *const iphdr;
    if iph as usize + core::mem::size_of::<iphdr>() > data_end {
        return TC_ACT_SHOT;
    }
    let ihl = (unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*iph).version_ihl)) }
        & 0x0f) as usize
        * 4;
    if iph as usize + ihl > data_end {
        return TC_ACT_SHOT;
    }

    let protocol = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*iph).protocol)) };
    if protocol == IPPROTO_TCP {
        return handle_tcp(skb, (iph as usize + ihl) as *const tcphdr);
    }

    TC_ACT_OK
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn tc_prog(skb: *mut __sk_buff) -> i32 {
    let protocol = vload!((*skb).protocol);
    if protocol == htons(ETH_P_IP) as u32 {
        return handle_ipv4(skb);
    }

    TC_ACT_OK
}

bpf_object!("GPL");
