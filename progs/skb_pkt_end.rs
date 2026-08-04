#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/skb_pkt_end.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::bpf_skb_store_bytes;
use bpf_rs_core::vload;
use core::ffi::c_void;

const IPPROTO_TCP: u8 = 6;
const BPF_F_RECOMPUTE_CSUM: u64 = 1 << 0;

// struct ethhdr (linux/if_ether.h): full layout, only used for its size.
#[repr(C)]
struct EthHdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

// struct iphdr (linux/ip.h): only `protocol` is read; the rest is kept as
// raw fields so the struct's size (and thus `protocol`'s offset, and the
// following tcphdr's offset) matches the real header exactly.
#[repr(C)]
struct IpHdr {
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

// offsetof(struct iphdr, protocol)
const IPHDR_PROTOCOL_OFFSET: u32 = 1 + 1 + 2 + 2 + 2 + 1;

// struct tcphdr (linux/tcp.h): only dest/urg_ptr are read; the rest is kept
// as raw fields for the correct struct size.
#[repr(C)]
struct TcpHdr {
    source: u16,
    dest: u16,
    seq: u32,
    ack_seq: u32,
    flags: u16,
    window: u16,
    check: u16,
    urg_ptr: u16,
}

const ETH_IPV4_TCP_SIZE: usize =
    14 + core::mem::size_of::<IpHdr>() + core::mem::size_of::<TcpHdr>();

// `data`/`data_end` must each be loaded exactly once and the value reused
// for both the bounds check and the pointer arithmetic below: the verifier
// ties a packet pointer's checked range to the specific register produced
// by its load instruction, not to the ctx field it came from. C's
// non-volatile `skb->data` reads get CSE'd by clang into a single load
// here for the same reason; `vload!` would force two independent loads
// and drop the range on the second one.
#[inline(always)]
fn get_iphdr(data: usize, data_end: usize) -> *const IpHdr {
    if data + ETH_IPV4_TCP_SIZE > data_end {
        return core::ptr::null();
    }

    let eth = data as *const EthHdr;
    unsafe { eth.add(1) as *const IpHdr }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn main_prog(skb: *const __sk_buff) -> i32 {
    let data = vload!((*skb).data) as usize;
    let data_end = vload!((*skb).data_end) as usize;

    let ip = get_iphdr(data, data_end);
    if ip.is_null() {
        return -1;
    }

    let mut proto = unsafe { (*ip).protocol };
    if proto != IPPROTO_TCP {
        return -1;
    }

    let tcp = unsafe { ip.add(1) as *const TcpHdr };
    if unsafe { (*tcp).dest } != 0 {
        return -1;
    }

    let urg_ptr = unsafe { (*tcp).urg_ptr } as i32;

    // Checksum validation part
    proto = proto.wrapping_add(1);
    let offset = core::mem::size_of::<EthHdr>() as u32 + IPHDR_PROTOCOL_OFFSET;
    bpf_skb_store_bytes(
        skb as *const c_void,
        offset,
        &proto as *const u8 as *const c_void,
        core::mem::size_of::<u8>() as u32,
        BPF_F_RECOMPUTE_CSUM,
    );

    urg_ptr
}

bpf_object!("GPL");
