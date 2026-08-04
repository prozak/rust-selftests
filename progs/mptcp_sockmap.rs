#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/mptcp_sockmap.c, bpf-rs-core idiom.

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_sk_redirect_map, bpf_sock_map_update};
use bpf_rs_core::maps::BpfMap;
use bpf_rs_core::vload;

const BPF_MAP_TYPE_SOCKMAP: usize = 15;
const BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: u32 = 5;
const BPF_NOEXIST: u64 = 1;

#[no_mangle]
static mut sk_index: i32 = 0;
#[no_mangle]
static mut redirect_idx: i32 = 0;
#[no_mangle]
static mut trace_port: i32 = 0;
#[no_mangle]
static mut helper_ret: i32 = 0;

#[link_section = ".maps"]
#[no_mangle]
static sock_map: BpfMap<u32, u32, BPF_MAP_TYPE_SOCKMAP, 100> = BpfMap::new();

// UAPI struct bpf_sock_ops, fields through `sk` (bpf.h). `sk` is a
// __bpf_md_ptr union (pointer overlaid with u64 padding), represented as u64
// like __sk_buff.sk. Fields after `sk` are unused by this program and
// omitted; layout/offsets up to `sk` must match the kernel struct exactly
// since the verifier rewrites this field access by byte offset.
#[allow(non_camel_case_types, dead_code)]
#[repr(C)]
struct bpf_sock_ops {
    op: u32,
    reply_union: [u32; 4],
    family: u32,
    remote_ip4: u32,
    local_ip4: u32,
    remote_ip6: [u32; 4],
    local_ip6: [u32; 4],
    remote_port: u32,
    local_port: u32,
    is_fullsock: u32,
    snd_cwnd: u32,
    srtt_us: u32,
    bpf_sock_ops_cb_flags: u32,
    state: u32,
    rtt_min: u32,
    snd_ssthresh: u32,
    rcv_nxt: u32,
    snd_nxt: u32,
    snd_una: u32,
    mss_cache: u32,
    ecn_flags: u32,
    rate_delivered: u32,
    rate_interval_us: u32,
    packets_out: u32,
    retrans_out: u32,
    total_retrans: u32,
    segs_in: u32,
    data_segs_in: u32,
    segs_out: u32,
    data_segs_out: u32,
    lost_out: u32,
    sacked_out: u32,
    sk_txhash: u32,
    bytes_received: u64,
    bytes_acked: u64,
    sk: u64,
}

#[link_section = "sockops"]
#[no_mangle]
extern "C" fn mptcp_sockmap_inject(skops: *const bpf_sock_ops) -> i32 {
    let local_port = vload!((*skops).local_port);
    let op = vload!((*skops).op);
    let port = unsafe { trace_port };

    // only accept specified connection
    if local_port as i32 != port || op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB {
        return 1;
    }

    let sk = vload!((*skops).sk);
    if sk == 0 {
        return 1;
    }

    // update sk handler
    let key = unsafe { sk_index as u32 };
    let ret = bpf_sock_map_update(skops as *mut bpf_sock_ops, &sock_map, &key, BPF_NOEXIST);
    unsafe { helper_ret = ret as i32 };

    1
}

#[link_section = "sk_skb/stream_verdict"]
#[no_mangle]
extern "C" fn mptcp_sockmap_redirect(skb: *const __sk_buff) -> i32 {
    // redirect skb to the sk under sock_map[redirect_idx]
    let key = unsafe { redirect_idx as u32 };
    bpf_sk_redirect_map(skb as *const _, &sock_map, key, 0) as i32
}

bpf_object!("GPL");
