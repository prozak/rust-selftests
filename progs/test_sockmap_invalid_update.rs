#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_sockmap_invalid_update.c,
// bpf-rs-core idiom.
//
// Deliberately invalid: bpf_map_update_elem() on a BPF_MAP_TYPE_SOCKMAP is
// not a permitted helper for SEC("sockops") programs (verifier.c
// check_map_func_compatibility() / may_update_sockmap() only allow
// map_delete_elem there; map_update_elem needs the dedicated
// bpf_sock_map_update() helper instead). The kernel test asserts
// open_and_load() returns NULL for this object.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_map_update_elem_ptr;
use bpf_rs_core::maps::BpfMap;
use bpf_rs_core::vload;
use core::ffi::c_void;

const BPF_MAP_TYPE_SOCKMAP: usize = 15;

#[link_section = ".maps"]
#[no_mangle]
static map: BpfMap<u32, u64, BPF_MAP_TYPE_SOCKMAP, 1> = BpfMap::new();

// UAPI struct bpf_sock_ops, fields through `sk` (bpf.h). `sk` is a
// __bpf_md_ptr union (pointer overlaid with u64 padding), represented as
// u64 like __sk_buff.sk. Fields after `sk` are unused by this program and
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
extern "C" fn bpf_sockmap(skops: *const bpf_sock_ops) -> i32 {
    let key: u32 = 0;
    let sk = vload!((*skops).sk);

    if sk != 0 {
        bpf_map_update_elem_ptr(&map, &key, sk as *const c_void, 0);
    }
    0
}

bpf_object!("GPL");
