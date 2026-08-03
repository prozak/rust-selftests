#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_sockmap_progs_query.c
// (bpf-rs-core idiom). Two trivial verdict programs attached/queried via
// bpf_prog_attach/bpf_prog_query against sock_map; neither ever runs real
// traffic in the test, so the bodies just return SK_PASS.

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::maps::BpfMap;

const SK_PASS: i32 = 1;
/// enum bpf_map_type::BPF_MAP_TYPE_SOCKMAP (not in bpf-rs-core::maps yet).
const SOCKMAP: usize = 15;

/// UAPI struct sk_msg_md, full layout (bpf.h). data/data_end/sk are
/// pointer-typed unions, represented as u64 (same convention as
/// __sk_buff's flow_keys/sk fields).
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct sk_msg_md {
    pub data: u64,
    pub data_end: u64,
    pub family: u32,
    pub remote_ip4: u32,
    pub local_ip4: u32,
    pub remote_ip6: [u32; 4],
    pub local_ip6: [u32; 4],
    pub remote_port: u32,
    pub local_port: u32,
    pub size: u32,
    pub sk: u64,
}

#[link_section = ".maps"]
#[no_mangle]
static sock_map: BpfMap<u32, u64, SOCKMAP, 1> = BpfMap::new();

#[link_section = "sk_skb"]
#[no_mangle]
extern "C" fn prog_skb_verdict(_skb: *const __sk_buff) -> i32 {
    SK_PASS
}

#[link_section = "sk_msg"]
#[no_mangle]
extern "C" fn prog_skmsg_verdict(_msg: *const sk_msg_md) -> i32 {
    SK_PASS
}

bpf_object!("GPL");
