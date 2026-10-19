// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bench_sockmap_prog.c
// (bpf-rs-core idiom). benchs/bench_sockmap.c attaches the parser/verdict
// programs to two sockmaps holding the ends of a socket pair, sets
// `pkt_size`/`verdict_dir` and reads `process_byte` and `dropped`: the
// stream verdict and sk_msg programs redirect (or pass) every packet and
// count its bytes. `verdict_dir` is the C's `int` passed as the helpers'
// u64 flags (sign-extended).

#![allow(non_upper_case_globals)]

use core::ptr::addr_of_mut;

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_msg_redirect_map, bpf_sk_redirect_map, sync_fetch_and_add};
use bpf_rs_core::maps::BpfMap;
use bpf_rs_core::{bpf_object, vload};

const BPF_MAP_TYPE_SOCKMAP: usize = 15;
const SK_DROP: i64 = 0;
const SK_PASS: i32 = 1;

/// UAPI struct sk_msg_md, full layout (bpf.h). data/data_end/sk are
/// pointer-typed unions, represented as u64 (test_skmsg_load_helpers.rs).
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

#[no_mangle]
static mut process_byte: isize = 0;
#[no_mangle]
static mut verdict_dir: i32 = 0;
#[no_mangle]
static mut dropped: i32 = 0;
#[no_mangle]
static mut pkt_size: i32 = 0;

#[link_section = ".maps"]
#[no_mangle]
static sock_map_rx: BpfMap<i32, i32, BPF_MAP_TYPE_SOCKMAP, 20> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static sock_map_tx: BpfMap<i32, i32, BPF_MAP_TYPE_SOCKMAP, 20> = BpfMap::new();

#[link_section = "sk_skb/stream_parser"]
#[no_mangle]
extern "C" fn prog_skb_parser(_skb: *mut __sk_buff) -> i32 {
    unsafe { pkt_size }
}

#[link_section = "sk_skb/stream_verdict"]
#[no_mangle]
extern "C" fn prog_skb_verdict(skb: *mut __sk_buff) -> i32 {
    let one: u32 = 1;
    let ret = bpf_sk_redirect_map(skb, &sock_map_rx, one, unsafe { verdict_dir } as i64 as u64);

    if ret == SK_DROP {
        unsafe { dropped += 1 };
    }
    sync_fetch_and_add(unsafe { addr_of_mut!(process_byte) }, vload!((*skb).len) as isize);
    ret as i32
}

#[link_section = "sk_skb/stream_verdict"]
#[no_mangle]
extern "C" fn prog_skb_pass(skb: *mut __sk_buff) -> i32 {
    sync_fetch_and_add(unsafe { addr_of_mut!(process_byte) }, vload!((*skb).len) as isize);
    SK_PASS
}

#[link_section = "sk_msg"]
#[no_mangle]
extern "C" fn prog_skmsg_verdict(msg: *mut sk_msg_md) -> i32 {
    let one: u32 = 1;

    sync_fetch_and_add(unsafe { addr_of_mut!(process_byte) }, vload!((*msg).size) as isize);
    bpf_msg_redirect_map(msg, &sock_map_tx, one, unsafe { verdict_dir } as i64 as u64) as i32
}

#[link_section = "sk_msg"]
#[no_mangle]
extern "C" fn prog_skmsg_pass(msg: *mut sk_msg_md) -> i32 {
    sync_fetch_and_add(unsafe { addr_of_mut!(process_byte) }, vload!((*msg).size) as isize);
    SK_PASS
}

bpf_object!("GPL");
