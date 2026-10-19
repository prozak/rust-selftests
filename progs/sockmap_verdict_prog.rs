// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/sockmap_verdict_prog.c
// (bpf-rs-core idiom). The sk_skb verdict program test_maps.c attaches to
// its sockmaps: the first payload byte picks the rx or tx map, the second
// the slot, and the first eight bytes are overwritten with 0xdeadbeef
// nibbles before the redirect.

use core::ffi::c_void;

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_sk_redirect_map, bpf_skb_pull_data, sink_val};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::{bpf_object, vload};

const SOCKMAP: usize = 15;
const SK_DROP: i32 = 0;

#[link_section = ".maps"]
#[no_mangle]
static sock_map_rx: BpfMap<i32, i32, SOCKMAP, 20> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static sock_map_tx: BpfMap<i32, i32, SOCKMAP, 20> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static sock_map_msg: BpfMap<i32, i32, SOCKMAP, 20> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static sock_map_break: BpfMap<i32, i32, { maps::ARRAY }, 20> = BpfMap::new();

#[link_section = "sk_skb2"]
#[no_mangle]
extern "C" fn bpf_prog2(skb: *mut __sk_buff) -> i32 {
    let mut data_end = vload!((*skb).data_end) as usize as *mut u8;
    let mut data = vload!((*skb).data) as usize as *mut u8;
    let lport = vload!((*skb).local_port);
    let rport = vload!((*skb).remote_port);
    let mut d = data;

    sink_val(lport as i32);
    sink_val(rport as i32);

    if unsafe { data.add(8) } > data_end {
        if bpf_skb_pull_data(skb as *const c_void, 8) != 0 {
            return SK_DROP;
        }

        data = vload!((*skb).data) as usize as *mut u8;
        data_end = vload!((*skb).data_end) as usize as *mut u8;

        if unsafe { data.add(8) } > data_end {
            return SK_DROP;
        }

        d = data;
    }

    let (map, sk) = unsafe {
        let map = *d;
        let sk = *d.add(1);

        *d = 0xd;
        *d.add(1) = 0xe;
        *d.add(2) = 0xa;
        *d.add(3) = 0xd;
        *d.add(4) = 0xb;
        *d.add(5) = 0xe;
        *d.add(6) = 0xe;
        *d.add(7) = 0xf;
        (map, sk)
    };

    if map == 0 {
        return bpf_sk_redirect_map(skb, &sock_map_rx, sk as u32, 0) as i32;
    }
    bpf_sk_redirect_map(skb, &sock_map_tx, sk as u32, 0) as i32
}

bpf_object!("GPL");
