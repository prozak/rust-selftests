// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_tcpnotify_kern.c
// (bpf-rs-core idiom). A sockops program for test_tcpnotify_user.c: on the
// test port it enables the retransmit/RTO callbacks, and on every
// retransmit records the count in global_map and emits a tcp_notifier
// through the perf event array.

use core::ffi::c_void;
use core::ptr::{addr_of_mut, read_volatile, write_volatile};

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_map_lookup_elem, bpf_map_update_elem, bpf_perf_event_output, bpf_sock_ops_cb_flags_set,
};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::bpf_map;

const TESTPORT: u32 = 12877;
const BPF_ANY: u64 = 0;
const BPF_F_CURRENT_CPU: u64 = 0xffffffff;

const BPF_SOCK_OPS_RTO_CB_FLAG: i32 = 1 << 0;
const BPF_SOCK_OPS_RETRANS_CB_FLAG: i32 = 1 << 1;

const BPF_SOCK_OPS_TIMEOUT_INIT: i32 = 1;
const BPF_SOCK_OPS_RWND_INIT: i32 = 2;
const BPF_SOCK_OPS_TCP_CONNECT_CB: i32 = 3;
const BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: i32 = 4;
const BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: i32 = 5;
const BPF_SOCK_OPS_NEEDS_ECN: i32 = 6;
const BPF_SOCK_OPS_BASE_RTT: i32 = 7;
const BPF_SOCK_OPS_RTO_CB: i32 = 8;
const BPF_SOCK_OPS_RETRANS_CB: i32 = 9;
const BPF_SOCK_OPS_TCP_LISTEN_CB: i32 = 11;

/* test_tcpnotify.h */
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy)]
struct tcpnotify_globals {
    total_retrans: u32,
    ncalls: u32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct tcp_notifier {
    r#type: u8,
    subtype: u8,
    source: u8,
    hash: u8,
}

/// UAPI struct bpf_sock_ops (linux/bpf.h) through skb_hwtstamp; the
/// args/reply/replylong union is its first word `reply` plus padding.
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct bpf_sock_ops {
    pub op: u32,
    pub reply: u32,
    pub args_rest: [u32; 3],
    pub family: u32,
    pub remote_ip4: u32,
    pub local_ip4: u32,
    pub remote_ip6: [u32; 4],
    pub local_ip6: [u32; 4],
    pub remote_port: u32,
    pub local_port: u32,
    pub is_fullsock: u32,
    pub snd_cwnd: u32,
    pub srtt_us: u32,
    pub bpf_sock_ops_cb_flags: u32,
    pub state: u32,
    pub rtt_min: u32,
    pub snd_ssthresh: u32,
    pub rcv_nxt: u32,
    pub snd_nxt: u32,
    pub snd_una: u32,
    pub mss_cache: u32,
    pub ecn_flags: u32,
    pub rate_delivered: u32,
    pub rate_interval_us: u32,
    pub packets_out: u32,
    pub retrans_out: u32,
    pub total_retrans: u32,
    pub segs_in: u32,
    pub data_segs_in: u32,
    pub segs_out: u32,
    pub data_segs_out: u32,
    pub lost_out: u32,
    pub sacked_out: u32,
    pub sk_txhash: u32,
    pub bytes_received: u64,
    pub bytes_acked: u64,
    pub sk: u64,
    pub skb_data: u64,
    pub skb_data_end: u64,
    pub skb_len: u32,
    pub skb_tcp_flags: u32,
    pub skb_hwtstamp: u64,
}

#[link_section = ".maps"]
#[no_mangle]
static global_map: BpfMap<u32, tcpnotify_globals, { maps::ARRAY }, 4> = BpfMap::new();

bpf_map! {
    perf_event_map {
        r#type: *const [i32; maps::PERF_EVENT_ARRAY],
        key: *const i32,
        value: *const u32,
    }
}

#[link_section = "sockops"]
#[no_mangle]
extern "C" fn bpf_testcb(skops: *mut bpf_sock_ops) -> i32 {
    let mut rv: i32 = -1;

    let op = unsafe { read_volatile(addr_of_mut!((*skops).op)) } as i32;

    if u32::from_be(unsafe { read_volatile(addr_of_mut!((*skops).remote_port)) }) != TESTPORT {
        unsafe { write_volatile(addr_of_mut!((*skops).reply), -1i32 as u32) };
        return 0;
    }

    match op {
        BPF_SOCK_OPS_TIMEOUT_INIT
        | BPF_SOCK_OPS_RWND_INIT
        | BPF_SOCK_OPS_NEEDS_ECN
        | BPF_SOCK_OPS_BASE_RTT
        | BPF_SOCK_OPS_RTO_CB => {
            rv = 1;
        }

        BPF_SOCK_OPS_TCP_CONNECT_CB
        | BPF_SOCK_OPS_TCP_LISTEN_CB
        | BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB
        | BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB => {
            bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_RETRANS_CB_FLAG | BPF_SOCK_OPS_RTO_CB_FLAG);
            rv = 1;
        }
        BPF_SOCK_OPS_RETRANS_CB => 'block: {
            let key: u32 = 0;
            let msg = tcp_notifier {
                r#type: 0xde,
                subtype: 0xad,
                source: 0xbe,
                hash: 0xef,
            };

            rv = 1;

            /* Update results */
            let gp = bpf_map_lookup_elem(&global_map, &key) as *mut tcpnotify_globals;
            if gp.is_null() {
                break 'block;
            }
            let mut g = unsafe { *gp };
            g.total_retrans = unsafe { read_volatile(addr_of_mut!((*skops).total_retrans)) };
            g.ncalls = g.ncalls.wrapping_add(1);
            bpf_map_update_elem(&global_map, &key, &g, BPF_ANY);
            bpf_perf_event_output(skops as *const c_void, &perf_event_map, BPF_F_CURRENT_CPU, &msg, 4);
        }
        _ => {
            rv = -1;
        }
    }
    unsafe { write_volatile(addr_of_mut!((*skops).reply), rv as u32) };
    1
}

bpf_object!("GPL");
