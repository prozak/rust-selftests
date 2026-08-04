#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/tcp_rtt.c, bpf-rs-core idiom.

use bpf_rs_core::helpers::{bpf_sk_storage_get, bpf_sock_ops_cb_flags_set, bpf_tcp_sock};
use bpf_rs_core::{bpf_map, bpf_object};

#[repr(C)]
pub struct tcp_rtt_storage {
    pub invoked: u32,
    pub dsack_dups: u32,
    pub delivered: u32,
    pub delivered_ce: u32,
    pub icsk_retransmits: u32,

    pub mrtt_us: u32, /* args[0] */
    pub srtt: u32,    /* args[1] */
}

// UAPI struct bpf_sock (linux/bpf.h), full layout. dst_port is __be16
// followed by a 16-bit zero-padding bitfield.
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct bpf_sock {
    pub bound_dev_if: u32,
    pub family: u32,
    pub r#type: u32,
    pub protocol: u32,
    pub mark: u32,
    pub priority: u32,
    pub src_ip4: u32,
    pub src_ip6: [u32; 4],
    pub src_port: u32,
    pub dst_port: u16,
    pub _pad: u16,
    pub dst_ip4: u32,
    pub dst_ip6: [u32; 4],
    pub state: u32,
    pub rx_queue_mapping: i32,
}

// UAPI struct bpf_sock_ops (linux/bpf.h), full layout. The C source's
// leading union { args[4]; reply; replylong[4]; } is represented by its
// largest/first-declared member, args[4], same size either way.
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct bpf_sock_ops {
    pub op: u32,
    pub args: [u32; 4],
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
    pub sk: *mut bpf_sock,
    pub skb_data: *mut core::ffi::c_void,
    pub skb_data_end: *mut core::ffi::c_void,
    pub skb_len: u32,
    pub skb_tcp_flags: u32,
    pub skb_hwtstamp: u64,
}

// UAPI struct bpf_tcp_sock (linux/bpf.h), full layout.
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct bpf_tcp_sock_uapi {
    pub snd_cwnd: u32,
    pub srtt_us: u32,
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
    pub bytes_received: u64,
    pub bytes_acked: u64,
    pub dsack_dups: u32,
    pub delivered: u32,
    pub delivered_ce: u32,
    pub icsk_retransmits: u32,
}

const BPF_SOCK_OPS_TCP_CONNECT_CB: i32 = 3;
const BPF_SOCK_OPS_RTT_CB: i32 = 12;
const BPF_SOCK_OPS_RTT_CB_FLAG: i32 = 1 << 3;
const BPF_SK_STORAGE_GET_F_CREATE: u64 = 1;

// No __uint(max_entries, ...) in the C source (BPF_MAP_TYPE_SK_STORAGE is
// sized implicitly), so this needs the bpf_map! escape hatch rather than
// the BpfMap<K, V, TYPE, MAX> generic.
bpf_map! {
    socket_storage_map {
        r#type: *const [i32; 24],    // BPF_MAP_TYPE_SK_STORAGE
        map_flags: *const [i32; 1],  // BPF_F_NO_PREALLOC
        key: *const i32,
        value: *const tcp_rtt_storage,
    }
}

#[link_section = "sockops"]
#[no_mangle]
extern "C" fn _sockops(ctx: *mut bpf_sock_ops) -> i32 {
    let op = unsafe { (*ctx).op } as i32;

    let sk = unsafe { (*ctx).sk };
    if sk.is_null() {
        return 1;
    }

    let storage = bpf_sk_storage_get(
        &socket_storage_map,
        sk as *mut core::ffi::c_void,
        core::ptr::null_mut(),
        BPF_SK_STORAGE_GET_F_CREATE,
    ) as *mut tcp_rtt_storage;
    if storage.is_null() {
        return 1;
    }

    if op == BPF_SOCK_OPS_TCP_CONNECT_CB {
        bpf_sock_ops_cb_flags_set(ctx, BPF_SOCK_OPS_RTT_CB_FLAG);
        return 1;
    }

    if op != BPF_SOCK_OPS_RTT_CB {
        return 1;
    }

    let tcp_sk = bpf_tcp_sock(sk as *const core::ffi::c_void) as *mut bpf_tcp_sock_uapi;
    if tcp_sk.is_null() {
        return 1;
    }

    unsafe {
        (*storage).invoked += 1;

        (*storage).dsack_dups = (*tcp_sk).dsack_dups;
        (*storage).delivered = (*tcp_sk).delivered;
        (*storage).delivered_ce = (*tcp_sk).delivered_ce;
        (*storage).icsk_retransmits = (*tcp_sk).icsk_retransmits;

        (*storage).mrtt_us = (*ctx).args[0];
        (*storage).srtt = (*ctx).args[1];
    }

    1
}

bpf_object!("GPL");
