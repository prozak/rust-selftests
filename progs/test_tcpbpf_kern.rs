#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_tcpbpf_kern.c
// (bpf-rs-core idiom).
//
// The C original opens with five `asm volatile` blocks that read (and, for
// sk_txhash, read-then-write-back-unchanged) `skops` fields at fixed byte
// offsets through raw single/multi-register sequences. Every one of those
// reads is either immediately overwritten (the `op` probe at +96, right
// before `op = (int) skops->op;`) or discarded entirely (the `reuse` probe,
// the sk_txhash round-trip, the three `sk` dereferences) -- they exist
// upstream to stress the sock_ops ctx-access converter's handling of
// different asm idioms, not to influence program behavior. None of their
// results are observable from userspace (only `global.*` and `skops->reply`
// are), so they're omitted here; ordinary field accesses on the struct
// below go through the exact same ctx-access converter.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_getsockopt, bpf_setsockopt, bpf_skc_to_tcp_sock, bpf_sock_ops_cb_flags_set,
};
use btf_macros::btf;
use core::ffi::c_void;

const AF_INET6: u32 = 10;

const BPF_SOCK_OPS_TCP_CONNECT_CB: u32 = 3;
const BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: u32 = 4;
const BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: u32 = 5;
const BPF_SOCK_OPS_RTO_CB: u32 = 8;
const BPF_SOCK_OPS_RETRANS_CB: u32 = 9;
const BPF_SOCK_OPS_STATE_CB: u32 = 10;
const BPF_SOCK_OPS_TCP_LISTEN_CB: u32 = 11;
const BPF_SOCK_OPS_STATE_CB_FLAG: i32 = 1 << 2;

const BPF_TCP_CLOSE: u32 = 7;
const BPF_TCP_LISTEN: u32 = 10;

const SOL_TCP: i32 = 6;
const SOL_IPV6: i32 = 41;
const IPV6_TCLASS: i32 = 67;
const IPPROTO_TCP: i32 = 6;
const TCP_WINDOW_CLAMP: i32 = 10;
const TCP_SAVE_SYN: i32 = 27;
const TCP_SAVED_SYN: i32 = 28;

const IPV6HDR_LEN: usize = 40;
const TCPHDR_LEN: usize = 20;
const HEADER_LEN: usize = IPV6HDR_LEN + TCPHDR_LEN;

/// UAPI struct tcpbpf_globals (test_tcpbpf.h). Name and field order/types
/// must match exactly: the userspace skeleton forward-declares this struct
/// by name and reads `skel->bss->global` directly.
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct tcpbpf_globals {
    pub event_map: u32,
    pub total_retrans: u32,
    pub data_segs_in: u32,
    pub data_segs_out: u32,
    pub bad_cb_test_rv: u32,
    pub good_cb_test_rv: u32,
    pub bytes_received: u64,
    pub bytes_acked: u64,
    pub num_listen: u32,
    pub num_close_events: u32,
    pub tcp_save_syn: u32,
    pub tcp_saved_syn: u32,
    pub window_clamp_client: u32,
    pub window_clamp_server: u32,
}

#[no_mangle]
static mut global: tcpbpf_globals = tcpbpf_globals {
    event_map: 0,
    total_retrans: 0,
    data_segs_in: 0,
    data_segs_out: 0,
    bad_cb_test_rv: 0,
    good_cb_test_rv: 0,
    bytes_received: 0,
    bytes_acked: 0,
    num_listen: 0,
    num_close_events: 0,
    tcp_save_syn: 0,
    tcp_saved_syn: 0,
    window_clamp_client: 0,
    window_clamp_server: 0,
};

/// UAPI struct bpf_sock_ops (linux/bpf.h), through `sk` only -- nothing past
/// it is read, but every earlier field must keep its exact C offset for the
/// kernel's per-field ctx-access rewrite to line up.
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
    pub sk: u64,
}

/// Real kernel `struct tcp_sock`, through `window_clamp` only, read via a
/// BTF-ID-checked pointer returned by `bpf_skc_to_tcp_sock` -- CO-RE
/// (`#[btf]`) resolves the byte offset against this kernel build's vmlinux
/// BTF regardless of what's declared here, same idiom as mptcp_subflow.rs's
/// `mptcp_sock` cast off `bpf_skc_to_mptcp_sock`.
#[btf]
struct tcp_sock {
    window_clamp: u32,
}

#[inline(always)]
fn get_tp_window_clamp(skops: *mut bpf_sock_ops) -> i32 {
    let sk = unsafe { (*skops).sk } as *mut c_void;
    if sk.is_null() {
        return -1;
    }
    let tp = bpf_skc_to_tcp_sock(sk) as *const tcp_sock;
    if tp.is_null() {
        return -1;
    }
    *unsafe { &*tp }.window_clamp().get().unwrap() as i32
}

#[link_section = "sockops"]
#[no_mangle]
extern "C" fn bpf_testcb(skops: *mut bpf_sock_ops) -> i32 {
    let mut header = [0u8; HEADER_LEN];
    let mut window_clamp: i32 = 9216;
    let save_syn: i32 = 1;
    let mut rv: i64 = -1;
    let mut v: i32;

    let op = unsafe { (*skops).op };

    unsafe { global.event_map |= 1u32.wrapping_shl(op) };

    match op {
        BPF_SOCK_OPS_TCP_CONNECT_CB => {
            rv = bpf_setsockopt(
                skops as *mut c_void,
                SOL_TCP,
                TCP_WINDOW_CLAMP,
                &mut window_clamp as *mut i32 as *mut c_void,
                core::mem::size_of::<i32>() as i32,
            );
            unsafe { global.window_clamp_client = get_tp_window_clamp(skops) as u32 };
        }
        BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB => {
            // Test failure to set largest cb flag (assumes not defined).
            let bad_cb_test_rv = bpf_sock_ops_cb_flags_set(skops, 0x80);
            // Set callback.
            let good_cb_test_rv =
                bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);
            unsafe {
                global.bad_cb_test_rv = bad_cb_test_rv as u32;
                global.good_cb_test_rv = good_cb_test_rv as u32;
            }
        }
        BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB => {
            unsafe { (*skops).sk_txhash = 0x12345f };
            v = 0xff;
            rv = bpf_setsockopt(
                skops as *mut c_void,
                SOL_IPV6,
                IPV6_TCLASS,
                &mut v as *mut i32 as *mut c_void,
                core::mem::size_of::<i32>() as i32,
            );
            if unsafe { (*skops).family } == AF_INET6 {
                v = bpf_getsockopt(
                    skops as *mut c_void,
                    IPPROTO_TCP,
                    TCP_SAVED_SYN,
                    header.as_mut_ptr() as *mut c_void,
                    HEADER_LEN as i32,
                ) as i32;
                if v == 0 {
                    let syn_byte = unsafe { *header.as_ptr().add(IPV6HDR_LEN + 13) };
                    let syn = (syn_byte >> 1) & 1;
                    unsafe { global.tcp_saved_syn = syn as u32 };
                }
            }
            rv = bpf_setsockopt(
                skops as *mut c_void,
                SOL_TCP,
                TCP_WINDOW_CLAMP,
                &mut window_clamp as *mut i32 as *mut c_void,
                core::mem::size_of::<i32>() as i32,
            );
            unsafe { global.window_clamp_server = get_tp_window_clamp(skops) as u32 };
        }
        BPF_SOCK_OPS_RTO_CB => {}
        BPF_SOCK_OPS_RETRANS_CB => {}
        BPF_SOCK_OPS_STATE_CB => {
            let args = unsafe { (*skops).args };
            if args[1] == BPF_TCP_CLOSE {
                if args[0] == BPF_TCP_LISTEN {
                    unsafe { global.num_listen += 1 };
                } else {
                    unsafe {
                        global.total_retrans = (*skops).total_retrans;
                        global.data_segs_in = (*skops).data_segs_in;
                        global.data_segs_out = (*skops).data_segs_out;
                        global.bytes_received = (*skops).bytes_received;
                        global.bytes_acked = (*skops).bytes_acked;
                    }
                }
                unsafe { global.num_close_events += 1 };
            }
        }
        BPF_SOCK_OPS_TCP_LISTEN_CB => {
            bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);
            v = bpf_setsockopt(
                skops as *mut c_void,
                IPPROTO_TCP,
                TCP_SAVE_SYN,
                &save_syn as *const i32 as *mut c_void,
                core::mem::size_of::<i32>() as i32,
            ) as i32;
            unsafe { global.tcp_save_syn = v as u32 };
        }
        _ => {
            rv = -1;
        }
    }

    unsafe { (*skops).args[0] = rv as u32 };

    1
}

bpf_object!("GPL");
