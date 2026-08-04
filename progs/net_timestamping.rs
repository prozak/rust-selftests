#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/net_timestamping.c
// (bpf-rs-core idiom).
//
// `struct bpf_sock_ops` is hand declared with the exact UAPI field order
// (linux/bpf.h) -- same rationale/layout as mptcp_sock.rs. Every read off a
// ctx pointer of this shape goes through `vload!`, matching mptcp_sock.rs's
// precedent (the C source never marks these `volatile` either -- the
// kernel's sock_ops_convert_ctx_access() rewrite applies to the ctx pointer
// type regardless of C syntax).
//
// `bpf_cast_to_kern_ctx(skops)` + `skb->head + skb->end` reinterpreted as
// `struct skb_shared_info *` reuses type_cast.rs's md_skb technique
// (`#[btf]` chase, raw pointer add, `bpf_probe_read_kernel` off the
// resulting untrusted/computed address instead of the missing
// bpf_core_cast()/BPF_CORE_TYPE_ID_TARGET relocation).
//
// `bpf_sock_ops_enable_tx_tstamp` is a real kfunc (`__ksym` in the C
// source); declared `extern "C"` with c_void args, same convention as every
// other kfunc extern in this repo (getpeername_unix_prog.rs,
// verifier_vfs_accept.rs).

use core::ffi::c_void;

use bpf_rs_core::helpers::{
    bpf_get_current_pid_tgid, bpf_get_socket_cookie, bpf_getsockopt, bpf_ktime_get_ns,
    bpf_load_hdr_opt, bpf_map_delete_elem, bpf_map_lookup_elem, bpf_map_update_elem,
    bpf_probe_read_kernel, bpf_setsockopt, bpf_sk_storage_get, bpf_skc_to_tcp_sock,
    bpf_sock_ops_cb_flags_set,
};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::progs::fentry_arg as arg;
use bpf_rs_core::{bpf_map, bpf_object, vload};
use btf_macros::btf;

// enum bpf_map_type: BPF_MAP_TYPE_SK_STORAGE.
const BPF_MAP_TYPE_SK_STORAGE: usize = 24;
// enum: BPF_F_NO_PREALLOC.
const BPF_F_NO_PREALLOC: usize = 1;
const BPF_SK_STORAGE_GET_F_CREATE: u64 = 1;

// uapi/linux/bpf.h sock_ops op list, 0-indexed from BPF_SOCK_OPS_VOID.
const BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: u32 = 4;
const BPF_SOCK_OPS_TSTAMP_SCHED_CB: u32 = 16;
const BPF_SOCK_OPS_TSTAMP_SND_SW_CB: u32 = 17;
const BPF_SOCK_OPS_TSTAMP_ACK_CB: u32 = 19;
const BPF_SOCK_OPS_TSTAMP_SENDMSG_CB: u32 = 20;

// linux/bpf.h SK_BPF_CB_* / setsockopt(SOL_SOCKET, SK_BPF_CB_FLAGS, ...).
const SK_BPF_CB_TX_TIMESTAMPING: i32 = 1;
const SK_BPF_CB_FLAGS: i32 = 1009;
const SOL_SOCKET: i32 = 1;
const EOPNOTSUPP: i32 = 95;

const BPF_ANY: u64 = 0;

const DELAY_TOLERANCE_NSEC: u64 = 10_000_000_000; // 10 second as an example

/// UAPI struct bpf_sock_ops (linux/bpf.h), full layout through
/// skb_hwtstamp -- same hand-declared struct as mptcp_sock.rs (the
/// args/reply/replylong anonymous union is represented by its widest
/// member's storage; only size/alignment of later offsets matter here).
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct bpf_sock_ops {
    pub op: u32,
    pub reply_union: [u32; 4],
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

#[repr(C)]
struct sk_stg {
    sendmsg_ns: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct sk_tskey {
    cookie: u64,
    tskey: u32,
    // Explicit trailing pad: `{cookie: u64, tskey: u32}` alone still leaves
    // a compiler-inserted 4-byte gap to round the struct up to 16 bytes,
    // and hash-map lookups compare the full key including that gap. A
    // plain `core::mem::zeroed()` + per-field store does NOT reliably zero
    // it -- LLVM splits the aggregate init into stores at each named
    // field's own offset and drops the write to the unnamed gap entirely,
    // leaving it as leftover stack garbage that differs between calls (the
    // C original avoids this because `struct sk_tskey key = {0};` zeros
    // the whole object as one operation). Naming the gap turns it into a
    // real field the optimizer must store, so `_pad: 0` always lands.
    _pad: u32,
}

#[repr(C)]
struct delay_info {
    sendmsg_ns: u64,
    sched_delay: u32,
    snd_sw_delay: u32,
    ack_delay: u32,
}

#[btf]
struct sock {
    sk_bpf_cb_flags: u8,
}

#[btf]
struct bpf_sock_ops_kern {
    skb: *mut sk_buff,
}

#[btf]
struct sk_buff {
    head: *const u8,
    end: u32,
}

#[btf]
struct skb_shared_info {
    tskey: u32,
}

bpf_map! {
    sk_stg_map {
        r#type: *const [i32; BPF_MAP_TYPE_SK_STORAGE],
        map_flags: *const [i32; BPF_F_NO_PREALLOC],
        key: *const i32,
        value: *const sk_stg,
    }
}

#[link_section = ".maps"]
#[no_mangle]
static time_map: BpfMap<sk_tskey, delay_info, { maps::HASH }, 1024> = BpfMap::new();

#[no_mangle]
static mut monitored_pid: u32 = 0;

#[no_mangle]
static mut nr_active: i32 = 0;
#[no_mangle]
static mut nr_snd: i32 = 0;
#[no_mangle]
static mut nr_passive: i32 = 0;
#[no_mangle]
static mut nr_sched: i32 = 0;
#[no_mangle]
static mut nr_txsw: i32 = 0;
#[no_mangle]
static mut nr_ack: i32 = 0;

extern "C" {
    fn bpf_cast_to_kern_ctx(ctx: *mut c_void) -> *mut c_void;
    fn bpf_sock_ops_enable_tx_tstamp(skops_kern: *mut c_void, flags: u64) -> i32;
}

#[inline(never)]
fn get_sk_bpf_cb_flags(sk: *mut sock) -> u8 {
    let sk_ref = unsafe { &*sk };
    unsafe { *sk_ref.sk_bpf_cb_flags().as_ptr() }
}

#[inline(never)]
fn get_shinfo_tskey(skops_kern: *mut c_void) -> u32 {
    let kern_ref = unsafe { &*(skops_kern as *const bpf_sock_ops_kern) };
    let skb = unsafe { *kern_ref.skb().as_ptr() };
    let skb_ref = unsafe { &*skb };

    let head_ptr = unsafe { *skb_ref.head().as_ptr() };
    let end_val = unsafe { *skb_ref.end().as_ptr() };
    let shinfo_ptr = unsafe { head_ptr.add(end_val as usize) } as *const skb_shared_info;
    let shinfo_ref = unsafe { &*shinfo_ptr };

    let mut tskey_val: u32 = 0;
    bpf_probe_read_kernel(
        &mut tskey_val,
        4,
        shinfo_ref.tskey().as_ptr() as *const c_void,
    );
    tskey_val
}

fn bpf_test_sockopt(ctx: *mut bpf_sock_ops, expected: i32) -> i32 {
    let mut new: i32 = SK_BPF_CB_TX_TIMESTAMPING;
    let mut tmp: i32 = 0;
    let opt = SK_BPF_CB_FLAGS;
    let level = SOL_SOCKET;

    if bpf_setsockopt(
        ctx,
        level,
        opt,
        &mut new as *mut i32 as *mut c_void,
        4,
    ) != expected as i64
    {
        return 1;
    }

    let ret = bpf_getsockopt(ctx, level, opt, &mut tmp as *mut i32 as *mut c_void, 4);
    if ret != expected as i64 || (expected == 0 && tmp != new) {
        return 1;
    }

    0
}

fn bpf_test_access_sockopt(ctx: *mut bpf_sock_ops) -> bool {
    bpf_test_sockopt(ctx, -EOPNOTSUPP) != 0
}

fn bpf_test_access_load_hdr_opt(skops: *mut bpf_sock_ops) -> bool {
    let mut opt: [u8; 3] = [0; 3];
    let ret = bpf_load_hdr_opt(skops, opt.as_mut_ptr() as *mut c_void, 3, 0);
    ret != -EOPNOTSUPP as i64
}

fn bpf_test_access_cb_flags_set(skops: *mut bpf_sock_ops) -> bool {
    let ret = bpf_sock_ops_cb_flags_set(skops, 0);
    ret != -EOPNOTSUPP as i64
}

fn bpf_test_access_bpf_calls(skops: *mut bpf_sock_ops) -> bool {
    if bpf_test_access_sockopt(skops) {
        return true;
    }
    if bpf_test_access_load_hdr_opt(skops) {
        return true;
    }
    if bpf_test_access_cb_flags_set(skops) {
        return true;
    }
    false
}

fn bpf_test_delay(skops: *mut bpf_sock_ops, sk: *mut c_void) -> bool {
    let timestamp = bpf_ktime_get_ns();

    if bpf_test_access_bpf_calls(skops) {
        return false;
    }

    let skops_kern = unsafe { bpf_cast_to_kern_ctx(skops as *mut c_void) };

    let cookie = bpf_get_socket_cookie(skops);
    if cookie == 0 {
        return false;
    }

    let op = vload!((*skops).op);
    let mut key = sk_tskey {
        cookie,
        tskey: 0,
        _pad: 0,
    };

    if op == BPF_SOCK_OPS_TSTAMP_SENDMSG_CB {
        let stg = bpf_sk_storage_get(&sk_stg_map, sk as *const c_void, core::ptr::null(), 0)
            as *mut sk_stg;
        if stg.is_null() {
            return false;
        }
        let dinfo = delay_info {
            sendmsg_ns: unsafe { (*stg).sendmsg_ns },
            sched_delay: 0,
            snd_sw_delay: 0,
            ack_delay: 0,
        };
        unsafe {
            bpf_sock_ops_enable_tx_tstamp(skops_kern, 0);
        }
        // Read fresh AFTER enabling tx tstamp: the C source reads
        // shinfo->tskey only after the enable call, since it's what
        // populates the field on this skb in the no-user-opt-in case.
        let tskey = get_shinfo_tskey(skops_kern);
        if tskey == 0 {
            return false;
        }
        key.tskey = tskey;
        bpf_map_update_elem(&time_map, &key, &dinfo, BPF_ANY);
        return true;
    }

    let tskey = get_shinfo_tskey(skops_kern);
    if tskey == 0 {
        return false;
    }
    key.tskey = tskey;

    let val = bpf_map_lookup_elem(&time_map, &key) as *mut delay_info;
    if val.is_null() {
        return false;
    }

    let delay: u64;
    match op {
        BPF_SOCK_OPS_TSTAMP_SCHED_CB => unsafe {
            let sched_delay = timestamp.wrapping_sub((*val).sendmsg_ns) as u32;
            (*val).sched_delay = sched_delay;
            delay = sched_delay as u64;
        },
        BPF_SOCK_OPS_TSTAMP_SND_SW_CB => unsafe {
            let prior_ts = (*val).sched_delay as u64 + (*val).sendmsg_ns;
            let snd_sw_delay = timestamp.wrapping_sub(prior_ts) as u32;
            (*val).snd_sw_delay = snd_sw_delay;
            delay = snd_sw_delay as u64;
        },
        BPF_SOCK_OPS_TSTAMP_ACK_CB => unsafe {
            let prior_ts =
                (*val).snd_sw_delay as u64 + (*val).sched_delay as u64 + (*val).sendmsg_ns;
            let ack_delay = timestamp.wrapping_sub(prior_ts) as u32;
            (*val).ack_delay = ack_delay;
            delay = ack_delay as u64;
        },
        _ => return false,
    }

    if delay >= DELAY_TOLERANCE_NSEC {
        return false;
    }

    // Since it's the last one, remove from the map after latency check.
    if op == BPF_SOCK_OPS_TSTAMP_ACK_CB {
        bpf_map_delete_elem(&time_map, &key);
    }

    true
}

#[link_section = "fentry/tcp_sendmsg_locked"]
#[no_mangle]
extern "C" fn trace_tcp_sendmsg_locked(ctx: *const u64) -> i32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let timestamp = bpf_ktime_get_ns();
    let sk = arg(ctx, 0) as *mut sock;
    let flag = get_sk_bpf_cb_flags(sk);

    if pid != unsafe { monitored_pid } || flag == 0 {
        return 0;
    }

    let stg = bpf_sk_storage_get(
        &sk_stg_map,
        sk as *const c_void,
        core::ptr::null(),
        BPF_SK_STORAGE_GET_F_CREATE,
    ) as *mut sk_stg;
    if stg.is_null() {
        return 0;
    }

    unsafe {
        (*stg).sendmsg_ns = timestamp;
        nr_snd += 1;
    }

    0
}

#[link_section = "sockops"]
#[no_mangle]
extern "C" fn skops_sockopt(ctx: *mut bpf_sock_ops) -> i32 {
    let bpf_sk = vload!((*ctx).sk) as *mut c_void;
    if bpf_sk.is_null() {
        return 1;
    }

    let sk = bpf_skc_to_tcp_sock(bpf_sk as *const c_void);
    if sk.is_null() {
        return 1;
    }

    let op = vload!((*ctx).op);
    match op {
        BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB => {
            if bpf_test_sockopt(ctx, 0) == 0 {
                unsafe { nr_active += 1 };
            }
        }
        BPF_SOCK_OPS_TSTAMP_SENDMSG_CB => {
            if bpf_test_delay(ctx, sk) {
                unsafe { nr_snd += 1 };
            }
        }
        BPF_SOCK_OPS_TSTAMP_SCHED_CB => {
            if bpf_test_delay(ctx, sk) {
                unsafe { nr_sched += 1 };
            }
        }
        BPF_SOCK_OPS_TSTAMP_SND_SW_CB => {
            if bpf_test_delay(ctx, sk) {
                unsafe { nr_txsw += 1 };
            }
        }
        BPF_SOCK_OPS_TSTAMP_ACK_CB => {
            if bpf_test_delay(ctx, sk) {
                unsafe { nr_ack += 1 };
            }
        }
        _ => {}
    }

    1
}

bpf_object!("GPL");
