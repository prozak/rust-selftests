#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/netns_cookie_prog.c
// (bpf-rs-core idiom).

use core::ffi::c_void;

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_get_netns_cookie, bpf_sk_storage_get, bpf_sock_map_update};
use bpf_rs_core::{bpf_map, bpf_object};

const AF_INET6: u32 = 10;

const BPF_SOCK_OPS_TCP_CONNECT_CB: u32 = 3;
const BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: u32 = 4;
const BPF_SK_STORAGE_GET_F_CREATE: u64 = 1;
const BPF_NOEXIST: u64 = 1;

const TCX_PASS: i32 = 0;
const SK_PASS: i32 = 1;

// UAPI struct bpf_sock_ops (linux/bpf.h), full layout, same shape as
// tcp_rtt.rs's copy. `sk` is typed as a raw void pointer here since this
// program never dereferences its pointee, only forwards it.
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_sock_ops {
    op: u32,
    args: [u32; 4],
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
    sk: *mut c_void,
    skb_data: *mut c_void,
    skb_data_end: *mut c_void,
    skb_len: u32,
    skb_tcp_flags: u32,
    skb_hwtstamp: u64,
}

/// UAPI struct sk_msg_md (bpf.h). data/data_end/sk are __bpf_md_ptr, kept as
/// u64 like other translations' overlay representation (see
/// test_sockmap_redir.rs).
#[allow(non_camel_case_types)]
#[repr(C)]
struct sk_msg_md {
    data: u64,
    data_end: u64,
    family: u32,
    remote_ip4: u32,
    local_ip4: u32,
    remote_ip6: [u32; 4],
    local_ip6: [u32; 4],
    remote_port: u32,
    local_port: u32,
    size: u32,
    sk: u64,
}

// No __uint(max_entries, ...) in the C source (BPF_MAP_TYPE_SK_STORAGE is
// sized implicitly), so this needs the bpf_map! escape hatch rather than
// the BpfMap<K, V, TYPE, MAX> generic.
bpf_map! {
    sockops_netns_cookies {
        r#type: *const [i32; 24],    // BPF_MAP_TYPE_SK_STORAGE
        map_flags: *const [i32; 1],  // BPF_F_NO_PREALLOC
        key: *const i32,
        value: *const i32,
    }
}

bpf_map! {
    sk_msg_netns_cookies {
        r#type: *const [i32; 24],    // BPF_MAP_TYPE_SK_STORAGE
        map_flags: *const [i32; 1],  // BPF_F_NO_PREALLOC
        key: *const i32,
        value: *const i32,
    }
}

bpf_map! {
    sock_map {
        r#type: *const [i32; 15], // BPF_MAP_TYPE_SOCKMAP
        max_entries: *const [i32; 2],
        key: *const u32,
        value: *const u64,
    }
}

#[no_mangle]
static mut tcx_init_netns_cookie: i32 = 0;
#[no_mangle]
static mut tcx_netns_cookie: i32 = 0;
#[no_mangle]
static mut cgroup_skb_init_netns_cookie: i32 = 0;
#[no_mangle]
static mut cgroup_skb_netns_cookie: i32 = 0;

#[link_section = "sockops"]
#[no_mangle]
extern "C" fn get_netns_cookie_sockops(ctx: *mut bpf_sock_ops) -> i32 {
    let key: u32 = 0;

    if unsafe { (*ctx).family } != AF_INET6 {
        return 1;
    }

    let sk = unsafe { (*ctx).sk };
    if sk.is_null() {
        return 1;
    }

    let op = unsafe { (*ctx).op };
    if op == BPF_SOCK_OPS_TCP_CONNECT_CB {
        let cookie =
            bpf_sk_storage_get(&sockops_netns_cookies, sk, core::ptr::null_mut(), BPF_SK_STORAGE_GET_F_CREATE)
                as *mut i32;
        if cookie.is_null() {
            return 1;
        }

        unsafe { *cookie = bpf_get_netns_cookie(ctx) as i32 };
    } else if op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB {
        bpf_sock_map_update(ctx, &sock_map, &key, BPF_NOEXIST);
    }

    1
}

#[link_section = "sk_msg"]
#[no_mangle]
extern "C" fn get_netns_cookie_sk_msg(msg: *const sk_msg_md) -> i32 {
    if unsafe { (*msg).family } != AF_INET6 {
        return 1;
    }

    let sk = unsafe { (*msg).sk } as *mut c_void;
    if sk.is_null() {
        return 1;
    }

    let cookie =
        bpf_sk_storage_get(&sk_msg_netns_cookies, sk, core::ptr::null_mut(), BPF_SK_STORAGE_GET_F_CREATE)
            as *mut i32;
    if cookie.is_null() {
        return 1;
    }

    unsafe { *cookie = bpf_get_netns_cookie(msg) as i32 };

    1
}

#[link_section = "tcx/ingress"]
#[no_mangle]
extern "C" fn get_netns_cookie_tcx(skb: *const __sk_buff) -> i32 {
    unsafe {
        tcx_init_netns_cookie = bpf_get_netns_cookie(core::ptr::null::<c_void>()) as i32;
        tcx_netns_cookie = bpf_get_netns_cookie(skb) as i32;
    }
    TCX_PASS
}

#[link_section = "cgroup_skb/ingress"]
#[no_mangle]
extern "C" fn get_netns_cookie_cgroup_skb(skb: *const __sk_buff) -> i32 {
    unsafe {
        cgroup_skb_init_netns_cookie = bpf_get_netns_cookie(core::ptr::null::<c_void>()) as i32;
        cgroup_skb_netns_cookie = bpf_get_netns_cookie(skb) as i32;
    }
    SK_PASS
}

bpf_object!("GPL");
