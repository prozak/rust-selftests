#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_sock_fields.c
// (bpf-rs-core idiom).
//
// `struct bpf_sock`/`struct bpf_tcp_sock` field reads through a
// `skb->sk`-derived pointer (or its bpf_sk_fullsock()/bpf_tcp_sock() views)
// go through the kernel's ctx-style narrow-access rewrite (see
// bpf_sock_is_valid_access/bpf_tcp_sock_is_valid_access in net/core/filter.c)
// exactly like a real ctx field, so every read uses vload!/vload_as! to keep
// each access a separate, correctly-sized BPF_LDX the verifier can rewrite.

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{
    bpf_map_update_elem, bpf_sk_ancestor_cgroup_id, bpf_sk_cgroup_id, bpf_sk_fullsock,
    bpf_sk_storage_get, bpf_skc_to_tcp_sock, bpf_spin_lock, bpf_spin_unlock, bpf_tcp_sock,
};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::{vload, vload_as};
use btf_macros::btf;
use core::ffi::c_void;

const EGRESS_LINUM_IDX: u32 = 0;
const INGRESS_LINUM_IDX: u32 = 1;
const READ_SK_DST_PORT_LINUM_IDX: u32 = 2;

const CG_OK: i32 = 1;
const BPF_ANY: u64 = 0;
const BPF_SK_STORAGE_GET_F_CREATE: u64 = 1;

const AF_INET6: u32 = 10;
const IPPROTO_TCP: u32 = 6;
const BPF_TCP_LISTEN: u32 = 10;
const BPF_TCP_SYN_SENT: u32 = 2;

// struct bpf_spin_lock { __u32 val; }; -- matched by BTF struct name.
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_spin_lock {
    val: u32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_spinlock_cnt {
    lock: bpf_spin_lock,
    cnt: u32,
}

// UAPI struct bpf_sock (linux/bpf.h). Named exactly like the kernel type so
// bpftool's skeleton forward-declares against the copy already pulled in by
// the userspace test via <linux/bpf.h>, instead of an incomplete type.
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_sock {
    bound_dev_if: u32,
    family: u32,
    r#type: u32,
    protocol: u32,
    mark: u32,
    priority: u32,
    src_ip4: u32,
    src_ip6: [u32; 4],
    src_port: u32,
    dst_port: u16,
    _pad: u16,
    dst_ip4: u32,
    dst_ip6: [u32; 4],
    state: u32,
    rx_queue_mapping: i32,
}

const ZERO_SOCK: bpf_sock = bpf_sock {
    bound_dev_if: 0,
    family: 0,
    r#type: 0,
    protocol: 0,
    mark: 0,
    priority: 0,
    src_ip4: 0,
    src_ip6: [0; 4],
    src_port: 0,
    dst_port: 0,
    _pad: 0,
    dst_ip4: 0,
    dst_ip6: [0; 4],
    state: 0,
    rx_queue_mapping: 0,
};

// UAPI struct bpf_tcp_sock (linux/bpf.h), same by-name requirement as
// bpf_sock above.
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_tcp_sock {
    snd_cwnd: u32,
    srtt_us: u32,
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
    bytes_received: u64,
    bytes_acked: u64,
    dsack_dups: u32,
    delivered: u32,
    delivered_ce: u32,
    icsk_retransmits: u32,
}

const ZERO_TCP_SOCK: bpf_tcp_sock = bpf_tcp_sock {
    snd_cwnd: 0,
    srtt_us: 0,
    rtt_min: 0,
    snd_ssthresh: 0,
    rcv_nxt: 0,
    snd_nxt: 0,
    snd_una: 0,
    mss_cache: 0,
    ecn_flags: 0,
    rate_delivered: 0,
    rate_interval_us: 0,
    packets_out: 0,
    retrans_out: 0,
    total_retrans: 0,
    segs_in: 0,
    data_segs_in: 0,
    segs_out: 0,
    data_segs_out: 0,
    lost_out: 0,
    sacked_out: 0,
    bytes_received: 0,
    bytes_acked: 0,
    dsack_dups: 0,
    delivered: 0,
    delivered_ce: 0,
    icsk_retransmits: 0,
};

// struct sockaddr_in6 (netinet/in.h / linux/in6.h), collapsing in6_addr to
// its u32x4 view -- the only shape this program touches.
#[allow(non_camel_case_types)]
#[repr(C)]
struct sockaddr_in6 {
    sin6_family: u16,
    sin6_port: u16,
    sin6_flowinfo: u32,
    sin6_addr: [u32; 4],
    sin6_scope_id: u32,
}

// Kernel struct tcp_sock (net/tcp.h), through lsndtime only -- CO-RE via
// bpf_skc_to_tcp_sock()'s BTF-ID-checked cast.
#[btf]
struct tcp_sock {
    lsndtime: u32,
}

#[link_section = ".maps"]
#[no_mangle]
static linum_map: BpfMap<u32, u32, { maps::ARRAY }, 3> = BpfMap::new();

bpf_map! {
    sk_pkt_out_cnt {
        r#type: *const [i32; 24],   // BPF_MAP_TYPE_SK_STORAGE
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        key: *const i32,
        value: *const bpf_spinlock_cnt,
    }
}

bpf_map! {
    sk_pkt_out_cnt10 {
        r#type: *const [i32; 24],
        map_flags: *const [i32; 1],
        key: *const i32,
        value: *const bpf_spinlock_cnt,
    }
}

#[no_mangle]
static mut listen_tp: bpf_tcp_sock = ZERO_TCP_SOCK;
#[no_mangle]
static mut srv_sa6: sockaddr_in6 = sockaddr_in6 {
    sin6_family: 0,
    sin6_port: 0,
    sin6_flowinfo: 0,
    sin6_addr: [0; 4],
    sin6_scope_id: 0,
};
#[no_mangle]
static mut cli_tp: bpf_tcp_sock = ZERO_TCP_SOCK;
#[no_mangle]
static mut srv_tp: bpf_tcp_sock = ZERO_TCP_SOCK;
#[no_mangle]
static mut listen_sk: bpf_sock = ZERO_SOCK;
#[no_mangle]
static mut srv_sk: bpf_sock = ZERO_SOCK;
#[no_mangle]
static mut cli_sk: bpf_sock = ZERO_SOCK;
#[no_mangle]
static mut parent_cg_id: u64 = 0;
#[no_mangle]
static mut child_cg_id: u64 = 0;
#[no_mangle]
static mut lsndtime: u64 = 0;

#[inline(always)]
fn is_loopback6(sk: *const bpf_sock) -> bool {
    vload!((*sk).src_ip6[0]) == 0
        && vload!((*sk).src_ip6[1]) == 0
        && vload!((*sk).src_ip6[2]) == 0
        && vload!((*sk).src_ip6[3]) == 1u32.swap_bytes()
}

#[inline(always)]
fn skcpy(dst: *mut bpf_sock, src: *const bpf_sock) {
    unsafe {
        (*dst).bound_dev_if = vload!((*src).bound_dev_if);
        (*dst).family = vload!((*src).family);
        (*dst).r#type = vload!((*src).r#type);
        (*dst).protocol = vload!((*src).protocol);
        (*dst).mark = vload!((*src).mark);
        (*dst).priority = vload!((*src).priority);
        (*dst).src_ip4 = vload!((*src).src_ip4);
        (*dst).src_ip6[0] = vload!((*src).src_ip6[0]);
        (*dst).src_ip6[1] = vload!((*src).src_ip6[1]);
        (*dst).src_ip6[2] = vload!((*src).src_ip6[2]);
        (*dst).src_ip6[3] = vload!((*src).src_ip6[3]);
        (*dst).src_port = vload!((*src).src_port);
        (*dst).dst_ip4 = vload!((*src).dst_ip4);
        (*dst).dst_ip6[0] = vload!((*src).dst_ip6[0]);
        (*dst).dst_ip6[1] = vload!((*src).dst_ip6[1]);
        (*dst).dst_ip6[2] = vload!((*src).dst_ip6[2]);
        (*dst).dst_ip6[3] = vload!((*src).dst_ip6[3]);
        (*dst).dst_port = vload!((*src).dst_port);
        (*dst).state = vload!((*src).state);
    }
}

#[inline(always)]
fn tpcpy(dst: *mut bpf_tcp_sock, src: *const bpf_tcp_sock) {
    unsafe {
        (*dst).snd_cwnd = vload!((*src).snd_cwnd);
        (*dst).srtt_us = vload!((*src).srtt_us);
        (*dst).rtt_min = vload!((*src).rtt_min);
        (*dst).snd_ssthresh = vload!((*src).snd_ssthresh);
        (*dst).rcv_nxt = vload!((*src).rcv_nxt);
        (*dst).snd_nxt = vload!((*src).snd_nxt);
        (*dst).snd_una = vload!((*src).snd_una);
        (*dst).mss_cache = vload!((*src).mss_cache);
        (*dst).ecn_flags = vload!((*src).ecn_flags);
        (*dst).rate_delivered = vload!((*src).rate_delivered);
        (*dst).rate_interval_us = vload!((*src).rate_interval_us);
        (*dst).packets_out = vload!((*src).packets_out);
        (*dst).retrans_out = vload!((*src).retrans_out);
        (*dst).total_retrans = vload!((*src).total_retrans);
        (*dst).segs_in = vload!((*src).segs_in);
        (*dst).data_segs_in = vload!((*src).data_segs_in);
        (*dst).segs_out = vload!((*src).segs_out);
        (*dst).data_segs_out = vload!((*src).data_segs_out);
        (*dst).lost_out = vload!((*src).lost_out);
        (*dst).sacked_out = vload!((*src).sacked_out);
        (*dst).bytes_received = vload!((*src).bytes_received);
        (*dst).bytes_acked = vload!((*src).bytes_acked);
    }
}

#[inline(always)]
fn ret_log(linum_idx: u32, linum: u32) -> i32 {
    bpf_map_update_elem(&linum_map, &linum_idx, &linum, BPF_ANY);
    CG_OK
}

#[link_section = "cgroup_skb/egress"]
#[no_mangle]
extern "C" fn egress_read_sock_fields(skb: *const __sk_buff) -> i32 {
    let mut cli_cnt_init = bpf_spinlock_cnt {
        lock: bpf_spin_lock { val: 0 },
        cnt: 0xeB9F,
    };
    let linum_idx: u32 = EGRESS_LINUM_IDX;

    let sk = vload!((*skb).sk) as *mut bpf_sock;
    if sk.is_null() {
        return ret_log(linum_idx, 138);
    }

    // Not testing the egress traffic or the listening socket, which are
    // covered by the cgroup_skb/ingress test program.
    if vload!((*sk).family) != AF_INET6
        || !is_loopback6(sk)
        || vload!((*sk).state) == BPF_TCP_LISTEN
    {
        return CG_OK;
    }

    let sk_ret: *mut bpf_sock;
    let tp_ret: *mut bpf_tcp_sock;

    if vload!((*sk).src_port) == (unsafe { srv_sa6.sin6_port }).swap_bytes() as u32 {
        // Server socket
        sk_ret = core::ptr::addr_of_mut!(srv_sk);
        tp_ret = core::ptr::addr_of_mut!(srv_tp);
    } else if vload!((*sk).dst_port) == unsafe { srv_sa6.sin6_port } {
        // Client socket
        sk_ret = core::ptr::addr_of_mut!(cli_sk);
        tp_ret = core::ptr::addr_of_mut!(cli_tp);
    } else {
        // Not the testing egress traffic
        return CG_OK;
    }

    // It must be a fullsock for cgroup_skb/egress prog
    let sk = bpf_sk_fullsock(sk as *const core::ffi::c_void) as *mut bpf_sock;
    if sk.is_null() {
        return ret_log(linum_idx, 163);
    }

    // Not the testing egress traffic
    if vload!((*sk).protocol) != IPPROTO_TCP {
        return CG_OK;
    }

    let tp = bpf_tcp_sock(sk as *const core::ffi::c_void) as *mut bpf_tcp_sock;
    if tp.is_null() {
        return ret_log(linum_idx, 171);
    }

    skcpy(sk_ret, sk);
    tpcpy(tp_ret, tp);

    let (pkt_out_cnt, pkt_out_cnt10): (*mut bpf_spinlock_cnt, *mut bpf_spinlock_cnt) =
        if sk_ret == core::ptr::addr_of_mut!(srv_sk) {
            let ktp = bpf_skc_to_tcp_sock(sk as *mut c_void) as *mut tcp_sock;
            if ktp.is_null() {
                return ret_log(linum_idx, 180);
            }

            unsafe { lsndtime = *(&*ktp).lsndtime().get().unwrap() as u64 };

            let cgid = bpf_sk_cgroup_id(ktp as *mut c_void);
            if cgid == 0 {
                return ret_log(linum_idx, 186);
            }
            unsafe { child_cg_id = cgid };

            let acgid = bpf_sk_ancestor_cgroup_id(ktp as *mut c_void, 2);
            if acgid == 0 {
                return ret_log(linum_idx, 190);
            }
            unsafe { parent_cg_id = acgid };

            // The userspace has created it for srv sk
            (
                bpf_sk_storage_get(&sk_pkt_out_cnt, ktp, core::ptr::null_mut(), 0)
                    as *mut bpf_spinlock_cnt,
                bpf_sk_storage_get(&sk_pkt_out_cnt10, ktp, core::ptr::null_mut(), 0)
                    as *mut bpf_spinlock_cnt,
            )
        } else {
            let init = core::ptr::addr_of_mut!(cli_cnt_init) as *mut c_void;
            (
                bpf_sk_storage_get(&sk_pkt_out_cnt, sk, init, BPF_SK_STORAGE_GET_F_CREATE)
                    as *mut bpf_spinlock_cnt,
                bpf_sk_storage_get(&sk_pkt_out_cnt10, sk, init, BPF_SK_STORAGE_GET_F_CREATE)
                    as *mut bpf_spinlock_cnt,
            )
        };

    if pkt_out_cnt.is_null() || pkt_out_cnt10.is_null() {
        return ret_log(linum_idx, 206);
    }

    // Even both cnt and cnt10 have lock defined in their BTF, intentionally
    // one cnt takes lock while one does not as a test for the spinlock
    // support in BPF_MAP_TYPE_SK_STORAGE.
    unsafe {
        (*pkt_out_cnt).cnt = (*pkt_out_cnt).cnt.wrapping_add(1);
        bpf_spin_lock(core::ptr::addr_of_mut!((*pkt_out_cnt10).lock));
        (*pkt_out_cnt10).cnt = (*pkt_out_cnt10).cnt.wrapping_add(10);
        bpf_spin_unlock(core::ptr::addr_of_mut!((*pkt_out_cnt10).lock));
    }

    CG_OK
}

#[link_section = "cgroup_skb/ingress"]
#[no_mangle]
extern "C" fn ingress_read_sock_fields(skb: *const __sk_buff) -> i32 {
    let linum_idx: u32 = INGRESS_LINUM_IDX;

    let sk = vload!((*skb).sk) as *mut bpf_sock;
    if sk.is_null() {
        return ret_log(linum_idx, 231);
    }

    // Not the testing ingress traffic to the server
    if vload!((*sk).family) != AF_INET6
        || !is_loopback6(sk)
        || vload!((*sk).src_port) != (unsafe { srv_sa6.sin6_port }).swap_bytes() as u32
    {
        return CG_OK;
    }

    // Only interested in the listening socket
    if vload!((*sk).state) != BPF_TCP_LISTEN {
        return CG_OK;
    }

    // It must be a fullsock for cgroup_skb/ingress prog
    let sk = bpf_sk_fullsock(sk as *const core::ffi::c_void) as *mut bpf_sock;
    if sk.is_null() {
        return ret_log(linum_idx, 245);
    }

    let tp = bpf_tcp_sock(sk as *const core::ffi::c_void) as *mut bpf_tcp_sock;
    if tp.is_null() {
        return ret_log(linum_idx, 249);
    }

    skcpy(core::ptr::addr_of_mut!(listen_sk), sk);
    tpcpy(core::ptr::addr_of_mut!(listen_tp), tp);

    CG_OK
}

// NOTE: 4-byte load from bpf_sock at dst_port offset is quirky. It gets
// rewritten by the access converter to a 2-byte load for backward
// compatibility. Treating the load result as a be16 value makes the code
// portable across little- and big-endian platforms.
#[inline(never)]
fn sk_dst_port_load_word(sk: *const bpf_sock) -> bool {
    vload_as!((*sk).dst_port, u32) == 0xcafeu16.swap_bytes() as u32
}

#[inline(never)]
fn sk_dst_port_load_half(sk: *const bpf_sock) -> bool {
    vload_as!((*sk).dst_port, u16) == 0xcafeu16.swap_bytes()
}

#[inline(never)]
fn sk_dst_port_load_byte(sk: *const bpf_sock) -> bool {
    let base = unsafe { core::ptr::addr_of!((*sk).dst_port) as *const u8 };
    let byte0 = unsafe { core::ptr::read_volatile(base) };
    let byte1 = unsafe { core::ptr::read_volatile(base.add(1)) };
    byte0 == 0xca && byte1 == 0xfe
}

#[link_section = "cgroup_skb/egress"]
#[no_mangle]
extern "C" fn read_sk_dst_port(skb: *const __sk_buff) -> i32 {
    let linum_idx: u32 = READ_SK_DST_PORT_LINUM_IDX;

    let sk = vload!((*skb).sk) as *mut bpf_sock;
    if sk.is_null() {
        return ret_log(linum_idx, 294);
    }

    // Ignore everything but the SYN from the client socket
    if vload!((*sk).state) != BPF_TCP_SYN_SENT {
        return CG_OK;
    }

    if !sk_dst_port_load_word(sk) {
        return ret_log(linum_idx, 301);
    }
    if !sk_dst_port_load_half(sk) {
        return ret_log(linum_idx, 303);
    }
    if !sk_dst_port_load_byte(sk) {
        return ret_log(linum_idx, 305);
    }

    CG_OK
}

bpf_object!("GPL");
