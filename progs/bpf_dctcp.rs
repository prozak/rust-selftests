// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_dctcp.c
// (bpf-rs-core idiom). A DCTCP congestion control as a struct_ops map
// (tcp_congestion_ops), plus a second instance that only sets init and
// set_state. prog_tests/bpf_tcp_ca.c attaches `dctcp`, runs a connection
// with the socket storage the test seeds (stg_result), and in the fallback
// subtest writes fallback_cc before the load and reads back cc_res,
// tcp_cdg_res and ebusy_cnt; bpf_iter_setsockopt.c switches sockets to it.
//
// The congestion state lives in icsk_ca_priv (inet_csk_ca(sk)); tcp_sk(sk)
// and inet_csk(sk) are the same pointer. icsk_ca_state is a kernel
// bitfield (BPF_CORE_READ_BITFIELD in the C), read through the byte before
// icsk_retransmits as bpf_cc_cubic.rs does. The two instances set disjoint
// members, so the second one uses the CO-RE flavor
// tcp_congestion_ops___nouse (bpf_tcp_ops.rs). The C's two file-local
// `static unsigned int` parameters are folded into constants by clang; the
// same here. The strings are C `char` arrays (the test strscpy()s
// fallback_cc and strcmp()s cc_res).
// BTF_C_CHAR: u8

use core::ffi::c_void;
use core::ptr::{addr_of, addr_of_mut, read_volatile};

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_getsockopt, bpf_setsockopt, bpf_sk_storage_delete, bpf_sk_storage_get, bpf_tcp_send_ack,
};
use bpf_rs_core::progs::fentry_arg as arg;
use bpf_rs_core::bpf_map;
use btf_macros::btf;

const EBUSY: i64 = 16;
const SOL_TCP: i32 = 6;
const TCP_CONGESTION: i32 = 13;
const TCP_CA_NAME_MAX: usize = 16;
const TCP_ECN_OK: u8 = 1;
const TCP_ECN_DEMAND_CWR: u8 = 4;
const TCP_CONG_NEEDS_ECN: u32 = 0x2;
const TCP_CA_Recovery: u8 = 3;
const CA_EVENT_LOSS: u32 = 3;
const CA_EVENT_ECN_NO_CE: u32 = 4;
const CA_EVENT_ECN_IS_CE: u32 = 5;
const ICSK_ACK_TIMER: u8 = 2;
const ICSK_ACK_NOW: u8 = 16;

#[link_section = ".rodata"]
#[no_mangle]
static fallback_cc: [u8; TCP_CA_NAME_MAX] = [0; TCP_CA_NAME_MAX];
#[link_section = ".rodata"]
#[no_mangle]
static bpf_dctcp: [u8; 10] = *b"bpf_dctcp\0";
#[link_section = ".rodata"]
#[no_mangle]
static tcp_cdg: [u8; 4] = *b"cdg\0";
#[no_mangle]
static mut cc_res: [u8; TCP_CA_NAME_MAX] = [0; TCP_CA_NAME_MAX];
#[no_mangle]
static mut tcp_cdg_res: i32 = 0;
#[no_mangle]
static mut stg_result: i32 = 0;
#[no_mangle]
static mut ebusy_cnt: i32 = 0;

bpf_map! {
    sk_stg_map {
        r#type: *const [i32; 24],   // BPF_MAP_TYPE_SK_STORAGE
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        key: *const i32,
        value: *const i32,
    }
}

const DCTCP_MAX_ALPHA: u32 = 1024;

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_dctcp {
    old_delivered: u32,
    old_delivered_ce: u32,
    prior_rcv_nxt: u32,
    dctcp_alpha: u32,
    next_seq: u32,
    ce_state: u32,
    loss_cwnd: u32,
}

const DCTCP_SHIFT_G: u32 = 4; /* g = 1/2^4 */
const DCTCP_ALPHA_ON_INIT: u32 = DCTCP_MAX_ALPHA;

#[btf]
struct tcp_sock {
    snd_cwnd: u32,
    snd_ssthresh: u32,
    delivered: u32,
    delivered_ce: u32,
    ecn_flags: u8,
    rcv_nxt: u32,
    snd_nxt: u32,
    snd_una: u32,
}

#[btf]
struct icsk_ack_t {
    pending: u8,
}

#[btf]
struct inet_connection_sock {
    icsk_retransmits: u8,
    icsk_ack: icsk_ack_t,
    icsk_ca_priv: [u64; 13],
}

extern "C" {
    fn tcp_reno_cong_avoid(sk: *mut c_void, ack: u32, acked: u32);
}

#[inline(always)]
fn inet_csk_ca(sk: *const c_void) -> *mut bpf_dctcp {
    unsafe { &*(sk as *const inet_connection_sock) }.icsk_ca_priv().as_mut_ptr() as *mut bpf_dctcp
}

/// `BPF_CORE_READ_BITFIELD(inet_csk(sk), icsk_ca_state)`: the five low bits
/// of the byte before icsk_retransmits
#[inline(always)]
fn icsk_ca_state(sk: *const c_void) -> u8 {
    let anchor = unsafe { &*(sk as *const inet_connection_sock) }.icsk_retransmits().as_ptr();
    (unsafe { *anchor.sub(1) }) & 0x1F
}

#[inline(always)]
fn before(seq1: u32, seq2: u32) -> bool {
    (seq1.wrapping_sub(seq2) as i32) < 0
}

#[inline(always)]
unsafe fn dctcp_reset(tp: *const tcp_sock, ca: *mut bpf_dctcp) {
    (*ca).next_seq = *(&*tp).snd_nxt().as_ptr();

    (*ca).old_delivered = *(&*tp).delivered().as_ptr();
    (*ca).old_delivered_ce = *(&*tp).delivered_ce().as_ptr();
}

// BPF_PROG(bpf_dctcp_init, struct sock *sk)
#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn bpf_dctcp_init(ctx: *const u64) {
    let sk = arg(ctx, 0) as *mut c_void;
    let tp = sk as *const tcp_sock;
    let ca = inet_csk_ca(sk);

    unsafe {
        if (*(&*tp).ecn_flags().as_ptr() & TCP_ECN_OK) == 0 && read_volatile(addr_of!(fallback_cc[0])) != 0 {
            /* Switch to fallback */
            if bpf_setsockopt(sk, SOL_TCP, TCP_CONGESTION, addr_of!(fallback_cc) as *const c_void, TCP_CA_NAME_MAX as i32)
                == -EBUSY
            {
                ebusy_cnt += 1;
            }

            /* Switch back to myself and the recurred bpf_dctcp_init()
             * will get -EBUSY for all bpf_setsockopt(TCP_CONGESTION),
             * except the last "cdg" one.
             */
            if bpf_setsockopt(sk, SOL_TCP, TCP_CONGESTION, addr_of!(bpf_dctcp) as *const c_void, 10) == -EBUSY {
                ebusy_cnt += 1;
            }

            /* Switch back to fallback */
            if bpf_setsockopt(sk, SOL_TCP, TCP_CONGESTION, addr_of!(fallback_cc) as *const c_void, TCP_CA_NAME_MAX as i32)
                == -EBUSY
            {
                ebusy_cnt += 1;
            }

            /* Expecting -ENOTSUPP for tcp_cdg_res */
            tcp_cdg_res = bpf_setsockopt(sk, SOL_TCP, TCP_CONGESTION, addr_of!(tcp_cdg) as *const c_void, 4) as i32;
            bpf_getsockopt(sk, SOL_TCP, TCP_CONGESTION, addr_of_mut!(cc_res) as *mut c_void, TCP_CA_NAME_MAX as i32);
            return;
        }

        (*ca).prior_rcv_nxt = *(&*tp).rcv_nxt().as_ptr();
        (*ca).dctcp_alpha = core::cmp::min(DCTCP_ALPHA_ON_INIT, DCTCP_MAX_ALPHA);
        (*ca).loss_cwnd = 0;
        (*ca).ce_state = 0;

        let stg = bpf_sk_storage_get(&sk_stg_map, tp as *const c_void, core::ptr::null(), 0) as *mut i32;
        if !stg.is_null() {
            stg_result = *stg;
            bpf_sk_storage_delete(&sk_stg_map, tp as *mut c_void);
        }
        dctcp_reset(tp, ca);
    }
}

// __u32 BPF_PROG(bpf_dctcp_ssthresh, struct sock *sk)
#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn bpf_dctcp_ssthresh(ctx: *const u64) -> u32 {
    let sk = arg(ctx, 0) as *mut c_void;
    let ca = inet_csk_ca(sk);
    let tp = sk as *const tcp_sock;

    unsafe {
        let snd_cwnd = *(&*tp).snd_cwnd().as_ptr();
        (*ca).loss_cwnd = snd_cwnd;
        core::cmp::max(
            snd_cwnd.wrapping_sub((snd_cwnd.wrapping_mul((*ca).dctcp_alpha)) >> 11),
            2,
        )
    }
}

// BPF_PROG(bpf_dctcp_update_alpha, struct sock *sk, __u32 flags)
#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn bpf_dctcp_update_alpha(ctx: *const u64) {
    let sk = arg(ctx, 0) as *mut c_void;
    let tp = sk as *const tcp_sock;
    let ca = inet_csk_ca(sk);

    unsafe {
        /* Expired RTT */
        if !before(*(&*tp).snd_una().as_ptr(), (*ca).next_seq) {
            let mut delivered_ce: u32 = (*(&*tp).delivered_ce().as_ptr()).wrapping_sub((*ca).old_delivered_ce);
            let mut alpha: u32 = (*ca).dctcp_alpha;

            /* alpha = (1 - g) * alpha + g * F */

            // min_not_zero(alpha, alpha >> dctcp_shift_g)
            let y = alpha >> DCTCP_SHIFT_G;
            let mnz = if alpha == 0 {
                y
            } else if y == 0 {
                alpha
            } else {
                core::cmp::min(alpha, y)
            };
            alpha = alpha.wrapping_sub(mnz);
            if delivered_ce != 0 {
                let delivered: u32 = (*(&*tp).delivered().as_ptr()).wrapping_sub((*ca).old_delivered);

                /* If dctcp_shift_g == 1, a 32bit value would overflow
                 * after 8 M packets.
                 */
                delivered_ce <<= 10 - DCTCP_SHIFT_G;
                delivered_ce /= core::cmp::max(1, delivered);

                alpha = core::cmp::min(alpha.wrapping_add(delivered_ce), DCTCP_MAX_ALPHA);
            }
            (*ca).dctcp_alpha = alpha;
            dctcp_reset(tp, ca);
        }
    }
}

#[inline(always)]
unsafe fn dctcp_react_to_loss(sk: *mut c_void) {
    let ca = inet_csk_ca(sk);
    let tp = sk as *const tcp_sock;

    let snd_cwnd = *(&*tp).snd_cwnd().as_ptr();
    (*ca).loss_cwnd = snd_cwnd;
    *(&*tp).snd_ssthresh().as_mut_ptr() = core::cmp::max(snd_cwnd >> 1, 2);
}

// BPF_PROG(bpf_dctcp_state, struct sock *sk, __u8 new_state)
#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn bpf_dctcp_state(ctx: *const u64) {
    let sk = arg(ctx, 0) as *mut c_void;
    let new_state = arg(ctx, 1) as u8;

    if new_state == TCP_CA_Recovery && new_state != icsk_ca_state(sk) {
        unsafe { dctcp_react_to_loss(sk) };
    }
    /* We handle RTO in bpf_dctcp_cwnd_event to ensure that we perform only
     * one loss-adjustment per RTT.
     */
}

#[inline(always)]
unsafe fn dctcp_ece_ack_cwr(sk: *mut c_void, ce_state: u32) {
    let tp = sk as *const tcp_sock;
    let ecn_flags = (&*tp).ecn_flags().as_mut_ptr();

    if ce_state == 1 {
        *ecn_flags |= TCP_ECN_DEMAND_CWR;
    } else {
        *ecn_flags &= !TCP_ECN_DEMAND_CWR;
    }
}

/* Minimal DCTP CE state machine:
 *
 * S:	0 <- last pkt was non-CE
 *	1 <- last pkt was CE
 */
#[inline(always)]
unsafe fn dctcp_ece_ack_update(sk: *mut c_void, evt: u32, prior_rcv_nxt: *mut u32, ce_state: *mut u32) {
    let new_ce_state: u32 = if evt == CA_EVENT_ECN_IS_CE { 1 } else { 0 };

    if *ce_state != new_ce_state {
        /* CE state has changed, force an immediate ACK to
         * reflect the new CE state. If an ACK was delayed,
         * send that first to reflect the prior CE state.
         */
        let pending = (&*(sk as *const inet_connection_sock)).icsk_ack().pending().as_mut_ptr();
        if (*pending & ICSK_ACK_TIMER) != 0 {
            dctcp_ece_ack_cwr(sk, *ce_state);
            bpf_tcp_send_ack(sk, *prior_rcv_nxt);
        }
        let pending = (&*(sk as *const inet_connection_sock)).icsk_ack().pending().as_mut_ptr();
        *pending |= ICSK_ACK_NOW;
    }
    *prior_rcv_nxt = *(&*(sk as *const tcp_sock)).rcv_nxt().as_ptr();
    *ce_state = new_ce_state;
    dctcp_ece_ack_cwr(sk, new_ce_state);
}

// BPF_PROG(bpf_dctcp_cwnd_event, struct sock *sk, enum tcp_ca_event ev)
#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn bpf_dctcp_cwnd_event(ctx: *const u64) {
    let sk = arg(ctx, 0) as *mut c_void;
    let ev = arg(ctx, 1) as u32;
    let ca = inet_csk_ca(sk);

    unsafe {
        match ev {
            CA_EVENT_ECN_IS_CE | CA_EVENT_ECN_NO_CE => {
                dctcp_ece_ack_update(sk, ev, addr_of_mut!((*ca).prior_rcv_nxt), addr_of_mut!((*ca).ce_state));
            }
            CA_EVENT_LOSS => {
                dctcp_react_to_loss(sk);
            }
            _ => {
                /* Don't care for the rest. */
            }
        }
    }
}

// __u32 BPF_PROG(bpf_dctcp_cwnd_undo, struct sock *sk)
#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn bpf_dctcp_cwnd_undo(ctx: *const u64) -> u32 {
    let sk = arg(ctx, 0) as *mut c_void;
    let ca = inet_csk_ca(sk);

    unsafe { core::cmp::max(*(&*(sk as *const tcp_sock)).snd_cwnd().as_ptr(), (*ca).loss_cwnd) }
}

// BPF_PROG(bpf_dctcp_cong_avoid, struct sock *sk, __u32 ack, __u32 acked)
#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn bpf_dctcp_cong_avoid(ctx: *const u64) {
    let sk = arg(ctx, 0) as *mut c_void;
    let ack = arg(ctx, 1) as u32;
    let acked = arg(ctx, 2) as u32;

    unsafe { tcp_reno_cong_avoid(sk, ack, acked) };
}

// struct tcp_congestion_ops (net/tcp.h): only the members each instance
// initializes are declared; libbpf matches them against the kernel type by
// name, and strips the ___nouse flavor suffix.
#[allow(non_camel_case_types)]
#[repr(C)]
struct tcp_congestion_ops___nouse {
    init: extern "C" fn(*const u64),
    set_state: extern "C" fn(*const u64),
    flags: u32,
    name: [u8; 16],
}

unsafe impl Sync for tcp_congestion_ops___nouse {}

#[link_section = ".struct_ops"]
#[no_mangle]
static dctcp_nouse: tcp_congestion_ops___nouse = tcp_congestion_ops___nouse {
    init: bpf_dctcp_init,
    set_state: bpf_dctcp_state,
    flags: TCP_CONG_NEEDS_ECN,
    name: *b"bpf_dctcp_nouse\0",
};

#[allow(non_camel_case_types)]
#[repr(C)]
struct tcp_congestion_ops {
    init: extern "C" fn(*const u64),
    in_ack_event: extern "C" fn(*const u64),
    cwnd_event: extern "C" fn(*const u64),
    ssthresh: extern "C" fn(*const u64) -> u32,
    cong_avoid: extern "C" fn(*const u64),
    undo_cwnd: extern "C" fn(*const u64) -> u32,
    set_state: extern "C" fn(*const u64),
    flags: u32,
    name: [u8; 16],
}

unsafe impl Sync for tcp_congestion_ops {}

#[link_section = ".struct_ops"]
#[no_mangle]
static dctcp: tcp_congestion_ops = tcp_congestion_ops {
    init: bpf_dctcp_init,
    in_ack_event: bpf_dctcp_update_alpha,
    cwnd_event: bpf_dctcp_cwnd_event,
    ssthresh: bpf_dctcp_ssthresh,
    cong_avoid: bpf_dctcp_cong_avoid,
    undo_cwnd: bpf_dctcp_cwnd_undo,
    set_state: bpf_dctcp_state,
    flags: TCP_CONG_NEEDS_ECN,
    name: *b"bpf_dctcp\0\0\0\0\0\0\0",
};

bpf_object!("GPL");
