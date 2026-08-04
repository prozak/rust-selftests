#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_cc_cubic.c
// (bpf-rs-core idiom).
//
// `cong_control` replaces `cong_avoid`/`tcp_cwnd_reduction`/
// `tcp_update_pacing_rate`, which are inlined by the kernel proper; this
// program reimplements those three static helpers in Rust and calls back
// into the real CUBIC implementation via the `cubictcp_*`/`tcp_reno_*`
// kfuncs for everything else (`tcp_sk(sk)`/`inet_csk(sk)` are
// address-identical casts, same container_of chain documented in
// tcp_ca_incompl_cong_ops.rs).
//
// Each distinct `#[btf]` field read/write is isolated in its own
// `#[inline(never)]` accessor taking the root pointer, per
// btf-second-field-access-same-root-crashes-opt /
// btf-chain-merge-across-branches-corrupts-debuginfo (kfree_skb.rs is the
// established idiom this mirrors) — this program touches far more fields
// than any prior translation, so the one-field-per-function discipline is
// load-bearing throughout, not just incidental.
//
// `icsk_ca_state` is a real kernel bitfield (`__u8 icsk_ca_state:5, ...`),
// which a direct `#[btf]` field relocation can never resolve (see
// btf-bitfield-field-access-needs-adjacent-plain-field-workaround): the
// containing byte is reached instead via the adjacent plain sibling field
// `icsk_retransmits` (immediately after `icsk_ca_state`'s byte) minus one.
//
// `div64_u64`'s plain `/` would otherwise compile to a reachable
// div-by-zero panic (see runtime-div-inserts-panic-const-div-by-zero);
// guarded the same way as test_tc_edt.rs.

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_jiffies64;
use bpf_rs_core::progs::fentry_arg;
use btf_macros::btf;

const TCP_PACING_SS_RATIO: u64 = 200;
const TCP_PACING_CA_RATIO: u64 = 120;
const TCP_REORDERING: u32 = 12;
const TCP_INFINITE_SSTHRESH: u32 = 0x7fffffff;
const TCP_CA_CWR: u32 = 2;
const TCP_CA_RECOVERY: u32 = 3;
const FLAG_DATA_ACKED: i32 = 0x04;
const FLAG_FORWARD_PROGRESS: i32 = 0x34; // FLAG_ACKED (0x14) | FLAG_DATA_SACKED (0x20)
const FLAG_SND_UNA_ADVANCED: i32 = 0x400;
const USEC_PER_SEC: u64 = 1_000_000;

extern "C" {
    fn cubictcp_init(sk: *mut c_void);
    fn cubictcp_cwnd_event_tx_start(sk: *mut c_void);
    fn cubictcp_recalc_ssthresh(sk: *mut c_void) -> u32;
    fn cubictcp_state(sk: *mut c_void, new_state: u8);
    fn tcp_reno_undo_cwnd(sk: *mut c_void) -> u32;
    fn cubictcp_acked(sk: *mut c_void, sample: *const c_void);
    fn cubictcp_cong_avoid(sk: *mut c_void, ack: u32, acked: u32);
}

#[btf]
struct sock {
    sk_pacing_rate: u64,
    sk_max_pacing_rate: u64,
}

#[btf]
struct inet_connection_sock {
    icsk_retransmits: u8,
}

#[btf]
struct tcp_sock {
    mss_cache: u32,
    snd_cwnd: u32,
    snd_cwnd_stamp: u32,
    snd_ssthresh: u32,
    packets_out: u32,
    srtt_us: u32,
    sacked_out: u32,
    lost_out: u32,
    retrans_out: u32,
    prior_cwnd: u32,
    prr_delivered: u32,
    prr_out: u32,
    snd_una: u32,
    high_seq: u32,
    reordering: u32,
}

#[btf]
struct rate_sample {
    acked_sacked: u32,
    losses: i32,
}

#[inline(never)]
fn sk_set_pacing_rate(sk: *const sock, v: u64) {
    unsafe { *(&*sk).sk_pacing_rate().as_mut_ptr() = v };
}

#[inline(never)]
fn sk_max_pacing_rate(sk: *const sock) -> u64 {
    *unsafe { &*sk }.sk_max_pacing_rate().get().unwrap()
}

#[inline(never)]
fn icsk_ca_state_anchor_byte(icsk: *const inet_connection_sock) -> u8 {
    let anchor = unsafe { &*icsk }.icsk_retransmits().as_ptr();
    unsafe { *anchor.sub(1) }
}

#[inline(never)]
fn tp_mss_cache(tp: *const tcp_sock) -> u32 {
    *unsafe { &*tp }.mss_cache().get().unwrap()
}

#[inline(never)]
fn tp_snd_cwnd(tp: *const tcp_sock) -> u32 {
    *unsafe { &*tp }.snd_cwnd().get().unwrap()
}

#[inline(never)]
fn tp_set_snd_cwnd(tp: *const tcp_sock, v: u32) {
    unsafe { *(&*tp).snd_cwnd().as_mut_ptr() = v };
}

#[inline(never)]
fn tp_set_snd_cwnd_stamp(tp: *const tcp_sock, v: u32) {
    unsafe { *(&*tp).snd_cwnd_stamp().as_mut_ptr() = v };
}

#[inline(never)]
fn tp_snd_ssthresh(tp: *const tcp_sock) -> u32 {
    *unsafe { &*tp }.snd_ssthresh().get().unwrap()
}

#[inline(never)]
fn tp_packets_out(tp: *const tcp_sock) -> u32 {
    *unsafe { &*tp }.packets_out().get().unwrap()
}

#[inline(never)]
fn tp_srtt_us(tp: *const tcp_sock) -> u32 {
    *unsafe { &*tp }.srtt_us().get().unwrap()
}

#[inline(never)]
fn tp_sacked_out(tp: *const tcp_sock) -> u32 {
    *unsafe { &*tp }.sacked_out().get().unwrap()
}

#[inline(never)]
fn tp_lost_out(tp: *const tcp_sock) -> u32 {
    *unsafe { &*tp }.lost_out().get().unwrap()
}

#[inline(never)]
fn tp_retrans_out(tp: *const tcp_sock) -> u32 {
    *unsafe { &*tp }.retrans_out().get().unwrap()
}

#[inline(never)]
fn tp_prior_cwnd(tp: *const tcp_sock) -> u32 {
    *unsafe { &*tp }.prior_cwnd().get().unwrap()
}

#[inline(never)]
fn tp_prr_delivered(tp: *const tcp_sock) -> u32 {
    *unsafe { &*tp }.prr_delivered().get().unwrap()
}

#[inline(never)]
fn tp_prr_out(tp: *const tcp_sock) -> u32 {
    *unsafe { &*tp }.prr_out().get().unwrap()
}

#[inline(never)]
fn tp_snd_una(tp: *const tcp_sock) -> u32 {
    *unsafe { &*tp }.snd_una().get().unwrap()
}

#[inline(never)]
fn tp_high_seq(tp: *const tcp_sock) -> u32 {
    *unsafe { &*tp }.high_seq().get().unwrap()
}

#[inline(never)]
fn tp_reordering(tp: *const tcp_sock) -> u32 {
    *unsafe { &*tp }.reordering().get().unwrap()
}

#[inline(never)]
fn rs_acked_sacked(rs: *const rate_sample) -> u32 {
    *unsafe { &*rs }.acked_sacked().get().unwrap()
}

#[inline(never)]
fn rs_losses(rs: *const rate_sample) -> i32 {
    *unsafe { &*rs }.losses().get().unwrap()
}

fn div64_u64(dividend: u64, divisor: u64) -> u64 {
    if divisor != 0 {
        dividend / divisor
    } else {
        0
    }
}

fn before(seq1: u32, seq2: u32) -> bool {
    (seq1.wrapping_sub(seq2) as i32) < 0
}

fn tcp_update_pacing_rate(tp: *const tcp_sock, sk: *const sock) {
    let mss_cache = tp_mss_cache(tp);
    let mut rate: u64 = (mss_cache as u64).wrapping_mul((USEC_PER_SEC / 100) << 3);

    let snd_cwnd = tp_snd_cwnd(tp);
    let snd_ssthresh = tp_snd_ssthresh(tp);
    if snd_cwnd < snd_ssthresh / 2 {
        rate = rate.wrapping_mul(TCP_PACING_SS_RATIO);
    } else {
        rate = rate.wrapping_mul(TCP_PACING_CA_RATIO);
    }

    let packets_out = tp_packets_out(tp);
    let cwnd_or_packets = if snd_cwnd > packets_out {
        snd_cwnd
    } else {
        packets_out
    };
    rate = rate.wrapping_mul(cwnd_or_packets as u64);

    let srtt_us = tp_srtt_us(tp);
    if srtt_us != 0 {
        rate = div64_u64(rate, srtt_us as u64);
    }

    let max_pacing_rate = sk_max_pacing_rate(sk);
    let pacing_rate = if rate < max_pacing_rate {
        rate
    } else {
        max_pacing_rate
    };
    sk_set_pacing_rate(sk, pacing_rate);
}

fn tcp_cwnd_reduction(tp: *const tcp_sock, newly_acked_sacked: i32, newly_lost: i32, flag: i32) {
    let packets_out = tp_packets_out(tp);
    let sacked_out = tp_sacked_out(tp);
    let lost_out = tp_lost_out(tp);
    let retrans_out = tp_retrans_out(tp);
    let pkts_in_flight = packets_out
        .wrapping_sub(sacked_out.wrapping_add(lost_out))
        .wrapping_add(retrans_out);

    let snd_ssthresh = tp_snd_ssthresh(tp);
    let delta = snd_ssthresh.wrapping_sub(pkts_in_flight) as i32;

    let prior_cwnd = tp_prior_cwnd(tp);
    if newly_acked_sacked <= 0 || prior_cwnd == 0 {
        return;
    }

    let prr_delivered = tp_prr_delivered(tp).wrapping_add(newly_acked_sacked as u32);
    let prr_out = tp_prr_out(tp);

    let mut sndcnt: i32;
    if delta < 0 {
        let dividend = (snd_ssthresh as u64)
            .wrapping_mul(prr_delivered as u64)
            .wrapping_add(prior_cwnd as u64)
            .wrapping_sub(1);
        sndcnt = (div64_u64(dividend, prior_cwnd as u64) as u32).wrapping_sub(prr_out) as i32;
    } else {
        let a = prr_delivered.wrapping_sub(prr_out);
        let b = newly_acked_sacked as u32;
        sndcnt = (if a > b { a } else { b }) as i32;
        if (flag & FLAG_SND_UNA_ADVANCED) != 0 && newly_lost == 0 {
            sndcnt = sndcnt.wrapping_add(1);
        }
        sndcnt = if delta < sndcnt { delta } else { sndcnt };
    }
    let floor = if prr_out != 0 { 0 } else { 1 };
    sndcnt = if sndcnt > floor { sndcnt } else { floor };

    tp_set_snd_cwnd(tp, pkts_in_flight.wrapping_add(sndcnt as u32));
}

fn tcp_may_raise_cwnd(tp: *const tcp_sock, flag: i32) -> bool {
    if tp_reordering(tp) > TCP_REORDERING {
        (flag & FLAG_FORWARD_PROGRESS) != 0
    } else {
        (flag & FLAG_DATA_ACKED) != 0
    }
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn bpf_cubic_init(ctx: *const u64) {
    let sk = fentry_arg(ctx, 0) as *mut c_void;
    unsafe { cubictcp_init(sk) };
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn bpf_cubic_cwnd_event_tx_start(ctx: *const u64) {
    let sk = fentry_arg(ctx, 0) as *mut c_void;
    unsafe { cubictcp_cwnd_event_tx_start(sk) };
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn bpf_cubic_cong_control(ctx: *const u64) {
    let sk_raw = fentry_arg(ctx, 0);
    let sk = sk_raw as *const sock;
    let tp = sk_raw as *const tcp_sock;
    let icsk = sk_raw as *const inet_connection_sock;
    let ack = fentry_arg(ctx, 1) as u32;
    let flag = fentry_arg(ctx, 2) as i32;
    let rs = fentry_arg(ctx, 3) as *const rate_sample;

    let ca_state = (icsk_ca_state_anchor_byte(icsk) & 0x1F) as u32;

    if ((1u32 << TCP_CA_CWR) | (1u32 << TCP_CA_RECOVERY)) & (1u32 << ca_state) != 0 {
        let acked_sacked = rs_acked_sacked(rs);
        let losses = rs_losses(rs);
        tcp_cwnd_reduction(tp, acked_sacked as i32, losses, flag);

        let snd_una = tp_snd_una(tp);
        let high_seq = tp_high_seq(tp);
        if !before(snd_una, high_seq) {
            let snd_ssthresh = tp_snd_ssthresh(tp);
            if snd_ssthresh < TCP_INFINITE_SSTHRESH && ca_state == TCP_CA_CWR {
                tp_set_snd_cwnd(tp, snd_ssthresh);
                tp_set_snd_cwnd_stamp(tp, bpf_jiffies64() as u32);
            }
        }
    } else if tcp_may_raise_cwnd(tp, flag) {
        let acked_sacked = rs_acked_sacked(rs);
        unsafe { cubictcp_cong_avoid(sk_raw as *mut c_void, ack, acked_sacked) };
        tp_set_snd_cwnd_stamp(tp, bpf_jiffies64() as u32);
    }

    tcp_update_pacing_rate(tp, sk);
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn bpf_cubic_recalc_ssthresh(ctx: *const u64) -> u32 {
    let sk = fentry_arg(ctx, 0) as *mut c_void;
    unsafe { cubictcp_recalc_ssthresh(sk) }
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn bpf_cubic_state(ctx: *const u64) {
    let sk = fentry_arg(ctx, 0) as *mut c_void;
    let new_state = fentry_arg(ctx, 1) as u8;
    unsafe { cubictcp_state(sk, new_state) };
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn bpf_cubic_acked(ctx: *const u64) {
    let sk = fentry_arg(ctx, 0) as *mut c_void;
    let sample = fentry_arg(ctx, 1) as *const c_void;
    unsafe { cubictcp_acked(sk, sample) };
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn bpf_cubic_undo_cwnd(ctx: *const u64) -> u32 {
    let sk = fentry_arg(ctx, 0) as *mut c_void;
    unsafe { tcp_reno_undo_cwnd(sk) }
}

// struct tcp_congestion_ops (net/tcp.h): only the members this program
// initializes are declared — libbpf's struct_ops relocation matches local
// struct members against the kernel type by name (see bpf_tcp_nogpl.rs).
#[allow(non_camel_case_types)]
#[repr(C)]
struct tcp_congestion_ops {
    init: extern "C" fn(*const u64),
    ssthresh: extern "C" fn(*const u64) -> u32,
    cong_control: extern "C" fn(*const u64),
    set_state: extern "C" fn(*const u64),
    undo_cwnd: extern "C" fn(*const u64) -> u32,
    cwnd_event_tx_start: extern "C" fn(*const u64),
    pkts_acked: extern "C" fn(*const u64),
    name: [u8; 16],
}

unsafe impl Sync for tcp_congestion_ops {}

#[link_section = ".struct_ops"]
#[no_mangle]
static cc_cubic: tcp_congestion_ops = tcp_congestion_ops {
    init: bpf_cubic_init,
    ssthresh: bpf_cubic_recalc_ssthresh,
    cong_control: bpf_cubic_cong_control,
    set_state: bpf_cubic_state,
    undo_cwnd: bpf_cubic_undo_cwnd,
    cwnd_event_tx_start: bpf_cubic_cwnd_event_tx_start,
    pkts_acked: bpf_cubic_acked,
    name: *b"bpf_cc_cubic\0\0\0\0",
};

bpf_object!("GPL");
