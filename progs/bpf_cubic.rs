#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_cubic.c,
// bpf-rs-core idiom.
//
// prog_tests/bpf_tcp_ca.c's test_cubic() opens/loads/attaches this
// struct_ops, sends 10MB over a real TCP connection with it as the
// congestion control, then asserts bpf_cubic_acked_called == 1 and both
// nodelay_*_reject bss flags are true. The arithmetic must be genuinely
// correct (not just verifier-legal) for the transfer to behave sanely,
// same class of test as bpf_cc_cubic.rs.
//
// sock / tcp_sock / inet_connection_sock all share address 0 with the
// struct_ops `sk` argument (container_of-collapse, same idiom as
// tcp_ca_update.rs), so each is declared as its own #[btf] root and cast
// directly from the raw ctx pointer. Every field access is its own
// #[inline(never)] accessor fn (one #[btf] chain per function) per
// [[btf-second-field-access-same-root-crashes-opt]].
//
// `extern unsigned long CONFIG_HZ __kconfig;` is dropped: prog_tests never
// reads skel->kconfig, and per [[kconfig-extern-userspace-field-access-unfixable]]
// rustc emits no BTF for extern statics, so keeping the extern would abort
// skeleton regen regardless. HZ is hardcoded to 1000, this session's
// FLAVOR=qemu test kernel's CONFIG_HZ (bpf-next-x86 checkout's .config).
//
// `tcp_is_cwnd_limited()`'s `is_cwnd_limited:1` bitfield has no plain
// sibling field *before* it, but `scaling_ratio` (a plain u8) sits exactly
// one byte before the bitfield's byte (confirmed via bpftool btf dump:
// scaling_ratio bits_offset=11888, is_cwnd_limited bits_offset=11899, same
// byte as repair/tcp_usec_ts/is_sack_reneg starting at 11896) -- same
// [[btf-bitfield-field-access-needs-adjacent-plain-field-workaround]]
// anchor+mask idiom as bpf_cc_cubic's icsk_ca_state.
//
// Signed-vs-unsigned comparison fidelity: C's `(__s32)(a - b) OP rhs` only
// performs a genuine signed comparison when rhs is itself signed
// (int/`static int` globals, or literal 0, as in before()/after()). When
// rhs is a `__u32` of the same rank the signed cast is a no-op for the
// comparison (usual arithmetic conversions convert the signed side back to
// unsigned, bit-for-bit identical to never casting), so those sites are
// translated as plain wrapping_sub + unsigned compare. When rhs is
// `unsigned long` (wider, 64-bit, from CONFIG_HZ-derived constants) the
// signed value is genuinely sign-extended before the unsigned widen, so
// those sites go through `as i32 as i64 as u64` before comparing/using.
// All divisions are guarded (`if divisor != 0`) per
// [[runtime-div-inserts-panic-const-div-by-zero]] even where the C
// preconditions make the zero case unreachable.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_jiffies64, bpf_setsockopt};
use bpf_rs_core::progs::fentry_arg as arg;
use btf_macros::btf;
use core::ffi::c_void;

const SOL_TCP: i32 = 6;
const TCP_NODELAY: i32 = 1;
const EOPNOTSUPP: i64 = 95;

const HZ: u32 = 1000;
const USEC_PER_MSEC: u64 = 1000;
const USEC_PER_SEC: u64 = 1_000_000;
const USEC_PER_JIFFY: u64 = USEC_PER_SEC / (HZ as u64);

const BICTCP_BETA_SCALE: u32 = 1024;
const BICTCP_HZ: u32 = 10;

const HYSTART_ACK_TRAIN: u32 = 0x1;
const HYSTART_DELAY: u32 = 0x2;
const HYSTART_DETECT: u32 = HYSTART_ACK_TRAIN | HYSTART_DELAY;

const HYSTART_MIN_SAMPLES: u8 = 8;
const HYSTART_DELAY_MIN: u32 = 4000;
const HYSTART_DELAY_MAX: u32 = 16000;

const FAST_CONVERGENCE: i32 = 1;
const BETA: u32 = 717;
const INITIAL_SSTHRESH: u32 = 0;
const BIC_SCALE: u32 = 41;
const TCP_FRIENDLINESS: i32 = 1;

const HYSTART: i32 = 1;
const HYSTART_LOW_WINDOW: u32 = 16;
const HYSTART_ACK_DELTA_US: i32 = 2000;

const CUBE_RTT_SCALE: u64 = (BIC_SCALE as u64) * 10;
const BETA_SCALE: u32 = 8 * (BICTCP_BETA_SCALE + BETA) / 3 / (BICTCP_BETA_SCALE - BETA);
const CUBE_FACTOR: u64 = (1u64 << (10 + 3 * BICTCP_HZ)) / (BIC_SCALE as u64 * 10);

const GSO_MAX_SIZE: u32 = 65536;
const SK_PACING_NONE: u32 = 0;
const TCP_CA_LOSS: u8 = 4;

static V: [u8; 64] = [
    0, 54, 54, 54, 118, 118, 118, 118, 123, 129, 134, 138, 143, 147, 151, 156, 157, 161, 164, 168,
    170, 173, 176, 179, 181, 185, 187, 190, 192, 194, 197, 199, 200, 202, 204, 206, 209, 211, 213,
    215, 217, 219, 221, 222, 224, 225, 227, 229, 231, 232, 234, 236, 237, 239, 240, 242, 244, 245,
    246, 248, 250, 251, 252, 254,
];

#[repr(C)]
struct BpfBictcp {
    cnt: u32,
    last_max_cwnd: u32,
    last_cwnd: u32,
    last_time: u32,
    bic_origin_point: u32,
    bic_k: u32,
    delay_min: u32,
    epoch_start: u32,
    ack_cnt: u32,
    tcp_cwnd: u32,
    unused: u16,
    sample_cnt: u8,
    found: u8,
    round_start: u32,
    end_seq: u32,
    last_ack: u32,
    curr_rtt: u32,
}

#[btf]
struct sock {
    sk_pacing_rate: u64,
    sk_pacing_status: u32,
}

#[btf]
struct tcp_sock {
    snd_cwnd: u32,
    snd_ssthresh: u32,
    lsndtime: u32,
    snd_nxt: u32,
    tcp_mstamp: u64,
    max_packets_out: u32,
    scaling_ratio: u8,
}

#[btf]
struct inet_connection_sock {
    icsk_ca_priv: [u64; 13],
}

#[btf]
struct ack_sample {
    rtt_us: i32,
}

#[inline(never)]
fn tp_snd_cwnd(tp: *const tcp_sock) -> u32 {
    *unsafe { &*tp }.snd_cwnd().get().unwrap()
}

#[inline(never)]
fn tp_snd_ssthresh_ptr(tp: *const tcp_sock) -> *mut u32 {
    unsafe { &*tp }.snd_ssthresh().as_mut_ptr()
}

#[inline(never)]
fn tp_lsndtime(tp: *const tcp_sock) -> u32 {
    *unsafe { &*tp }.lsndtime().get().unwrap()
}

#[inline(never)]
fn tp_snd_nxt(tp: *const tcp_sock) -> u32 {
    *unsafe { &*tp }.snd_nxt().get().unwrap()
}

#[inline(never)]
fn tp_tcp_mstamp(tp: *const tcp_sock) -> u64 {
    *unsafe { &*tp }.tcp_mstamp().get().unwrap()
}

#[inline(never)]
fn tp_max_packets_out(tp: *const tcp_sock) -> u32 {
    *unsafe { &*tp }.max_packets_out().get().unwrap()
}

#[inline(never)]
fn tp_scaling_ratio_ptr(tp: *const tcp_sock) -> *const u8 {
    unsafe { &*tp }.scaling_ratio().as_ptr()
}

#[inline(never)]
fn sk_pacing_rate_val(sk: *const sock) -> u64 {
    *unsafe { &*sk }.sk_pacing_rate().get().unwrap()
}

#[inline(never)]
fn sk_pacing_status_val(sk: *const sock) -> u32 {
    *unsafe { &*sk }.sk_pacing_status().get().unwrap()
}

#[inline(never)]
fn icsk_ca_priv_ptr(icsk: *const inet_connection_sock) -> *mut u64 {
    unsafe { &*icsk }.icsk_ca_priv().as_mut_ptr() as *mut u64
}

#[inline(never)]
fn sample_rtt_us(s: *const ack_sample) -> i32 {
    *unsafe { &*s }.rtt_us().get().unwrap()
}

#[inline(always)]
fn inet_csk_ca(sk: *const c_void) -> *mut BpfBictcp {
    icsk_ca_priv_ptr(sk as *const inet_connection_sock) as *mut BpfBictcp
}

#[inline(always)]
fn tcp_jiffies32() -> u32 {
    bpf_jiffies64() as u32
}

#[inline(always)]
fn before(seq1: u32, seq2: u32) -> bool {
    (seq1.wrapping_sub(seq2) as i32) < 0
}

#[inline(always)]
fn after(seq2: u32, seq1: u32) -> bool {
    before(seq1, seq2)
}

#[inline(always)]
fn safe_div_u32(a: u32, b: u32) -> u32 {
    if b != 0 {
        a / b
    } else {
        0
    }
}

#[inline(always)]
fn safe_div_u64(a: u64, b: u64) -> u64 {
    if b != 0 {
        a / b
    } else {
        0
    }
}

unsafe fn bictcp_reset(ca: *mut BpfBictcp) {
    (*ca).cnt = 0;
    (*ca).last_max_cwnd = 0;
    (*ca).last_cwnd = 0;
    (*ca).last_time = 0;
    (*ca).bic_origin_point = 0;
    (*ca).bic_k = 0;
    (*ca).delay_min = 0;
    (*ca).epoch_start = 0;
    (*ca).ack_cnt = 0;
    (*ca).tcp_cwnd = 0;
    (*ca).found = 0;
}

fn bictcp_clock_us(sk: *const c_void) -> u32 {
    tp_tcp_mstamp(sk as *const tcp_sock) as u32
}

fn bictcp_hystart_reset(sk: *const c_void) {
    let tp = sk as *const tcp_sock;
    let ca = inet_csk_ca(sk);
    let now = bictcp_clock_us(sk);
    unsafe {
        (*ca).round_start = now;
        (*ca).last_ack = now;
        (*ca).end_seq = tp_snd_nxt(tp);
        (*ca).curr_rtt = !0u32;
        (*ca).sample_cnt = 0;
    }
}

fn fls64(x_in: u64) -> u32 {
    if x_in == 0 {
        return 0;
    }
    let mut num: i32 = 63;
    let mut x = x_in;
    if x & (!0u64 << 32) == 0 {
        num -= 32;
        x <<= 32;
    }
    if x & (!0u64 << 48) == 0 {
        num -= 16;
        x <<= 16;
    }
    if x & (!0u64 << 56) == 0 {
        num -= 8;
        x <<= 8;
    }
    if x & (!0u64 << 60) == 0 {
        num -= 4;
        x <<= 4;
    }
    if x & (!0u64 << 62) == 0 {
        num -= 2;
        x <<= 2;
    }
    if x & (!0u64 << 63) == 0 {
        num -= 1;
    }
    (num + 1) as u32
}

fn cubic_root(a: u64) -> u32 {
    if a < 64 {
        return (V.get(a as usize).copied().unwrap_or(0) as u32 + 35) >> 6;
    }

    let b0 = fls64(a);
    let b = ((b0.wrapping_mul(84)) >> 8).wrapping_sub(1);
    let shift = (a >> (b.wrapping_mul(3))) as u32;

    if shift >= 64 {
        return 0;
    }

    let mut x = ((V.get(shift as usize).copied().unwrap_or(0) as u32).wrapping_add(10)) << b;
    x >>= 6;

    let denom = (x as u64).wrapping_mul((x.wrapping_sub(1)) as u64);
    x = (2u32.wrapping_mul(x)).wrapping_add(safe_div_u64(a, denom) as u32);
    x = (x.wrapping_mul(341)) >> 10;
    x
}

fn bictcp_update(ca: *mut BpfBictcp, cwnd: u32, acked: u32) {
    let now = tcp_jiffies32();

    unsafe {
        (*ca).ack_cnt = (*ca).ack_cnt.wrapping_add(acked);

        let diff32 = now.wrapping_sub((*ca).last_time);
        let diff64 = ((diff32 as i32) as i64) as u64;
        if (*ca).last_cwnd == cwnd && diff64 <= (HZ as u64) / 32 {
            return;
        }

        let skip_cubic = (*ca).epoch_start != 0 && now == (*ca).last_time;

        if !skip_cubic {
            (*ca).last_cwnd = cwnd;
            (*ca).last_time = now;

            if (*ca).epoch_start == 0 {
                (*ca).epoch_start = now;
                (*ca).ack_cnt = acked;
                (*ca).tcp_cwnd = cwnd;

                if (*ca).last_max_cwnd <= cwnd {
                    (*ca).bic_k = 0;
                    (*ca).bic_origin_point = cwnd;
                } else {
                    let diff = (*ca).last_max_cwnd.wrapping_sub(cwnd);
                    (*ca).bic_k = cubic_root(CUBE_FACTOR.wrapping_mul(diff as u64));
                    (*ca).bic_origin_point = (*ca).last_max_cwnd;
                }
            }

            let t_diff32 = now.wrapping_sub((*ca).epoch_start);
            let mut t: u64 = (((t_diff32 as i32) as i64) as u64).wrapping_mul(USEC_PER_JIFFY);
            t = t.wrapping_add((*ca).delay_min as u64);
            t <<= BICTCP_HZ;
            t = safe_div_u64(t, USEC_PER_SEC);

            let bic_k = (*ca).bic_k as u64;
            let below_origin = t < bic_k;
            let offs = if below_origin {
                bic_k.wrapping_sub(t)
            } else {
                t.wrapping_sub(bic_k)
            };

            let delta64 = CUBE_RTT_SCALE
                .wrapping_mul(offs)
                .wrapping_mul(offs)
                .wrapping_mul(offs)
                >> (10 + 3 * BICTCP_HZ);
            let delta = delta64 as u32;

            let bic_target = if below_origin {
                (*ca).bic_origin_point.wrapping_sub(delta)
            } else {
                (*ca).bic_origin_point.wrapping_add(delta)
            };

            if bic_target > cwnd {
                (*ca).cnt = safe_div_u32(cwnd, bic_target.wrapping_sub(cwnd));
            } else {
                (*ca).cnt = 100u32.wrapping_mul(cwnd);
            }

            if (*ca).last_max_cwnd == 0 && (*ca).cnt > 20 {
                (*ca).cnt = 20;
            }
        }

        if TCP_FRIENDLINESS != 0 {
            let scale = BETA_SCALE;
            let mut delta = cwnd.wrapping_mul(scale) >> 3;
            if (*ca).ack_cnt > delta && delta != 0 {
                let n = safe_div_u32((*ca).ack_cnt, delta);
                (*ca).ack_cnt = (*ca).ack_cnt.wrapping_sub(n.wrapping_mul(delta));
                (*ca).tcp_cwnd = (*ca).tcp_cwnd.wrapping_add(n);
            }

            if (*ca).tcp_cwnd > cwnd {
                delta = (*ca).tcp_cwnd.wrapping_sub(cwnd);
                let max_cnt = safe_div_u32(cwnd, delta);
                if (*ca).cnt > max_cnt {
                    (*ca).cnt = max_cnt;
                }
            }
        }

        (*ca).cnt = core::cmp::max((*ca).cnt, 2);
    }
}

fn tcp_in_slow_start(tp: *const tcp_sock) -> bool {
    tp_snd_cwnd(tp) < tp_snd_ssthresh_val(tp)
}

#[inline(never)]
fn tp_snd_ssthresh_val(tp: *const tcp_sock) -> u32 {
    *unsafe { &*tp }.snd_ssthresh().get().unwrap()
}

fn tcp_is_cwnd_limited(tp: *const tcp_sock) -> bool {
    let snd_cwnd = tp_snd_cwnd(tp);
    let snd_ssthresh = tp_snd_ssthresh_val(tp);
    if snd_cwnd < snd_ssthresh {
        let max_packets_out = tp_max_packets_out(tp);
        return snd_cwnd < 2u32.wrapping_mul(max_packets_out);
    }

    let anchor = tp_scaling_ratio_ptr(tp);
    let byte = unsafe { *anchor.add(1) };
    (byte & 0x08) != 0
}

fn hystart_ack_delay(sk: *const c_void) -> u32 {
    let rate = sk_pacing_rate_val(sk as *const sock);
    if rate == 0 {
        return 0;
    }
    let numer: u64 = (GSO_MAX_SIZE as u64).wrapping_mul(4).wrapping_mul(USEC_PER_SEC);
    let val = safe_div_u64(numer, rate);
    core::cmp::min(USEC_PER_MSEC, val) as u32
}

fn hystart_delay_thresh(x: u32) -> u32 {
    core::cmp::min(core::cmp::max(x, HYSTART_DELAY_MIN), HYSTART_DELAY_MAX)
}

fn hystart_update(sk: *const c_void, delay: u32) {
    let tp = sk as *const tcp_sock;
    let ca = inet_csk_ca(sk);

    if HYSTART_DETECT & HYSTART_ACK_TRAIN != 0 {
        let now = bictcp_clock_us(sk);
        unsafe {
            if ((now.wrapping_sub((*ca).last_ack)) as i32) <= HYSTART_ACK_DELTA_US {
                (*ca).last_ack = now;

                let mut threshold = (*ca).delay_min.wrapping_add(hystart_ack_delay(sk));

                if sk_pacing_status_val(sk as *const sock) == SK_PACING_NONE {
                    threshold >>= 1;
                }

                if now.wrapping_sub((*ca).round_start) > threshold {
                    (*ca).found = 1;
                    *tp_snd_ssthresh_ptr(tp) = tp_snd_cwnd(tp);
                }
            }
        }
    }

    if HYSTART_DETECT & HYSTART_DELAY != 0 {
        unsafe {
            if (*ca).curr_rtt > delay {
                (*ca).curr_rtt = delay;
            }
            if (*ca).sample_cnt < HYSTART_MIN_SAMPLES {
                (*ca).sample_cnt = (*ca).sample_cnt.wrapping_add(1);
            } else {
                let thresh = hystart_delay_thresh((*ca).delay_min >> 3);
                if (*ca).curr_rtt > (*ca).delay_min.wrapping_add(thresh) {
                    (*ca).found = 1;
                    *tp_snd_ssthresh_ptr(tp) = tp_snd_cwnd(tp);
                }
            }
        }
    }
}

#[no_mangle]
static mut nodelay_init_reject: bool = false;
#[no_mangle]
static mut nodelay_cwnd_event_tx_start_reject: bool = false;
#[no_mangle]
static mut bpf_cubic_acked_called: i32 = 0;

extern "C" {
    fn tcp_slow_start(tp: *mut c_void, acked: u32) -> u32;
    fn tcp_cong_avoid_ai(tp: *mut c_void, w: u32, acked: u32);
    fn tcp_reno_undo_cwnd(sk: *mut c_void) -> u32;
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn bpf_cubic_init(ctx: *const u64) {
    let sk = arg(ctx, 0) as *mut c_void;
    let ca = inet_csk_ca(sk);

    let true_val: i32 = 1;
    let ret = bpf_setsockopt(
        sk,
        SOL_TCP,
        TCP_NODELAY,
        &true_val as *const i32 as *const c_void,
        core::mem::size_of::<i32>() as i32,
    );
    if ret == -EOPNOTSUPP {
        unsafe { nodelay_init_reject = true };
    }

    unsafe { bictcp_reset(ca) };

    if HYSTART != 0 {
        bictcp_hystart_reset(sk as *const c_void);
    }

    if HYSTART == 0 && INITIAL_SSTHRESH != 0 {
        let tp = sk as *const tcp_sock;
        unsafe { *tp_snd_ssthresh_ptr(tp) = INITIAL_SSTHRESH };
    }
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn bpf_cubic_cwnd_event_tx_start(ctx: *const u64) {
    let sk = arg(ctx, 0) as *mut c_void;
    let ca = inet_csk_ca(sk);
    let now = tcp_jiffies32();

    let true_val: i32 = 1;
    let ret = bpf_setsockopt(
        sk,
        SOL_TCP,
        TCP_NODELAY,
        &true_val as *const i32 as *const c_void,
        core::mem::size_of::<i32>() as i32,
    );
    if ret == -EOPNOTSUPP {
        unsafe { nodelay_cwnd_event_tx_start_reject = true };
    }

    let lsndtime = tp_lsndtime(sk as *const tcp_sock);
    let delta = (now.wrapping_sub(lsndtime)) as i32;

    unsafe {
        if (*ca).epoch_start != 0 && delta > 0 {
            (*ca).epoch_start = (*ca).epoch_start.wrapping_add(delta as u32);
            if after((*ca).epoch_start, now) {
                (*ca).epoch_start = now;
            }
        }
    }
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn bpf_cubic_cong_avoid(ctx: *const u64) {
    let sk = arg(ctx, 0) as *const c_void;
    let ack = arg(ctx, 1) as u32;
    let mut acked = arg(ctx, 2) as u32;

    let tp = sk as *const tcp_sock;
    let ca = inet_csk_ca(sk);

    if !tcp_is_cwnd_limited(tp) {
        return;
    }

    if tcp_in_slow_start(tp) {
        if HYSTART != 0 {
            let end_seq = unsafe { (*ca).end_seq };
            if after(ack, end_seq) {
                bictcp_hystart_reset(sk);
            }
        }
        acked = unsafe { tcp_slow_start(tp as *mut c_void, acked) };
        if acked == 0 {
            return;
        }
    }

    bictcp_update(ca, tp_snd_cwnd(tp), acked);
    let cnt = unsafe { (*ca).cnt };
    unsafe { tcp_cong_avoid_ai(tp as *mut c_void, cnt, acked) };
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn bpf_cubic_recalc_ssthresh(ctx: *const u64) -> u32 {
    let sk = arg(ctx, 0) as *const c_void;
    let tp = sk as *const tcp_sock;
    let ca = inet_csk_ca(sk);

    let snd_cwnd = tp_snd_cwnd(tp);

    unsafe {
        (*ca).epoch_start = 0;

        if snd_cwnd < (*ca).last_max_cwnd && FAST_CONVERGENCE != 0 {
            (*ca).last_max_cwnd =
                snd_cwnd.wrapping_mul(BICTCP_BETA_SCALE + BETA) / (2 * BICTCP_BETA_SCALE);
        } else {
            (*ca).last_max_cwnd = snd_cwnd;
        }
    }

    core::cmp::max(snd_cwnd.wrapping_mul(BETA) / BICTCP_BETA_SCALE, 2)
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn bpf_cubic_state(ctx: *const u64) {
    let sk = arg(ctx, 0) as *const c_void;
    let new_state = arg(ctx, 1) as u8;

    if new_state == TCP_CA_LOSS {
        unsafe { bictcp_reset(inet_csk_ca(sk)) };
        bictcp_hystart_reset(sk);
    }
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn bpf_cubic_acked(ctx: *const u64) {
    let sk = arg(ctx, 0) as *const c_void;
    let sample = arg(ctx, 1) as *const ack_sample;
    let tp = sk as *const tcp_sock;
    let ca = inet_csk_ca(sk);

    unsafe { bpf_cubic_acked_called = 1 };

    let rtt_us = sample_rtt_us(sample);
    if rtt_us < 0 {
        return;
    }

    let now = tcp_jiffies32();
    unsafe {
        if (*ca).epoch_start != 0
            && ((((now.wrapping_sub((*ca).epoch_start)) as i32) as i64) as u64) < (HZ as u64)
        {
            return;
        }
    }

    let mut delay = rtt_us as u32;
    if delay == 0 {
        delay = 1;
    }

    unsafe {
        if (*ca).delay_min == 0 || (*ca).delay_min > delay {
            (*ca).delay_min = delay;
        }

        let found = (*ca).found;
        let snd_cwnd = tp_snd_cwnd(tp);
        let snd_ssthresh = tp_snd_ssthresh_val(tp);

        if found == 0
            && snd_cwnd < snd_ssthresh
            && HYSTART != 0
            && snd_cwnd >= HYSTART_LOW_WINDOW
        {
            hystart_update(sk, delay);
        }
    }
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn bpf_cubic_undo_cwnd(ctx: *const u64) -> u32 {
    let sk = arg(ctx, 0) as *mut c_void;
    unsafe { tcp_reno_undo_cwnd(sk) }
}

// struct tcp_congestion_ops (net/tcp.h): only the members this program
// initializes are declared -- libbpf's struct_ops relocation matches local
// struct members against the kernel type by name (see bpf_tcp_nogpl.rs).
#[allow(non_camel_case_types)]
#[repr(C)]
struct tcp_congestion_ops {
    init: extern "C" fn(*const u64),
    ssthresh: extern "C" fn(*const u64) -> u32,
    cong_avoid: extern "C" fn(*const u64),
    set_state: extern "C" fn(*const u64),
    undo_cwnd: extern "C" fn(*const u64) -> u32,
    cwnd_event_tx_start: extern "C" fn(*const u64),
    pkts_acked: extern "C" fn(*const u64),
    name: [u8; 16],
}

unsafe impl Sync for tcp_congestion_ops {}

#[link_section = ".struct_ops"]
#[no_mangle]
static cubic: tcp_congestion_ops = tcp_congestion_ops {
    init: bpf_cubic_init,
    ssthresh: bpf_cubic_recalc_ssthresh,
    cong_avoid: bpf_cubic_cong_avoid,
    set_state: bpf_cubic_state,
    undo_cwnd: bpf_cubic_undo_cwnd,
    cwnd_event_tx_start: bpf_cubic_cwnd_event_tx_start,
    pkts_acked: bpf_cubic_acked,
    name: *b"bpf_cubic\0\0\0\0\0\0\0",
};

bpf_object!("GPL");
