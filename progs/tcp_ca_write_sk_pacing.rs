#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/tcp_ca_write_sk_pacing.c,
// bpf-rs-core idiom.
//
// prog_tests/bpf_tcp_ca.c's test_write_sk_pacing() only open_and_load +
// attach_struct_ops + destroy — no assertions on program bodies, so the
// four struct_ops callbacks below just need to load and run without
// verifier rejection, computing the same values the C original does.
//
// This selftests object is built with -DENABLE_ATOMICS_TESTS (Makefile's
// TRUNNER_BPF_CFLAGS, unconditional for this target), so write_sk_pacing_init
// takes the C source's __sync_bool_compare_and_swap branch: a BPF_CMPXCHG
// atomic on sk->sk_pacing_status, expressed as
// core::sync::atomic::AtomicU32::compare_exchange on the field's address
// (same idiom as atomics.rs's cmpxchg, minus the barrier-store return-value
// plumbing since the C source discards the CAS result too). Writes to
// sk->sk_pacing_status/sk_pacing_rate and tcp_sock's app_limited are
// permitted by net/ipv4/bpf_tcp_ca.c's bpf_tcp_ca_btf_struct_access() member
// allowlist; the ctx `sk` register is promoted from BTF type "sock" to
// "tcp_sock" at the raw ctx-array access (bpf_tcp_ca_is_valid_access), so
// fields of both local mirror structs below resolve against the same
// underlying pointer.

use bpf_rs_core::bpf_object;
use bpf_rs_core::progs::fentry_arg as arg;
use btf_macros::btf;
use core::sync::atomic::{AtomicU32, Ordering};

const SK_PACING_NONE: u32 = 0;
const SK_PACING_NEEDED: u32 = 1;
const USEC_PER_SEC: u64 = 1_000_000;

#[btf]
struct sock {
    sk_pacing_status: u32,
    sk_pacing_rate: u64,
    sk_max_pacing_rate: u64,
}

#[btf]
struct tcp_sock {
    sacked_out: u32,
    lost_out: u32,
    packets_out: u32,
    retrans_out: u32,
    snd_cwnd: u32,
    mss_cache: u32,
    srtt_us: u32,
    delivered: u32,
    app_limited: u32,
    snd_ssthresh: u32,
}

fn tcp_left_out(tp: *const tcp_sock) -> u32 {
    let sacked_out = unsafe { *(&*tp).sacked_out().as_ptr() };
    let lost_out = unsafe { *(&*tp).lost_out().as_ptr() };
    sacked_out.wrapping_add(lost_out)
}

fn tcp_packets_in_flight(tp: *const tcp_sock) -> u32 {
    let packets_out = unsafe { *(&*tp).packets_out().as_ptr() };
    let retrans_out = unsafe { *(&*tp).retrans_out().as_ptr() };
    packets_out
        .wrapping_sub(tcp_left_out(tp))
        .wrapping_add(retrans_out)
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn write_sk_pacing_init(ctx: *const u64) {
    let sk = arg(ctx, 0) as *const sock;
    let status_ptr = unsafe { (&*sk).sk_pacing_status().as_mut_ptr() } as *mut AtomicU32;
    let _ = unsafe {
        (*status_ptr).compare_exchange(
            SK_PACING_NONE,
            SK_PACING_NEEDED,
            Ordering::SeqCst,
            Ordering::SeqCst,
        )
    };
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn write_sk_pacing_cong_control(ctx: *const u64) {
    let sk = arg(ctx, 0) as *const sock;
    let tp = arg(ctx, 0) as *const tcp_sock;

    let snd_cwnd = unsafe { *(&*tp).snd_cwnd().as_ptr() };
    let mss_cache = unsafe { *(&*tp).mss_cache().as_ptr() };
    let srtt_us = unsafe { *(&*tp).srtt_us().as_ptr() };

    let cwnd_mss = snd_cwnd.wrapping_mul(mss_cache);
    let divisor: u64 = if srtt_us != 0 { srtt_us as u64 } else { 1u64 << 3 };
    let rate: u64 = ((cwnd_mss as u64).wrapping_mul(USEC_PER_SEC) << 3) / divisor;

    let max_pacing_rate = unsafe { *(&*sk).sk_max_pacing_rate().as_ptr() };
    let pacing_rate = if rate < max_pacing_rate {
        rate
    } else {
        max_pacing_rate
    };
    unsafe { *(&*sk).sk_pacing_rate().as_mut_ptr() = pacing_rate };

    let delivered = unsafe { *(&*tp).delivered().as_ptr() };
    let in_flight = tcp_packets_in_flight(tp);
    let app_limited_sum = delivered.wrapping_add(in_flight);
    let app_limited = if app_limited_sum != 0 { app_limited_sum } else { 1 };
    unsafe { *(&*tp).app_limited().as_mut_ptr() = app_limited };
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn write_sk_pacing_ssthresh(ctx: *const u64) -> u32 {
    let tp = arg(ctx, 0) as *const tcp_sock;
    unsafe { *(&*tp).snd_ssthresh().as_ptr() }
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn write_sk_pacing_undo_cwnd(ctx: *const u64) -> u32 {
    let tp = arg(ctx, 0) as *const tcp_sock;
    unsafe { *(&*tp).snd_cwnd().as_ptr() }
}

// struct tcp_congestion_ops (net/tcp.h): only the members this program
// initializes are declared — libbpf's struct_ops relocation matches local
// struct members against the kernel type by name (see bpf_tcp_nogpl.rs).
#[allow(non_camel_case_types)]
#[repr(C)]
struct tcp_congestion_ops {
    init: extern "C" fn(*const u64),
    cong_control: extern "C" fn(*const u64),
    ssthresh: extern "C" fn(*const u64) -> u32,
    undo_cwnd: extern "C" fn(*const u64) -> u32,
    name: [u8; 16],
}

unsafe impl Sync for tcp_congestion_ops {}

#[link_section = ".struct_ops"]
#[no_mangle]
static write_sk_pacing: tcp_congestion_ops = tcp_congestion_ops {
    init: write_sk_pacing_init,
    cong_control: write_sk_pacing_cong_control,
    ssthresh: write_sk_pacing_ssthresh,
    undo_cwnd: write_sk_pacing_undo_cwnd,
    name: *b"bpf_w_sk_pacing\0",
};

bpf_object!("GPL");
