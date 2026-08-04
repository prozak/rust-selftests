#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/tcp_ca_kfunc.c,
// bpf-rs-core idiom.
//
// prog_tests/bpf_tcp_ca.c's test_tcp_ca_kfunc() only asserts
// tcp_ca_kfunc__open_and_load() succeeds -- no attach, no behavioral
// checks. Every callback body is a pure forwarder: it reads its struct_ops
// ctx slots and hands them straight to kernel kfuncs (the real
// bbr_*/dctcp_*/cubictcp_* implementations, exported __ksym by
// net/ipv4/tcp_{bbr,dctcp,cubic}.c) without ever dereferencing `sk`,
// `rs`, or `sample` on this side -- so plain `*mut c_void`/`*const c_void`
// opaque pointers suffice, no #[btf] CO-RE chain needed. add_ksyms.py
// mirrors each kfunc's real FUNC_PROTO from vmlinux BTF by symbol name
// (see Makefile's KSYM_BTF_FILES / bpf_xdp_pull_data precedent), so the
// Rust-side extern signature only needs to match arg count/order and
// register-compatible scalar sizes, not the exact kernel field types.

use bpf_rs_core::bpf_object;
use bpf_rs_core::progs::fentry_arg as arg;
use core::ffi::c_void;

extern "C" {
    fn bbr_init(sk: *mut c_void);
    fn bbr_main(sk: *mut c_void, ack: u32, flag: i32, rs: *const c_void);
    fn bbr_sndbuf_expand(sk: *mut c_void) -> u32;
    fn bbr_undo_cwnd(sk: *mut c_void) -> u32;
    fn bbr_cwnd_event_tx_start(sk: *mut c_void);
    fn bbr_ssthresh(sk: *mut c_void) -> u32;
    fn bbr_min_tso_segs(sk: *mut c_void) -> u32;
    fn bbr_set_state(sk: *mut c_void, new_state: u8);

    fn dctcp_init(sk: *mut c_void);
    fn dctcp_update_alpha(sk: *mut c_void, flags: u32);
    fn dctcp_cwnd_event(sk: *mut c_void, ev: u32);
    fn dctcp_cwnd_event_tx_start(sk: *mut c_void);
    fn dctcp_ssthresh(sk: *mut c_void) -> u32;
    fn dctcp_cwnd_undo(sk: *mut c_void) -> u32;
    fn dctcp_state(sk: *mut c_void, new_state: u8);

    fn cubictcp_init(sk: *mut c_void);
    fn cubictcp_recalc_ssthresh(sk: *mut c_void) -> u32;
    fn cubictcp_cong_avoid(sk: *mut c_void, ack: u32, acked: u32);
    fn cubictcp_state(sk: *mut c_void, new_state: u8);
    fn cubictcp_cwnd_event_tx_start(sk: *mut c_void);
    fn cubictcp_acked(sk: *mut c_void, sample: *const c_void);
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn init(ctx: *const u64) {
    let sk = arg(ctx, 0) as *mut c_void;
    unsafe {
        bbr_init(sk);
        dctcp_init(sk);
        cubictcp_init(sk);
    }
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn in_ack_event(ctx: *const u64) {
    let sk = arg(ctx, 0) as *mut c_void;
    let flags = arg(ctx, 1) as u32;
    unsafe { dctcp_update_alpha(sk, flags) };
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn cong_control(ctx: *const u64) {
    let sk = arg(ctx, 0) as *mut c_void;
    let ack = arg(ctx, 1) as u32;
    let flag = arg(ctx, 2) as i32;
    let rs = arg(ctx, 3) as *const c_void;
    unsafe { bbr_main(sk, ack, flag, rs) };
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn cong_avoid(ctx: *const u64) {
    let sk = arg(ctx, 0) as *mut c_void;
    let ack = arg(ctx, 1) as u32;
    let acked = arg(ctx, 2) as u32;
    unsafe { cubictcp_cong_avoid(sk, ack, acked) };
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn sndbuf_expand(ctx: *const u64) -> u32 {
    let sk = arg(ctx, 0) as *mut c_void;
    unsafe { bbr_sndbuf_expand(sk) }
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn undo_cwnd(ctx: *const u64) -> u32 {
    let sk = arg(ctx, 0) as *mut c_void;
    unsafe {
        bbr_undo_cwnd(sk);
        dctcp_cwnd_undo(sk)
    }
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn cwnd_event(ctx: *const u64) {
    let sk = arg(ctx, 0) as *mut c_void;
    let event = arg(ctx, 1) as u32;
    unsafe { dctcp_cwnd_event(sk, event) };
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn cwnd_event_tx_start(ctx: *const u64) {
    let sk = arg(ctx, 0) as *mut c_void;
    unsafe {
        bbr_cwnd_event_tx_start(sk);
        dctcp_cwnd_event_tx_start(sk);
        cubictcp_cwnd_event_tx_start(sk);
    }
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn ssthresh(ctx: *const u64) -> u32 {
    let sk = arg(ctx, 0) as *mut c_void;
    unsafe {
        bbr_ssthresh(sk);
        dctcp_ssthresh(sk);
        cubictcp_recalc_ssthresh(sk)
    }
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn min_tso_segs(ctx: *const u64) -> u32 {
    let sk = arg(ctx, 0) as *mut c_void;
    unsafe { bbr_min_tso_segs(sk) }
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn set_state(ctx: *const u64) {
    let sk = arg(ctx, 0) as *mut c_void;
    let new_state = arg(ctx, 1) as u8;
    unsafe {
        bbr_set_state(sk, new_state);
        dctcp_state(sk, new_state);
        cubictcp_state(sk, new_state);
    }
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn pkts_acked(ctx: *const u64) {
    let sk = arg(ctx, 0) as *mut c_void;
    let sample = arg(ctx, 1) as *const c_void;
    unsafe { cubictcp_acked(sk, sample) };
}

// struct tcp_congestion_ops (net/tcp.h): every member this program sets.
// Must be named exactly `tcp_congestion_ops` -- libbpf's struct_ops
// relocation resolves the kernel type by the local type's name.
#[allow(non_camel_case_types)]
#[repr(C)]
struct tcp_congestion_ops {
    init: extern "C" fn(*const u64),
    in_ack_event: extern "C" fn(*const u64),
    cong_control: extern "C" fn(*const u64),
    cong_avoid: extern "C" fn(*const u64),
    sndbuf_expand: extern "C" fn(*const u64) -> u32,
    undo_cwnd: extern "C" fn(*const u64) -> u32,
    cwnd_event: extern "C" fn(*const u64),
    cwnd_event_tx_start: extern "C" fn(*const u64),
    ssthresh: extern "C" fn(*const u64) -> u32,
    min_tso_segs: extern "C" fn(*const u64) -> u32,
    set_state: extern "C" fn(*const u64),
    pkts_acked: extern "C" fn(*const u64),
    name: [u8; 16],
}

unsafe impl Sync for tcp_congestion_ops {}

#[link_section = ".struct_ops"]
#[no_mangle]
static tcp_ca_kfunc: tcp_congestion_ops = tcp_congestion_ops {
    init,
    in_ack_event,
    cong_control,
    cong_avoid,
    sndbuf_expand,
    undo_cwnd,
    cwnd_event,
    cwnd_event_tx_start,
    ssthresh,
    min_tso_segs,
    set_state,
    pkts_acked,
    name: *b"tcp_ca_kfunc\0\0\0\0",
};

bpf_object!("GPL");
