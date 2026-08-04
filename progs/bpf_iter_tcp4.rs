#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_iter_tcp4.c
// (bpf-rs-core idiom).
//
// Kernel-source shortcut reused throughout: `struct tcp_sock`'s first
// member is `struct inet_connection_sock inet_conn;` (comment: "has to be
// the first member of tcp_sock"), whose own first member is `struct
// inet_sock icsk_inet;` ("has to be the first member!"), whose own first
// member is `struct sock sk;` ("sk ... has to be the first ... member[]"),
// whose own first member is `struct sock_common __sk_common;`. All four
// types alias byte offset 0 of a `tcp_sock`, so `tp as *mut sock_common` /
// `as *mut sock` / `as *mut inet_connection_sock` / `as *mut inet_sock` are
// plain pointer reinterprets -- no CO-RE walk needed to find them, exactly
// like C's own `tcp_sk()`/`inet_csk()` casts in bpf_tracing_net.h. The same
// chain holds for `tcp_timewait_sock -> tw_sk (inet_timewait_sock) ->
// __tw_common (sock_common)` and `tcp_request_sock -> req
// (inet_request_sock) -> req (request_sock) -> __req_common
// (sock_common)`, so `dump_tw_sock`/`dump_req_sock` take the *inner*
// offset-0 type directly and never declare the outer wrapper struct at
// all. C's `inet_daddr`/`ir_loc_addr`/`tw_daddr`/etc. macros (see
// bpf_tracing_net.h) are just spelled-out field names through this same
// chain -- `sock_common` is declared once with the flattened members
// (`skc_daddr`, `skc_dport`, ... all sit in anonymous unions in the real
// struct, which auto-flatten onto the named outer struct the same way
// `skc_family` does in every other iter/tcp translation in this repo).
//
// `icsk->icsk_ack.ato` and `request_sock->num_timeout` are real bitfield
// members (`ato:8` inside a `__u32` storage word; `num_timeout:7` sharing a
// byte with `syncookie:1`). A `#[btf]` field access naming a bitfield
// member directly does NOT work here: libbpf's `BPF_CORE_FIELD_BYTE_OFFSET`
// relocation (relo_core.c's `bpf_core_calc_field_relo`) only fills in the
// resolved field size/type when the *target* member is a plain
// (non-bitfield) field; for a genuine target bitfield it leaves the size
// unset (0), which always mismatches a local plain `u8`'s size (1) and gets
// the instruction poisoned (load fails with "accesses field incorrectly").
// Workaround: CO-RE-resolve the address of a nearby *plain* (non-bitfield)
// sibling field instead (`pingpong`, two bytes before the `ato` word;
// `num_retrans`, the byte immediately before the `syncookie`/`num_timeout`
// byte), then reach the target byte with plain constant-offset pointer
// arithmetic on that already-resolved, verifier-trusted address and read it
// directly -- the verifier's `btf_struct_walk` validates the final
// (root_type, byte_offset) pair independent of how the offset was computed,
// so this is sound as long as build and run kernel match (same general
// precondition as every other byte-offset-only CO-RE trick in this repo).
//
// `CONFIG_HZ` is a `__kconfig extern`: rustc emits no BTF for extern
// statics, so keeping the extern makes skeleton regen fail to resolve it,
// and this program's only consumer (`prog_tests/bpf_iter.c`'s
// `test_tcp4()`) never touches `skel->kconfig` -- it only attaches the
// prog and does a content-blind `read()` until EOF. So instead of the
// extern, `CONFIG_HZ` is hardcoded to 1000, this kernel build's actual
// value (`.config`: `CONFIG_HZ_1000=y`), matching `jiffies_to_clock_t`'s
// real behavior exactly without needing the unemittable extern at all.
//
// `timer_active`/`timer_expires` and the final `%d` field in
// `dump_tcp_sock` each select between two or three *distinct* CO-RE field
// chains via runtime `if`/ternary and merge the result into one value used
// later -- the same "merging two distinct #[btf] chains' terminal reads
// into one if/else-selected SSA value" hazard documented in
// sock_iter_batch.rs. Each such branch is routed through its own
// `#[inline(never)]` reader function returning a plain scalar, so what
// merges afterward is an ordinary integer phi, not raw CO-RE relocation
// calls.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_jiffies64, bpf_probe_read_kernel, bpf_seq_printf, bpf_skc_to_tcp_request_sock,
    bpf_skc_to_tcp_sock, bpf_skc_to_tcp_timewait_sock,
};
use btf_macros::btf;
use core::ffi::c_void;
use core::mem::size_of_val;

const AF_INET: u16 = 2;
const TCP_SYN_RECV: u32 = 3;
const TCP_LISTEN: u32 = 10;
const TCP_INFINITE_SSTHRESH: u32 = 0x7fffffff;
const TCP_PINGPONG_THRESH: u8 = 3;
const ICSK_TIME_RETRANS: u8 = 1;
const ICSK_TIME_PROBE0: u8 = 3;
const ICSK_TIME_LOSS_PROBE: u8 = 5;
const ICSK_TIME_REO_TIMEOUT: u8 = 6;

const CONFIG_HZ: u64 = 1000;
const USER_HZ: u64 = 100;
const NSEC_PER_SEC: u64 = 1_000_000_000;

// ------------------------------------------------------------------ ctx --

#[repr(C)]
struct bpf_iter_meta {
    seq: *mut c_void,
    session_id: u64,
    seq_num: u64,
}

#[repr(C)]
struct bpf_iter__tcp {
    meta: *mut bpf_iter_meta,
    sk_common: *mut sock_common,
    uid: u32,
}

// -------------------------------------------------------- kernel structs --

#[btf]
struct atomic_t {
    counter: i32,
}

#[btf]
struct refcount_t {
    refs: atomic_t,
}

#[btf]
struct hlist_node {
    pprev: *mut hlist_node,
}

#[btf]
struct timer_list {
    entry: hlist_node,
    expires: u64,
}

#[btf]
struct sock_common {
    skc_daddr: u32,
    skc_rcv_saddr: u32,
    skc_dport: u16,
    skc_num: u16,
    skc_family: u16,
    skc_state: u8,
    skc_refcnt: refcount_t,
}

#[btf]
struct socket {}

#[btf]
struct inode {
    i_ino: u64,
}

#[btf]
struct socket_alloc {
    vfs_inode: inode,
}

#[btf]
struct sock {
    tcp_retransmit_timer: timer_list,
    sk_ack_backlog: u32,
    sk_socket: *mut socket,
}

#[btf]
struct inet_sock {
    inet_sport: u16,
}

#[btf]
struct fastopen_queue {
    max_qlen: i32,
}

#[btf]
struct request_sock_queue {
    fastopenq: fastopen_queue,
}

#[btf]
struct icsk_ack_t {
    quick: u8,
    pingpong: u8,
}

#[btf]
struct inet_connection_sock {
    icsk_accept_queue: request_sock_queue,
    icsk_keepalive_timer: timer_list,
    icsk_rto: u32,
    icsk_retransmits: u8,
    icsk_pending: u8,
    icsk_probes_out: u8,
    icsk_ack: icsk_ack_t,
}

#[btf]
struct tcp_sock {
    write_seq: u32,
    snd_una: u32,
    rcv_nxt: u32,
    copied_seq: u32,
    snd_cwnd: u32,
    snd_ssthresh: u32,
}

#[btf]
struct inet_timewait_sock {
    tw_substate: u8,
    tw_sport: u16,
    tw_timer: timer_list,
}

#[btf]
struct request_sock {
    num_retrans: u8,
    rsk_timer: timer_list,
}

// -------------------------------------------------------------- jiffies --

fn jiffies_to_clock_t(x: u64) -> u64 {
    let tick_nsec = (NSEC_PER_SEC + CONFIG_HZ / 2) / CONFIG_HZ;
    let user_hz_nsec = NSEC_PER_SEC / USER_HZ;
    if tick_nsec % user_hz_nsec == 0 {
        if CONFIG_HZ < USER_HZ {
            x * (USER_HZ / CONFIG_HZ)
        } else {
            x / (CONFIG_HZ / USER_HZ)
        }
    } else {
        x * tick_nsec / user_hz_nsec
    }
}

fn jiffies_delta_to_clock_t(delta: i64) -> u64 {
    if delta <= 0 {
        0
    } else {
        jiffies_to_clock_t(delta as u64)
    }
}

// ---------------------------------------------- branch-merge-safe readers --

#[inline(never)]
fn read_retransmit_expires(sp: *mut sock) -> u64 {
    let r = unsafe { &*sp };
    unsafe { *r.tcp_retransmit_timer().expires().as_ptr() }
}

#[inline(never)]
fn read_keepalive_expires(icsk: *mut inet_connection_sock) -> u64 {
    let r = unsafe { &*icsk };
    unsafe { *r.icsk_keepalive_timer().expires().as_ptr() }
}

#[inline(never)]
fn keepalive_timer_pending(icsk: *mut inet_connection_sock) -> bool {
    let r = unsafe { &*icsk };
    let pprev = unsafe { *r.icsk_keepalive_timer().entry().pprev().as_ptr() };
    !pprev.is_null()
}

#[inline(never)]
fn read_sk_ack_backlog(sp: *mut sock) -> i32 {
    let r = unsafe { &*sp };
    unsafe { *r.sk_ack_backlog().as_ptr() as i32 }
}

#[inline(never)]
fn read_rcv_copied_diff(tp: *mut tcp_sock) -> i32 {
    let r = unsafe { &*tp };
    let rcv_nxt = unsafe { *r.rcv_nxt().as_ptr() };
    let copied_seq = unsafe { *r.copied_seq().as_ptr() };
    rcv_nxt.wrapping_sub(copied_seq) as i32
}

#[inline(never)]
fn read_fastopen_max_qlen(icsk: *mut inet_connection_sock) -> i32 {
    let r = unsafe { &*icsk };
    unsafe { *r.icsk_accept_queue().fastopenq().max_qlen().as_ptr() }
}

#[inline(never)]
fn read_snd_ssthresh(tp: *mut tcp_sock) -> u32 {
    let r = unsafe { &*tp };
    unsafe { *r.snd_ssthresh().as_ptr() }
}

#[inline(never)]
fn is_initial_slowstart(tp: *mut tcp_sock) -> bool {
    read_snd_ssthresh(tp) >= TCP_INFINITE_SSTHRESH
}

// ------------------------------------------------------------- dumpers --

fn dump_tcp_sock(seq: *mut c_void, tp: *mut tcp_sock, uid: u32, seq_num: u32) -> i32 {
    let icsk = tp as *mut inet_connection_sock;
    let inet = tp as *mut inet_sock;
    let sp = tp as *mut sock;
    let skc_ref = unsafe { &*(tp as *mut sock_common) };
    let icsk_ref = unsafe { &*icsk };
    let inet_ref = unsafe { &*inet };
    let tp_ref = unsafe { &*tp };

    let dest = unsafe { *skc_ref.skc_daddr().as_ptr() };
    let src = unsafe { *skc_ref.skc_rcv_saddr().as_ptr() };
    let destp = (unsafe { *skc_ref.skc_dport().as_ptr() }).swap_bytes();
    let srcp = (unsafe { *inet_ref.inet_sport().as_ptr() }).swap_bytes();

    let icsk_pending = unsafe { *icsk_ref.icsk_pending().as_ptr() };
    let (timer_active, timer_expires): (i32, u64) = if icsk_pending == ICSK_TIME_RETRANS
        || icsk_pending == ICSK_TIME_REO_TIMEOUT
        || icsk_pending == ICSK_TIME_LOSS_PROBE
    {
        (1, read_retransmit_expires(sp))
    } else if icsk_pending == ICSK_TIME_PROBE0 {
        (4, read_retransmit_expires(sp))
    } else if keepalive_timer_pending(icsk) {
        (2, read_keepalive_expires(icsk))
    } else {
        (0, bpf_jiffies64())
    };

    let state = unsafe { *skc_ref.skc_state().as_ptr() };
    let rx_queue: i32 = if state as u32 == TCP_LISTEN {
        read_sk_ack_backlog(sp)
    } else {
        let d = read_rcv_copied_diff(tp);
        if d < 0 { 0 } else { d }
    };

    static FMT_ADDR: [u8; 26] = *b"%4d: %08X:%04X %08X:%04X \0";
    let params_addr: [u64; 5] = [seq_num as u64, src as u64, srcp as u64, dest as u64, destp as u64];
    bpf_seq_printf(
        seq,
        FMT_ADDR.as_ptr() as *const c_void,
        FMT_ADDR.len() as u32,
        params_addr.as_ptr() as *const c_void,
        size_of_val(&params_addr) as u32,
    );

    let write_seq = unsafe { *tp_ref.write_seq().as_ptr() };
    let snd_una = unsafe { *tp_ref.snd_una().as_ptr() };
    let icsk_retransmits = unsafe { *icsk_ref.icsk_retransmits().as_ptr() };
    let icsk_probes_out = unsafe { *icsk_ref.icsk_probes_out().as_ptr() };
    let refcnt = unsafe { *skc_ref.skc_refcnt().refs().counter().as_ptr() } as i64 as u64;

    let sp_ref = unsafe { &*sp };
    let sk_socket = unsafe { *sp_ref.sk_socket().as_ptr() };
    let mut ino: u64 = 0;
    if !sk_socket.is_null() {
        let salloc = sk_socket as *mut socket_alloc;
        let ino_addr = unsafe { &*salloc }.vfs_inode().i_ino().as_ptr();
        bpf_probe_read_kernel(&mut ino, 8, ino_addr as *const c_void);
    }

    static FMT_TCP2: [u8; 47] = *b"%02X %08X:%08X %02X:%08lX %08X %5u %8d %lu %d \0";
    let params_tcp2: [u64; 10] = [
        state as u64,
        (write_seq.wrapping_sub(snd_una)) as u64,
        (rx_queue as i64) as u64,
        (timer_active as i64) as u64,
        jiffies_delta_to_clock_t((timer_expires.wrapping_sub(bpf_jiffies64())) as i64),
        icsk_retransmits as u64,
        uid as u64,
        icsk_probes_out as u64,
        ino,
        refcnt,
    ];
    bpf_seq_printf(
        seq,
        FMT_TCP2.as_ptr() as *const c_void,
        FMT_TCP2.len() as u32,
        params_tcp2.as_ptr() as *const c_void,
        size_of_val(&params_tcp2) as u32,
    );

    let icsk_rto = unsafe { *icsk_ref.icsk_rto().as_ptr() };
    let quick = unsafe { *icsk_ref.icsk_ack().quick().as_ptr() };
    let pingpong_ptr = icsk_ref.icsk_ack().pingpong().as_ptr();
    let pingpong = unsafe { *pingpong_ptr };
    // `ato` is a bitfield two bytes after the plain `pingpong` byte (see
    // file header comment for why it isn't read as a #[btf] field directly).
    let ato = unsafe { *pingpong_ptr.add(2) };
    let pingpong_mode = (pingpong >= TCP_PINGPONG_THRESH) as u32;
    let snd_cwnd = unsafe { *tp_ref.snd_cwnd().as_ptr() };

    let last_field: i64 = if state as u32 == TCP_LISTEN {
        read_fastopen_max_qlen(icsk) as i64
    } else if is_initial_slowstart(tp) {
        -1
    } else {
        read_snd_ssthresh(tp) as i64
    };

    static FMT_TCP3: [u8; 22] = *b"%pK %lu %lu %u %u %d\n\0";
    let params_tcp3: [u64; 6] = [
        tp as u64,
        jiffies_to_clock_t(icsk_rto as u64),
        jiffies_to_clock_t(ato as u64),
        (((quick as u32) << 1) | pingpong_mode) as u64,
        snd_cwnd as u64,
        last_field as u64,
    ];
    bpf_seq_printf(
        seq,
        FMT_TCP3.as_ptr() as *const c_void,
        FMT_TCP3.len() as u32,
        params_tcp3.as_ptr() as *const c_void,
        size_of_val(&params_tcp3) as u32,
    );

    0
}

fn dump_tw_sock(seq: *mut c_void, tw: *mut inet_timewait_sock, uid: u32, seq_num: u32) -> i32 {
    let _ = uid;
    let skc_ref = unsafe { &*(tw as *mut sock_common) };
    let tw_ref = unsafe { &*tw };

    let delta =
        (unsafe { *tw_ref.tw_timer().expires().as_ptr() }).wrapping_sub(bpf_jiffies64()) as i64;

    let dest = unsafe { *skc_ref.skc_daddr().as_ptr() };
    let src = unsafe { *skc_ref.skc_rcv_saddr().as_ptr() };
    let destp = (unsafe { *skc_ref.skc_dport().as_ptr() }).swap_bytes();
    let srcp = (unsafe { *tw_ref.tw_sport().as_ptr() }).swap_bytes();

    static FMT_ADDR: [u8; 26] = *b"%4d: %08X:%04X %08X:%04X \0";
    let params_addr: [u64; 5] = [seq_num as u64, src as u64, srcp as u64, dest as u64, destp as u64];
    bpf_seq_printf(
        seq,
        FMT_ADDR.as_ptr() as *const c_void,
        FMT_ADDR.len() as u32,
        params_addr.as_ptr() as *const c_void,
        size_of_val(&params_addr) as u32,
    );

    let tw_substate = unsafe { *tw_ref.tw_substate().as_ptr() };
    let refcnt = unsafe { *skc_ref.skc_refcnt().refs().counter().as_ptr() } as i64 as u64;

    static FMT_TWREQ2: [u8; 50] = *b"%02X %08X:%08X %02X:%08lX %08X %5d %8d %d %d %pK\n\0";
    let params_twreq2: [u64; 11] = [
        tw_substate as u64,
        0,
        0,
        3,
        jiffies_delta_to_clock_t(delta),
        0,
        0,
        0,
        0,
        refcnt,
        tw as u64,
    ];
    bpf_seq_printf(
        seq,
        FMT_TWREQ2.as_ptr() as *const c_void,
        FMT_TWREQ2.len() as u32,
        params_twreq2.as_ptr() as *const c_void,
        size_of_val(&params_twreq2) as u32,
    );

    0
}

fn dump_req_sock(seq: *mut c_void, req: *mut request_sock, uid: u32, seq_num: u32) -> i32 {
    let skc_ref = unsafe { &*(req as *mut sock_common) };
    let req_ref = unsafe { &*req };

    let mut ttd =
        (unsafe { *req_ref.rsk_timer().expires().as_ptr() }).wrapping_sub(bpf_jiffies64()) as i64;
    if ttd < 0 {
        ttd = 0;
    }

    let ir_loc_addr = unsafe { *skc_ref.skc_rcv_saddr().as_ptr() };
    let ir_num = unsafe { *skc_ref.skc_num().as_ptr() };
    let ir_rmt_addr = unsafe { *skc_ref.skc_daddr().as_ptr() };
    let ir_rmt_port = (unsafe { *skc_ref.skc_dport().as_ptr() }).swap_bytes();

    static FMT_ADDR: [u8; 26] = *b"%4d: %08X:%04X %08X:%04X \0";
    let params_addr: [u64; 5] = [
        seq_num as u64,
        ir_loc_addr as u64,
        ir_num as u64,
        ir_rmt_addr as u64,
        ir_rmt_port as u64,
    ];
    bpf_seq_printf(
        seq,
        FMT_ADDR.as_ptr() as *const c_void,
        FMT_ADDR.len() as u32,
        params_addr.as_ptr() as *const c_void,
        size_of_val(&params_addr) as u32,
    );

    // `syncookie`/`num_timeout` share the byte immediately after the plain
    // `num_retrans` byte (see file header comment for why `num_timeout`
    // isn't read as a #[btf] field directly).
    let num_retrans_ptr = req_ref.num_retrans().as_ptr();
    let syncookie_timeout_byte = unsafe { *num_retrans_ptr.add(1) };
    let num_timeout = (syncookie_timeout_byte >> 1) & 0x7F;

    static FMT_TWREQ2: [u8; 50] = *b"%02X %08X:%08X %02X:%08lX %08X %5d %8d %d %d %pK\n\0";
    let params_twreq2: [u64; 11] = [
        TCP_SYN_RECV as u64,
        0,
        0,
        1,
        jiffies_to_clock_t(ttd as u64),
        num_timeout as u64,
        uid as u64,
        0,
        0,
        0,
        req as u64,
    ];
    bpf_seq_printf(
        seq,
        FMT_TWREQ2.as_ptr() as *const c_void,
        FMT_TWREQ2.len() as u32,
        params_twreq2.as_ptr() as *const c_void,
        size_of_val(&params_twreq2) as u32,
    );

    0
}

// ------------------------------------------------------------- programs --

#[link_section = "iter/tcp"]
#[no_mangle]
extern "C" fn dump_tcp4(ctx: *const bpf_iter__tcp) -> i32 {
    let ctx = unsafe { &*ctx };
    let sk_common = ctx.sk_common;
    if sk_common.is_null() {
        return 0;
    }
    let meta = unsafe { &*ctx.meta };
    let uid = ctx.uid;
    let seq_num = meta.seq_num as u32;

    if seq_num == 0 {
        static FMT0: [u8; 98] =
            *b"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\0";
        bpf_seq_printf(
            meta.seq,
            FMT0.as_ptr() as *const c_void,
            FMT0.len() as u32,
            core::ptr::null(),
            0,
        );
    }

    let skc_ref = unsafe { &*sk_common };
    let family = unsafe { *skc_ref.skc_family().as_ptr() };
    if family != AF_INET {
        return 0;
    }

    let tp = bpf_skc_to_tcp_sock(sk_common as *const c_void) as *mut tcp_sock;
    if !tp.is_null() {
        return dump_tcp_sock(meta.seq, tp, uid, seq_num);
    }

    let tw = bpf_skc_to_tcp_timewait_sock(sk_common as *const c_void) as *mut inet_timewait_sock;
    if !tw.is_null() {
        return dump_tw_sock(meta.seq, tw, uid, seq_num);
    }

    let req = bpf_skc_to_tcp_request_sock(sk_common as *const c_void) as *mut request_sock;
    if !req.is_null() {
        return dump_req_sock(meta.seq, req, uid, seq_num);
    }

    0
}

bpf_object!("GPL");
