#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_tcp_estats.c
// (bpf-rs-core idiom). Per the C source's own comment, this is "a unit test
// case only for verifier purpose without bpf program execution" — the
// userspace test (prog_tests/tcp_estats.c) only bpf_prog_test_load()s it as
// BPF_PROG_TYPE_TRACEPOINT and never attaches/runs it. The C source mocks
// its own minimal `sock`/`inet_sock`/`sock_common` layouts (not the real
// kernel ones) purely to exercise a code-generation pattern; here they are
// reproduced as fixed byte offsets read via bpf_probe_read_kernel (matching
// C's `_(P)` macro), same technique as the pt_regs->di offset idiom.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_get_prandom_u32, bpf_ktime_get_ns, bpf_map_update_elem, bpf_probe_read_kernel};
use bpf_rs_core::maps::{self, BpfMap};
use core::ffi::c_void;

const TCP_ESTATS_MAGIC: u32 = 0xBAADBEEF;
const TCP_ESTATS_TX_RESET: i32 = 8; // 9th value of enum tcp_estats_event_type
const AF_INET6: u16 = 10;
const BPF_ANY: u64 = 0;

// struct sock_common / sock / inet_sock mock layout (x86_64, natural
// alignment, matching the C source's field order exactly):
//   skc_family            offset 0,  2 bytes
//   (padding to 8 for the __addrpair union)
//   skc_daddr             offset 8,  4 bytes
//   skc_rcv_saddr         offset 12, 4 bytes
//   skc_dport             offset 16, 2 bytes
//   skc_num               offset 18, 2 bytes
//   skc_v6_daddr          offset 20, 16 bytes
//   skc_v6_rcv_saddr      offset 36, 16 bytes
//   (struct sock ends at 56, 8-byte aligned)
//   inet_saddr            offset 56, 4 bytes
//   inet_sport            offset 60, 2 bytes
const OFF_SK_FAMILY: u64 = 0;
const OFF_SKC_DADDR: u64 = 8;
const OFF_SKC_DPORT: u64 = 16;
const OFF_SKC_V6_DADDR: u64 = 20;
const OFF_SKC_V6_RCV_SADDR: u64 = 36;
const OFF_INET_SADDR: u64 = 56;
const OFF_INET_SPORT: u64 = 60;

#[repr(C)]
struct TcpEstatsEvent {
    pid: i32,
    cpu: i32,
    ts: u64,
    magic: u32,
    event_type: i32,
}

#[repr(C, packed)]
struct TcpEstatsConnId {
    local_address_type: u32,
    local_address: [u8; 16],
    rem_address: [u8; 16],
    localport: u16,
    remport: u16,
}

#[repr(C)]
struct TcpEstatsBasicEvent {
    event: TcpEstatsEvent,
    conn_id: TcpEstatsConnId,
}

#[link_section = ".maps"]
#[no_mangle]
static ev_record_map: BpfMap<u32, TcpEstatsBasicEvent, { maps::HASH }, 1024> = BpfMap::new();

#[inline(always)]
fn probe_u8(addr: u64, off: u64) -> u8 {
    let mut v: u8 = 0;
    bpf_probe_read_kernel(&mut v, 1, (addr + off) as *const c_void);
    v
}

#[inline(always)]
fn probe_u16(addr: u64, off: u64) -> u16 {
    let mut v: u16 = 0;
    bpf_probe_read_kernel(&mut v, 2, (addr + off) as *const c_void);
    v
}

#[inline(always)]
fn tcp_estats_ev_init(event: &mut TcpEstatsEvent, event_type: i32) {
    event.magic = TCP_ESTATS_MAGIC;
    event.ts = bpf_ktime_get_ns();
    event.event_type = event_type;
}

#[inline(always)]
fn unaligned_u32_set4(dst: &mut [u8], from_addr: u64) {
    dst[0] = probe_u8(from_addr, 0);
    dst[1] = probe_u8(from_addr, 1);
    dst[2] = probe_u8(from_addr, 2);
    dst[3] = probe_u8(from_addr, 3);
}

#[inline(always)]
fn conn_id_ipv4_init(conn_id: &mut TcpEstatsConnId, saddr: u64, daddr: u64) {
    conn_id.local_address_type = 1; // TCP_ESTATS_ADDRTYPE_IPV4
    unaligned_u32_set4(&mut conn_id.local_address[0..4], saddr);
    unaligned_u32_set4(&mut conn_id.rem_address[0..4], daddr);
}

#[inline(always)]
fn conn_id_ipv6_init(conn_id: &mut TcpEstatsConnId, saddr: u64, daddr: u64) {
    conn_id.local_address_type = 2; // TCP_ESTATS_ADDRTYPE_IPV6
    unaligned_u32_set4(&mut conn_id.local_address[0..4], saddr);
    unaligned_u32_set4(&mut conn_id.local_address[4..8], saddr + 4);
    unaligned_u32_set4(&mut conn_id.local_address[8..12], saddr + 8);
    unaligned_u32_set4(&mut conn_id.local_address[12..16], saddr + 12);

    unaligned_u32_set4(&mut conn_id.rem_address[0..4], daddr);
    unaligned_u32_set4(&mut conn_id.rem_address[4..8], daddr + 4);
    unaligned_u32_set4(&mut conn_id.rem_address[8..12], daddr + 8);
    unaligned_u32_set4(&mut conn_id.rem_address[12..16], daddr + 12);
}

#[inline(always)]
fn tcp_estats_conn_id_init(conn_id: &mut TcpEstatsConnId, sk: u64) {
    conn_id.localport = probe_u16(sk, OFF_INET_SPORT);
    conn_id.remport = probe_u16(sk, OFF_SKC_DPORT);

    if probe_u16(sk, OFF_SK_FAMILY) == AF_INET6 {
        conn_id_ipv6_init(conn_id, sk + OFF_SKC_V6_RCV_SADDR, sk + OFF_SKC_V6_DADDR);
    } else {
        conn_id_ipv4_init(conn_id, sk + OFF_INET_SADDR, sk + OFF_SKC_DADDR);
    }
}

#[inline(always)]
fn tcp_estats_init(
    sk: u64,
    event: &mut TcpEstatsEvent,
    conn_id: &mut TcpEstatsConnId,
    event_type: i32,
) {
    tcp_estats_ev_init(event, event_type);
    tcp_estats_conn_id_init(conn_id, sk);
}

#[inline(always)]
fn send_basic_event(sk: u64, event_type: i32) {
    let mut ev = TcpEstatsBasicEvent {
        event: TcpEstatsEvent {
            pid: 0,
            cpu: 0,
            ts: 0,
            magic: 0,
            event_type: 0,
        },
        conn_id: TcpEstatsConnId {
            local_address_type: 0,
            local_address: [0; 16],
            rem_address: [0; 16],
            localport: 0,
            remport: 0,
        },
    };
    let key = bpf_get_prandom_u32();

    tcp_estats_init(sk, &mut ev.event, &mut ev.conn_id, event_type);
    bpf_map_update_elem(&ev_record_map, &key, &ev, BPF_ANY);
}

#[link_section = "tp/dummy/tracepoint"]
#[no_mangle]
extern "C" fn _dummy_tracepoint(ctx: *const u8) -> i32 {
    // `struct dummy_tracepoint_args { unsigned long long pad; struct sock *sock; }`
    let sock = unsafe { core::ptr::read_unaligned(ctx.add(8) as *const u64) };
    if sock == 0 {
        return 0;
    }

    send_basic_event(sock, TCP_ESTATS_TX_RESET);
    0
}

bpf_object!("GPL");
