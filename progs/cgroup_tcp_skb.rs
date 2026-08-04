#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/cgroup_tcp_skb.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::bpf_skb_load_bytes;
use bpf_rs_core::vload;
use core::ffi::c_void;

const ETH_P_IPV6: u16 = 0x86DD;
const IPPROTO_TCP: u8 = 6;

#[inline(always)]
fn htons(x: u16) -> u16 {
    x.to_be()
}

// cgroup_tcp_skb.h states, in declaration order.
const INIT: u32 = 0;
const CLOSED: u32 = 1;
const SYN_SENT: u32 = 2;
const SYN_RECV_SENDING_SYN_ACK: u32 = 3;
const SYN_RECV: u32 = 4;
const ESTABLISHED: u32 = 5;
const FIN_WAIT1: u32 = 6;
const FIN_WAIT2: u32 = 7;
const CLOSE_WAIT_SENDING_ACK: u32 = 8;
const CLOSE_WAIT: u32 = 9;
const LAST_ACK: u32 = 11;
const TIME_WAIT_SENDING_ACK: u32 = 12;
const TIME_WAIT: u32 = 13;

// struct ipv6hdr (linux/ipv6.h): only nexthdr is read; the rest is kept as
// raw bytes so the struct's size (and thus the following field offset)
// matches the real header exactly.
#[repr(C)]
struct Ipv6Hdr {
    ver_priority: u8,
    flow_lbl: [u8; 3],
    payload_len: u16,
    nexthdr: u8,
    hop_limit: u8,
    saddr: [u32; 4],
    daddr: [u32; 4],
}

// struct tcphdr (linux/tcp.h). The bitfield word (res1:4, doff:4, then the
// 8 one-bit flags) is split into its two constituent wire bytes: on this
// little-endian bitfield layout, the flag bits land exactly on the second
// byte's bit positions (bit0=fin .. bit7=cwr) as transmitted on the wire,
// so a plain `flags: u8` + bit tests reproduces the C bitfield reads
// without needing an actual Rust bitfield.
#[repr(C)]
struct TcpHdr {
    source: u16,
    dest: u16,
    seq: u32,
    ack_seq: u32,
    doff_res: u8,
    flags: u8,
    window: u16,
    check: u16,
    urg_ptr: u16,
}

const TH_FIN: u8 = 0x01;
const TH_SYN: u8 = 0x02;
const TH_ACK: u8 = 0x10;

impl TcpHdr {
    #[inline(always)]
    fn fin(&self) -> bool {
        self.flags & TH_FIN != 0
    }
    #[inline(always)]
    fn syn(&self) -> bool {
        self.flags & TH_SYN != 0
    }
    #[inline(always)]
    fn ack(&self) -> bool {
        self.flags & TH_ACK != 0
    }
}

#[no_mangle]
static mut g_sock_port: u16 = 0;
#[no_mangle]
static mut g_sock_state: u32 = 0;
#[no_mangle]
static mut g_unexpected: i32 = 0;
#[no_mangle]
static mut g_packet_count: u32 = 0;

#[inline(always)]
fn needed_tcp_pkt(skb: *const __sk_buff, tcph: &mut TcpHdr) -> bool {
    if vload!((*skb).protocol) != htons(ETH_P_IPV6) as u32 {
        return false;
    }

    let mut ip6h: Ipv6Hdr = unsafe { core::mem::zeroed() };
    if bpf_skb_load_bytes(
        skb as *const c_void,
        0,
        &mut ip6h as *mut Ipv6Hdr as *mut c_void,
        core::mem::size_of::<Ipv6Hdr>() as u32,
    ) != 0
    {
        return false;
    }

    if ip6h.nexthdr != IPPROTO_TCP {
        return false;
    }

    if bpf_skb_load_bytes(
        skb as *const c_void,
        core::mem::size_of::<Ipv6Hdr>() as u32,
        tcph as *mut TcpHdr as *mut c_void,
        core::mem::size_of::<TcpHdr>() as u32,
    ) != 0
    {
        return false;
    }

    let port = unsafe { g_sock_port };
    if tcph.source != htons(port) && tcph.dest != htons(port) {
        return false;
    }

    true
}

/* Run accept() on a socket in the cgroup to receive a new connection. */
#[inline(always)]
fn egress_accept(tcph: &TcpHdr) -> bool {
    if unsafe { g_sock_state } == SYN_RECV_SENDING_SYN_ACK {
        if tcph.fin() || !tcph.syn() || !tcph.ack() {
            unsafe { g_unexpected += 1 };
        } else {
            unsafe { g_sock_state = SYN_RECV };
        }
        return true;
    }

    false
}

#[inline(always)]
fn ingress_accept(tcph: &TcpHdr) -> bool {
    match unsafe { g_sock_state } {
        s if s == INIT => {
            if !tcph.syn() || tcph.fin() || tcph.ack() {
                unsafe { g_unexpected += 1 };
            } else {
                unsafe { g_sock_state = SYN_RECV_SENDING_SYN_ACK };
            }
        }
        s if s == SYN_RECV => {
            if tcph.fin() || tcph.syn() || !tcph.ack() {
                unsafe { g_unexpected += 1 };
            } else {
                unsafe { g_sock_state = ESTABLISHED };
            }
        }
        _ => return false,
    }

    true
}

/* Run connect() on a socket in the cgroup to start a new connection. */
#[inline(always)]
fn egress_connect(tcph: &TcpHdr) -> bool {
    if unsafe { g_sock_state } == INIT {
        if !tcph.syn() || tcph.fin() || tcph.ack() {
            unsafe { g_unexpected += 1 };
        } else {
            unsafe { g_sock_state = SYN_SENT };
        }
        return true;
    }

    false
}

#[inline(always)]
fn ingress_connect(tcph: &TcpHdr) -> bool {
    if unsafe { g_sock_state } == SYN_SENT {
        if tcph.fin() || !tcph.syn() || !tcph.ack() {
            unsafe { g_unexpected += 1 };
        } else {
            unsafe { g_sock_state = ESTABLISHED };
        }
        return true;
    }

    false
}

/* The connection is closed by the peer outside the cgroup. */
#[inline(always)]
fn egress_close_remote(tcph: &TcpHdr) -> bool {
    match unsafe { g_sock_state } {
        s if s == ESTABLISHED => {}
        s if s == CLOSE_WAIT_SENDING_ACK => {
            if tcph.fin() || tcph.syn() || !tcph.ack() {
                unsafe { g_unexpected += 1 };
            } else {
                unsafe { g_sock_state = CLOSE_WAIT };
            }
        }
        s if s == CLOSE_WAIT => {
            if !tcph.fin() {
                unsafe { g_unexpected += 1 };
            } else {
                unsafe { g_sock_state = LAST_ACK };
            }
        }
        _ => return false,
    }

    true
}

#[inline(always)]
fn ingress_close_remote(tcph: &TcpHdr) -> bool {
    match unsafe { g_sock_state } {
        s if s == ESTABLISHED => {
            if tcph.fin() {
                unsafe { g_sock_state = CLOSE_WAIT_SENDING_ACK };
            }
        }
        s if s == LAST_ACK => {
            if tcph.fin() || tcph.syn() || !tcph.ack() {
                unsafe { g_unexpected += 1 };
            } else {
                unsafe { g_sock_state = CLOSED };
            }
        }
        _ => return false,
    }

    true
}

/* The connection is closed by the endpoint inside the cgroup. */
#[inline(always)]
fn egress_close_local(tcph: &TcpHdr) -> bool {
    match unsafe { g_sock_state } {
        s if s == ESTABLISHED => {
            if tcph.fin() {
                unsafe { g_sock_state = FIN_WAIT1 };
            }
        }
        s if s == TIME_WAIT_SENDING_ACK => {
            if tcph.fin() || tcph.syn() || !tcph.ack() {
                unsafe { g_unexpected += 1 };
            } else {
                unsafe { g_sock_state = TIME_WAIT };
            }
        }
        _ => return false,
    }

    true
}

#[inline(always)]
fn ingress_close_local(tcph: &TcpHdr) -> bool {
    match unsafe { g_sock_state } {
        s if s == ESTABLISHED => {}
        s if s == FIN_WAIT1 => {
            if tcph.fin() || tcph.syn() || !tcph.ack() {
                unsafe { g_unexpected += 1 };
            } else {
                unsafe { g_sock_state = FIN_WAIT2 };
            }
        }
        s if s == FIN_WAIT2 => {
            if !tcph.fin() || tcph.syn() || !tcph.ack() {
                unsafe { g_unexpected += 1 };
            } else {
                unsafe { g_sock_state = TIME_WAIT_SENDING_ACK };
            }
        }
        _ => return false,
    }

    true
}

/* Check the types of outgoing packets of a server socket to make sure they
 * are consistent with the state of the server socket.
 *
 * The connection is closed by the client side.
 */
#[link_section = "cgroup_skb/egress"]
#[no_mangle]
extern "C" fn server_egress(skb: *const __sk_buff) -> i32 {
    let mut tcph: TcpHdr = unsafe { core::mem::zeroed() };
    if !needed_tcp_pkt(skb, &mut tcph) {
        return 1;
    }

    unsafe { g_packet_count += 1 };

    /* Egress of the server socket. */
    if egress_accept(&tcph) || egress_close_remote(&tcph) {
        return 1;
    }

    unsafe { g_unexpected += 1 };
    1
}

/* Check the types of incoming packets of a server socket to make sure they
 * are consistent with the state of the server socket.
 *
 * The connection is closed by the client side.
 */
#[link_section = "cgroup_skb/ingress"]
#[no_mangle]
extern "C" fn server_ingress(skb: *const __sk_buff) -> i32 {
    let mut tcph: TcpHdr = unsafe { core::mem::zeroed() };
    if !needed_tcp_pkt(skb, &mut tcph) {
        return 1;
    }

    unsafe { g_packet_count += 1 };

    /* Ingress of the server socket. */
    if ingress_accept(&tcph) || ingress_close_remote(&tcph) {
        return 1;
    }

    unsafe { g_unexpected += 1 };
    1
}

/* Check the types of outgoing packets of a server socket to make sure they
 * are consistent with the state of the server socket.
 *
 * The connection is closed by the server side.
 */
#[link_section = "cgroup_skb/egress"]
#[no_mangle]
extern "C" fn server_egress_srv(skb: *const __sk_buff) -> i32 {
    let mut tcph: TcpHdr = unsafe { core::mem::zeroed() };
    if !needed_tcp_pkt(skb, &mut tcph) {
        return 1;
    }

    unsafe { g_packet_count += 1 };

    /* Egress of the server socket. */
    if egress_accept(&tcph) || egress_close_local(&tcph) {
        return 1;
    }

    unsafe { g_unexpected += 1 };
    1
}

/* Check the types of incoming packets of a server socket to make sure they
 * are consistent with the state of the server socket.
 *
 * The connection is closed by the server side.
 */
#[link_section = "cgroup_skb/ingress"]
#[no_mangle]
extern "C" fn server_ingress_srv(skb: *const __sk_buff) -> i32 {
    let mut tcph: TcpHdr = unsafe { core::mem::zeroed() };
    if !needed_tcp_pkt(skb, &mut tcph) {
        return 1;
    }

    unsafe { g_packet_count += 1 };

    /* Ingress of the server socket. */
    if ingress_accept(&tcph) || ingress_close_local(&tcph) {
        return 1;
    }

    unsafe { g_unexpected += 1 };
    1
}

/* Check the types of outgoing packets of a client socket to make sure they
 * are consistent with the state of the client socket.
 *
 * The connection is closed by the server side.
 */
#[link_section = "cgroup_skb/egress"]
#[no_mangle]
extern "C" fn client_egress_srv(skb: *const __sk_buff) -> i32 {
    let mut tcph: TcpHdr = unsafe { core::mem::zeroed() };
    if !needed_tcp_pkt(skb, &mut tcph) {
        return 1;
    }

    unsafe { g_packet_count += 1 };

    /* Egress of the server socket. */
    if egress_connect(&tcph) || egress_close_remote(&tcph) {
        return 1;
    }

    unsafe { g_unexpected += 1 };
    1
}

/* Check the types of incoming packets of a client socket to make sure they
 * are consistent with the state of the client socket.
 *
 * The connection is closed by the server side.
 */
#[link_section = "cgroup_skb/ingress"]
#[no_mangle]
extern "C" fn client_ingress_srv(skb: *const __sk_buff) -> i32 {
    let mut tcph: TcpHdr = unsafe { core::mem::zeroed() };
    if !needed_tcp_pkt(skb, &mut tcph) {
        return 1;
    }

    unsafe { g_packet_count += 1 };

    /* Ingress of the server socket. */
    if ingress_connect(&tcph) || ingress_close_remote(&tcph) {
        return 1;
    }

    unsafe { g_unexpected += 1 };
    1
}

/* Check the types of outgoing packets of a client socket to make sure they
 * are consistent with the state of the client socket.
 *
 * The connection is closed by the client side.
 */
#[link_section = "cgroup_skb/egress"]
#[no_mangle]
extern "C" fn client_egress(skb: *const __sk_buff) -> i32 {
    let mut tcph: TcpHdr = unsafe { core::mem::zeroed() };
    if !needed_tcp_pkt(skb, &mut tcph) {
        return 1;
    }

    unsafe { g_packet_count += 1 };

    /* Egress of the server socket. */
    if egress_connect(&tcph) || egress_close_local(&tcph) {
        return 1;
    }

    unsafe { g_unexpected += 1 };
    1
}

/* Check the types of incoming packets of a client socket to make sure they
 * are consistent with the state of the client socket.
 *
 * The connection is closed by the client side.
 */
#[link_section = "cgroup_skb/ingress"]
#[no_mangle]
extern "C" fn client_ingress(skb: *const __sk_buff) -> i32 {
    let mut tcph: TcpHdr = unsafe { core::mem::zeroed() };
    if !needed_tcp_pkt(skb, &mut tcph) {
        return 1;
    }

    unsafe { g_packet_count += 1 };

    /* Ingress of the server socket. */
    if ingress_connect(&tcph) || ingress_close_local(&tcph) {
        return 1;
    }

    unsafe { g_unexpected += 1 };
    1
}

bpf_object!("GPL");
