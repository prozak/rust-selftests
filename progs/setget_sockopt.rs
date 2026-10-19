// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/setget_sockopt.c
// (bpf-rs-core idiom). prog_tests/setget_sockopt.c attaches the three
// programs to a cgroup, creates/binds/connects TCP sockets over a veth
// (its name and ifindex are set in .rodata at open time) and reads the
// `nr_*` counters: each program runs the socket-option tables through
// bpf_loop callbacks, flipping the boolean options and setting/restoring
// the integer ones, and checks each value read back with bpf_getsockopt.
//
// The four `static const` tables, the three congestion-control names,
// `veth` and `veth_ifindex` are the C's .rodata in the C's order
// (`// C_LAYOUT:`); the tables' `flip:1` bitfield is a plain u32 member
// here, `// BTF_C_MEMBERS:` gives the struct the C's member BTF. The
// strings are C `char` arrays (`// BTF_C_CHAR:`). The C's `extern unsigned
// long CONFIG_HZ __kconfig` is declared but never read, so the C object has
// no .kconfig section and the translation declares none. bpf_core_cast(sk,
// struct tcp_sock) is bpf_rdonly_cast with the kernel type id
// (`// BTF_TYPE_ID:`); the socket fields are read through `#[btf]` views
// (sk_family/sk_state are __sk_common's skc_family/skc_state, as
// bpf_tracing_net.h defines them). The C's static helpers that clang keeps
// as .text subprograms carry their names (`#[export_name]`); the
// `__always_inline` ones and the ones clang folds are inlined.
// BTF_C_CHAR: u8
// BTF_TYPE_ID: tid_tcp_sock struct tcp_sock
// BTF_C_MEMBERS: sockopt_test
// C_LAYOUT: .rodata
// The uninitialized C locals (option values, cc names, saved_syn) are
// MaybeUninit; the structs have no padding. The bpf_loop callbacks' table
// index goes through black_box after the C's `__u32 i` truncation: rustc
// otherwise compares a 32-bit copy of the index and zero-extends the
// original by shifts for the table offset, and the verifier bounds only
// the copy ("access may be outside object bounds", lesson 43). clang keeps
// bpf_test_sockopt as a subprogram for one of its five call sites and
// inlines the other four; here it is a subprogram everywhere.
// translint: allow(kconfig)

#![allow(non_upper_case_globals)]

use core::ffi::c_void;
use core::hint::black_box;
use core::mem::MaybeUninit;
use core::ptr::{addr_of, read_volatile};

use bpf_rs_core::helpers::{bpf_getsockopt, bpf_loop, bpf_setsockopt, bpf_skc_to_tcp_sock, bpf_strncmp};
use bpf_rs_core::progs::fentry_arg as arg;
use bpf_rs_core::{bpf_object, vload, vstore};
use btf_macros::btf;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const SOCK_STREAM: u16 = 1;
const IPPROTO_IP: i32 = 0;
const IPPROTO_TCP: i32 = 6;
const IPPROTO_IPV6: i32 = 41;
const SOL_SOCKET: i32 = 1;
const SOL_TCP: i32 = 6;

const SO_REUSEADDR: i32 = 2;
const SO_SNDBUF: i32 = 7;
const SO_RCVBUF: i32 = 8;
const SO_KEEPALIVE: i32 = 9;
const SO_PRIORITY: i32 = 12;
const SO_REUSEPORT: i32 = 15;
const SO_RCVLOWAT: i32 = 18;
const SO_BINDTODEVICE: i32 = 25;
const SO_MARK: i32 = 36;
const SO_MAX_PACING_RATE: i32 = 47;
const SO_BINDTOIFINDEX: i32 = 62;
const SO_TXREHASH: i32 = 74;

const TCP_NODELAY: i32 = 1;
const TCP_MAXSEG: i32 = 2;
const TCP_KEEPIDLE: i32 = 4;
const TCP_KEEPINTVL: i32 = 5;
const TCP_KEEPCNT: i32 = 6;
const TCP_SYNCNT: i32 = 7;
const TCP_WINDOW_CLAMP: i32 = 10;
const TCP_CONGESTION: i32 = 13;
const TCP_THIN_LINEAR_TIMEOUTS: i32 = 16;
const TCP_USER_TIMEOUT: i32 = 18;
const TCP_NOTSENT_LOWAT: i32 = 25;
const TCP_SAVE_SYN: i32 = 27;
const TCP_SAVED_SYN: i32 = 28;
const TCP_RTO_MAX_MS: i32 = 44;
const TCP_BPF_DELACK_MAX: i32 = 1003;
const TCP_BPF_RTO_MIN: i32 = 1004;
const TCP_BPF_SOCK_OPS_CB_FLAGS: i32 = 1008;

const IP_TOS: i32 = 1;
const IP_TRANSPARENT: i32 = 19;
const IPV6_TCLASS: i32 = 67;
const IPV6_AUTOFLOWLABEL: i32 = 70;
const IPV6_TRANSPARENT: i32 = 75;

/* enum (uapi/linux/bpf.h): sock_ops op list, cb flags, TCP states */
const BPF_SOCK_OPS_TCP_CONNECT_CB: u32 = 3;
const BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: u32 = 4;
const BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: u32 = 5;
const BPF_SOCK_OPS_STATE_CB: u32 = 10;
const BPF_SOCK_OPS_TCP_LISTEN_CB: u32 = 11;
const BPF_SOCK_OPS_STATE_CB_FLAG: i32 = 1 << 2;
const BPF_SOCK_OPS_ALL_CB_FLAGS: i32 = 0x7F;
const BPF_TCP_CLOSE_WAIT: u32 = 8;
/* kernel sk_state */
const TCP_ESTABLISHED: u8 = 1;
const TCP_LISTEN: u8 = 10;

const IFNAMSIZ: usize = 16;

/// UAPI struct bpf_sockopt (linux/bpf.h). sk/optval/optval_end are
/// __bpf_md_ptr unions, represented as u64.
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct bpf_sockopt {
    pub sk: u64,
    pub optval: u64,
    pub optval_end: u64,
    pub level: i32,
    pub optname: i32,
    pub optlen: i32,
    pub retval: i32,
}

/// UAPI struct bpf_sock_ops (linux/bpf.h), full layout through
/// skb_hwtstamp (mptcp_sock.rs): the kernel rewrites ctx loads by byte
/// offset, so the layout must be the real one. The `args`/`reply`/
/// `replylong` union is its widest member's storage; `args[1]` is
/// reply_union[1].
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct bpf_sock_ops {
    pub op: u32,
    pub reply_union: [u32; 4],
    pub family: u32,
    pub remote_ip4: u32,
    pub local_ip4: u32,
    pub remote_ip6: [u32; 4],
    pub local_ip6: [u32; 4],
    pub remote_port: u32,
    pub local_port: u32,
    pub is_fullsock: u32,
    pub snd_cwnd: u32,
    pub srtt_us: u32,
    pub bpf_sock_ops_cb_flags: u32,
    pub state: u32,
    pub rtt_min: u32,
    pub snd_ssthresh: u32,
    pub rcv_nxt: u32,
    pub snd_nxt: u32,
    pub snd_una: u32,
    pub mss_cache: u32,
    pub ecn_flags: u32,
    pub rate_delivered: u32,
    pub rate_interval_us: u32,
    pub packets_out: u32,
    pub retrans_out: u32,
    pub total_retrans: u32,
    pub segs_in: u32,
    pub data_segs_in: u32,
    pub segs_out: u32,
    pub data_segs_out: u32,
    pub lost_out: u32,
    pub sacked_out: u32,
    pub sk_txhash: u32,
    pub bytes_received: u64,
    pub bytes_acked: u64,
    pub sk: u64,
    pub skb_data: u64,
    pub skb_data_end: u64,
    pub skb_len: u32,
    pub skb_tcp_flags: u32,
    pub skb_hwtstamp: u64,
}

#[btf]
struct sock_common {
    skc_family: u16,
    skc_state: u8,
}

#[btf]
struct sock {
    __sk_common: sock_common,
    sk_type: u16,
    sk_protocol: u16,
}

#[btf]
struct socket {
    sk: *mut sock,
}

#[btf]
struct tcp_sock {
    bpf_sock_ops_cb_flags: u8,
}

extern "C" {
    fn tid_tcp_sock() -> u64;
    fn bpf_rdonly_cast(obj: *const c_void, btf_id: u32) -> *mut c_void;
}

#[link_section = ".rodata"]
#[no_mangle]
static veth: [u8; IFNAMSIZ] = [0; IFNAMSIZ];
#[link_section = ".rodata"]
#[no_mangle]
static veth_ifindex: i32 = 0;

#[no_mangle]
static mut nr_listen: i32 = 0;
#[no_mangle]
static mut nr_passive: i32 = 0;
#[no_mangle]
static mut nr_active: i32 = 0;
#[no_mangle]
static mut nr_connect: i32 = 0;
#[no_mangle]
static mut nr_binddev: i32 = 0;
#[no_mangle]
static mut nr_socket_post_create: i32 = 0;
#[no_mangle]
static mut nr_fin_wait1: i32 = 0;

#[allow(non_camel_case_types)]
#[repr(C)]
struct sockopt_test {
    opt: i32,
    new: i32,
    restore: i32,
    expected: i32,
    tcp_expected: i32,
    flip: u32, // unsigned int flip:1 in the C
}

const fn t(opt: i32, new: i32, restore: i32, expected: i32, tcp_expected: i32, flip: u32) -> sockopt_test {
    sockopt_test { opt, new, restore, expected, tcp_expected, flip }
}

#[link_section = ".rodata"]
#[export_name = "not_exist_cc"]
static not_exist_cc: [u8; 10] = *b"not_exist\0";
#[link_section = ".rodata"]
#[export_name = "cubic_cc"]
static cubic_cc: [u8; 6] = *b"cubic\0";
#[link_section = ".rodata"]
#[export_name = "reno_cc"]
static reno_cc: [u8; 5] = *b"reno\0";

#[link_section = ".rodata"]
#[export_name = "sol_socket_tests"]
static sol_socket_tests: [sockopt_test; 11] = [
    t(SO_REUSEADDR, 0, 0, 0, 0, 1),
    t(SO_SNDBUF, 8123, 0, 8123 * 2, 0, 0),
    t(SO_RCVBUF, 8123, 0, 8123 * 2, 0, 0),
    t(SO_KEEPALIVE, 0, 0, 0, 0, 1),
    t(SO_PRIORITY, 0xeb9f, 0, 0xeb9f, 0, 0),
    t(SO_REUSEPORT, 0, 0, 0, 0, 1),
    t(SO_RCVLOWAT, 8123, 0, 8123, 0, 0),
    t(SO_MARK, 0xeb9f, 0, 0xeb9f, 0, 0),
    t(SO_MAX_PACING_RATE, 0xeb9f, 0, 0xeb9f, 0, 0),
    t(SO_TXREHASH, 0, 0, 0, 0, 1),
    t(0, 0, 0, 0, 0, 0),
];

#[link_section = ".rodata"]
#[export_name = "sol_tcp_tests"]
static sol_tcp_tests: [sockopt_test; 15] = [
    t(TCP_NODELAY, 0, 0, 0, 0, 1),
    t(TCP_KEEPIDLE, 123, 321, 123, 0, 0),
    t(TCP_KEEPINTVL, 123, 321, 123, 0, 0),
    t(TCP_KEEPCNT, 123, 124, 123, 0, 0),
    t(TCP_SYNCNT, 123, 124, 123, 0, 0),
    t(TCP_WINDOW_CLAMP, 8123, 8124, 8123, 0, 0),
    t(TCP_CONGESTION, 0, 0, 0, 0, 0),
    t(TCP_THIN_LINEAR_TIMEOUTS, 0, 0, 0, 0, 1),
    t(TCP_USER_TIMEOUT, 123400, 0, 123400, 0, 0),
    t(TCP_NOTSENT_LOWAT, 1314, 0, 1314, 0, 0),
    t(TCP_BPF_SOCK_OPS_CB_FLAGS, BPF_SOCK_OPS_ALL_CB_FLAGS, 0, BPF_SOCK_OPS_ALL_CB_FLAGS, 0, 0),
    t(TCP_BPF_DELACK_MAX, 40000, 0, 40000, 0, 0),
    t(TCP_BPF_RTO_MIN, 40000, 0, 40000, 0, 0),
    t(TCP_RTO_MAX_MS, 2000, 0, 2000, 0, 0),
    t(0, 0, 0, 0, 0, 0),
];

#[link_section = ".rodata"]
#[export_name = "sol_ip_tests"]
static sol_ip_tests: [sockopt_test; 3] = [
    t(IP_TOS, 0xe1, 0, 0xe1, 0xe0, 0),
    t(IP_TRANSPARENT, 0, 0, 0, 0, 1),
    t(0, 0, 0, 0, 0, 0),
];

#[link_section = ".rodata"]
#[export_name = "sol_ipv6_tests"]
static sol_ipv6_tests: [sockopt_test; 4] = [
    t(IPV6_TCLASS, 0xe1, 0, 0xe1, 0xe0, 0),
    t(IPV6_AUTOFLOWLABEL, 0, 0, 0, 0, 1),
    t(IPV6_TRANSPARENT, 0, 0, 0, 0, 1),
    t(0, 0, 0, 0, 0, 0),
];

#[allow(non_camel_case_types)]
#[repr(C)]
struct loop_ctx {
    ctx: *mut c_void,
    sk: *mut sock,
}

#[inline(always)]
fn sk_family(sk: *mut sock) -> u16 {
    unsafe { *(&*sk).__sk_common().skc_family().as_ptr() }
}

#[inline(always)]
fn sk_state(sk: *mut sock) -> u8 {
    unsafe { *(&*sk).__sk_common().skc_state().as_ptr() }
}

#[inline(always)]
fn sk_is_tcp(sk: *mut sock) -> bool {
    let family = sk_family(sk);
    (family == AF_INET || family == AF_INET6)
        && unsafe { *(&*sk).sk_type().as_ptr() } == SOCK_STREAM
        && unsafe { *(&*sk).sk_protocol().as_ptr() } == IPPROTO_TCP as u16
}

#[inline(never)]
#[export_name = "bpf_test_sockopt_flip"]
extern "C" fn bpf_test_sockopt_flip(ctx: *mut c_void, sk: *mut sock, t: *const sockopt_test, level: i32) -> i32 {
    let mut old = MaybeUninit::<i32>::uninit();
    let mut tmp = MaybeUninit::<i32>::uninit();
    let opt = unsafe { (*t).opt };

    if opt == SO_TXREHASH && !sk_is_tcp(sk) {
        return 0;
    }

    if bpf_getsockopt(ctx, level, opt, old.as_mut_ptr() as *mut c_void, 4) != 0 {
        return 1;
    }
    let mut old = unsafe { old.assume_init() };
    /* kernel initialized txrehash to 255 */
    if level == SOL_SOCKET && opt == SO_TXREHASH && old != 0 && old != 1 {
        old = 1;
    }

    let new: i32 = (old == 0) as i32;
    if bpf_setsockopt(ctx, level, opt, &new as *const i32 as *const c_void, 4) != 0 {
        return 1;
    }
    if bpf_getsockopt(ctx, level, opt, tmp.as_mut_ptr() as *mut c_void, 4) != 0
        || unsafe { tmp.assume_init() } != new
    {
        return 1;
    }

    if bpf_setsockopt(ctx, level, opt, &old as *const i32 as *const c_void, 4) != 0 {
        return 1;
    }

    0
}

#[inline(never)]
#[export_name = "bpf_test_sockopt_int"]
extern "C" fn bpf_test_sockopt_int(ctx: *mut c_void, sk: *mut sock, t: *const sockopt_test, level: i32) -> i32 {
    let mut old = MaybeUninit::<i32>::uninit();
    let mut tmp = MaybeUninit::<i32>::uninit();

    let opt = unsafe { (*t).opt };
    let new = unsafe { (*t).new };
    let expected = if unsafe { *(&*sk).sk_type().as_ptr() } == SOCK_STREAM && unsafe { (*t).tcp_expected } != 0 {
        unsafe { (*t).tcp_expected }
    } else {
        unsafe { (*t).expected }
    };

    if bpf_getsockopt(ctx, level, opt, old.as_mut_ptr() as *mut c_void, 4) != 0
        || unsafe { old.assume_init() } == new
    {
        return 1;
    }
    let mut old = unsafe { old.assume_init() };

    if bpf_setsockopt(ctx, level, opt, &new as *const i32 as *const c_void, 4) != 0 {
        return 1;
    }
    if bpf_getsockopt(ctx, level, opt, tmp.as_mut_ptr() as *mut c_void, 4) != 0
        || unsafe { tmp.assume_init() } != expected
    {
        return 1;
    }

    if unsafe { (*t).restore } != 0 {
        old = unsafe { (*t).restore };
    }
    if bpf_setsockopt(ctx, level, opt, &old as *const i32 as *const c_void, 4) != 0 {
        return 1;
    }

    0
}

#[export_name = "bpf_test_socket_sockopt"]
extern "C" fn bpf_test_socket_sockopt(i: u64, lc: *mut loop_ctx) -> i64 {
    let i = black_box(i as u32);

    if i >= 11 {
        return 1;
    }

    let t = unsafe { addr_of!(sol_socket_tests).cast::<sockopt_test>().add(i as usize) };
    if unsafe { (*t).opt } == 0 {
        return 1;
    }

    let lc = unsafe { &*lc };
    if unsafe { (*t).flip } != 0 {
        return bpf_test_sockopt_flip(lc.ctx, lc.sk, t, SOL_SOCKET) as i64;
    }

    bpf_test_sockopt_int(lc.ctx, lc.sk, t, SOL_SOCKET) as i64
}

#[export_name = "bpf_test_ip_sockopt"]
extern "C" fn bpf_test_ip_sockopt(i: u64, lc: *mut loop_ctx) -> i64 {
    let i = black_box(i as u32);

    if i >= 3 {
        return 1;
    }

    let t = unsafe { addr_of!(sol_ip_tests).cast::<sockopt_test>().add(i as usize) };
    if unsafe { (*t).opt } == 0 {
        return 1;
    }

    let lc = unsafe { &*lc };
    if unsafe { (*t).flip } != 0 {
        return bpf_test_sockopt_flip(lc.ctx, lc.sk, t, IPPROTO_IP) as i64;
    }

    bpf_test_sockopt_int(lc.ctx, lc.sk, t, IPPROTO_IP) as i64
}

#[export_name = "bpf_test_ipv6_sockopt"]
extern "C" fn bpf_test_ipv6_sockopt(i: u64, lc: *mut loop_ctx) -> i64 {
    let i = black_box(i as u32);

    if i >= 4 {
        return 1;
    }

    let t = unsafe { addr_of!(sol_ipv6_tests).cast::<sockopt_test>().add(i as usize) };
    if unsafe { (*t).opt } == 0 {
        return 1;
    }

    let lc = unsafe { &*lc };
    if unsafe { (*t).flip } != 0 {
        return bpf_test_sockopt_flip(lc.ctx, lc.sk, t, IPPROTO_IPV6) as i64;
    }

    bpf_test_sockopt_int(lc.ctx, lc.sk, t, IPPROTO_IPV6) as i64
}

#[export_name = "bpf_test_tcp_sockopt"]
extern "C" fn bpf_test_tcp_sockopt(i: u64, lc: *mut loop_ctx) -> i64 {
    let i = black_box(i as u32);

    if i >= 15 {
        return 1;
    }

    let t = unsafe { addr_of!(sol_tcp_tests).cast::<sockopt_test>().add(i as usize) };
    if unsafe { (*t).opt } == 0 {
        return 1;
    }

    let lc = unsafe { &*lc };
    let ctx = lc.ctx;
    let sk = lc.sk;

    if unsafe { (*t).opt } == TCP_CONGESTION {
        let mut old_cc = MaybeUninit::<[u8; 16]>::uninit();
        let mut tmp_cc = MaybeUninit::<[u8; 16]>::uninit();

        if bpf_setsockopt(ctx, IPPROTO_TCP, TCP_CONGESTION, addr_of!(not_exist_cc) as *const c_void, 10) == 0 {
            return 1;
        }
        if bpf_getsockopt(ctx, IPPROTO_TCP, TCP_CONGESTION, old_cc.as_mut_ptr() as *mut c_void, 16) != 0 {
            return 1;
        }
        let (new_cc, new_cc_len): (*const c_void, i32) =
            if bpf_strncmp(old_cc.as_ptr() as *const c_void, 16, addr_of!(cubic_cc) as *const c_void) == 0 {
                (addr_of!(reno_cc) as *const c_void, 5)
            } else {
                (addr_of!(cubic_cc) as *const c_void, 6)
            };
        if bpf_setsockopt(ctx, IPPROTO_TCP, TCP_CONGESTION, new_cc, new_cc_len) != 0 {
            return 1;
        }
        if bpf_getsockopt(ctx, IPPROTO_TCP, TCP_CONGESTION, tmp_cc.as_mut_ptr() as *mut c_void, 16) != 0 {
            return 1;
        }
        if bpf_strncmp(tmp_cc.as_ptr() as *const c_void, 16, new_cc) != 0 {
            return 1;
        }
        if bpf_setsockopt(ctx, IPPROTO_TCP, TCP_CONGESTION, old_cc.as_ptr() as *const c_void, 16) != 0 {
            return 1;
        }
        return 0;
    }

    if unsafe { (*t).flip } != 0 {
        return bpf_test_sockopt_flip(ctx, sk, t, IPPROTO_TCP) as i64;
    }

    bpf_test_sockopt_int(ctx, sk, t, IPPROTO_TCP) as i64
}

#[inline(never)]
#[export_name = "bpf_test_sockopt"]
extern "C" fn bpf_test_sockopt(ctx: *mut c_void, sk: *mut sock) -> i32 {
    let mut lc = loop_ctx { ctx, sk };

    let family = sk_family(sk);
    let proto = unsafe { *(&*sk).sk_protocol().as_ptr() };

    let mut n = bpf_loop(11, bpf_test_socket_sockopt, &mut lc, 0);
    if n != 11 {
        return -1;
    }

    if proto == IPPROTO_TCP as u16 {
        n = bpf_loop(15, bpf_test_tcp_sockopt, &mut lc, 0);
        if n != 15 {
            return -1;
        }
    }

    if family == AF_INET {
        n = bpf_loop(3, bpf_test_ip_sockopt, &mut lc, 0);
        if n != 3 {
            return -1;
        }
    } else {
        n = bpf_loop(4, bpf_test_ipv6_sockopt, &mut lc, 0);
        if n != 4 {
            return -1;
        }
    }

    0
}

#[inline(always)]
fn binddev_test(ctx: *mut c_void) -> i32 {
    let empty_ifname: [u8; 1] = [0];
    let mut ifindex = MaybeUninit::<i32>::uninit();
    let zero: i32 = 0;

    if bpf_setsockopt(ctx, SOL_SOCKET, SO_BINDTODEVICE, addr_of!(veth) as *const c_void, IFNAMSIZ as i32) != 0 {
        return -1;
    }
    if bpf_getsockopt(ctx, SOL_SOCKET, SO_BINDTOIFINDEX, ifindex.as_mut_ptr() as *mut c_void, 4) != 0
        || unsafe { ifindex.assume_init() } != unsafe { read_volatile(addr_of!(veth_ifindex)) }
    {
        return -1;
    }

    if bpf_setsockopt(ctx, SOL_SOCKET, SO_BINDTODEVICE, empty_ifname.as_ptr() as *const c_void, 1) != 0 {
        return -1;
    }
    if bpf_getsockopt(ctx, SOL_SOCKET, SO_BINDTOIFINDEX, ifindex.as_mut_ptr() as *mut c_void, 4) != 0
        || unsafe { ifindex.assume_init() } != 0
    {
        return -1;
    }

    if bpf_setsockopt(ctx, SOL_SOCKET, SO_BINDTOIFINDEX, addr_of!(veth_ifindex) as *const c_void, 4) != 0 {
        return -1;
    }
    if bpf_getsockopt(ctx, SOL_SOCKET, SO_BINDTOIFINDEX, ifindex.as_mut_ptr() as *mut c_void, 4) != 0
        || unsafe { ifindex.assume_init() } != unsafe { read_volatile(addr_of!(veth_ifindex)) }
    {
        return -1;
    }

    if bpf_setsockopt(ctx, SOL_SOCKET, SO_BINDTOIFINDEX, &zero as *const i32 as *const c_void, 4) != 0 {
        return -1;
    }
    if bpf_getsockopt(ctx, SOL_SOCKET, SO_BINDTOIFINDEX, ifindex.as_mut_ptr() as *mut c_void, 4) != 0
        || unsafe { ifindex.assume_init() } != 0
    {
        return -1;
    }

    0
}

#[inline(never)]
#[export_name = "test_tcp_maxseg"]
extern "C" fn test_tcp_maxseg(ctx: *mut c_void, sk: *mut sock) -> i32 {
    let val: i32 = 1314;
    let mut tmp = MaybeUninit::<i32>::uninit();

    if sk_state(sk) != TCP_ESTABLISHED {
        return bpf_setsockopt(ctx, IPPROTO_TCP, TCP_MAXSEG, &val as *const i32 as *const c_void, 4) as i32;
    }

    if bpf_getsockopt(ctx, IPPROTO_TCP, TCP_MAXSEG, tmp.as_mut_ptr() as *mut c_void, 4) != 0
        || unsafe { tmp.assume_init() } > val
    {
        return -1;
    }

    0
}

#[inline(never)]
#[export_name = "test_tcp_saved_syn"]
extern "C" fn test_tcp_saved_syn(ctx: *mut c_void, sk: *mut sock) -> i32 {
    let mut saved_syn = MaybeUninit::<[u8; 20]>::uninit();
    let one: i32 = 1;

    if sk_state(sk) == TCP_LISTEN {
        return bpf_setsockopt(ctx, IPPROTO_TCP, TCP_SAVE_SYN, &one as *const i32 as *const c_void, 4) as i32;
    }

    bpf_getsockopt(ctx, IPPROTO_TCP, TCP_SAVED_SYN, saved_syn.as_mut_ptr() as *mut c_void, 20) as i32
}

#[link_section = "lsm_cgroup/socket_post_create"]
#[no_mangle]
extern "C" fn socket_post_create(ctx: *const u64) -> i32 {
    let sockp = arg(ctx, 0) as *const socket;
    let sk = unsafe { *(&*sockp).sk().as_ptr() };

    if sk.is_null() {
        return 1;
    }

    unsafe {
        nr_socket_post_create += (bpf_test_sockopt(sk as *mut c_void, sk) == 0) as i32;
        nr_binddev += (binddev_test(sk as *mut c_void) == 0) as i32;
    }

    1
}

#[link_section = "cgroup/getsockopt"]
#[no_mangle]
extern "C" fn _getsockopt(ctx: *mut bpf_sockopt) -> i32 {
    let sk = vload!((*ctx).sk);
    let optval = vload!((*ctx).optval) as *mut i32;

    if sk == 0 || vload!((*ctx).level) != SOL_TCP || vload!((*ctx).optname) != TCP_BPF_SOCK_OPS_CB_FLAGS {
        return 1;
    }

    let tp = unsafe { bpf_rdonly_cast(sk as *const c_void, tid_tcp_sock() as u32) } as *const tcp_sock;
    if (vload!((*ctx).optval) + 4) as u64 <= vload!((*ctx).optval_end) {
        unsafe { *optval = *(&*tp).bpf_sock_ops_cb_flags().as_ptr() as i32 };
        vstore!((*ctx).retval, 0);
    }
    1
}

#[no_mangle]
static mut v4mapped_v6_ip_tos_enable: i32 = 0;
#[no_mangle]
static mut v4mapped_v6_ip_tos_ret: i32 = 0;
#[no_mangle]
static mut v4mapped_v6_ip_tos_cnt: i32 = 0;
#[no_mangle]
static mut v4mapped_v6_ip_tos_val: i32 = 0;

#[inline(always)]
fn test_v4mapped_v6_ip_tos(skops: *mut bpf_sock_ops) {
    let tos: i32 = unsafe { v4mapped_v6_ip_tos_val };

    if unsafe { v4mapped_v6_ip_tos_enable } == 0 || vload!((*skops).op) != BPF_SOCK_OPS_TCP_CONNECT_CB {
        return;
    }
    if vload!((*skops).family) != AF_INET6 as u32 {
        return;
    }

    unsafe {
        v4mapped_v6_ip_tos_cnt += 1;
        v4mapped_v6_ip_tos_ret =
            bpf_setsockopt(skops, IPPROTO_IP, IP_TOS, &tos as *const i32 as *const c_void, 4) as i32;
    }
}

#[link_section = "sockops"]
#[no_mangle]
extern "C" fn skops_sockopt(skops: *mut bpf_sock_ops) -> i32 {
    let bpf_sk = vload!((*skops).sk);

    if bpf_sk == 0 {
        return 1;
    }

    let sk = bpf_skc_to_tcp_sock(bpf_sk as *const c_void) as *mut sock;
    if sk.is_null() {
        return 1;
    }

    if unsafe { v4mapped_v6_ip_tos_enable } != 0 {
        test_v4mapped_v6_ip_tos(skops);
        return 1;
    }

    let ctx = skops as *mut c_void;
    match vload!((*skops).op) {
        BPF_SOCK_OPS_TCP_LISTEN_CB => unsafe {
            nr_listen += (!(bpf_test_sockopt(ctx, sk) != 0
                || test_tcp_maxseg(ctx, sk) != 0
                || test_tcp_saved_syn(ctx, sk) != 0)) as i32;
        },
        BPF_SOCK_OPS_TCP_CONNECT_CB => unsafe {
            nr_connect += (!(bpf_test_sockopt(ctx, sk) != 0 || test_tcp_maxseg(ctx, sk) != 0)) as i32;
        },
        BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB => unsafe {
            nr_active += (!(bpf_test_sockopt(ctx, sk) != 0 || test_tcp_maxseg(ctx, sk) != 0)) as i32;
        },
        BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB => unsafe {
            nr_passive += (!(bpf_test_sockopt(ctx, sk) != 0
                || test_tcp_maxseg(ctx, sk) != 0
                || test_tcp_saved_syn(ctx, sk) != 0)) as i32;
            let flags: i32 = vload!((*skops).bpf_sock_ops_cb_flags) as i32 | BPF_SOCK_OPS_STATE_CB_FLAG;
            bpf_setsockopt(skops, SOL_TCP, TCP_BPF_SOCK_OPS_CB_FLAGS, &flags as *const i32 as *const c_void, 4);
        },
        BPF_SOCK_OPS_STATE_CB => {
            if vload!((*skops).reply_union[1]) == BPF_TCP_CLOSE_WAIT {
                unsafe { nr_fin_wait1 += (bpf_test_sockopt(ctx, sk) == 0) as i32 };
            }
        }
        _ => {}
    }

    1
}

bpf_object!("GPL");
