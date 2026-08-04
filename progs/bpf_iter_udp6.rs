#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_iter_udp6.c
// (bpf-rs-core idiom).
//
// `struct bpf_iter__udp` (net/ipv4/udp.c) declares `uid` and `bucket` as
// `__aligned(8)`, so `bucket` sits at byte offset 24, not the 20 a plain
// `{ptr, ptr, u32, i32}` struct would naturally give it; an explicit `_pad`
// field reproduces that gap.
//
// C's `bpf_skc_to_udp6_sock(udp_sk)` result (`udp6_sk`) is only used for its
// NULL check (confirming `udp_sk` is really a UDPv6 socket); every field
// access afterwards still goes through the original `udp_sk`/`inet_sock`
// chain, so no `udp6_sock`/`ipv6_pinfo` BTF type is needed here.
//
// C's `inet_dport` is bpf_tracing_net.h's naming macro for
// `sk.__sk_common.skc_dport` (there is no real `inet_dport` field on
// `inet_sock`); `sk_v6_daddr`/`sk_v6_rcv_saddr` similarly name
// `__sk_common.skc_v6_daddr`/`skc_v6_rcv_saddr`, and `s6_addr32` names
// `in6_u.u6_addr32`. All of those chains are spelled out explicitly below.
//
// `sock_i_ino()`'s `container_of(sk_socket, struct socket_alloc, socket)`
// collapses to a plain pointer reinterpretation because `socket` is
// `socket_alloc`'s first member (offset 0) -- same trick already used in
// bpf_iter_netlink.rs.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_probe_read_kernel, bpf_seq_printf, bpf_skc_to_udp6_sock};
use btf_macros::btf;
use core::ffi::c_void;

#[repr(C)]
struct bpf_iter_meta {
    seq: *mut c_void,
    session_id: u64,
    seq_num: u64,
}

#[repr(C)]
struct bpf_iter__udp {
    meta: *mut bpf_iter_meta,
    udp_sk: *mut udp_sock,
    uid: u32,
    _pad: u32,
    bucket: i32,
}

#[btf]
struct atomic_t {
    counter: i32,
}

#[btf]
struct refcount_t {
    refs: atomic_t,
}

#[btf]
struct in6_u {
    u6_addr32: [u32; 4],
}

#[btf]
struct in6_addr {
    in6_u: in6_u,
}

#[btf]
struct sk_backlog {
    rmem_alloc: atomic_t,
}

#[btf]
struct sock_common {
    skc_dport: u16,
    skc_state: u8,
    skc_refcnt: refcount_t,
    skc_v6_daddr: in6_addr,
    skc_v6_rcv_saddr: in6_addr,
}

#[btf]
struct socket {}

#[btf]
struct sock {
    __sk_common: sock_common,
    sk_backlog: sk_backlog,
    sk_wmem_alloc: refcount_t,
    sk_drops: atomic_t,
    sk_socket: *mut socket,
}

#[btf]
struct inet_sock {
    sk: sock,
    inet_sport: u16,
}

#[btf]
struct numa_drop_counters {
    drops0: atomic_t,
    drops1: atomic_t,
}

#[btf]
struct udp_sock {
    inet: inet_sock,
    forward_deficit: i32,
    drop_counters: numa_drop_counters,
}

#[btf]
struct inode {
    i_ino: u64,
}

#[btf]
struct socket_alloc {
    vfs_inode: inode,
}

#[link_section = "iter/udp"]
#[no_mangle]
extern "C" fn dump_udp6(ctx: *const bpf_iter__udp) -> i32 {
    let ctx = unsafe { &*ctx };
    let udp_sk = ctx.udp_sk;
    if udp_sk.is_null() {
        return 0;
    }

    let meta = unsafe { &*ctx.meta };
    let seq = meta.seq;

    if meta.seq_num == 0 {
        static HEADER: [u8; 164] = *b"  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n\0";
        bpf_seq_printf(
            seq,
            HEADER.as_ptr() as *const c_void,
            HEADER.len() as u32,
            core::ptr::null(),
            0,
        );
    }

    let udp6_check = bpf_skc_to_udp6_sock(udp_sk as *mut c_void);
    if udp6_check.is_null() {
        return 0;
    }

    let udp_ref = unsafe { &*udp_sk };
    let inet = udp_ref.inet();
    let s = inet.sk();

    let inet_sport = unsafe { *inet.inet_sport().as_ptr() };
    let inet_dport = unsafe { *s.__sk_common().skc_dport().as_ptr() };
    let srcp = u16::from_be(inet_sport);
    let destp = u16::from_be(inet_dport);

    let rmem_alloc = unsafe { *s.sk_backlog().rmem_alloc().counter().as_ptr() };
    let forward_deficit = unsafe { *udp_ref.forward_deficit().as_ptr() };
    let rqueue = rmem_alloc.wrapping_sub(forward_deficit);

    let src_ptr =
        s.__sk_common().skc_v6_rcv_saddr().in6_u().u6_addr32().as_ptr() as *const u32;
    let dest_ptr = s.__sk_common().skc_v6_daddr().in6_u().u6_addr32().as_ptr() as *const u32;
    let (src0, src1, src2, src3) = unsafe {
        (*src_ptr, *src_ptr.add(1), *src_ptr.add(2), *src_ptr.add(3))
    };
    let (dest0, dest1, dest2, dest3) = unsafe {
        (*dest_ptr, *dest_ptr.add(1), *dest_ptr.add(2), *dest_ptr.add(3))
    };

    static FMT1: [u8; 50] = *b"%5d: %08X%08X%08X%08X:%04X %08X%08X%08X%08X:%04X \0";
    let params1: [u64; 11] = [
        ctx.bucket as i64 as u64,
        src0 as u64,
        src1 as u64,
        src2 as u64,
        src3 as u64,
        srcp as u64,
        dest0 as u64,
        dest1 as u64,
        dest2 as u64,
        dest3 as u64,
        destp as u64,
    ];
    bpf_seq_printf(
        seq,
        FMT1.as_ptr() as *const c_void,
        FMT1.len() as u32,
        params1.as_ptr() as *const c_void,
        core::mem::size_of_val(&params1) as u32,
    );

    let sk_state = unsafe { *s.__sk_common().skc_state().as_ptr() };
    let sk_wmem_alloc = unsafe { *s.sk_wmem_alloc().refs().counter().as_ptr() };
    let sk_refcnt = unsafe { *s.__sk_common().skc_refcnt().refs().counter().as_ptr() };

    let sk_socket = unsafe { *s.sk_socket().as_ptr() };
    let mut ino: u64 = 0;
    if !sk_socket.is_null() {
        let salloc = sk_socket as *mut socket_alloc;
        let ino_addr = unsafe { &*salloc }.vfs_inode().i_ino().as_ptr();
        bpf_probe_read_kernel(&mut ino, core::mem::size_of::<u64>() as u32, ino_addr as *const c_void);
    }

    let sk_drops0 = unsafe { *udp_ref.drop_counters().drops0().counter().as_ptr() };
    let sk_drops1 = unsafe { *udp_ref.drop_counters().drops1().counter().as_ptr() };
    let drops = sk_drops0.wrapping_add(sk_drops1);

    static FMT2: [u8; 54] = *b"%02X %08X:%08X %02X:%08lX %08X %5u %8d %lu %d %pK %u\n\0";
    let params2: [u64; 12] = [
        sk_state as u64,
        (sk_wmem_alloc.wrapping_sub(1)) as i64 as u64,
        rqueue as i64 as u64,
        0,
        0,
        0,
        ctx.uid as u64,
        0,
        ino,
        sk_refcnt as i64 as u64,
        udp_sk as u64,
        drops as i64 as u64,
    ];
    bpf_seq_printf(
        seq,
        FMT2.as_ptr() as *const c_void,
        FMT2.len() as u32,
        params2.as_ptr() as *const c_void,
        core::mem::size_of_val(&params2) as u32,
    );

    0
}

bpf_object!("GPL");
