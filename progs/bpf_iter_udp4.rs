#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_iter_udp4.c
// (bpf-rs-core idiom).
//
// Field-access chain mirrors bpf_iter_netlink.rs / bpf_iter_setsockopt.rs:
// C's `inet->sk.sk_family` / `inet->inet_daddr` etc. macro-expand (see
// include/net/sock.h, include/net/inet_sock.h) to
// `inet->sk.__sk_common.skc_family` / `inet->sk.__sk_common.skc_daddr`; the
// anonymous unions wrapping skc_daddr/skc_rcv_saddr/skc_dport/skc_hash in the
// real `sock_common` are flattened here as plain named fields, same as
// bpf_iter_setsockopt.rs's `sock_common` -- #[btf] field relocation matches
// by name at each nesting level and tolerates the collapsed anonymous
// wrappers.
//
// `sock_i_ino()` is the same container_of(sk_socket, socket_alloc, socket)
// pattern as bpf_iter_netlink.rs's dump_netlink.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_probe_read_kernel, bpf_seq_printf};
use btf_macros::btf;
use core::ffi::c_void;

const AF_INET6: u16 = 10;

fn ntohs(x: u16) -> u16 {
    u16::from_be(x)
}

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
    uid: u64,
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
struct numa_drop_counters {
    drops0: atomic_t,
    drops1: atomic_t,
}

#[btf]
struct sk_backlog {
    rmem_alloc: atomic_t,
}

#[btf]
struct sock_common {
    skc_daddr: u32,
    skc_rcv_saddr: u32,
    skc_dport: u16,
    skc_family: u16,
    skc_state: u8,
    skc_refcnt: refcount_t,
}

#[btf]
struct socket {}

#[btf]
struct sock {
    __sk_common: sock_common,
    sk_backlog: sk_backlog,
    sk_wmem_alloc: refcount_t,
    sk_socket: *mut socket,
}

#[btf]
struct inet_sock {
    sk: sock,
    inet_sport: u16,
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
extern "C" fn dump_udp4(ctx: *const bpf_iter__udp) -> i32 {
    let ctx = unsafe { &*ctx };
    let udp_sk = ctx.udp_sk;
    if udp_sk.is_null() {
        return 0;
    }

    let meta = unsafe { &*ctx.meta };
    let seq_num = meta.seq_num;
    if seq_num == 0 {
        static FMT0: [u8; 116] = *b"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n\0";
        bpf_seq_printf(
            meta.seq,
            FMT0.as_ptr() as *const c_void,
            FMT0.len() as u32,
            core::ptr::null(),
            0,
        );
    }

    let udp_ref = unsafe { &*udp_sk };
    let inet = udp_ref.inet();
    let s = inet.sk();

    // filter out udp6 sockets
    let family = unsafe { *s.__sk_common().skc_family().as_ptr() };
    if family == AF_INET6 {
        return 0;
    }

    let dest = unsafe { *s.__sk_common().skc_daddr().as_ptr() };
    let src = unsafe { *s.__sk_common().skc_rcv_saddr().as_ptr() };
    let srcp = ntohs(unsafe { *inet.inet_sport().as_ptr() });
    let destp = ntohs(unsafe { *s.__sk_common().skc_dport().as_ptr() });
    let rmem_alloc = unsafe { *s.sk_backlog().rmem_alloc().counter().as_ptr() };
    let forward_deficit = unsafe { *udp_ref.forward_deficit().as_ptr() };
    let rqueue = rmem_alloc.wrapping_sub(forward_deficit);

    static FMT1: [u8; 26] = *b"%5d: %08X:%04X %08X:%04X \0";
    let params1: [u64; 5] = [
        ctx.bucket as i64 as u64,
        src as u64,
        srcp as u64,
        dest as u64,
        destp as u64,
    ];
    bpf_seq_printf(
        meta.seq,
        FMT1.as_ptr() as *const c_void,
        FMT1.len() as u32,
        params1.as_ptr() as *const c_void,
        core::mem::size_of_val(&params1) as u32,
    );

    let state = unsafe { *s.__sk_common().skc_state().as_ptr() };
    let wmem_alloc_minus1 = (unsafe { *s.sk_wmem_alloc().refs().counter().as_ptr() }).wrapping_sub(1);
    let uid = ctx.uid as u32;
    let sk_socket = unsafe { *s.sk_socket().as_ptr() };
    let mut ino: u64 = 0;
    if !sk_socket.is_null() {
        let salloc = sk_socket as *mut socket_alloc;
        let ino_addr = unsafe { &*salloc }.vfs_inode().i_ino().as_ptr();
        bpf_probe_read_kernel(&mut ino, core::mem::size_of::<u64>() as u32, ino_addr as *const c_void);
    }
    let refcnt = unsafe { *s.__sk_common().skc_refcnt().refs().counter().as_ptr() };
    let drops0 = unsafe { *udp_ref.drop_counters().drops0().counter().as_ptr() };
    let drops1 = unsafe { *udp_ref.drop_counters().drops1().counter().as_ptr() };
    let drops = drops0.wrapping_add(drops1);

    static FMT2: [u8; 54] = *b"%02X %08X:%08X %02X:%08lX %08X %5u %8d %lu %d %pK %u\n\0";
    let params2: [u64; 12] = [
        state as u64,
        wmem_alloc_minus1 as i64 as u64,
        rqueue as i64 as u64,
        0,
        0,
        0,
        uid as u64,
        0,
        ino,
        refcnt as i64 as u64,
        udp_sk as u64,
        drops as i64 as u64,
    ];
    bpf_seq_printf(
        meta.seq,
        FMT2.as_ptr() as *const c_void,
        FMT2.len() as u32,
        params2.as_ptr() as *const c_void,
        core::mem::size_of_val(&params2) as u32,
    );

    0
}

bpf_object!("GPL");
