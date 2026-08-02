#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_iter_netlink.c
// (bpf-rs-core idiom).
//
// C's `s = &nlk->sk;` is elided: `sk` is the first member of
// `netlink_sock` (kernel comment: "struct sock has to be the first member of
// netlink_sock"), so its address equals `nlk`'s; printing `nlk` for `%pK`
// gives the same bit pattern the C original prints for `s`.
//
// C's `SOCK_INODE()` computes `container_of(socket, struct socket_alloc,
// socket)->vfs_inode`: `socket` is `socket_alloc`'s first member (offset 0),
// so the container_of collapses to a plain pointer reinterpretation; only
// the `vfs_inode` field offset needs a real (CO-RE) relocation, exactly as
// the C comment notes ("container_of ... forced type conversion, direct
// access cannot be used") -- reached only through `as_ptr()` + a probe read,
// never a direct load.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_probe_read_kernel, bpf_seq_printf};
use btf_macros::btf;
use core::ffi::c_void;

#[repr(C)]
struct bpf_iter_meta {
    seq: *mut c_void,
    session_id: u64,
    seq_num: u64,
}

#[repr(C)]
struct bpf_iter__netlink {
    meta: *mut bpf_iter_meta,
    sk: *mut netlink_sock,
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
struct sock_common {
    skc_refcnt: refcount_t,
}

#[btf]
struct sk_backlog {
    rmem_alloc: atomic_t,
}

#[btf]
struct socket {}

#[btf]
struct sock {
    __sk_common: sock_common,
    sk_backlog: sk_backlog,
    sk_wmem_alloc: refcount_t,
    sk_drops: atomic_t,
    sk_protocol: u16,
    sk_socket: *mut socket,
}

#[btf]
struct netlink_sock {
    sk: sock,
    portid: u32,
    groups: *mut u64,
    cb_running: u8,
}

#[btf]
struct inode {
    i_ino: u64,
}

#[btf]
struct socket_alloc {
    vfs_inode: inode,
}

#[link_section = "iter/netlink"]
#[no_mangle]
extern "C" fn dump_netlink(ctx: *const bpf_iter__netlink) -> i32 {
    let ctx = unsafe { &*ctx };
    let nlk = ctx.sk;
    if nlk.is_null() {
        return 0;
    }
    let meta = unsafe { &*ctx.meta };
    let nlk_ref = unsafe { &*nlk };
    let s = nlk_ref.sk();

    if meta.seq_num == 0 {
        static FMT0: [u8; 90] = *b"sk               Eth Pid        Groups   Rmem     Wmem     Dump  Locks    Drops    Inode\n\0";
        bpf_seq_printf(
            meta.seq,
            FMT0.as_ptr() as *const c_void,
            FMT0.len() as u32,
            core::ptr::null(),
            0,
        );
    }

    let sk_protocol = unsafe { *s.sk_protocol().as_ptr() } as u64;
    static FMT1: [u8; 10] = *b"%pK %-3d \0";
    let params1: [u64; 2] = [nlk as u64, sk_protocol];
    bpf_seq_printf(
        meta.seq,
        FMT1.as_ptr() as *const c_void,
        FMT1.len() as u32,
        params1.as_ptr() as *const c_void,
        core::mem::size_of_val(&params1) as u32,
    );

    let groups_ptr = unsafe { *nlk_ref.groups().as_ptr() };
    let mut group: u64 = 0;
    if !groups_ptr.is_null() {
        bpf_probe_read_kernel(
            &mut group,
            core::mem::size_of::<u64>() as u32,
            groups_ptr as *const c_void,
        );
    }

    let portid = unsafe { *nlk_ref.portid().as_ptr() } as u64;
    let group32 = (group as u32) as u64;
    let rmem_alloc = unsafe { *s.sk_backlog().rmem_alloc().counter().as_ptr() } as i64 as u64;
    let wmem_alloc = unsafe { *s.sk_wmem_alloc().refs().counter().as_ptr() };
    let wmem_alloc_minus1 = wmem_alloc.wrapping_sub(1) as i64 as u64;
    let cb_running = unsafe { *nlk_ref.cb_running().as_ptr() } as u64;
    let refcnt =
        unsafe { *s.__sk_common().skc_refcnt().refs().counter().as_ptr() } as i64 as u64;
    static FMT2: [u8; 32] = *b"%-10u %08x %-8d %-8d %-5d %-8d \0";
    let params2: [u64; 6] = [portid, group32, rmem_alloc, wmem_alloc_minus1, cb_running, refcnt];
    bpf_seq_printf(
        meta.seq,
        FMT2.as_ptr() as *const c_void,
        FMT2.len() as u32,
        params2.as_ptr() as *const c_void,
        core::mem::size_of_val(&params2) as u32,
    );

    let sk_socket = unsafe { *s.sk_socket().as_ptr() };
    let mut ino: u64 = 0;
    if !sk_socket.is_null() {
        let salloc = sk_socket as *mut socket_alloc;
        let ino_addr = unsafe { &*salloc }.vfs_inode().i_ino().as_ptr();
        bpf_probe_read_kernel(
            &mut ino,
            core::mem::size_of::<u64>() as u32,
            ino_addr as *const c_void,
        );
    }

    let sk_drops = unsafe { *s.sk_drops().counter().as_ptr() } as i64 as u64;
    static FMT3: [u8; 12] = *b"%-8u %-8lu\n\0";
    let params3: [u64; 2] = [sk_drops, ino];
    bpf_seq_printf(
        meta.seq,
        FMT3.as_ptr() as *const c_void,
        FMT3.len() as u32,
        params3.as_ptr() as *const c_void,
        core::mem::size_of_val(&params3) as u32,
    );

    0
}

bpf_object!("GPL");
