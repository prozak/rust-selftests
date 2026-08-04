#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_iter_unix.c
// (bpf-rs-core idiom).
//
// `sk = (struct sock *)unix_sk` is elided: `sk` is the first member of
// `unix_sock` (kernel comment on `struct unix_sock`: `struct sock sk;` is
// the first field), so the raw pointer cast is address-preserving, same
// trick as bpf_iter_netlink.rs's `netlink_sock`/`sock` cast.
//
// `unix_sk->addr->name->sun_path` walks through `struct unix_address`'s
// `struct sockaddr_un name[]` flexible array member. Per
// test_skc_to_unix_sock.rs's confirmed finding, the field-reloc pipeline
// only resolves named-field byte-offset paths, not array terminals feeding
// further field chains, so `name`/`sun_path` are reached via the same
// hand-computed offset from `addr` (pahole-confirmed identical on this
// repo's UML and QEMU vmlinux images: `name` at byte 8 of `unix_address`,
// `sun_path` at byte 2 of `sockaddr_un`). Reads through that hand-computed
// address use `bpf_probe_read_kernel`, matching the C's direct load through
// a stable UAPI struct layout.

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_map_update_elem, bpf_probe_read_kernel, bpf_seq_printf};
use bpf_rs_core::maps::BpfMap;
use btf_macros::btf;

const BPF_MAP_TYPE_SOCKMAP: usize = 15;

const SIZEOF_SHORT: i32 = 2; // sizeof(short) == sizeof(sa_family_t)
const SIZEOF_SOCKADDR_UN: i32 = 110; // sizeof(struct sockaddr_un): 2 + 108
const UNIX_ADDR_NAME_OFFSET: usize = 8; // offsetof(struct unix_address, name)
const SOCKADDR_UN_SUN_PATH_OFFSET: usize = 2; // offsetof(struct sockaddr_un, sun_path)
const SUN_PATH_OFFSET_FROM_ADDR: usize = UNIX_ADDR_NAME_OFFSET + SOCKADDR_UN_SUN_PATH_OFFSET;

const TCP_ESTABLISHED: u8 = 1;
const TCP_LISTEN: u8 = 10;
const SS_UNCONNECTED: u64 = 1;
const SS_CONNECTING: u64 = 2;
const SS_CONNECTED: u64 = 3;
const SS_DISCONNECTING: u64 = 4;
const SO_ACCEPTCON: u64 = 1 << 16;

#[repr(C)]
struct bpf_iter_meta {
    seq: *mut c_void,
    session_id: u64,
    seq_num: u64,
}

#[repr(C)]
struct bpf_iter__unix {
    meta: *mut bpf_iter_meta,
    unix_sk: *mut unix_sock,
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
    skc_state: u8,
    skc_refcnt: refcount_t,
}

#[btf]
struct socket {}

#[btf]
struct sock {
    __sk_common: sock_common,
    sk_socket: *mut socket,
    sk_type: u16,
}

#[btf]
struct unix_address {
    len: i32,
}

#[btf]
struct unix_sock {
    addr: *mut unix_address,
}

#[btf]
struct inode {
    i_ino: u64,
}

#[btf]
struct socket_alloc {
    vfs_inode: inode,
}

#[link_section = ".maps"]
#[no_mangle]
static sockmap: BpfMap<u32, u64, BPF_MAP_TYPE_SOCKMAP, 1> = BpfMap::new();

#[link_section = "iter/unix"]
#[no_mangle]
extern "C" fn dump_unix(ctx: *const bpf_iter__unix) -> i32 {
    let ctx = unsafe { &*ctx };
    let unix_sk = ctx.unix_sk;
    if unix_sk.is_null() {
        return 0;
    }
    let sk = unix_sk as *mut sock;

    let meta = unsafe { &*ctx.meta };
    let seq = meta.seq;
    let seq_num = meta.seq_num;

    if seq_num == 0 {
        static FMT_HDR: [u8; 68] =
            *b"Num               RefCount Protocol Flags    Type St    Inode Path\n\0";
        bpf_seq_printf(
            seq,
            FMT_HDR.as_ptr() as *const c_void,
            FMT_HDR.len() as u32,
            core::ptr::null(),
            0,
        );
    }

    let s = unsafe { &*sk };
    let refcnt = unsafe { *s.__sk_common().skc_refcnt().refs().counter().as_ptr() } as u32 as u64;
    let sk_state = unsafe { *s.__sk_common().skc_state().as_ptr() };
    let sk_type = unsafe { *s.sk_type().as_ptr() } as u64;
    let sk_socket = unsafe { *s.sk_socket().as_ptr() };

    let flags: u64 = if sk_state == TCP_LISTEN { SO_ACCEPTCON } else { 0 };

    let state: u64 = if !sk_socket.is_null() {
        if sk_state == TCP_ESTABLISHED {
            SS_CONNECTED
        } else {
            SS_UNCONNECTED
        }
    } else if sk_state == TCP_ESTABLISHED {
        SS_CONNECTING
    } else {
        SS_DISCONNECTING
    };

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

    static FMT_MAIN: [u8; 35] = *b"%pK: %08X %08X %08X %04X %02X %8lu\0";
    let params_main: [u64; 7] = [unix_sk as u64, refcnt, 0, flags, sk_type, state, ino];
    bpf_seq_printf(
        seq,
        FMT_MAIN.as_ptr() as *const c_void,
        FMT_MAIN.len() as u32,
        params_main.as_ptr() as *const c_void,
        core::mem::size_of_val(&params_main) as u32,
    );

    let addr_ptr = unsafe { *(&*unix_sk).addr().as_ptr() };
    if !addr_ptr.is_null() {
        let sun_path_base = (addr_ptr as usize).wrapping_add(SUN_PATH_OFFSET_FROM_ADDR);

        let mut first: u8 = 0;
        bpf_probe_read_kernel(&mut first, 1, sun_path_base as *const c_void);

        if first != 0 {
            static FMT_PATH: [u8; 4] = *b" %s\0";
            let params_path: [u64; 1] = [sun_path_base as u64];
            bpf_seq_printf(
                seq,
                FMT_PATH.as_ptr() as *const c_void,
                FMT_PATH.len() as u32,
                params_path.as_ptr() as *const c_void,
                core::mem::size_of_val(&params_path) as u32,
            );
        } else {
            let addr_len = unsafe { *(&*(addr_ptr as *const unix_address)).len().as_ptr() };
            let len = addr_len - SIZEOF_SHORT;

            static FMT_AT: [u8; 3] = *b" @\0";
            bpf_seq_printf(
                seq,
                FMT_AT.as_ptr() as *const c_void,
                FMT_AT.len() as u32,
                core::ptr::null(),
                0,
            );

            let mut i: i32 = 1;
            while i < len {
                if i >= SIZEOF_SOCKADDR_UN {
                    break;
                }

                let mut byte: u8 = 0;
                bpf_probe_read_kernel(
                    &mut byte,
                    1,
                    sun_path_base.wrapping_add(i as usize) as *const c_void,
                );
                let printed = if byte != 0 { byte } else { b'@' };

                static FMT_C: [u8; 3] = *b"%c\0";
                let params_c: [u64; 1] = [printed as u64];
                bpf_seq_printf(
                    seq,
                    FMT_C.as_ptr() as *const c_void,
                    FMT_C.len() as u32,
                    params_c.as_ptr() as *const c_void,
                    core::mem::size_of_val(&params_c) as u32,
                );

                i += 1;
            }
        }
    }

    static FMT_NL: [u8; 2] = *b"\n\0";
    bpf_seq_printf(
        seq,
        FMT_NL.as_ptr() as *const c_void,
        FMT_NL.len() as u32,
        core::ptr::null(),
        0,
    );

    // Test for deadlock.
    let key: u32 = 0;
    bpf_map_update_elem(&sockmap, &key, unsafe { &*sk }, 0);

    0
}

bpf_object!("GPL");
