// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/lsm_cgroup.c
// (bpf-rs-core idiom). prog_tests/lsm_cgroup.c attaches the lsm_cgroup
// programs to a cgroup, creates/binds sockets and reads the `called_*`
// counters, the two `*_retval` globals and the cgroup storage back.
//
// The three CONFIG_SECURITY_* bools are the C's weak `__kconfig` externs
// (`// BTF_KCONFIG:` below, scripts/ksym_vars.py mirrors the C object's
// declarations): libbpf fills them from the running kernel's config and the
// consumer reads them through `skel->kconfig` to pick the expected
// socket_alloc behaviour. clang tests each as `w != 0` in socket_alloc, so
// the Rust compares `!= 0` too.
//
// `sk->sk_kern_sock` is a one-bit kernel bitfield; a `#[btf]` field access
// naming a bitfield member does not work (bpf_iter_tcp4.rs explains the
// libbpf FIELD_BYTE_OFFSET size mismatch), so the byte holding it is
// reached from the plain `sk_shutdown` byte right after it and masked with
// 0x2 (bit 1: `sk_gso_disabled:1, sk_kern_sock:1, ...`), which is what the
// C object compiles to (`w1 = *(u8 *)(r1 + 0x3c8); w1 &= 0x2`).
//
// `struct sockaddr_ll` is 20 bytes with no implicit padding, so `= {}` and
// the 20-byte bpf_probe_read_kernel() are the same here.

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_get_local_storage, bpf_get_retval, bpf_getsockopt, bpf_probe_read_kernel,
    bpf_set_retval, bpf_setsockopt,
};
use bpf_rs_core::progs::fentry_arg as arg;
use btf_macros::btf;
use core::ffi::c_void;

// BTF_KCONFIG: CONFIG_SECURITY_SELINUX
// BTF_KCONFIG: CONFIG_SECURITY_SMACK
// BTF_KCONFIG: CONFIG_SECURITY_APPARMOR
extern "C" {
    static CONFIG_SECURITY_SELINUX: u8;
    static CONFIG_SECURITY_SMACK: u8;
    static CONFIG_SECURITY_APPARMOR: u8;
}

const AF_PACKET: i32 = 17;
const AF_UNIX: i32 = 1;
const SOL_SOCKET: i32 = 1;
const SO_PRIORITY: i32 = 12;

#[btf]
struct sock_common {
    skc_family: u16,
}

#[btf]
struct sock {
    __sk_common: sock_common,
    sk_shutdown: u8,
}

#[btf]
struct socket {
    sk: *mut sock,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct sockaddr_ll {
    sll_family: u16,
    sll_protocol: u16,
    sll_ifindex: i32,
    sll_hatype: u16,
    sll_pkttype: u8,
    sll_halen: u8,
    sll_addr: [u8; 8],
}

bpf_map! {
    cgroup_storage {
        r#type: *const [i32; 19], // BPF_MAP_TYPE_CGROUP_STORAGE
        key: *const u64,
        value: *const u64,
    }
}

#[no_mangle]
static mut called_socket_post_create: i32 = 0;
#[no_mangle]
static mut called_socket_post_create2: i32 = 0;
#[no_mangle]
static mut called_socket_bind: i32 = 0;
#[no_mangle]
static mut called_socket_bind2: i32 = 0;
#[no_mangle]
static mut called_socket_alloc: i32 = 0;
#[no_mangle]
static mut called_socket_clone: i32 = 0;
#[no_mangle]
static mut skipcap_retval: i32 = -4095;
#[no_mangle]
static mut socket_retval: i32 = -4095;

#[inline(always)]
fn test_local_storage() -> i32 {
    let val = bpf_get_local_storage(&cgroup_storage, 0) as *mut u64;
    if val.is_null() {
        return 0;
    }
    unsafe { *val += 1 };

    1
}

#[inline(always)]
fn real_create(sockp: *const socket, family: i32, protocol: i32) -> i32 {
    let mut prio: i32 = 123;

    /* Reject non-tx-only AF_PACKET. */
    if family == AF_PACKET && protocol != 0 {
        return 0; /* EPERM */
    }

    let sk = unsafe { *(&*sockp).sk().as_ptr() };
    if sk.is_null() {
        return 1;
    }

    /* The rest of the sockets get default policy. */
    if bpf_setsockopt(sk, SOL_SOCKET, SO_PRIORITY, &prio as *const i32 as *const c_void, 4) != 0 {
        return 0; /* EPERM */
    }

    /* Make sure bpf_getsockopt is allowed and works. */
    prio = 0;
    if bpf_getsockopt(sk, SOL_SOCKET, SO_PRIORITY, &mut prio as *mut i32 as *mut c_void, 4) != 0 {
        return 0; /* EPERM */
    }
    if prio != 123 {
        return 0; /* EPERM */
    }

    /* Can access cgroup local storage. */
    if test_local_storage() == 0 {
        return 0; /* EPERM */
    }

    1
}

/* __cgroup_bpf_run_lsm_socket */
#[link_section = "lsm_cgroup/socket_post_create"]
#[no_mangle]
extern "C" fn socket_post_create(ctx: *const u64) -> i32 {
    unsafe { called_socket_post_create += 1 };
    real_create(arg(ctx, 0) as *const socket, arg(ctx, 1) as i32, arg(ctx, 3) as i32)
}

/* __cgroup_bpf_run_lsm_socket */
#[link_section = "lsm_cgroup/socket_post_create"]
#[no_mangle]
extern "C" fn socket_post_create2(ctx: *const u64) -> i32 {
    unsafe { called_socket_post_create2 += 1 };
    real_create(arg(ctx, 0) as *const socket, arg(ctx, 1) as i32, arg(ctx, 3) as i32)
}

#[inline(always)]
fn real_bind(sockp: *const socket, address: *const c_void) -> i32 {
    let mut sa = sockaddr_ll {
        sll_family: 0,
        sll_protocol: 0,
        sll_ifindex: 0,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    };
    let sk = unsafe { *(&*sockp).sk().as_ptr() };

    if sk.is_null() {
        return 1;
    }

    if unsafe { *(&*sk).__sk_common().skc_family().as_ptr() } != AF_PACKET as u16 {
        return 1;
    }

    // sk->sk_kern_sock: bit 1 of the byte before sk_shutdown
    let shutdown = unsafe { &*sk }.sk_shutdown().as_ptr();
    if unsafe { *shutdown.sub(1) } & 0x2 != 0 {
        return 1;
    }

    bpf_probe_read_kernel(&mut sa, core::mem::size_of::<sockaddr_ll>() as u32, address);
    if sa.sll_protocol != 0 {
        return 0; /* EPERM */
    }

    /* Can access cgroup local storage. */
    if test_local_storage() == 0 {
        return 0; /* EPERM */
    }

    1
}

/* __cgroup_bpf_run_lsm_socket */
#[link_section = "lsm_cgroup/socket_bind"]
#[no_mangle]
extern "C" fn socket_bind(ctx: *const u64) -> i32 {
    unsafe { called_socket_bind += 1 };
    real_bind(arg(ctx, 0) as *const socket, arg(ctx, 1) as *const c_void)
}

/* __cgroup_bpf_run_lsm_socket */
#[link_section = "lsm_cgroup/socket_bind"]
#[no_mangle]
extern "C" fn socket_bind2(ctx: *const u64) -> i32 {
    unsafe { called_socket_bind2 += 1 };
    real_bind(arg(ctx, 0) as *const socket, arg(ctx, 1) as *const c_void)
}

/* __cgroup_bpf_run_lsm_current (via bpf_lsm_current_hooks) */
#[link_section = "lsm_cgroup/sk_alloc_security"]
#[no_mangle]
extern "C" fn socket_alloc(ctx: *const u64) -> i32 {
    let family = arg(ctx, 1) as i32;

    unsafe { called_socket_alloc += 1 };
    /* if already have non-bpf lsms installed, EPERM will cause memory leak of non-bpf lsms */
    if unsafe { CONFIG_SECURITY_SELINUX != 0 || CONFIG_SECURITY_SMACK != 0 || CONFIG_SECURITY_APPARMOR != 0 } {
        return 1;
    }

    if family == AF_UNIX {
        return 0; /* EPERM */
    }

    /* Can access cgroup local storage. */
    if test_local_storage() == 0 {
        return 0; /* EPERM */
    }

    1
}

/* __cgroup_bpf_run_lsm_sock */
#[link_section = "lsm_cgroup/inet_csk_clone"]
#[no_mangle]
extern "C" fn socket_clone(ctx: *const u64) -> i32 {
    let newsk = arg(ctx, 0) as *mut sock;
    let mut prio: i32 = 234;

    if newsk.is_null() {
        return 1;
    }

    /* Accepted request sockets get a different priority. */
    if bpf_setsockopt(newsk, SOL_SOCKET, SO_PRIORITY, &prio as *const i32 as *const c_void, 4) != 0 {
        return 1;
    }

    /* Make sure bpf_getsockopt is allowed and works. */
    prio = 0;
    if bpf_getsockopt(newsk, SOL_SOCKET, SO_PRIORITY, &mut prio as *mut i32 as *mut c_void, 4) != 0 {
        return 1;
    }
    if prio != 234 {
        return 1;
    }

    /* Can access cgroup local storage. */
    if test_local_storage() == 0 {
        return 1;
    }

    unsafe { called_socket_clone += 1 };

    1
}

#[link_section = "lsm_cgroup/inode_xattr_skipcap"]
#[no_mangle]
extern "C" fn skipcap_first(_ctx: *const u64) -> i32 {
    0
}

#[link_section = "lsm_cgroup/inode_xattr_skipcap"]
#[no_mangle]
extern "C" fn skipcap_second(_ctx: *const u64) -> i32 {
    unsafe { skipcap_retval = bpf_get_retval() };
    bpf_set_retval(0);
    1
}

#[link_section = "lsm_cgroup/socket_create"]
#[no_mangle]
extern "C" fn socket_first(_ctx: *const u64) -> i32 {
    0
}

#[link_section = "lsm_cgroup/socket_create"]
#[no_mangle]
extern "C" fn socket_second(_ctx: *const u64) -> i32 {
    unsafe { socket_retval = bpf_get_retval() };
    bpf_set_retval(0);
    1
}

bpf_object!("GPL");
