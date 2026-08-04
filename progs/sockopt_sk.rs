#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/sockopt_sk.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_get_netns_cookie, bpf_getsockopt, bpf_sk_storage_get, bpf_tcp_sock,
};
use core::ffi::c_void;

const AF_NETLINK: u32 = 16;
const AF_INET: u32 = 2;
const SOCK_RAW: u32 = 3;

const SOL_IP: i32 = 0;
const IP_TOS: i32 = 1;
const IP_FREEBIND: i32 = 15;

const SOL_SOCKET: i32 = 1;
const SO_SNDBUF: i32 = 7;

const SOL_TCP: i32 = 6;
const TCP_CONGESTION: i32 = 13;
const TCP_SAVED_SYN: i32 = 28;
const TCP_ZEROCOPY_RECEIVE: i32 = 35;

const SOL_CUSTOM: i32 = 0xdeadbeefu32 as i32;

const BPF_SK_STORAGE_GET_F_CREATE: u64 = 1;

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

/// UAPI struct bpf_sock (linux/bpf.h), through `type` only.
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct bpf_sock {
    pub bound_dev_if: u32,
    pub family: u32,
    pub r#type: u32,
}

#[repr(C)]
struct sockopt_sk {
    val: u8,
}

bpf_map! {
    socket_storage_map {
        r#type: *const [i32; 24],  // BPF_MAP_TYPE_SK_STORAGE
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        key: *const i32,
        value: *const sockopt_sk,
    }
}

#[no_mangle]
static mut page_size: i32 = 0;

// C's __builtin_memcpy of a small fixed-size string lowers to an llvm.memcpy
// that add_ksyms.py rewrites into an unresolvable extern bpf_arena_memcpy
// kfunc call; a volatile byte loop is the one pattern the optimizer can't
// fold into that shape.
#[inline(always)]
unsafe fn vcopy(dst: *mut u8, src: *const u8, len: usize) {
    let mut i = 0usize;
    while i < len {
        core::ptr::write_volatile(dst.add(i), core::ptr::read_volatile(src.add(i)));
        i += 1;
    }
}

#[inline(always)]
fn out(ctx: &mut bpf_sockopt) -> i32 {
    // optval larger than PAGE_SIZE use kernel's buffer.
    if ctx.optlen > unsafe { page_size } {
        ctx.optlen = 0;
    }
    1
}

#[link_section = "cgroup/getsockopt"]
#[no_mangle]
extern "C" fn _getsockopt(ctx: *mut bpf_sockopt) -> i32 {
    let c = unsafe { &mut *ctx };
    let optval = c.optval as *mut u8;
    let optval_end = c.optval_end as *mut u8;

    // Bypass AF_NETLINK.
    let sk_ptr = c.sk as *const bpf_sock;
    if !sk_ptr.is_null() {
        let sk = unsafe { &*sk_ptr };
        if sk.family == AF_NETLINK {
            return out(c);
        }
    }

    // Make sure bpf_get_netns_cookie is callable.
    if bpf_get_netns_cookie(core::ptr::null::<c_void>()) == 0 {
        return 0;
    }
    if bpf_get_netns_cookie(ctx as *const c_void) == 0 {
        return 0;
    }

    if c.level == SOL_IP && c.optname == IP_TOS {
        // Not interested in SOL_IP:IP_TOS; let next BPF program in the
        // cgroup chain or kernel handle it.
        return out(c);
    }

    if c.level == SOL_SOCKET && c.optname == SO_SNDBUF {
        // Not interested in SOL_SOCKET:SO_SNDBUF; let next BPF program in
        // the cgroup chain or kernel handle it.
        return out(c);
    }

    if c.level == SOL_TCP && c.optname == TCP_CONGESTION {
        // Not interested in SOL_TCP:TCP_CONGESTION; let next BPF program in
        // the cgroup chain or kernel handle it.
        return out(c);
    }

    if c.level == SOL_TCP && c.optname == TCP_ZEROCOPY_RECEIVE {
        // Verify that TCP_ZEROCOPY_RECEIVE triggers. It has a custom
        // implementation for performance reasons.

        // Check that optval contains address (__u64)
        if unsafe { optval.add(8) } > optval_end {
            return 0; // bounds check
        }

        let address = unsafe { core::ptr::read_unaligned(optval as *const u64) };
        if address != 0 {
            return 0; // unexpected data
        }

        return out(c);
    }

    if c.level == SOL_IP && c.optname == IP_FREEBIND {
        if unsafe { optval.add(1) } > optval_end {
            return 0; // bounds check
        }

        c.retval = 0; // Reset system call return value to zero

        // Always export 0x55
        unsafe { *optval = 0x55 };
        c.optlen = 1;

        // Userspace buffer is PAGE_SIZE * 2, but BPF program can only see
        // the first PAGE_SIZE bytes of data.
        if (optval_end as usize) - (optval as usize) != unsafe { page_size } as usize {
            return 0; // unexpected data size
        }

        return 1;
    }

    if c.level != SOL_CUSTOM {
        return 0; // deny everything except custom level
    }

    if unsafe { optval.add(1) } > optval_end {
        return 0; // bounds check
    }

    let storage = bpf_sk_storage_get(
        &socket_storage_map,
        c.sk as *mut c_void,
        core::ptr::null_mut(),
        BPF_SK_STORAGE_GET_F_CREATE,
    ) as *mut sockopt_sk;
    if storage.is_null() {
        return 0; // couldn't get sk storage
    }

    if c.retval == 0 {
        return 0; // kernel should not have handled SOL_CUSTOM, something is
                  // wrong!
    }
    c.retval = 0; // Reset system call return value to zero

    unsafe { *optval = (*storage).val };
    c.optlen = 1;

    1
}

#[link_section = "cgroup/setsockopt"]
#[no_mangle]
extern "C" fn _setsockopt(ctx: *mut bpf_sockopt) -> i32 {
    let c = unsafe { &mut *ctx };
    let optval = c.optval as *mut u8;
    let optval_end = c.optval_end as *mut u8;

    // Bypass AF_NETLINK.
    let sk_ptr = c.sk as *const bpf_sock;
    if !sk_ptr.is_null() {
        let sk = unsafe { &*sk_ptr };
        if sk.family == AF_NETLINK {
            return out(c);
        }

        if sk.family == AF_INET && sk.r#type == SOCK_RAW {
            let tp = bpf_tcp_sock(c.sk as *mut c_void);

            if !tp.is_null() {
                let mut saved_syn = [0u8; 60];
                bpf_getsockopt(
                    c.sk as *mut c_void,
                    SOL_TCP,
                    TCP_SAVED_SYN,
                    saved_syn.as_mut_ptr() as *mut c_void,
                    60,
                );
                // consumed: ctx->optlen = -1 below applies here too.
                c.optlen = -1;
                return 1;
            }

            return out(c);
        }
    }

    // Make sure bpf_get_netns_cookie is callable.
    if bpf_get_netns_cookie(core::ptr::null::<c_void>()) == 0 {
        return 0;
    }
    if bpf_get_netns_cookie(ctx as *const c_void) == 0 {
        return 0;
    }

    if c.level == SOL_IP && c.optname == IP_TOS {
        // Not interested in SOL_IP:IP_TOS; let next BPF program in the
        // cgroup chain or kernel handle it.
        c.optlen = 0; // bypass optval>PAGE_SIZE
        return 1;
    }

    if c.level == SOL_SOCKET && c.optname == SO_SNDBUF {
        // Overwrite SO_SNDBUF value

        if unsafe { optval.add(4) } > optval_end {
            return 0; // bounds check
        }

        unsafe { core::ptr::write_unaligned(optval as *mut u32, 0x55AA) };
        c.optlen = 4;

        return 1;
    }

    if c.level == SOL_TCP && c.optname == TCP_CONGESTION {
        // Always use cubic

        if unsafe { optval.add(5) } > optval_end {
            return 0; // bounds check
        }

        unsafe { vcopy(optval, b"cubic".as_ptr(), 5) };
        c.optlen = 5;

        return 1;
    }

    if c.level == SOL_IP && c.optname == IP_FREEBIND {
        // Original optlen is larger than PAGE_SIZE.
        if c.optlen != unsafe { page_size } * 2 {
            return 0; // unexpected data size
        }

        if unsafe { optval.add(1) } > optval_end {
            return 0; // bounds check
        }

        // Make sure we can trim the buffer.
        unsafe { *optval = 0 };
        c.optlen = 1;

        // Userspace buffer is PAGE_SIZE * 2, but BPF program can only see
        // the first PAGE_SIZE bytes of data.
        if (optval_end as usize) - (optval as usize) != unsafe { page_size } as usize {
            return 0; // unexpected data size
        }

        return 1;
    }

    if c.level != SOL_CUSTOM {
        return 0; // deny everything except custom level
    }

    if unsafe { optval.add(1) } > optval_end {
        return 0; // bounds check
    }

    let storage = bpf_sk_storage_get(
        &socket_storage_map,
        c.sk as *mut c_void,
        core::ptr::null_mut(),
        BPF_SK_STORAGE_GET_F_CREATE,
    ) as *mut sockopt_sk;
    if storage.is_null() {
        return 0; // couldn't get sk storage
    }

    unsafe { (*storage).val = *optval };

    // BPF has consumed this option, don't call kernel setsockopt handler.
    c.optlen = -1;

    1
}

bpf_object!("GPL");
