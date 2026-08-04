#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bind6_prog.c
// (bpf-rs-core idiom). load_byte()/load_word() from bind_prog.h become
// explicit per-byte/per-halfword volatile loads off the ctx field address
// (little-endian variant), matching the narrow-ctx-access verifier test.

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_getsockopt, bpf_setsockopt};

const AF_INET6: u32 = 10;
const SOCK_STREAM: u32 = 1;
const SOCK_DGRAM: u32 = 2;

const SOL_SOCKET: i32 = 1;
const SO_PRIORITY: i32 = 12;
const SO_REUSEPORT: i32 = 15;
const SO_BINDTODEVICE: i32 = 25;
const SO_MARK: i32 = 36;
const SO_BINDTOIFINDEX: i32 = 62;

const ENODEV: i64 = 19;

const IFNAMSIZ: usize = 16;

const SERV6_IP_0: u32 = 0xfaceb00c;
const SERV6_IP_1: u32 = 0x12345678;
const SERV6_IP_2: u32 = 0x00000000;
const SERV6_IP_3: u32 = 0x0000abcd;
const SERV6_PORT: u16 = 6060;
const SERV6_REWRITE_IP_0: u32 = 0x00000000;
const SERV6_REWRITE_IP_1: u32 = 0x00000000;
const SERV6_REWRITE_IP_2: u32 = 0x00000000;
const SERV6_REWRITE_IP_3: u32 = 0x00000001;
const SERV6_REWRITE_PORT: u16 = 6666;

/// UAPI struct bpf_sock_addr (linux/bpf.h). sk is a __bpf_md_ptr union,
/// represented as u64.
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct bpf_sock_addr {
    pub user_family: u32,
    pub user_ip4: u32,
    pub user_ip6: [u32; 4],
    pub user_port: u32,
    pub family: u32,
    pub r#type: u32,
    pub protocol: u32,
    pub msg_src_ip4: u32,
    pub msg_src_ip6: [u32; 4],
    pub sk: u64,
}

/// UAPI struct bpf_sock (linux/bpf.h). Only the fields up to and including
/// `family` are used; matching the real byte layout is what matters (the
/// verifier checks sock-typed field access by offset).
#[repr(C)]
#[allow(dead_code)]
struct BpfSock {
    bound_dev_if: u32,
    family: u32,
}

#[inline(always)]
fn load_byte(addr: *const u32, b: u32) -> u32 {
    let base = addr as *const u8;
    (unsafe { core::ptr::read_volatile(base.add(b as usize)) } as u32) << (8 * b)
}

#[inline(always)]
fn load_word(addr: *const u32, w: u32) -> u32 {
    let base = addr as *const u16;
    (unsafe { core::ptr::read_volatile(base.add(w as usize)) } as u32) << (16 * w)
}

// Static device-name buffers: a runtime array-literal deref-assign into a
// stack buffer gets MemCpyOpt-rewritten into an unresolvable extern
// `bpf_arena_memcpy` kfunc call, so the fixed byte content lives in .rodata
// statics instead (link-time initialized, no runtime copy).
static VETH1: [u8; IFNAMSIZ] = *b"test_sock_addr1\0";
static VETH2: [u8; IFNAMSIZ] = *b"test_sock_addr2\0";
static MISSING_DEV: [u8; IFNAMSIZ] = *b"nonexistent_dev\0";
static DEL_BIND: [u8; IFNAMSIZ] = [0u8; IFNAMSIZ];

#[inline(never)]
fn bind_to_device(ctx: *mut bpf_sock_addr) -> i32 {
    let ctx_void = ctx as *mut c_void;

    let veth1 = core::ptr::addr_of!(VETH1) as *const u8 as *mut c_void;
    let veth2 = core::ptr::addr_of!(VETH2) as *const u8 as *mut c_void;
    let missing = core::ptr::addr_of!(MISSING_DEV) as *const u8 as *mut c_void;
    let del_bind = core::ptr::addr_of!(DEL_BIND) as *const u8 as *mut c_void;
    let mut veth1_idx: i32 = 0;
    let mut veth2_idx: i32 = 0;

    if bpf_setsockopt(
        ctx_void,
        SOL_SOCKET,
        SO_BINDTODEVICE,
        veth1,
        IFNAMSIZ as i32,
    ) != 0
    {
        return 1;
    }
    if bpf_getsockopt(
        ctx_void,
        SOL_SOCKET,
        SO_BINDTOIFINDEX,
        &mut veth1_idx as *mut i32 as *mut c_void,
        core::mem::size_of::<i32>() as i32,
    ) != 0
        || veth1_idx == 0
    {
        return 1;
    }
    if bpf_setsockopt(
        ctx_void,
        SOL_SOCKET,
        SO_BINDTODEVICE,
        veth2,
        IFNAMSIZ as i32,
    ) != 0
    {
        return 1;
    }
    if bpf_getsockopt(
        ctx_void,
        SOL_SOCKET,
        SO_BINDTOIFINDEX,
        &mut veth2_idx as *mut i32 as *mut c_void,
        core::mem::size_of::<i32>() as i32,
    ) != 0
        || veth2_idx == 0
        || veth1_idx == veth2_idx
    {
        return 1;
    }
    if bpf_setsockopt(
        ctx_void,
        SOL_SOCKET,
        SO_BINDTODEVICE,
        missing,
        IFNAMSIZ as i32,
    ) != -ENODEV
    {
        return 1;
    }
    if bpf_setsockopt(
        ctx_void,
        SOL_SOCKET,
        SO_BINDTOIFINDEX,
        &mut veth1_idx as *mut i32 as *mut c_void,
        core::mem::size_of::<i32>() as i32,
    ) != 0
    {
        return 1;
    }
    if bpf_setsockopt(
        ctx_void,
        SOL_SOCKET,
        SO_BINDTODEVICE,
        del_bind,
        IFNAMSIZ as i32,
    ) != 0
    {
        return 1;
    }

    0
}

#[inline(never)]
fn bind_reuseport(ctx: *mut bpf_sock_addr) -> i32 {
    let ctx_void = ctx as *mut c_void;
    let mut val: i32 = 1;

    if bpf_setsockopt(
        ctx_void,
        SOL_SOCKET,
        SO_REUSEPORT,
        &mut val as *mut i32 as *mut c_void,
        core::mem::size_of::<i32>() as i32,
    ) != 0
    {
        return 1;
    }
    if bpf_getsockopt(
        ctx_void,
        SOL_SOCKET,
        SO_REUSEPORT,
        &mut val as *mut i32 as *mut c_void,
        core::mem::size_of::<i32>() as i32,
    ) != 0
        || val == 0
    {
        return 1;
    }
    val = 0;
    if bpf_setsockopt(
        ctx_void,
        SOL_SOCKET,
        SO_REUSEPORT,
        &mut val as *mut i32 as *mut c_void,
        core::mem::size_of::<i32>() as i32,
    ) != 0
    {
        return 1;
    }
    if bpf_getsockopt(
        ctx_void,
        SOL_SOCKET,
        SO_REUSEPORT,
        &mut val as *mut i32 as *mut c_void,
        core::mem::size_of::<i32>() as i32,
    ) != 0
        || val != 0
    {
        return 1;
    }

    0
}

#[inline(never)]
fn misc_opts(ctx: *mut bpf_sock_addr, opt: i32) -> i32 {
    let ctx_void = ctx as *mut c_void;
    let mut old: i32 = 0;
    let mut tmp: i32 = 0;
    let new: i32 = 0xeb9f;

    if bpf_getsockopt(
        ctx_void,
        SOL_SOCKET,
        opt,
        &mut old as *mut i32 as *mut c_void,
        core::mem::size_of::<i32>() as i32,
    ) != 0
        || old == new
    {
        return 1;
    }
    if bpf_setsockopt(
        ctx_void,
        SOL_SOCKET,
        opt,
        &new as *const i32 as *mut c_void,
        core::mem::size_of::<i32>() as i32,
    ) != 0
    {
        return 1;
    }
    if bpf_getsockopt(
        ctx_void,
        SOL_SOCKET,
        opt,
        &mut tmp as *mut i32 as *mut c_void,
        core::mem::size_of::<i32>() as i32,
    ) != 0
        || tmp != new
    {
        return 1;
    }
    if bpf_setsockopt(
        ctx_void,
        SOL_SOCKET,
        opt,
        &mut old as *mut i32 as *mut c_void,
        core::mem::size_of::<i32>() as i32,
    ) != 0
    {
        return 1;
    }

    0
}

#[link_section = "cgroup/bind6"]
#[no_mangle]
extern "C" fn bind_v6_prog(ctx: *const bpf_sock_addr) -> i32 {
    let ctx_mut = ctx as *mut bpf_sock_addr;
    let ctx_ref = unsafe { &mut *ctx_mut };

    let sk = ctx_ref.sk as *const BpfSock;
    if sk.is_null() {
        return 0;
    }

    if unsafe { (*sk).family } != AF_INET6 {
        return 0;
    }

    if ctx_ref.r#type != SOCK_STREAM && ctx_ref.r#type != SOCK_DGRAM {
        return 0;
    }

    if ctx_ref.user_ip6[0] != SERV6_IP_0.to_be()
        || ctx_ref.user_ip6[1] != SERV6_IP_1.to_be()
        || ctx_ref.user_ip6[2] != SERV6_IP_2.to_be()
        || ctx_ref.user_ip6[3] != SERV6_IP_3.to_be()
        || ctx_ref.user_port != (SERV6_PORT as u16).to_be() as u32
    {
        return 0;
    }

    // u8 narrow loads:
    for i in 0..4usize {
        let addr = core::ptr::addr_of!(ctx_ref.user_ip6[i]);
        let mut user_ip6: u32 = 0;
        user_ip6 |= load_byte(addr, 0);
        user_ip6 |= load_byte(addr, 1);
        user_ip6 |= load_byte(addr, 2);
        user_ip6 |= load_byte(addr, 3);
        if ctx_ref.user_ip6[i] != user_ip6 {
            return 0;
        }
    }

    {
        let addr = core::ptr::addr_of!(ctx_ref.user_port);
        let mut user_port: u16 = 0;
        user_port |= load_byte(addr, 0) as u16;
        user_port |= load_byte(addr, 1) as u16;
        if ctx_ref.user_port != user_port as u32 {
            return 0;
        }
    }

    // u16 narrow loads:
    for i in 0..4usize {
        let addr = core::ptr::addr_of!(ctx_ref.user_ip6[i]);
        let mut user_ip6: u32 = 0;
        user_ip6 |= load_word(addr, 0);
        user_ip6 |= load_word(addr, 1);
        if ctx_ref.user_ip6[i] != user_ip6 {
            return 0;
        }
    }

    // Bind to device and unbind it.
    if bind_to_device(ctx_mut) != 0 {
        return 0;
    }

    // Test for misc socket options.
    if misc_opts(ctx_mut, SO_MARK) != 0 || misc_opts(ctx_mut, SO_PRIORITY) != 0 {
        return 0;
    }

    // Set reuseport and unset.
    if bind_reuseport(ctx_mut) != 0 {
        return 0;
    }

    ctx_ref.user_ip6[0] = SERV6_REWRITE_IP_0.to_be();
    ctx_ref.user_ip6[1] = SERV6_REWRITE_IP_1.to_be();
    ctx_ref.user_ip6[2] = SERV6_REWRITE_IP_2.to_be();
    ctx_ref.user_ip6[3] = SERV6_REWRITE_IP_3.to_be();
    ctx_ref.user_port = SERV6_REWRITE_PORT.to_be() as u32;

    1
}

#[link_section = "cgroup/bind6"]
#[no_mangle]
extern "C" fn bind_v6_deny_prog(_ctx: *const bpf_sock_addr) -> i32 {
    0
}

bpf_object!("GPL");
