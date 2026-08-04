#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bind4_prog.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_getsockopt, bpf_setsockopt};
use core::ffi::c_void;
use core::ptr::{addr_of, addr_of_mut};

const AF_INET: u32 = 2;
const SOCK_STREAM: u32 = 1;
const SOCK_DGRAM: u32 = 2;

const SOL_SOCKET: i32 = 1;
const SO_PRIORITY: i32 = 12;
const SO_REUSEPORT: i32 = 15;
const SO_BINDTODEVICE: i32 = 25;
const SO_MARK: i32 = 36;
const SO_BINDTOIFINDEX: i32 = 62;

const ENODEV: i64 = 19;

const SERV4_IP: u32 = 0xc0a801fe; /* 192.168.1.254 */
const SERV4_PORT: u16 = 4040;
const SERV4_REWRITE_IP: u32 = 0x7f000001; /* 127.0.0.1 */
const SERV4_REWRITE_PORT: u16 = 4444;

const IFNAMSIZ: usize = 16;

/// UAPI struct bpf_sock_addr (linux/bpf.h). sk is a __bpf_md_ptr union,
/// represented as u64 (this TU doesn't define __KERNEL__/__VMLINUX_H__, so
/// the real C object's field is also a plain __u64).
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

/// UAPI struct bpf_sock (linux/bpf.h), truncated to the fields this
/// translation reads (`family` at its real byte offset).
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_sock {
    bound_dev_if: u32,
    family: u32,
}

fn fill_name(buf: &mut [u8; IFNAMSIZ], name: &[u8]) {
    let ptr = buf.as_mut_ptr();
    let mut i = 0;
    while i < name.len() {
        unsafe { core::ptr::write_volatile(ptr.add(i), name[i]) };
        i += 1;
    }
}

fn bind_to_device(ctx: *mut bpf_sock_addr) -> i32 {
    let mut veth1: [u8; IFNAMSIZ] = [0; IFNAMSIZ];
    let mut veth2: [u8; IFNAMSIZ] = [0; IFNAMSIZ];
    let mut missing: [u8; IFNAMSIZ] = [0; IFNAMSIZ];
    let mut del_bind: [u8; IFNAMSIZ] = [0; IFNAMSIZ];
    fill_name(&mut veth1, b"test_sock_addr1");
    fill_name(&mut veth2, b"test_sock_addr2");
    fill_name(&mut missing, b"nonexistent_dev");
    let mut veth1_idx: i32 = 0;
    let mut veth2_idx: i32 = 0;

    if bpf_setsockopt(
        ctx,
        SOL_SOCKET,
        SO_BINDTODEVICE,
        veth1.as_mut_ptr() as *mut c_void,
        IFNAMSIZ as i32,
    ) != 0
    {
        return 1;
    }
    if bpf_getsockopt(
        ctx,
        SOL_SOCKET,
        SO_BINDTOIFINDEX,
        addr_of_mut!(veth1_idx) as *mut c_void,
        core::mem::size_of::<i32>() as i32,
    ) != 0
        || veth1_idx == 0
    {
        return 1;
    }
    if bpf_setsockopt(
        ctx,
        SOL_SOCKET,
        SO_BINDTODEVICE,
        veth2.as_mut_ptr() as *mut c_void,
        IFNAMSIZ as i32,
    ) != 0
    {
        return 1;
    }
    if bpf_getsockopt(
        ctx,
        SOL_SOCKET,
        SO_BINDTOIFINDEX,
        addr_of_mut!(veth2_idx) as *mut c_void,
        core::mem::size_of::<i32>() as i32,
    ) != 0
        || veth2_idx == 0
        || veth1_idx == veth2_idx
    {
        return 1;
    }
    if bpf_setsockopt(
        ctx,
        SOL_SOCKET,
        SO_BINDTODEVICE,
        missing.as_mut_ptr() as *mut c_void,
        IFNAMSIZ as i32,
    ) != -ENODEV
    {
        return 1;
    }
    if bpf_setsockopt(
        ctx,
        SOL_SOCKET,
        SO_BINDTOIFINDEX,
        addr_of_mut!(veth1_idx) as *mut c_void,
        core::mem::size_of::<i32>() as i32,
    ) != 0
    {
        return 1;
    }
    if bpf_setsockopt(
        ctx,
        SOL_SOCKET,
        SO_BINDTODEVICE,
        del_bind.as_mut_ptr() as *mut c_void,
        IFNAMSIZ as i32,
    ) != 0
    {
        return 1;
    }

    0
}

fn bind_reuseport(ctx: *mut bpf_sock_addr) -> i32 {
    let mut val: i32 = 1;

    if bpf_setsockopt(
        ctx,
        SOL_SOCKET,
        SO_REUSEPORT,
        addr_of_mut!(val) as *mut c_void,
        core::mem::size_of::<i32>() as i32,
    ) != 0
    {
        return 1;
    }
    if bpf_getsockopt(
        ctx,
        SOL_SOCKET,
        SO_REUSEPORT,
        addr_of_mut!(val) as *mut c_void,
        core::mem::size_of::<i32>() as i32,
    ) != 0
        || val == 0
    {
        return 1;
    }
    val = 0;
    if bpf_setsockopt(
        ctx,
        SOL_SOCKET,
        SO_REUSEPORT,
        addr_of_mut!(val) as *mut c_void,
        core::mem::size_of::<i32>() as i32,
    ) != 0
    {
        return 1;
    }
    if bpf_getsockopt(
        ctx,
        SOL_SOCKET,
        SO_REUSEPORT,
        addr_of_mut!(val) as *mut c_void,
        core::mem::size_of::<i32>() as i32,
    ) != 0
        || val != 0
    {
        return 1;
    }

    0
}

fn misc_opts(ctx: *mut bpf_sock_addr, opt: i32) -> i32 {
    let mut old: i32 = 0;
    let mut tmp: i32 = 0;
    let mut new: i32 = 0xeb9f;

    if bpf_getsockopt(
        ctx,
        SOL_SOCKET,
        opt,
        addr_of_mut!(old) as *mut c_void,
        core::mem::size_of::<i32>() as i32,
    ) != 0
        || old == new
    {
        return 1;
    }
    if bpf_setsockopt(
        ctx,
        SOL_SOCKET,
        opt,
        addr_of_mut!(new) as *mut c_void,
        core::mem::size_of::<i32>() as i32,
    ) != 0
    {
        return 1;
    }
    if bpf_getsockopt(
        ctx,
        SOL_SOCKET,
        opt,
        addr_of_mut!(tmp) as *mut c_void,
        core::mem::size_of::<i32>() as i32,
    ) != 0
        || tmp != new
    {
        return 1;
    }
    if bpf_setsockopt(
        ctx,
        SOL_SOCKET,
        opt,
        addr_of_mut!(old) as *mut c_void,
        core::mem::size_of::<i32>() as i32,
    ) != 0
    {
        return 1;
    }

    0
}

#[link_section = "cgroup/bind4"]
#[no_mangle]
extern "C" fn bind_v4_prog(ctx: *mut bpf_sock_addr) -> i32 {
    let c = unsafe { &mut *ctx };

    let sk = c.sk as *const bpf_sock;
    if sk.is_null() {
        return 0;
    }

    if unsafe { (*sk).family } != AF_INET {
        return 0;
    }

    if c.r#type != SOCK_STREAM && c.r#type != SOCK_DGRAM {
        return 0;
    }

    if c.user_ip4 != SERV4_IP.to_be() || c.user_port != SERV4_PORT.to_be() as u32 {
        return 0;
    }

    // u8 narrow loads:
    let ip4_bytes = addr_of!(c.user_ip4) as *const u8;
    let mut user_ip4: u32 = 0;
    user_ip4 |= (unsafe { core::ptr::read_volatile(ip4_bytes) } as u32) << 0;
    user_ip4 |= (unsafe { core::ptr::read_volatile(ip4_bytes.add(1)) } as u32) << 8;
    user_ip4 |= (unsafe { core::ptr::read_volatile(ip4_bytes.add(2)) } as u32) << 16;
    user_ip4 |= (unsafe { core::ptr::read_volatile(ip4_bytes.add(3)) } as u32) << 24;
    if c.user_ip4 != user_ip4 {
        return 0;
    }

    let port_bytes = addr_of!(c.user_port) as *const u8;
    let mut user_port: u32 = 0;
    user_port |= (unsafe { core::ptr::read_volatile(port_bytes) } as u32) << 0;
    user_port |= (unsafe { core::ptr::read_volatile(port_bytes.add(1)) } as u32) << 8;
    if c.user_port != user_port {
        return 0;
    }

    // u16 narrow loads:
    let ip4_words = addr_of!(c.user_ip4) as *const u16;
    let mut user_ip4_w: u32 = 0;
    user_ip4_w |= (unsafe { core::ptr::read_volatile(ip4_words) } as u32) << 0;
    user_ip4_w |= (unsafe { core::ptr::read_volatile(ip4_words.add(1)) } as u32) << 16;
    if c.user_ip4 != user_ip4_w {
        return 0;
    }

    /* Bind to device and unbind it. */
    if bind_to_device(ctx) != 0 {
        return 0;
    }

    /* Test for misc socket options. */
    if misc_opts(ctx, SO_MARK) != 0 || misc_opts(ctx, SO_PRIORITY) != 0 {
        return 0;
    }

    /* Set reuseport and unset */
    if bind_reuseport(ctx) != 0 {
        return 0;
    }

    c.user_ip4 = SERV4_REWRITE_IP.to_be();
    c.user_port = SERV4_REWRITE_PORT.to_be() as u32;

    1
}

#[link_section = "cgroup/bind4"]
#[no_mangle]
extern "C" fn bind_v4_deny_prog(_ctx: *mut bpf_sock_addr) -> i32 {
    0
}

bpf_object!("GPL");
