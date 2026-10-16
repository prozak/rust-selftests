// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// BTF_C_CHAR: u8

// Direct translation of tools/testing/selftests/bpf/progs/test_skc_to_unix_sock.c
// (bpf-rs-core idiom).
//
// `unix_sk->addr->name->sun_path[i]` walks two internal kernel structs
// (`struct unix_sock`, `struct unix_address`) and one stable UAPI struct
// (`struct sockaddr_un`). The internal-struct hops (`sock->sk`,
// `unix_sock->addr`, `unix_address->len`) go through `#[btf]` so their byte
// offsets are CO-RE-relocated against the target kernel, same as
// cgroup_ancestor.rs's sock-nesting chain. `unix_address->name` is a
// flexible array member (`struct sockaddr_un name[]`); the field-reloc
// pipeline here only supports named-field byte-offset paths, not array
// terminals feeding further field chains, so its address is reached the same
// way recvmsg_unix_prog.rs reaches `sun_path`: a hand offset from `addr`,
// confirmed once via `pahole -C unix_address` against both this repo's UML
// (bpf-next) and QEMU (bpf-next-x86) vmlinux images (identical: `name` at
// byte 8, `struct sockaddr_un` size 8 header + array). `sun_path` itself sits
// at byte 2 of `sockaddr_un` (`sun_family` is `__kernel_sa_family_t`, a
// 2-byte UAPI type) -- the same UAPI-stable constant recvmsg_unix_prog.rs
// already relies on. Reads through this hand-computed address use
// `bpf_probe_read_kernel`, not a direct load: once arithmetic leaves the
// `#[btf]`-relocated chain the pointer is an ordinary scalar to the
// verifier, not a trusted `PTR_TO_BTF_ID`.

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel, bpf_skc_to_unix_sock};
use bpf_rs_core::progs::fentry_arg as arg;
use btf_macros::btf;

const SIZEOF_SHORT: i32 = 2; // sizeof(short) == sizeof(sa_family_t)
const SIZEOF_SUN_PATH: i32 = 108; // sizeof(unix_sk->addr->name->sun_path)
const UNIX_ADDR_NAME_OFFSET: usize = 8; // offsetof(struct unix_address, name)
const SOCKADDR_UN_SUN_PATH_OFFSET: usize = 2; // offsetof(struct sockaddr_un, sun_path)
const SUN_PATH_OFFSET_FROM_ADDR: usize = UNIX_ADDR_NAME_OFFSET + SOCKADDR_UN_SUN_PATH_OFFSET;

#[link_section = ".rodata"]
#[no_mangle]
static my_pid: i32 = 0;

#[no_mangle]
static mut path: [u8; 256] = [0; 256];

#[btf]
struct sock {}

#[btf]
struct socket {
    sk: *mut sock,
}

#[btf]
struct unix_address {
    len: i32,
}

#[btf]
struct unix_sock {
    addr: *mut unix_address,
}

#[link_section = "fentry/unix_listen"]
#[no_mangle]
extern "C" fn unix_listen(ctx: *const u64) -> i32 {
    let sock_ptr = arg(ctx, 0) as *const socket;

    let pid = (bpf_get_current_pid_tgid() >> 32) as i32;
    let want_pid = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(my_pid)) };
    if pid != want_pid {
        return 0;
    }

    let sk_ptr = unsafe { *(&*sock_ptr).sk().as_ptr() };
    let unix_sk = bpf_skc_to_unix_sock(sk_ptr as *mut c_void) as *const unix_sock;
    if unix_sk.is_null() {
        return 0;
    }

    let addr_ptr = unsafe { *(&*unix_sk).addr().as_ptr() };
    let sun_path_base = (addr_ptr as usize).wrapping_add(SUN_PATH_OFFSET_FROM_ADDR);

    let mut first: u8 = 0;
    bpf_probe_read_kernel(&mut first, 1, sun_path_base as *const c_void);
    if first != 0 {
        return 0;
    }

    let addr_len = unsafe { *(&*(addr_ptr as *const unix_address)).len().as_ptr() };
    let len = addr_len - SIZEOF_SHORT;

    unsafe {
        core::ptr::addr_of_mut!(path).cast::<u8>().write(b'@');
    }

    let mut i: i32 = 1;
    while i < len {
        if i >= SIZEOF_SUN_PATH {
            break;
        }

        let mut byte: u8 = 0;
        bpf_probe_read_kernel(&mut byte, 1, sun_path_base.wrapping_add(i as usize) as *const c_void);
        unsafe {
            core::ptr::addr_of_mut!(path).cast::<u8>().add(i as usize).write(byte);
        }

        i += 1;
    }

    0
}

bpf_object!("GPL");
