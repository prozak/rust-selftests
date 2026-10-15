// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/sendmsg_unix_prog.c
// (bpf-rs-core idiom).
//
// bpf_core_cast(sa_kern->uaddr, struct sockaddr_un) is
// bpf_rdonly_cast(ptr, bpf_core_type_id_kernel(struct sockaddr_un)); the type
// id is the BTF_TYPE_ID declaration below (scripts/type_id.py).
// offsetof(struct sockaddr_un, sun_path) is a CO-RE relocation in the C;
// here it is the UAPI constant 2 (sun_family is a 2-byte
// __kernel_sa_family_t immediately followed by sun_path), the value that
// relocation resolves to on every kernel.

// BTF_TYPE_ID: tid_sockaddr_un struct sockaddr_un

use bpf_rs_core::bpf_object;
use btf_macros::btf;
use core::ffi::c_void;

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

/// Local CO-RE view of the kernel's struct bpf_sock_addr_kern (matched by
/// name); only the two members this program reads.
#[btf]
struct bpf_sock_addr_kern {
    uaddr: *const u8,
    uaddrlen: u32,
}

#[btf]
struct sockaddr_un {
    sun_path: [u8; 108],
}

extern "C" {
    fn bpf_rdonly_cast(obj: *const c_void, btf_id: u32) -> *mut c_void;
    fn tid_sockaddr_un() -> u64;
    fn bpf_cast_to_kern_ctx(ctx: *mut c_void) -> *mut c_void;
    fn bpf_sock_addr_set_sun_path(
        sa_kern: *mut c_void,
        sun_path: *const u8,
        sun_path_sz: u32,
    ) -> i32;
}

// Not `const`/`static` in the C original (`__u8 SERVUN_REWRITE_ADDRESS[]`),
// so it lives in writable .data there, not .rodata. This matters here: the
// bpf_sock_addr_set_sun_path kfunc's (ptr, size) argument pair is classified
// KF_ARG_PTR_TO_MEM_SIZE, which the verifier checks for BOTH read AND write
// access regardless of the kfunc's actual `const u8 *` parameter type — a
// .rodata (read-only, frozen) global fails that check. `static mut` (not a
// plain `static`) is required to land this in .data instead of .rodata.
#[no_mangle]
static mut SERVUN_REWRITE_ADDRESS: [u8; 30] = *b"\0bpf_cgroup_unix_test_rewrite\0";

// offsetof(struct sockaddr_un, sun_path): a __kernel_sa_family_t (2 bytes)
// immediately followed by sun_path, no padding.
const SUN_PATH_OFFSET: usize = 2;
// sizeof(SERVUN_REWRITE_ADDRESS) - 1: the address bytes without the
// compiler-appended trailing NUL.
const REWRITE_LEN: usize = 29;

#[link_section = "cgroup/sendmsg_unix"]
#[no_mangle]
extern "C" fn sendmsg_unix_prog(ctx: *const bpf_sock_addr) -> i32 {
    let sa_kern =
        unsafe { bpf_cast_to_kern_ctx(ctx as *mut c_void) } as *const bpf_sock_addr_kern;
    let rewrite_addr = core::ptr::addr_of!(SERVUN_REWRITE_ADDRESS) as *const u8;

    // Rewrite destination.
    let ret = unsafe {
        bpf_sock_addr_set_sun_path(sa_kern as *mut c_void, rewrite_addr, REWRITE_LEN as u32)
    };
    if ret != 0 {
        return 0;
    }

    let sa_kern_ref = unsafe { &*sa_kern };
    let unaddrlen = (SUN_PATH_OFFSET + REWRITE_LEN) as u32;
    let got_uaddrlen = *sa_kern_ref.uaddrlen().get().unwrap();
    if got_uaddrlen != unaddrlen {
        return 0;
    }

    let uaddr = *sa_kern_ref.uaddr().get().unwrap();
    let sa_kern_unaddr =
        unsafe { bpf_rdonly_cast(uaddr as *const c_void, tid_sockaddr_un() as u32) }
            as *const sockaddr_un;
    let sun_path = unsafe { (*sa_kern_unaddr).sun_path().as_ptr() } as *const u8;
    let mut i = 0usize;
    while i < REWRITE_LEN {
        if unsafe { *sun_path.add(i) != *rewrite_addr.add(i) } {
            return 0;
        }
        i += 1;
    }

    1
}

#[link_section = "cgroup/sendmsg_unix"]
#[no_mangle]
extern "C" fn sendmsg_unix_deny_prog(_ctx: *const bpf_sock_addr) -> i32 {
    0
}

bpf_object!("GPL");
