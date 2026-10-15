// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/recvmsg_unix_prog.c
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

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use btf_macros::btf;

const SERVUN_ADDRESS_LEN: usize = 22;
const SUN_PATH_LEN: usize = SERVUN_ADDRESS_LEN - 1; // sizeof(SERVUN_ADDRESS) - 1
const SOCKADDR_UN_SUN_PATH_OFFSET: usize = 2; // offsetof(struct sockaddr_un, sun_path)
const UNADDRLEN: u32 = (SOCKADDR_UN_SUN_PATH_OFFSET + SERVUN_ADDRESS_LEN - 1) as u32;

#[no_mangle]
static mut SERVUN_ADDRESS: [u8; SERVUN_ADDRESS_LEN] = *b"\0bpf_cgroup_unix_test\0";

// Minimal local BTF view of the kernel's `struct bpf_sock_addr_kern`
// (include/linux/filter.h): only the fields this program reads. CO-RE
// field-byte-offset relocation matches these by name against the target
// kernel's real struct.
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
    fn bpf_cast_to_kern_ctx(obj: *mut c_void) -> *mut c_void;
    fn bpf_sock_addr_set_sun_path(sa_kern: *mut c_void, sun_path: *const u8, sun_path_sz: u32) -> i32;
}

#[link_section = "cgroup/recvmsg_unix"]
#[no_mangle]
extern "C" fn recvmsg_unix_prog(ctx: *mut c_void) -> i32 {
    let sa_kern = unsafe { bpf_cast_to_kern_ctx(ctx) } as *const bpf_sock_addr_kern;

    // Address of the static's data, never a copy of the whole array: a
    // bulk [u8; N] copy gets MemCpyOpt-rewritten to an unresolvable
    // `bpf_arena_memcpy` kfunc call (this object has no arena map, so the
    // kfunc ksym never resolves and the load is rejected).
    let servun_ptr = core::ptr::addr_of!(SERVUN_ADDRESS) as *const u8;

    let ret =
        unsafe { bpf_sock_addr_set_sun_path(sa_kern as *mut c_void, servun_ptr, SUN_PATH_LEN as u32) };
    if ret != 0 {
        return 1;
    }

    let uaddrlen = *unsafe { &*sa_kern }.uaddrlen().get().unwrap();
    if uaddrlen != UNADDRLEN {
        return 1;
    }

    let uaddr = *unsafe { &*sa_kern }.uaddr().get().unwrap();
    let sa_kern_unaddr =
        unsafe { bpf_rdonly_cast(uaddr as *const c_void, tid_sockaddr_un() as u32) }
            as *const sockaddr_un;
    let sun_path = unsafe { (*sa_kern_unaddr).sun_path().as_ptr() } as *const u8;
    let mut i = 0usize;
    while i < SUN_PATH_LEN {
        if unsafe { *sun_path.add(i) != *servun_ptr.add(i) } {
            return 1;
        }
        i += 1;
    }

    1
}

bpf_object!("GPL");
