#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/getsockname_unix_prog.c
// (bpf-rs-core idiom).
//
// The C original does:
//   sa_kern_unaddr = bpf_core_cast(sa_kern->uaddr, struct sockaddr_un);
//   memcmp(sa_kern_unaddr->sun_path, SERVUN_REWRITE_ADDRESS, ...)
// bpf_core_cast expands to bpf_rdonly_cast(ptr, bpf_core_type_id_kernel(struct
// sockaddr_un)) -- a BPF_TYPE_ID_TARGET CO-RE relocation this pipeline cannot
// emit (btf-macros only emits field byte_offset/field_exists relocations).
// struct sockaddr_un has no CO-RE-reachable path from bpf_sock_addr_kern
// either way, so instead of retyping the pointer we read the bytes directly:
// sun_path sits right after the 2-byte sun_family (no padding, standard UAPI
// layout), so `uaddr + 2` for `path_len` bytes via bpf_probe_read_kernel is
// exactly the memory memcmp() would have walked, without needing the pointer
// to carry a verifier-tracked struct sockaddr_un type.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_probe_read_kernel;
use btf_macros::btf;
use core::ffi::c_void;

/// UAPI struct bpf_sock_addr (linux/bpf.h). sk is a __bpf_md_ptr union,
/// represented as u64. No field is read here; the type only needs to carry
/// the right BTF name for the ctx parameter.
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

#[btf]
struct bpf_sock_addr_kern {
    uaddr: *mut u8,
    uaddrlen: u32,
}

extern "C" {
    fn bpf_cast_to_kern_ctx(obj: *const c_void) -> *mut c_void;
    fn bpf_sock_addr_set_sun_path(
        sa_kern: *mut c_void,
        sun_path: *const u8,
        sun_path_sz: u32,
    ) -> i32;
}

// offsetof(struct sockaddr_un, sun_path): sun_family is a 2-byte
// __kernel_sa_family_t immediately followed by sun_path, no padding.
const SUN_PATH_OFFSET: u32 = 2;
const SERVUN_REWRITE_LEN: usize = 30;
const PATH_LEN: usize = SERVUN_REWRITE_LEN - 1;

// C's SERVUN_REWRITE_ADDRESS is a plain (non-const) global, so clang places
// it in .data; a Rust `static` (no `mut`) is truly immutable and rustc
// places it in .rodata instead, which loads as a read-only map and makes
// bpf_sock_addr_set_sun_path's (const-ness dropped by the ksym pipeline,
// see below) write-classified access get rejected with "write into map
// forbidden". `static mut` reproduces the C section placement.
#[no_mangle]
static mut SERVUN_REWRITE_ADDRESS: [u8; SERVUN_REWRITE_LEN] =
    *b"\0bpf_cgroup_unix_test_rewrite\0";

#[link_section = "cgroup/getsockname_unix"]
#[no_mangle]
extern "C" fn getsockname_unix_prog(ctx: *const bpf_sock_addr) -> i32 {
    let sa_kern =
        unsafe { bpf_cast_to_kern_ctx(ctx as *const c_void) } as *mut bpf_sock_addr_kern;
    let sa_kern_ref = unsafe { &*sa_kern };

    let servun_ptr = core::ptr::addr_of!(SERVUN_REWRITE_ADDRESS) as *const u8;
    let path_len = PATH_LEN as u32;
    let unaddrlen = SUN_PATH_OFFSET + path_len;

    let ret = unsafe { bpf_sock_addr_set_sun_path(sa_kern as *mut c_void, servun_ptr, path_len) };
    if ret != 0 {
        return 1;
    }

    let uaddrlen = unsafe { *sa_kern_ref.uaddrlen().as_ptr() };
    if uaddrlen != unaddrlen {
        return 1;
    }

    let uaddr = unsafe { *sa_kern_ref.uaddr().as_ptr() };
    let sun_path = unsafe { (uaddr as *const u8).add(SUN_PATH_OFFSET as usize) };

    let mut buf = [0u8; PATH_LEN];
    bpf_probe_read_kernel(&mut buf, path_len, sun_path as *const c_void);

    let mut i = 0usize;
    while i < PATH_LEN {
        if buf[i] != unsafe { *servun_ptr.add(i) } {
            return 1;
        }
        i += 1;
    }

    1
}

bpf_object!("GPL");
