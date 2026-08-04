#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/recvmsg_unix_prog.c
// (bpf-rs-core idiom).
//
// The C original's `sa_kern_unaddr = bpf_core_cast(sa_kern->uaddr, struct
// sockaddr_un)` expands to `bpf_rdonly_cast(ptr, bpf_core_type_id_kernel(...))`,
// which needs a clang `__builtin_btf_type_id` TYPE_ID CO-RE relocation; this
// toolchain's field_reloc pass only supports FIELD_BYTE_OFFSET/FIELD_EXISTS
// relocations, not TYPE_ID (see rust-bpf/bpf-postproc/src/field_reloc.rs), so
// that specific cast can't be reproduced. `struct sockaddr_un` is stable UAPI
// (2-byte sun_family, then sun_path immediately follows, no padding) rather
// than an internal kernel struct, so the cast is unnecessary anyway: reading
// `sa_kern->uaddr` (a plain named field of `bpf_sock_addr_kern`, relocatable
// by byte offset like any other CO-RE field) and computing `+2` by hand,
// fault-tolerantly loaded via `bpf_probe_read_kernel`, reproduces the same
// bytes the original macro would have exposed through `sun_path`.

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_probe_read_kernel;
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

extern "C" {
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
    let sun_path_addr = (uaddr as usize).wrapping_add(SOCKADDR_UN_SUN_PATH_OFFSET);

    let mut sun_path: [u8; SUN_PATH_LEN] = [0; SUN_PATH_LEN];
    bpf_probe_read_kernel(&mut sun_path, SUN_PATH_LEN as u32, sun_path_addr as *const c_void);

    let mut i = 0usize;
    while i < SUN_PATH_LEN {
        let want = unsafe { core::ptr::read_volatile(servun_ptr.add(i)) };
        if sun_path[i] != want {
            return 1;
        }
        i += 1;
    }

    1
}

bpf_object!("GPL");
