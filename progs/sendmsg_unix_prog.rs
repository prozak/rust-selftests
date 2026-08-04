#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/sendmsg_unix_prog.c
// (bpf-rs-core idiom).
//
// The C original re-types sa_kern->uaddr via
// bpf_core_cast(sa_kern->uaddr, struct sockaddr_un), which expands to
// bpf_rdonly_cast(ptr, bpf_core_type_id_kernel(struct sockaddr_un)) — the
// type-id argument is a BPF_CORE_TYPE_ID_KERNEL relocation, a CO-RE kind
// btf-macros does not emit (it only emits byte_offset/field_exists field
// relocations). Passing btf_id 0 instead (the only thing this pipeline can
// produce) would make bpf_rdonly_cast return PTR_TO_MEM with mem_size == 0,
// which rejects any access at all — not usable here since we genuinely need
// to read sun_path.
//
// struct sockaddr_un is a stable UAPI layout (sun_path always immediately
// follows the 2-byte sa_family_t, see include/uapi/linux/un.h), so instead
// of retyping the pointer we read sa_kern->uaddr as a raw address (an
// ordinary CO-RE field access, matched by name against the kernel's
// struct bpf_sock_addr_kern — the same mechanism the C source uses for
// sa_kern->uaddrlen), add the constant sun_path offset by hand, and reach
// the bytes with bpf_probe_read_kernel(). bpf_probe_read_kernel's pointer
// argument is ARG_ANYTHING, so the verifier never needs to know the
// pointee's BTF type at all.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_probe_read_kernel;
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

extern "C" {
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

fn bytes_equal(a: *const u8, b: *const u8, len: usize) -> bool {
    for i in 0..len {
        let x = unsafe { core::ptr::read_volatile(a.add(i)) };
        let y = unsafe { core::ptr::read_volatile(b.add(i)) };
        if x != y {
            return false;
        }
    }
    true
}

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
    if uaddr.is_null() {
        return 0;
    }
    let sun_path_ptr = unsafe { uaddr.add(SUN_PATH_OFFSET) };

    let mut buf = [0u8; REWRITE_LEN];
    let n = bpf_probe_read_kernel(&mut buf, REWRITE_LEN as u32, sun_path_ptr as *const c_void);
    if n != 0 {
        return 0;
    }

    if !bytes_equal(buf.as_ptr(), rewrite_addr, REWRITE_LEN) {
        return 0;
    }

    1
}

#[link_section = "cgroup/sendmsg_unix"]
#[no_mangle]
extern "C" fn sendmsg_unix_deny_prog(_ctx: *const bpf_sock_addr) -> i32 {
    0
}

bpf_object!("GPL");
