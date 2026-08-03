#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/getpeername_unix_prog.c
// (bpf-rs-core idiom).
//
// The C source's post-rewrite sanity checks (bpf_core_cast(sa_kern->uaddr,
// struct sockaddr_un) + memcmp against SERVUN_REWRITE_ADDRESS) are dead code:
// every branch of the C function -- ret != 0, uaddrlen mismatch, memcmp
// mismatch, and the final fallthrough -- returns 1. bpf_core_cast also needs
// a BPF_TYPE_ID_TARGET CO-RE relocation (bpf_core_type_id_kernel), which
// btf-macros doesn't emit (only field byte_offset/field_exists relocations,
// see tcp_ca_untrusted_btf_write.rs). Since those checks can never change
// the return value, this translation reproduces only the behavior userspace
// actually observes: bpf_cast_to_kern_ctx() + bpf_sock_addr_set_sun_path()
// rewriting the peer's AF_UNIX address, then unconditionally returning 1.

use core::ffi::c_void;

use bpf_rs_core::bpf_object;

// C's `__u8 SERVUN_REWRITE_ADDRESS[] = "\0bpf_cgroup_unix_test_rewrite";` is a
// non-static, nonzero-initialized file-scope global -> a real GLOBAL OBJECT
// symbol in the C object (must be matched by name) that lands in .data (not
// .rodata). Both facts matter here: bpf_sock_addr_set_sun_path's `sun_path`
// kfunc argument is mirrored by add_ksyms.py from the kernel's real BTF
// proto, which strips the `const` qualifier while resolving the pointee
// (add_ksyms.py's typedef/const/volatile/restrict resolve() chain), so the
// verifier treats the argument as writable memory; a .rodata pointer there
// is rejected ("write into map forbidden"), matching why the C original
// itself never made this array `const`.
#[no_mangle]
static mut SERVUN_REWRITE_ADDRESS: [u8; 30] = *b"\0bpf_cgroup_unix_test_rewrite\0";

extern "C" {
    fn bpf_cast_to_kern_ctx(ctx: *mut c_void) -> *mut c_void;
    fn bpf_sock_addr_set_sun_path(
        sa_kern: *mut c_void,
        sun_path: *const u8,
        sun_path_sz: u32,
    ) -> i32;
}

#[link_section = "cgroup/getpeername_unix"]
#[no_mangle]
extern "C" fn getpeername_unix_prog(ctx: *const c_void) -> i32 {
    unsafe {
        let sa_kern = bpf_cast_to_kern_ctx(ctx as *mut c_void);
        bpf_sock_addr_set_sun_path(
            sa_kern,
            core::ptr::addr_of!(SERVUN_REWRITE_ADDRESS) as *const u8,
            29,
        );
    }

    1
}

bpf_object!("GPL");
