#![no_std]
#![no_main]

// BTF_C_CHAR: u8

// Direct translation of tools/testing/selftests/bpf/progs/xdp_dummy.c
// (bpf-rs-core idiom).
//
// The ctx is never dereferenced, but it must NOT be typed as an opaque
// pointer: prog_tests/fexit_bpf2bpf.c's func_replace_progmap attaches an
// freplace to xdp_dummy_prog, and the kernel checks the target's BTF
// signature at attach time. A `*const c_void` parameter emits a `c_void`
// pointee where the C emits `struct xdp_md`, and the attach is rejected —
// the prover still proves the pair EQUIV, because the difference is in the
// BTF rather than in what the code computes.
//
// prog_tests/btf_dump.c also checks the license DATASEC's exact char[4]
// representation. BTF_C_CHAR makes bpf_object!'s byte array match C char.

use bpf_rs_core::bpf_object;

/// UAPI struct xdp_md (linux/bpf.h).
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct xdp_md {
    pub data: u32,
    pub data_end: u32,
    pub data_meta: u32,
    pub ingress_ifindex: u32,
    pub rx_queue_index: u32,
    pub egress_ifindex: u32,
}

const XDP_PASS: i32 = 2;

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_dummy_prog(_ctx: *const xdp_md) -> i32 {
    XDP_PASS
}

/// Named after a syscall stub so prog_tests/fexit_bpf2bpf.c's
/// fentry_to_xdp_prog can attach a `fentry/__x64_sys_nop` tracing program
/// to THIS XDP program by fd, proving a tracing prog can target a BPF prog
/// whose name shadows a kernel symbol. Same signature rule as above.
#[link_section = "xdp"]
#[no_mangle]
extern "C" fn __x64_sys_nop(_ctx: *const xdp_md) -> i32 {
    XDP_PASS
}

bpf_object!("GPL");
