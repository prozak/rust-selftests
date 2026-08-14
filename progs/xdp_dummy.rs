#![no_std]
#![no_main]

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
// KNOWN GAP: prog_tests/btf_dump.c parses THIS object by name and
// string-compares a dump of its `license` DATASEC against
//     SEC("license") char[4] _license = (char[4])['G','P','L',];
// Our `bpf_object!` emits `[u8; 4]`, which the pipeline renders as
// `unsigned char[4]`, and nothing in the Rust type system maps to BTF
// `char` (u8 -> "unsigned char", i8 -> "signed char"). So
// btf_dump/datasec_data FAILS with this object while passing with the C
// one. Tracked separately as a BTF-emission issue; the translated code
// itself is correct and proves equivalent.

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

bpf_object!("GPL");
