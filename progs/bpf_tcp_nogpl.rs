#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_tcp_nogpl.c,
// bpf-rs-core idiom.
//
// license is intentionally non-GPL ("X"): prog_tests/bpf_tcp_ca.c's
// test_invalid_license() asserts open_and_load() fails with "struct ops
// programs must have a GPL compatible license" — the kernel's
// check_struct_ops_btf_id() rejects any struct_ops program whose object
// license isn't GPL-compatible, before any other validation.

use bpf_rs_core::bpf_object;

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn nogpltcp_init(_ctx: *const u64) {}

// struct tcp_congestion_ops (net/tcp.h): only the members this program
// initializes are declared — libbpf's struct_ops relocation matches local
// struct members against the kernel type by name, so a partial mirror is
// sufficient (see bpf-rs-core map-value special-field convention).
#[allow(non_camel_case_types)]
#[repr(C)]
struct tcp_congestion_ops {
    init: extern "C" fn(*const u64),
    name: [u8; 16],
}

unsafe impl Sync for tcp_congestion_ops {}

#[link_section = ".struct_ops"]
#[no_mangle]
static bpf_nogpltcp: tcp_congestion_ops = tcp_congestion_ops {
    init: nogpltcp_init,
    name: *b"bpf_nogpltcp\0\0\0\0",
};

bpf_object!("X");
