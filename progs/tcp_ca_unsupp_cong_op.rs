#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/tcp_ca_unsupp_cong_op.c,
// bpf-rs-core idiom.
//
// get_info is intentionally not part of the kernel's allowed member set for
// struct tcp_congestion_ops (see net/ipv4/bpf_tcp_ca.c's
// bpf_tcp_ca_check_member()): prog_tests/bpf_tcp_ca.c's
// test_unsupp_cong_op() asserts open_and_load() fails with "attach to
// unsupported member get_info" — a kernel-side struct_ops registration
// check keyed on the member name, independent of the program body.

use bpf_rs_core::bpf_object;

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn unsupp_cong_op_get_info(_ctx: *const u64) -> usize {
    0
}

// struct tcp_congestion_ops (net/tcp.h): only the members this program
// initializes are declared — libbpf's struct_ops relocation matches local
// struct members against the kernel type by name (see bpf_tcp_nogpl.rs).
#[allow(non_camel_case_types)]
#[repr(C)]
struct tcp_congestion_ops {
    get_info: extern "C" fn(*const u64) -> usize,
    name: [u8; 16],
}

unsafe impl Sync for tcp_congestion_ops {}

#[link_section = ".struct_ops"]
#[no_mangle]
static unsupp_cong_op: tcp_congestion_ops = tcp_congestion_ops {
    get_info: unsupp_cong_op_get_info,
    name: *b"bpf_unsupp_op\0\0\0",
};

bpf_object!("GPL");
