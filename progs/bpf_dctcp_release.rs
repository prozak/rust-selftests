#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_dctcp_release.c,
// bpf-rs-core idiom.
//
// prog_tests/bpf_tcp_ca.c's test_rel_setsockopt() asserts
// bpf_dctcp_release__open_and_load() FAILS with libbpf print output
// containing "program of this type cannot use helper bpf_setsockopt": the
// kernel's struct_ops "release" member has no attach cookie context that
// permits bpf_setsockopt (net/ipv4/bpf_tcp_ca.c's bpf_tcp_ca_check_attach_btf_id
// only allows setsockopt from tcp_congestion_ops members reachable while a
// socket lock is held for the operation, which "release" is not) — the
// verifier rejects the helper call for this attach_btf_id regardless of
// program content, so a faithful translation naturally reproduces the
// required load failure.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_setsockopt;
use bpf_rs_core::progs::fentry_arg;
use core::ffi::c_void;

const SOL_TCP: i32 = 6;
const TCP_CONGESTION: i32 = 13;

static CUBIC: [u8; 6] = *b"cubic\0";

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn dctcp_nouse_release(ctx: *const u64) {
    let sk = fentry_arg(ctx, 0) as *mut c_void;
    bpf_setsockopt(
        sk,
        SOL_TCP,
        TCP_CONGESTION,
        CUBIC.as_ptr() as *const c_void,
        CUBIC.len() as i32,
    );
}

// struct tcp_congestion_ops (net/tcp.h): only the members this program
// initializes are declared — libbpf's struct_ops relocation matches local
// struct members against the kernel type by name (see bpf_tcp_nogpl.rs).
#[allow(non_camel_case_types)]
#[repr(C)]
struct tcp_congestion_ops {
    release: extern "C" fn(*const u64),
    name: [u8; 16],
}

unsafe impl Sync for tcp_congestion_ops {}

#[link_section = ".struct_ops"]
#[no_mangle]
static dctcp_rel: tcp_congestion_ops = tcp_congestion_ops {
    release: dctcp_nouse_release,
    name: *b"bpf_dctcp_rel\0\0\0",
};

bpf_object!("GPL");
