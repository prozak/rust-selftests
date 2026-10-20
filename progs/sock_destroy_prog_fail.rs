// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Translation of tools/testing/selftests/bpf/progs/sock_destroy_prog_fail.c,
// bpf-rs-core idiom.
//
// A NEGATIVE verifier test: bpf_sock_destroy is a kfunc the kernel allows
// only to socket iterator programs; calling it from a tp_btf program is
// rejected with the message declared below. `struct sock` and
// `struct sock_common` are opaque here (the program only forwards the
// pointer; the C's cast is address-preserving), and the kfunc's prototype is
// mirrored from the kernel's BTF, as in sock_destroy_prog.rs.

use bpf_rs_core::bpf_object;
use bpf_rs_core::progs::fentry_arg as arg;
use bpf_rs_core::test_tags;

#[repr(C)]
struct sock_common {
    _opaque: [u8; 0],
}

extern "C" {
    fn bpf_sock_destroy(sk: *mut sock_common) -> i32;
}

test_tags! {
    trace_tcp_destroy_sock: __failure, __msg("calling kernel function bpf_sock_destroy is not allowed");
}

#[link_section = "tp_btf/tcp_destroy_sock"]
#[no_mangle]
extern "C" fn trace_tcp_destroy_sock(ctx: *const u64) -> i32 {
    // C: BPF_PROG(trace_tcp_destroy_sock, struct sock *sk); should not load
    let sk = arg(ctx, 0) as *mut sock_common;
    unsafe { bpf_sock_destroy(sk) };

    0
}

bpf_object!("GPL");
