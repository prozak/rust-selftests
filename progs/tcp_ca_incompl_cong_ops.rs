#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/tcp_ca_incompl_cong_ops.c
// bpf-rs-core idiom.
//
// prog_tests/bpf_tcp_ca.c's test_incompl_cong_ops() expects
// tcp_ca_incompl_cong_ops__open_and_load() to SUCCEED (this is a plain
// struct_ops object, not a __failure/__msg negative test); the required
// cong_avoid()/cong_control() members are intentionally left unset in the
// .struct_ops map, and the kernel only rejects that at
// bpf_map__attach_struct_ops() time (tcp_register_congestion_control()),
// which the test asserts fails via ASSERT_ERR_PTR.
//
// tcp_sk(sk) is `container_of(sk, struct tcp_sock, inet_conn.icsk_inet.sk)`:
// struct sock is the first member of inet_sock, which is the first member of
// inet_connection_sock, which is the first member of tcp_sock, so the cast
// is address-identical and only the snd_ssthresh/snd_cwnd field offsets need
// a real CO-RE relocation (see bpf_iter_netlink.rs for the `#[btf]` +
// `.field().as_ptr()` idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::progs::fentry_arg;
use btf_macros::btf;

#[btf]
struct tcp_sock {
    snd_cwnd: u32,
    snd_ssthresh: u32,
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn incompl_cong_ops_ssthresh(ctx: *const u64) -> u32 {
    let sk = fentry_arg(ctx, 0) as *const tcp_sock;
    unsafe { *(&*sk).snd_ssthresh().as_ptr() }
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn incompl_cong_ops_undo_cwnd(ctx: *const u64) -> u32 {
    let sk = fentry_arg(ctx, 0) as *const tcp_sock;
    unsafe { *(&*sk).snd_cwnd().as_ptr() }
}

// struct tcp_congestion_ops (net/tcp.h): only the members this program
// initializes are declared — libbpf's struct_ops relocation matches local
// struct members against the kernel type by name (see bpf_tcp_nogpl.rs).
// cong_avoid/cong_control are intentionally left out, matching the C source.
#[allow(non_camel_case_types)]
#[repr(C)]
struct tcp_congestion_ops {
    ssthresh: extern "C" fn(*const u64) -> u32,
    undo_cwnd: extern "C" fn(*const u64) -> u32,
    name: [u8; 16],
}

unsafe impl Sync for tcp_congestion_ops {}

#[link_section = ".struct_ops"]
#[no_mangle]
static incompl_cong_ops: tcp_congestion_ops = tcp_congestion_ops {
    ssthresh: incompl_cong_ops_ssthresh,
    undo_cwnd: incompl_cong_ops_undo_cwnd,
    name: *b"bpf_incompl_ops\0",
};

bpf_object!("GPL");
