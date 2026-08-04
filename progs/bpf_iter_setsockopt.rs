#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_iter_setsockopt.c
// (bpf-rs-core idiom).
//
// C's `bpf_tcp_sk()` macro casts ctx->sk_common through bpf_skc_to_tcp_sock()
// and reinterprets the resulting tcp_sock* as struct sock* purely to read
// sk_family/sk_state/sk_num/sk_dport (via bpf_tracing_net.h's
// `#define sk_family __sk_common.skc_family` etc.). Those fields all live in
// sock_common, which sits at offset 0 of every struct in the tcp_sock ->
// inet_connection_sock -> inet_sock -> sock -> sock_common chain, so reading
// them straight off ctx->sk_common (already a sock_common*) is bit-identical
// and avoids needing a #[btf] tcp_sock/sock schema at all; bpf_getsockopt/
// bpf_setsockopt only need the tcp_sock pointer as an opaque handle.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_get_prandom_u32, bpf_getsockopt, bpf_setsockopt, bpf_skc_to_tcp_sock, bpf_strncmp,
};
use btf_macros::btf;
use core::ffi::c_void;

const AF_INET6: u16 = 10;
const TCP_ESTABLISHED: u8 = 1;
const TCP_LISTEN: u8 = 10;
const SOL_TCP: i32 = 6;
const TCP_CONGESTION: i32 = 13;
const TCP_CA_NAME_MAX: usize = 16;

#[repr(C)]
struct bpf_iter_meta {
    seq: *mut c_void,
    session_id: u64,
    seq_num: u64,
}

#[repr(C)]
struct bpf_iter__tcp {
    meta: *mut bpf_iter_meta,
    sk_common: *mut sock_common,
}

#[btf]
struct sock_common {
    skc_family: u16,
    skc_state: u8,
    skc_num: u16,
    skc_dport: u16,
}

#[no_mangle]
static mut reuse_listen_hport: u16 = 0;
#[no_mangle]
static mut listen_hport: u16 = 0;

#[link_section = ".rodata"]
#[no_mangle]
static cubic_cc: [u8; 10] = *b"bpf_cubic\0";

#[no_mangle]
static mut dctcp_cc: [u8; TCP_CA_NAME_MAX] = *b"bpf_dctcp\0\0\0\0\0\0\0";

#[no_mangle]
static mut random_retry: bool = false;

#[link_section = "iter/tcp"]
#[no_mangle]
extern "C" fn change_tcp_cc(ctx: *const bpf_iter__tcp) -> i32 {
    let ctx = unsafe { &*ctx };
    let skc = ctx.sk_common;
    if skc.is_null() {
        return 0;
    }

    let tp: *mut c_void = bpf_skc_to_tcp_sock(skc as *mut c_void);
    if tp.is_null() {
        return 0;
    }

    let skc_ref = unsafe { &*skc };
    let family = unsafe { *skc_ref.skc_family().as_ptr() };
    let state = unsafe { *skc_ref.skc_state().as_ptr() };
    let num = unsafe { *skc_ref.skc_num().as_ptr() };
    let dport = unsafe { *skc_ref.skc_dport().as_ptr() };

    let reuse_hport = unsafe { reuse_listen_hport };
    let hport = unsafe { listen_hport };

    if family != AF_INET6
        || (state != TCP_LISTEN && state != TCP_ESTABLISHED)
        || (num != reuse_hport && num != hport && u16::from_be(dport) != hport)
    {
        return 0;
    }

    let mut cur_cc: [u8; TCP_CA_NAME_MAX] = [0; TCP_CA_NAME_MAX];
    let ret = bpf_getsockopt(
        tp,
        SOL_TCP,
        TCP_CONGESTION,
        cur_cc.as_mut_ptr() as *mut c_void,
        core::mem::size_of_val(&cur_cc) as i32,
    );
    if ret != 0 {
        return 0;
    }

    let cmp = bpf_strncmp(
        cur_cc.as_ptr() as *const c_void,
        TCP_CA_NAME_MAX as u32,
        core::ptr::addr_of!(cubic_cc) as *const c_void,
    );
    if cmp != 0 {
        return 0;
    }

    if unsafe { random_retry } && bpf_get_prandom_u32() % 4 == 1 {
        return 1;
    }

    bpf_setsockopt(
        tp,
        SOL_TCP,
        TCP_CONGESTION,
        core::ptr::addr_of_mut!(dctcp_cc) as *mut c_void,
        TCP_CA_NAME_MAX as i32,
    );

    0
}

bpf_object!("GPL");
