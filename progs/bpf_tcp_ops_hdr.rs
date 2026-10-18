// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_tcp_ops_hdr.c
// (bpf-rs-core idiom). One struct bpf_tcp_ops instance whose listen and
// connect callbacks turn on header-option parsing and writing for the
// socket, hdr_opt_len reserves four bytes, write_hdr_opt stores an
// experimental option and parse_hdr looks it up on the receiving side;
// prog_tests/bpf_tcp_ops_hdr.c reads the counters and the two found bytes.
// Only the five members the C sets are declared (libbpf matches the kernel
// struct's members by name).

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_load_hdr_opt, bpf_reserve_hdr_opt, bpf_store_hdr_opt};
use bpf_rs_core::progs::fentry_arg as arg;

/* Experimental option kind and payload written/parsed by this test. */
const TEST_OPT_KIND: u8 = 0xFD;
const TEST_OPT_LEN: u8 = 4;
const TEST_OPT_D0: u8 = 0xAB;
const TEST_OPT_D1: u8 = 0xCD;

const BPF_TCP_OPS_FLAG_PARSE_HDR_OPT_ALL: u32 = 2;
const BPF_TCP_OPS_FLAG_PARSE_HDR_OPT_UNKNOWN: u32 = 4;
const BPF_TCP_OPS_FLAG_WRITE_HDR_OPT: u32 = 8;

#[no_mangle]
static mut hdr_opt_len_cnt: i32 = 0;
#[no_mangle]
static mut write_cnt: i32 = 0;
#[no_mangle]
static mut parse_cnt: i32 = 0;
#[no_mangle]
static mut found_cnt: i32 = 0;
#[no_mangle]
static mut found_d0: u8 = 0;
#[no_mangle]
static mut found_d1: u8 = 0;

#[allow(non_camel_case_types)]
#[repr(C)]
struct tcp_sock {
    _priv: [u8; 0],
}

extern "C" {
    fn bpf_tcp_ops_set_flags(tp: *mut tcp_sock, enable: u32, disable: u32) -> i32;
}

// BPF_PROG(test_listen, struct sock *sk)
#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn test_listen(ctx: *const u64) {
    let sk = arg(ctx, 0) as *mut tcp_sock;
    unsafe {
        bpf_tcp_ops_set_flags(
            sk,
            BPF_TCP_OPS_FLAG_PARSE_HDR_OPT_ALL | BPF_TCP_OPS_FLAG_WRITE_HDR_OPT,
            0,
        );
    }
}

// BPF_PROG(test_connect, struct sock *sk)
#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn test_connect(ctx: *const u64) {
    let sk = arg(ctx, 0) as *mut tcp_sock;
    unsafe {
        bpf_tcp_ops_set_flags(
            sk,
            BPF_TCP_OPS_FLAG_PARSE_HDR_OPT_UNKNOWN | BPF_TCP_OPS_FLAG_WRITE_HDR_OPT,
            0,
        );
    }
}

// BPF_PROG(test_hdr_opt_len, struct sock *sk, struct sk_buff *skb,
//          struct request_sock *req, struct sk_buff *syn_skb,
//          enum tcp_synack_type synack_type, unsigned int *remaining)
#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn test_hdr_opt_len(ctx: *const u64) {
    unsafe { hdr_opt_len_cnt += 1 };

    /*
     * Reserve TEST_OPT_LEN bytes; the helper decrements *remaining. Stacks
     * with other progs in the cgroup hierarchy.
     */
    bpf_reserve_hdr_opt(ctx as *mut c_void, TEST_OPT_LEN as u32, 0);
}

// BPF_PROG(test_write_hdr_opt, struct sock *sk, struct sk_buff *skb,
//          struct request_sock *req, struct sk_buff *syn_skb,
//          enum tcp_synack_type synack_type, __u32 opt_off)
#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn test_write_hdr_opt(ctx: *const u64) {
    let opt: [u8; 4] = [TEST_OPT_KIND, TEST_OPT_LEN, TEST_OPT_D0, TEST_OPT_D1];

    /*
     * bpf_store_hdr_opt() takes the program ctx (the kernel reads the
     * outgoing skb from it); it appends after any options already written
     * in the reserved window, rejects duplicates, and confines the write to
     * the header option scratch. Stacks across progs in the cgroup hierarchy.
     */
    if bpf_store_hdr_opt(ctx as *mut c_void, opt.as_ptr() as *const c_void, 4, 0) != 0 {
        return;
    }

    unsafe { write_cnt += 1 };
}

// BPF_PROG(test_parse_hdr, struct sock *sk, struct sk_buff *skb)
#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn test_parse_hdr(ctx: *const u64) {
    let mut opt: [u8; 4] = [TEST_OPT_KIND, TEST_OPT_LEN, TEST_OPT_D0, TEST_OPT_D1];

    unsafe { parse_cnt += 1 };

    /*
     * Look up the experimental option written by test_write_hdr_opt() in
     * the incoming skb. For an experimental kind the search matches on the
     * 2-byte magic in opt[2..3]; on a match the found option is copied back
     * into opt[].
     */
    if bpf_load_hdr_opt(ctx as *mut c_void, opt.as_mut_ptr() as *mut c_void, 4, 0) < 0 {
        return;
    }

    unsafe {
        found_d0 = core::ptr::read_volatile(opt.as_ptr().add(2));
        found_d1 = core::ptr::read_volatile(opt.as_ptr().add(3));
        found_cnt += 1;
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_tcp_ops {
    listen: extern "C" fn(*const u64),
    connect: extern "C" fn(*const u64),
    hdr_opt_len: extern "C" fn(*const u64),
    write_hdr_opt: extern "C" fn(*const u64),
    parse_hdr: extern "C" fn(*const u64),
}

unsafe impl Sync for bpf_tcp_ops {}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static test_hdr_ops: bpf_tcp_ops = bpf_tcp_ops {
    listen: test_listen,
    connect: test_connect,
    hdr_opt_len: test_hdr_opt_len,
    write_hdr_opt: test_write_hdr_opt,
    parse_hdr: test_parse_hdr,
};

bpf_object!("GPL");
