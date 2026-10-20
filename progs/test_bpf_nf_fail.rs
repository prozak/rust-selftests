// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![allow(non_camel_case_types)]

// Direct translation of tools/testing/selftests/bpf/progs/test_bpf_nf_fail.c
// (bpf-rs-core idiom).
//
// Conntrack kfunc misuse rejections. prog_tests/bpf_nf.c loads each
// program by name with its own expected-message table
// (test_bpf_nf_fail_tests[]), so only the four NULL-argument programs
// carry __failure/__msg tags, as in the C. As in test_bpf_nf.rs the
// nf_conn/nf_conn___init pointers are `*mut c_void` end to end (the
// verifier types them from the kfunc prototypes add_ksyms.py mirrors),
// bpf_ct_opts___local and the ipv4 bpf_sock_tuple are plain repr(C)
// structs (KF_ARG_PTR_TO_MEM_SIZE, checked by size), and the one field
// write goes through a #[btf] CO-RE accessor.

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::{bpf_object, test_tags};
use btf_macros::btf;
use core::ffi::c_void;
use core::mem::size_of;
use core::ptr::null_mut;

/// UAPI struct xdp_md (linux/bpf.h).
#[repr(C)]
struct xdp_md {
    data: u32,
    data_end: u32,
    data_meta: u32,
    ingress_ifindex: u32,
    rx_queue_index: u32,
    egress_ifindex: u32,
}

#[repr(C)]
struct bpf_ct_opts___local {
    netns_id: i32,
    error: i32,
    l4proto: u8,
    reserved: [u8; 3],
}

// The ipv4 member of UAPI `struct bpf_sock_tuple`; sizeof(tup.ipv4) is
// what the C passes as the tuple length.
#[repr(C)]
struct bpf_sock_tuple {
    saddr: u32,
    daddr: u32,
    sport: u16,
    dport: u16,
}

#[btf]
struct nf_conn {
    status: u64,
}

extern "C" {
    fn bpf_skb_ct_alloc(
        ctx: *mut __sk_buff,
        tuple: *mut bpf_sock_tuple,
        tuple_len: u32,
        opts: *mut bpf_ct_opts___local,
        opts_len: u32,
    ) -> *mut c_void;
    fn bpf_skb_ct_lookup(
        ctx: *mut __sk_buff,
        tuple: *mut bpf_sock_tuple,
        tuple_len: u32,
        opts: *mut bpf_ct_opts___local,
        opts_len: u32,
    ) -> *mut c_void;
    fn bpf_xdp_ct_lookup(
        ctx: *mut xdp_md,
        tuple: *mut bpf_sock_tuple,
        tuple_len: u32,
        opts: *mut bpf_ct_opts___local,
        opts_len: u32,
    ) -> *mut c_void;
    fn bpf_ct_insert_entry(ct: *mut c_void) -> *mut c_void;
    fn bpf_ct_release(ct: *mut c_void);
    fn bpf_ct_set_timeout(ct: *mut c_void, timeout: u32);
    fn bpf_ct_change_timeout(ct: *mut c_void, timeout: u32) -> i32;
    fn bpf_ct_set_status(ct: *mut c_void, status: u32) -> i32;
    fn bpf_ct_change_status(ct: *mut c_void, status: u32) -> i32;
}

const TUP_LEN: u32 = size_of::<bpf_sock_tuple>() as u32;
const OPTS_LEN: u32 = size_of::<bpf_ct_opts___local>() as u32;

// struct bpf_ct_opts___local opts = {};
#[inline(always)]
fn zero_opts() -> bpf_ct_opts___local {
    bpf_ct_opts___local {
        netns_id: 0,
        error: 0,
        l4proto: 0,
        reserved: [0; 3],
    }
}

// struct bpf_sock_tuple tup = {};
#[inline(always)]
fn zero_tup() -> bpf_sock_tuple {
    bpf_sock_tuple {
        saddr: 0,
        daddr: 0,
        sport: 0,
        dport: 0,
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn alloc_release(ctx: *mut __sk_buff) -> i32 {
    let mut opts = zero_opts();
    let mut tup = zero_tup();

    unsafe {
        let ct = bpf_skb_ct_alloc(ctx, &mut tup, TUP_LEN, &mut opts, OPTS_LEN);
        if ct.is_null() {
            return 0;
        }
        bpf_ct_release(ct);
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn insert_insert(ctx: *mut __sk_buff) -> i32 {
    let mut opts = zero_opts();
    let mut tup = zero_tup();

    unsafe {
        let ct = bpf_skb_ct_alloc(ctx, &mut tup, TUP_LEN, &mut opts, OPTS_LEN);
        if ct.is_null() {
            return 0;
        }
        let ct = bpf_ct_insert_entry(ct);
        if ct.is_null() {
            return 0;
        }
        let _ct = bpf_ct_insert_entry(ct);
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn lookup_insert(ctx: *mut __sk_buff) -> i32 {
    let mut opts = zero_opts();
    let mut tup = zero_tup();

    unsafe {
        let ct = bpf_skb_ct_lookup(ctx, &mut tup, TUP_LEN, &mut opts, OPTS_LEN);
        if ct.is_null() {
            return 0;
        }
        bpf_ct_insert_entry(ct);
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn write_not_allowlisted_field(ctx: *mut __sk_buff) -> i32 {
    let mut opts = zero_opts();
    let mut tup = zero_tup();

    unsafe {
        let ct = bpf_skb_ct_lookup(ctx, &mut tup, TUP_LEN, &mut opts, OPTS_LEN);
        if ct.is_null() {
            return 0;
        }
        // ct->status = 0xF00;
        *(&*(ct as *const nf_conn)).status().as_mut_ptr() = 0xF00;
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn set_timeout_after_insert(ctx: *mut __sk_buff) -> i32 {
    let mut opts = zero_opts();
    let mut tup = zero_tup();

    unsafe {
        let ct = bpf_skb_ct_alloc(ctx, &mut tup, TUP_LEN, &mut opts, OPTS_LEN);
        if ct.is_null() {
            return 0;
        }
        let ct = bpf_ct_insert_entry(ct);
        if ct.is_null() {
            return 0;
        }
        bpf_ct_set_timeout(ct, 0);
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn set_status_after_insert(ctx: *mut __sk_buff) -> i32 {
    let mut opts = zero_opts();
    let mut tup = zero_tup();

    unsafe {
        let ct = bpf_skb_ct_alloc(ctx, &mut tup, TUP_LEN, &mut opts, OPTS_LEN);
        if ct.is_null() {
            return 0;
        }
        let ct = bpf_ct_insert_entry(ct);
        if ct.is_null() {
            return 0;
        }
        bpf_ct_set_status(ct, 0);
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn change_timeout_after_alloc(ctx: *mut __sk_buff) -> i32 {
    let mut opts = zero_opts();
    let mut tup = zero_tup();

    unsafe {
        let ct = bpf_skb_ct_alloc(ctx, &mut tup, TUP_LEN, &mut opts, OPTS_LEN);
        if ct.is_null() {
            return 0;
        }
        bpf_ct_change_timeout(ct, 0);
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn change_status_after_alloc(ctx: *mut __sk_buff) -> i32 {
    let mut opts = zero_opts();
    let mut tup = zero_tup();

    unsafe {
        let ct = bpf_skb_ct_alloc(ctx, &mut tup, TUP_LEN, &mut opts, OPTS_LEN);
        if ct.is_null() {
            return 0;
        }
        bpf_ct_change_status(ct, 0);
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn lookup_null_bpf_tuple(ctx: *mut __sk_buff) -> i32 {
    let mut opts = zero_opts();

    unsafe {
        let ct = bpf_skb_ct_lookup(ctx, null_mut(), 0, &mut opts, OPTS_LEN);
        if !ct.is_null() {
            bpf_ct_release(ct);
        }
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn lookup_null_bpf_opts(ctx: *mut __sk_buff) -> i32 {
    let mut tup = zero_tup();

    unsafe {
        let ct = bpf_skb_ct_lookup(ctx, &mut tup, TUP_LEN, null_mut(), OPTS_LEN);
        if !ct.is_null() {
            bpf_ct_release(ct);
        }
    }
    0
}

#[link_section = "?xdp"]
#[no_mangle]
extern "C" fn xdp_lookup_null_bpf_tuple(ctx: *mut xdp_md) -> i32 {
    let mut opts = zero_opts();

    unsafe {
        let ct = bpf_xdp_ct_lookup(ctx, null_mut(), 0, &mut opts, OPTS_LEN);
        if !ct.is_null() {
            bpf_ct_release(ct);
        }
    }
    0
}

#[link_section = "?xdp"]
#[no_mangle]
extern "C" fn xdp_lookup_null_bpf_opts(ctx: *mut xdp_md) -> i32 {
    let mut tup = zero_tup();

    unsafe {
        let ct = bpf_xdp_ct_lookup(ctx, &mut tup, TUP_LEN, null_mut(), OPTS_LEN);
        if !ct.is_null() {
            bpf_ct_release(ct);
        }
    }
    0
}

test_tags! {
    lookup_null_bpf_tuple: __failure, __msg("Possibly NULL pointer passed to trusted R2");
    lookup_null_bpf_opts: __failure, __msg("Possibly NULL pointer passed to trusted R4");
    xdp_lookup_null_bpf_tuple: __failure, __msg("Possibly NULL pointer passed to trusted R2");
    xdp_lookup_null_bpf_opts: __failure, __msg("Possibly NULL pointer passed to trusted R4");
}

bpf_object!("GPL");
