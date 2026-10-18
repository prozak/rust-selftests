// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/skb_csum_complete.c
// (bpf-rs-core idiom). prog_tests/skb_csum_complete.c runs each program on
// pkt_v4 with BPF_F_TEST_SKB_CHECKSUM_COMPLETE and checks that the
// test-run reports the checksum state the comments below describe.

use core::ffi::c_void;

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_skb_change_tail, bpf_skb_store_bytes};
use bpf_rs_core::{bpf_object, vload};

const BPF_F_RECOMPUTE_CSUM: u64 = 1;

#[link_section = "tc"]
#[no_mangle]
extern "C" fn change_tail_trim(skb: *mut __sk_buff) -> i32 {
    /*
     * Drops CHECKSUM_COMPLETE. skb->csum still covers the trimmed bytes,
     * which hold the non-zero tcp.urg_ptr of pkt_v4, so it no longer
     * matches the packet.
     */
    let len = vload!((*skb).len);
    if bpf_skb_change_tail(skb as *const c_void, len.wrapping_sub(4), 0) != 0 {
        return 1;
    }
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn change_tail_grow_write(skb: *mut __sk_buff) -> i32 {
    let val: u8 = 0xab;

    /*
     * Drops CHECKSUM_COMPLETE. The new bytes are zero and do not change
     * the sum, but the write below can no longer update skb->csum.
     */
    let len = vload!((*skb).len);
    if bpf_skb_change_tail(skb as *const c_void, len.wrapping_add(4), 0) != 0 {
        return 1;
    }
    let len = vload!((*skb).len);
    if bpf_skb_store_bytes(
        skb as *const c_void,
        len.wrapping_sub(1),
        &val as *const u8 as *const c_void,
        1,
        BPF_F_RECOMPUTE_CSUM,
    ) != 0
    {
        return 2;
    }
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn store_no_recompute(skb: *mut __sk_buff) -> i32 {
    let val: u8 = 0xab;

    /* skb stays CHECKSUM_COMPLETE, but skb->csum is not updated. */
    let len = vload!((*skb).len);
    if bpf_skb_store_bytes(
        skb as *const c_void,
        len.wrapping_sub(1),
        &val as *const u8 as *const c_void,
        1,
        0,
    ) != 0
    {
        return 1;
    }
    0
}

bpf_object!("GPL");
