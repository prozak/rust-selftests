#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_tc_peer.c
// (bpf-rs-core idiom).

use core::ffi::c_void;

use bpf_rs_core::ctx::{__sk_buff, TC_ACT_SHOT};
use bpf_rs_core::helpers::{
    bpf_redirect, bpf_redirect_peer, bpf_skb_change_head, bpf_skb_store_bytes,
};
use bpf_rs_core::{bpf_object, vload, vstore};

const ETH_ALEN: usize = 6;
const ETH_HLEN: u32 = 14;
const BPF_F_EGRESS: u64 = 1 << 1;

#[link_section = ".rodata"]
#[no_mangle]
static IFINDEX_SRC: u32 = 0;

#[link_section = ".rodata"]
#[no_mangle]
static IFINDEX_DST: u32 = 0;

#[inline(always)]
fn ifindex_src() -> u32 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(IFINDEX_SRC)) }
}

#[inline(always)]
fn ifindex_dst() -> u32 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(IFINDEX_DST)) }
}

static SRC_MAC: [u8; ETH_ALEN] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
static DST_MAC: [u8; ETH_ALEN] = [0x00, 0x22, 0x33, 0x44, 0x55, 0x66];

#[link_section = "tc"]
#[no_mangle]
extern "C" fn tc_chk(_skb: *const __sk_buff) -> i32 {
    TC_ACT_SHOT
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn tc_dst(_skb: *const __sk_buff) -> i32 {
    bpf_redirect_peer(ifindex_src(), 0) as i32
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn tc_src(_skb: *const __sk_buff) -> i32 {
    bpf_redirect_peer(ifindex_dst(), 0) as i32
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn tc_dst_ing(skb: *mut __sk_buff) -> i32 {
    if vload!((*skb).mark) == 0 {
        vstore!((*skb).mark, 0x1);
        return bpf_redirect_peer(ifindex_src(), BPF_F_EGRESS) as i32;
    }

    bpf_redirect(ifindex_dst(), 0) as i32
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn tc_src_ing(skb: *mut __sk_buff) -> i32 {
    if vload!((*skb).mark) == 0 {
        vstore!((*skb).mark, 0x1);
        return bpf_redirect_peer(ifindex_dst(), BPF_F_EGRESS) as i32;
    }

    bpf_redirect(ifindex_src(), 0) as i32
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn tc_dst_l3(_skb: *const __sk_buff) -> i32 {
    bpf_redirect(ifindex_src(), 0) as i32
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn tc_src_l3(skb: *mut __sk_buff) -> i32 {
    let proto = vload!((*skb).protocol) as u16;

    if bpf_skb_change_head(skb as *const c_void, ETH_HLEN, 0) != 0 {
        return TC_ACT_SHOT;
    }

    if bpf_skb_store_bytes(
        skb as *const c_void,
        0,
        SRC_MAC.as_ptr() as *const c_void,
        ETH_ALEN as u32,
        0,
    ) != 0
    {
        return TC_ACT_SHOT;
    }

    if bpf_skb_store_bytes(
        skb as *const c_void,
        ETH_ALEN as u32,
        DST_MAC.as_ptr() as *const c_void,
        ETH_ALEN as u32,
        0,
    ) != 0
    {
        return TC_ACT_SHOT;
    }

    if bpf_skb_store_bytes(
        skb as *const c_void,
        ETH_ALEN as u32 * 2,
        core::ptr::addr_of!(proto) as *const c_void,
        core::mem::size_of::<u16>() as u32,
        0,
    ) != 0
    {
        return TC_ACT_SHOT;
    }

    bpf_redirect_peer(ifindex_dst(), 0) as i32
}

#[link_section = "license"]
#[no_mangle]
static __license: [u8; 4] = bpf_rs_core::__lic_bytes::<4>("GPL");

bpf_object!("GPL");
