#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_lwt_redirect.c
// (bpf-rs-core idiom).

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_redirect, bpf_skb_change_head, bpf_skb_store_bytes};
use bpf_rs_core::vload;

const ETH_HLEN: u32 = 14;
const BPF_OK: i32 = 0;
const BPF_DROP: i32 = 2;
const BPF_F_INGRESS: u64 = 1;

#[repr(C, packed)]
struct iphdr {
    version_ihl: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    check: u16,
    saddr: u32,
    daddr: u32,
}

#[inline(always)]
fn prepend_dummy_mac(skb: *const __sk_buff) -> i32 {
    let mac: [u8; 14] = [
        0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0xf, 0xe, 0xd, 0xc, 0xb, 0xa, 0x08, 0x00,
    ];

    if bpf_skb_change_head(skb as *const c_void, ETH_HLEN, 0) != 0 {
        return -1;
    }

    if bpf_skb_store_bytes(
        skb as *const c_void,
        0,
        mac.as_ptr() as *const c_void,
        mac.len() as u32,
        0,
    ) != 0
    {
        return -1;
    }

    0
}

#[inline(always)]
fn get_redirect_target(skb: *const __sk_buff) -> i32 {
    let data = vload!((*skb).data) as usize;
    let data_end = vload!((*skb).data_end) as usize;

    if data + core::mem::size_of::<iphdr>() > data_end {
        return -1;
    }

    let iph = data as *const iphdr;
    let daddr = unsafe { (*iph).daddr };
    (u32::from_be(daddr) & 0xff) as i32
}

#[link_section = "redir_ingress"]
#[no_mangle]
extern "C" fn test_lwt_redirect_in(skb: *const __sk_buff) -> i32 {
    let target = get_redirect_target(skb);
    if target < 0 {
        return BPF_OK;
    }

    if prepend_dummy_mac(skb) != 0 {
        return BPF_DROP;
    }

    bpf_redirect(target as u32, BPF_F_INGRESS) as i32
}

#[link_section = "redir_egress"]
#[no_mangle]
extern "C" fn test_lwt_redirect_out(skb: *const __sk_buff) -> i32 {
    let target = get_redirect_target(skb);
    if target < 0 {
        return BPF_OK;
    }

    if prepend_dummy_mac(skb) != 0 {
        return BPF_DROP;
    }

    bpf_redirect(target as u32, 0) as i32
}

#[link_section = "redir_egress_nomac"]
#[no_mangle]
extern "C" fn test_lwt_redirect_out_nomac(skb: *const __sk_buff) -> i32 {
    let target = get_redirect_target(skb);
    if target < 0 {
        return BPF_OK;
    }

    bpf_redirect(target as u32, 0) as i32
}

#[link_section = "redir_ingress_nomac"]
#[no_mangle]
extern "C" fn test_lwt_redirect_in_nomac(skb: *const __sk_buff) -> i32 {
    let target = get_redirect_target(skb);
    if target < 0 {
        return BPF_OK;
    }

    bpf_redirect(target as u32, BPF_F_INGRESS) as i32
}

bpf_object!("GPL");
