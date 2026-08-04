#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_lwt_reroute.c
// (bpf-rs-core idiom).
//
// Extracts the last byte of the daddr from the raw packet bytes at
// skb->data (bound-checked against data_end, same as the C cursor idiom)
// and uses it as the reroute mark.

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::{vload, vstore};

const BPF_OK: i32 = 0;
const BPF_DROP: i32 = 2;
const BPF_LWT_REROUTE: i32 = 128;

#[repr(C, packed)]
struct iphdr {
    #[allow(dead_code)]
    ihl_version: u8,
    #[allow(dead_code)]
    tos: u8,
    #[allow(dead_code)]
    tot_len: u16,
    #[allow(dead_code)]
    id: u16,
    #[allow(dead_code)]
    frag_off: u16,
    #[allow(dead_code)]
    ttl: u8,
    #[allow(dead_code)]
    protocol: u8,
    #[allow(dead_code)]
    check: u16,
    #[allow(dead_code)]
    saddr: u32,
    daddr: u32,
}

#[link_section = "lwt_xmit"]
#[no_mangle]
extern "C" fn test_lwt_reroute(skb: *mut __sk_buff) -> i32 {
    let start = vload!((*skb).data) as usize;
    let end = vload!((*skb).data_end) as usize;

    if vload!((*skb).mark) != 0 {
        return BPF_OK;
    }

    if start + core::mem::size_of::<iphdr>() > end {
        return BPF_DROP;
    }

    let iph = start as *const iphdr;
    let daddr = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*iph).daddr)) };
    let mark = u32::from_be(daddr) & 0xff;

    vstore!((*skb).mark, mark);

    if mark == 0 {
        return BPF_OK;
    }

    BPF_LWT_REROUTE
}

bpf_object!("GPL");
