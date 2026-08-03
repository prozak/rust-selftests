#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/lwt_misc.c
// (bpf-rs-core idiom).

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::bpf_lwt_push_encap;

const BPF_LWT_ENCAP_IP: u32 = 2;

#[repr(C, packed)]
struct iphdr {
    ihl_version: u8, // low nibble = ihl, high nibble = version
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

#[link_section = "lwt_xmit"]
#[no_mangle]
extern "C" fn test_missing_dst(skb: *const __sk_buff) -> i32 {
    let mut iph: iphdr = unsafe { core::mem::zeroed() };

    iph.ihl_version = 5 | (4u8 << 4);

    bpf_lwt_push_encap(
        skb as *const c_void,
        BPF_LWT_ENCAP_IP,
        &iph as *const iphdr as *const c_void,
        core::mem::size_of::<iphdr>() as u32,
    );

    0
}

bpf_object!("GPL");
