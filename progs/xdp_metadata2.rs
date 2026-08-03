#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/xdp_metadata2.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;

const XDP_PASS: i32 = 2;

/// UAPI struct xdp_md (linux/bpf.h).
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct xdp_md {
    pub data: u32,
    pub data_end: u32,
    pub data_meta: u32,
    pub ingress_ifindex: u32,
    pub rx_queue_index: u32,
    pub egress_ifindex: u32,
}

extern "C" {
    // enum xdp_rss_hash_type has underlying type int, same layout as u32.
    fn bpf_xdp_metadata_rx_hash(ctx: *const xdp_md, hash: *mut u32, rss_type: *mut u32) -> i32;
}

#[no_mangle]
static mut called: i32 = 0;

#[link_section = "freplace/rx"]
#[no_mangle]
extern "C" fn freplace_rx(ctx: *const xdp_md) -> i32 {
    let mut hash: u32 = 0;
    let mut rss_type: u32 = 0;
    // Call _any_ metadata function to make sure we don't crash.
    unsafe { bpf_xdp_metadata_rx_hash(ctx, &mut hash, &mut rss_type) };
    unsafe { called += 1 };
    XDP_PASS
}

bpf_object!("GPL");
